"""CLI for managing OAuth credentials for supported AI agents.

Installed as the ``credentials-helper`` console script (and runnable via
``python -m ai_credentials_helper.cli``). Pure Python — no bash/jq/xxd/curl.
All storage and OAuth work is delegated to the shared
``ai_credentials_helper.credentials`` module.

Modes (mutually exclusive, except --oauth-only which may accompany --send).
With no arguments, prints help (it does not dump credentials by default).
  --agent <name>   Which agent's credentials to operate on: claude (default)
                   or codex. For --receive, omitting this adopts whichever
                   agent the sender labeled the transfer with.
  --raw            Print the raw stored blob, exactly as stored.
  --simple         Print access_token / refresh_token / expires_at / expires.
  --oauth-only     Print only the portable token subset as compact JSON.
  --refresh        Refresh the access token, write it back, print --simple form.
                   (Claude only; codex refreshes tokens itself on use.)
  --import <file|-> Replace the active store from a file or stdin in its
                   backend-native representation.
  --send <host>    Encrypt the blob and send it to <host> over TCP (the
                   receiver must be running --receive first). With --oauth-only,
                   send only the portable token subset. The transfer is labeled
                   with the sending agent; a receiver pinned to a different
                   agent (via --agent) rejects it on both ends.
  --receive        Accept one TCP connection, verify+decrypt it, and write the
                   result to the store named in the sender's label. Pass
                   --agent to require a specific sender agent; a mismatch is a
                   hard error on both ends and neither store is touched.
  --serve          Serve repeated authenticated requests without changing stores.
  --request <host> Request and import --agent claude, codex, or all credentials.

--send/--receive are end-to-end encrypted with a shared passphrase
(CLAUDE_CREDENTIALS_PASSPHRASE, or an interactive prompt). Both ends must use
the same passphrase, and both ends must run a version of this tool that
supports the agent-identity envelope (this version) — an older, unlabelled
payload is rejected. See ai_credentials_helper.transfer_crypto for the
encryption construction and ai_credentials_helper.transfer_envelope for the
agent-identity envelope.
"""

import argparse
import getpass
import json
import logging
import os
import socket
import subprocess
import sys
import time
from datetime import datetime

from ai_credentials_helper import credentials as creds
from ai_credentials_helper import request_daemon, transfer_crypto, transfer_envelope

log = logging.getLogger("ai_credentials_helper.cli")

DEFAULT_PORT = 47299
SEND_TIMEOUT = 10  # seconds to wait for the TCP connection to the receiver

# On macOS, --send delegates the outbound TCP write to `nc`, an Apple platform
# binary exempt from Local Network Privacy. A third-party (Homebrew/uv/etc.)
# venv Python is blocked from LAN connect()s (EHOSTUNREACH); nc is not. Linux
# and WSL use the native socket path. Only the OUTBOUND hop is gated — --receive
# (bind/listen/accept) works natively in the venv Python, so it is not delegated.
# Overridable via env for tests.
NC_BINARY = os.environ.get("CLAUDE_CREDENTIALS_NC", "/usr/bin/nc")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _send_frame_native(frame: bytes, host: str, port: int) -> tuple[str | None, bytes]:
    try:
        with socket.create_connection((host, port), timeout=SEND_TIMEOUT) as conn:
            conn.sendall(frame)
            conn.shutdown(socket.SHUT_WR)
            # The receiver writes its authenticated ACK on this same connection
            # before closing (see _send_ack in _process_received_frame). A
            # timeout here just means no ACK arrived in time -- that is not a
            # send failure (the frame was already delivered), so it degrades to
            # an empty ack rather than raising; _report_send_ack treats empty as
            # "no acknowledgement received" instead of an error.
            try:
                ack = conn.recv(65535)
            except socket.timeout:
                ack = b""
    except socket.timeout:
        return f"timed out after {SEND_TIMEOUT}s", b""
    except OSError as exc:
        return str(exc) or "native socket error", b""
    return None, ack


def _send_frame_nc(frame: bytes, host: str, port: int) -> tuple[str | None, bytes]:
    try:
        proc = subprocess.run(
            [NC_BINARY, "-w", str(SEND_TIMEOUT), host, str(port)],
            input=frame,
            capture_output=True,
            timeout=SEND_TIMEOUT + 5,
        )
    except FileNotFoundError:
        return f"{NC_BINARY} not found", b""
    except subprocess.TimeoutExpired:
        return f"timed out after {SEND_TIMEOUT}s", b""
    if proc.returncode != 0:
        return proc.stderr.decode(errors="replace").strip() or f"nc exited {proc.returncode}", b""
    # nc keeps its read side open after our stdin EOF, so a receiver reply
    # written before it closes lands on nc's stdout -- that's the transport
    # for the authenticated ACK (verified live against a real listener; see
    # the design doc's "Verified assumptions" #2).
    return None, proc.stdout


def _send_frame(frame: bytes, host: str, port: int) -> tuple[str | None, str, bytes]:
    if sys.platform == "darwin":
        error, ack = _send_frame_nc(frame, host, port)
        return error, NC_BINARY, ack
    if sys.platform == "linux":
        error, ack = _send_frame_native(frame, host, port)
        return error, "native socket", ack
    return (
        "credential transfer is supported only on macOS, Linux, and WSL",
        "unsupported platform",
        b"",
    )


# Bound a hostile or buggy peer on --receive: drop a connection that goes idle,
# and refuse a stream larger than any real credential blob (~11 KB) so a peer
# cannot stream until memory exhaustion. Overridable via env for tuning/tests.
RECV_TIMEOUT = _int_env("CLAUDE_CREDENTIALS_RECV_TIMEOUT", 30)
MAX_PAYLOAD = _int_env("CLAUDE_CREDENTIALS_MAX_PAYLOAD", 1024 * 1024)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _store_label() -> str:
    """Human-readable description of the active backend's storage, for messages.

    Claude prints ``keychain service 'X'``; codex prints ``auth file 'X'`` —
    the noun matches the actual backend so users see something that maps to
    their filesystem (rather than ``None`` for codex, which has no keychain
    service at all).
    """
    if creds.KEYCHAIN_SERVICE:
        return f"keychain service {creds.KEYCHAIN_SERVICE!r}"
    # codex (and any future file-backed backend): show the file path.
    auth_path = getattr(creds._backend, "AUTH_PATH", None)
    return f"auth file {str(auth_path)!r}" if auth_path else "active store"


def _get_passphrase() -> str:
    """Return the transfer passphrase from the env, else prompt; never from argv.

    An empty passphrase is rejected (whether from an unset/empty env var or a
    bare Enter at the prompt) — an empty shared secret would defeat encryption.
    """
    pw = os.environ.get("CLAUDE_CREDENTIALS_PASSPHRASE")
    if not pw:
        if not sys.stdin.isatty():
            raise creds.CredentialsError(
                "no passphrase: set CLAUDE_CREDENTIALS_PASSPHRASE or run interactively"
            )
        pw = getpass.getpass("Passphrase: ")
    if not pw:
        raise creds.CredentialsError("empty passphrase not allowed")
    return pw


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="credentials-helper",
        description="Manage OAuth credentials for supported AI agents.",
        epilog=(
            "TCP transfers are end-to-end encrypted (AES-256-CBC + HMAC-SHA256) "
            "with a shared passphrase. Set CLAUDE_CREDENTIALS_PASSPHRASE on both "
            "ends, or you will be prompted. A wrong passphrase or tampered payload "
            "is rejected and the active store is left unchanged. The transfer is "
            "labeled with the sending agent; --receive without --agent adopts it, "
            "and a mismatched --agent is a hard error on both ends. Both ends must "
            "run a version of this tool that supports this agent label."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", "--verbose", action="store_true", help="log diagnostic detail to stderr")
    p.add_argument(
        "--agent",
        choices=("claude", "codex", "all"),
        default=None,
        help="which agent's credentials to operate on (default: claude; for "
             "--receive, omitting this adopts the sending agent named in the "
             "encrypted envelope; --request requires an agent and also accepts all)",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="skip backend safety checks on writes (e.g. JWT expiry). Shape "
             "checks still run. Use with care.",
    )
    p.add_argument("--raw", action="store_true", help="print the raw stored blob, as stored")
    p.add_argument("--simple", action="store_true", help="print the three OAuth fields")
    p.add_argument("--refresh", action="store_true", help="refresh the access token")
    p.add_argument(
        "--oauth-only",
        dest="oauth_only",
        action="store_true",
        help="only the portable token subset for the selected backend "
        "(alone, or as a --send modifier)",
    )
    p.add_argument(
        "--import",
        dest="import_path",
        metavar="<file|->",
        help="replace the active store in its backend-native representation",
    )
    p.add_argument(
        "--send", dest="send_host", metavar="<host>", help="encrypt and send the blob over TCP"
    )
    p.add_argument(
        "--send-port",
        dest="send_port",
        type=int,
        default=DEFAULT_PORT,
        metavar="<port>",
        help=f"destination port for --send/--request (default {DEFAULT_PORT})",
    )
    p.add_argument(
        "--receive", action="store_true", help="accept one TCP connection, decrypt, write it"
    )
    p.add_argument("--serve", action="store_true", help="serve repeated credential requests")
    p.add_argument("--request", dest="request_host", metavar="<host>",
                   help="request and import credentials from a serving host")
    p.add_argument("--bind", metavar="<address>",
                   help="IPv4 listening address for --serve (default: 0.0.0.0)")
    p.add_argument(
        "--port",
        dest="receive_port",
        type=int,
        default=DEFAULT_PORT,
        metavar="<port>",
        help=f"listening port for --receive/--serve (default {DEFAULT_PORT})",
    )
    return p


def _validate(args: argparse.Namespace) -> str | None:
    """Return an error message if the flag combination is invalid, else None."""
    if args.request_host is not None and not args.request_host:
        return "Error: --request requires a nonempty host"
    primary = sum(
        [
            args.raw,
            args.simple,
            args.refresh,
            bool(args.import_path),
            bool(args.send_host),
            args.receive,
            args.serve,
            bool(args.request_host),
        ]
    )
    if primary > 1:
        return (
            "Error: --raw, --simple, --refresh, --import, --send, --receive, --serve, --request "
            "are mutually exclusive"
        )
    if args.oauth_only and (
        args.raw or args.simple or args.refresh or args.import_path or args.receive
        or args.serve or args.request_host
    ):
        return "Error: --oauth-only can only be used by itself or with --send"
    if args.request_host and args.agent is None:
        return "Error: --request requires --agent claude, codex, or all"
    if args.agent == "all" and not args.request_host:
        return "Error: --agent all is only valid with --request"
    if args.serve and args.agent is not None:
        return "Error: --serve does not accept --agent"
    if args.serve and args.force:
        return "Error: --force is not valid with --serve"
    if args.bind is not None and not args.serve:
        return "Error: --bind is only valid with --serve"
    if (args.serve or args.request_host) and not (
        1 <= (args.receive_port if args.serve else args.send_port) <= 65535
    ):
        return "Error: port must be between 1 and 65535"
    if args.request_host and args.request_host.startswith("-"):
        return "Error: invalid request host"
    return None


def _format_expiry_verbose(expires_epoch: float) -> str:
    """Format expiry as 'June 23, 2026 8:13:12pm MDT' (no leading zeros, lowercase am/pm)."""
    dt = datetime.fromtimestamp(expires_epoch).astimezone()
    hour = dt.hour % 12 or 12
    ampm = "am" if dt.hour < 12 else "pm"
    return (
        f"{dt.strftime('%B')} {dt.day}, {dt.strftime('%Y')} "
        f"{hour}:{dt.strftime('%M:%S')}{ampm} {dt.strftime('%Z')}"
    )


def _print_simple(tokens: tuple[str, str, float]) -> None:
    access, refresh, expires_epoch = tokens
    expires_local = datetime.fromtimestamp(expires_epoch).strftime("%Y-%m-%d %I:%M:%S %p %Z")
    print(f"access_token:  {access}")
    print(f"refresh_token: {refresh}")
    print(f"expires_at:    {int(expires_epoch * 1000)}")
    print(f"expires:       {expires_local}")


def _default_backend_for(requested_agent: str | None) -> str:
    """Resolve the backend name to activate: ``requested_agent``, or claude if unset.

    Centralizes the back-compat default (claude) in one place so both
    ``main()`` and tests have a single source of truth for "no --agent means
    claude" -- argparse's own ``default=`` can no longer express this (see
    the ``--agent`` parser entry: it must be ``None`` so ``--receive`` can
    tell "not specified" apart from an explicit ``--agent claude``).
    """
    return requested_agent or "claude"


def _do_import(import_path: str) -> int:
    content = sys.stdin.read() if import_path == "-" else open(import_path, encoding="utf-8").read()
    content = content.strip()
    if not content:
        _err("Error: Import input is empty")
        return 1
    creds.write(content)
    _err(f"Imported {len(content.encode())} bytes to {_store_label()}")
    return 0


def _do_send(host: str, port: int, oauth_only: bool) -> int:
    plaintext = creds.oauth_only_json() if oauth_only else creds.read_raw()
    passphrase = _get_passphrase()
    enveloped = transfer_envelope.wrap(creds.backend_name(), plaintext)
    frame_text = transfer_crypto.encrypt(enveloped, passphrase)
    frame = frame_text.encode()
    # Hand the encrypted frame to the platform transport for the outbound TCP
    # write (see _send_frame). Both transports half-close their write side on
    # our EOF, so the receiver reads to EOF; the send->receive roundtrip test
    # pins this (it would hang otherwise). Both keep their own read side open
    # after that, so a receiver reply written before it closes is captured as
    # the ACK below (verified live against a real listener; see the design
    # doc's "Verified assumptions" #2). On macOS this is nc, and do NOT add
    # `-N` to its invocation: nc is Apple's variant where `-N num_probes` is
    # --apple-tcp-adp-wtimo (needs a numeric arg), not OpenBSD's
    # shutdown-on-EOF flag — passing it errors with "invalid tcp adaptive
    # write timeout value".
    log.debug("send: target %s:%d, %d-byte frame", host, port, len(frame))
    started = time.monotonic()
    error, transport, ack_bytes = _send_frame(frame, host, port)
    if error is not None:
        elapsed_ms = (time.monotonic() - started) * 1000
        log.debug("send: %s failed after %.0f ms — %s", transport, elapsed_ms, error)
        _err(f"Error: could not send to {host}:{port} — {error}")
        return 1
    log.debug("send: %s ok in %.0f ms", transport, (time.monotonic() - started) * 1000)
    note = " (oauth-only)" if oauth_only else ""
    sent_msg = f"Sent {len(frame)} encrypted bytes to {host}:{port} via TCP{note}"
    return _report_send_ack(ack_bytes, frame_text, passphrase, sent_msg)


def _report_send_ack(ack_bytes: bytes, frame_text: str, passphrase: str, sent_msg: str) -> int:
    """Interpret the receiver's ACK (captured on nc's stdout) and report the outcome.

    - A verified ``ok`` ack: print the send-success message, return 0.
    - A verified ``agent-mismatch`` or ``rejected`` ack: print the receiver's
      reason and return 1 -- the sender's exit code now reflects what
      actually happened to the store, not just whether bytes went out.
    - No ack at all, or one that fails MAC verification or parsing: the
      outcome is unknown, so return 1 without printing the peer's bytes.
      Fail closed. An on-path attacker can suppress the reply or inject a
      forged one, and "the tool told me it landed" must never be
      attacker-controlled. This costs no backward compatibility: a receiver
      too old to send an ack is also too old to accept the agent-labelled
      payload this sender emits, so that transfer fails at the receiver
      regardless (see the envelope rejection in _import_payload).
    """
    if not ack_bytes.strip():
        _err(sent_msg)
        _err(
            "Error: no acknowledgement received from the receiver; "
            "the outcome of the transfer is unknown"
        )
        return 1
    try:
        mac_key = transfer_crypto.mac_key_for_frame(frame_text, passphrase)
        salt = transfer_crypto.frame_salt(frame_text)
        status, detail = transfer_envelope.read_ack(
            ack_bytes.decode("utf-8", errors="replace").strip(), mac_key, salt
        )
    except (transfer_crypto.DecryptionError, transfer_envelope.EnvelopeError) as e:
        log.debug("send: received an unverifiable acknowledgement (%s)", e)
        _err(sent_msg)
        _err(
            "Error: the receiver's acknowledgement could not be verified; "
            "the outcome of the transfer is unknown"
        )
        return 1
    if status == "ok":
        _err(sent_msg)
        return 0
    if status == "agent-mismatch":
        _err(f"Error: agent mismatch — receiver rejected the transfer ({detail})")
        return 1
    # status == "rejected"
    _err(f"Error: receiver rejected the transfer ({detail})")
    return 1


def _pending_store_label(requested_agent: str | None) -> str:
    """``_store_label()`` once an agent is known; a neutral phrase otherwise.

    Before the envelope is unwrapped, the "active" backend is only main()'s
    provisional guess (it defaults to claude when --agent is omitted) --
    naming it in a pre-unwrap error would misleadingly imply that specific
    store was at risk. Once the receiver is pinned via --agent, or the wire
    agent has been read, name the real store.
    """
    return _store_label() if requested_agent is not None else "the credential store"


def _send_ack(conn, mac_key: bytes | None, salt: bytes | None, status: str, detail: str) -> None:
    """Best-effort send of an authenticated ACK line; never raises.

    ``mac_key``/``salt`` are None when the received frame was too malformed
    to derive them from at all (not even two well-formed lines) -- in that
    case there's nothing to authenticate an ACK with, so this is a silent
    no-op. Any socket error while sending is swallowed too: the ACK is
    advisory (see the design doc's timing caveat) -- the receiver's own exit
    code and stderr are authoritative for what happened to the store.
    """
    if mac_key is None or salt is None:
        return
    try:
        line = transfer_envelope.ack(mac_key, salt, status, detail)
        conn.sendall((line + "\n").encode())
    except (transfer_envelope.EnvelopeError, OSError) as e:
        log.debug("receive: failed to send ack (%s)", e)


def _process_received_frame(
    conn,
    frame: str,
    passphrase: str,
    *,
    verbose: bool,
    requested_agent: str | None,
    force: bool,
) -> int:
    """Decrypt+validate one received ``frame`` and write it; return the exit code.

    Split out of ``_do_receive`` so the socket read loop and this protocol
    logic aren't nested inside the same try/finally that owns ``conn`` --
    this function still takes ``conn`` because it must send the ACK on it
    before the caller closes the connection.
    """
    if not frame.strip():
        _err("Error: Received empty connection")
        return 1

    # Try to derive the ACK signing key from the frame's own salt -- this
    # only needs the frame's *shape* to be intact (two lines, valid base64,
    # a valid-looking hex tag), not for the HMAC tag itself to verify, so it
    # can succeed even when decrypt() is about to fail on a wrong passphrase.
    # If the frame is too malformed even for that, no ACK is possible at all.
    mac_key = salt = None
    try:
        salt = transfer_crypto.frame_salt(frame)
        mac_key = transfer_crypto.mac_key_for_frame(frame, passphrase)
    except transfer_crypto.DecryptionError:
        log.debug("receive: frame too malformed to derive an ack key; no ack will be sent")

    # Verify+decrypt BEFORE touching the active store: a wrong passphrase or a
    # forged/tampered payload is rejected here, leaving credentials untouched.
    try:
        content = transfer_crypto.decrypt(frame, passphrase).strip()
    except transfer_crypto.DecryptionError as e:
        log.debug("receive: decryption/verification failed (%s)", e)
        _err(f"Error: {e}; {_pending_store_label(requested_agent)} left unchanged")
        _send_ack(conn, mac_key, salt, "rejected", "decryption failed")
        return 1
    log.debug("receive: verified + decrypted %d bytes", len(content.encode()))

    # The envelope names which agent this payload belongs to. An unlabelled
    # (legacy-sender) payload is rejected outright -- see the design doc's
    # "Unlabelled (legacy) payloads are rejected" section: this is the
    # security-conservative choice, not a fallback to the receiver's --agent.
    try:
        wire_agent, payload = transfer_envelope.unwrap(content)
    except transfer_envelope.EnvelopeError as e:
        _err(f"Error: {e}; {_pending_store_label(requested_agent)} left unchanged")
        _send_ack(conn, mac_key, salt, "rejected", "no agent label")
        return 1

    if requested_agent is not None and requested_agent != wire_agent:
        _err(
            f"Error: agent mismatch — sender sent '{wire_agent}', this receiver "
            f"is pinned to '{requested_agent}'; {_store_label()} left unchanged"
        )
        _send_ack(
            conn, mac_key, salt, "agent-mismatch",
            f"sender={wire_agent} receiver={requested_agent}",
        )
        return 1

    creds.set_backend(wire_agent)
    _err(f"Detected agent: {wire_agent} (from sender)")

    if force:
        creds._backend.FORCE_WRITE = True
        _err("WARNING: --force set; skipping backend write-time safety checks")

    # The blob must be a credential document for the now-resolved backend --
    # an authentic HMAC and a valid agent label alone don't make a payload a
    # valid blob, and writing garbage would corrupt the store.
    try:
        data = creds.parse_blob(payload)
    except ValueError:
        _err(
            "Error: decrypted payload is not a valid credential blob; "
            f"{_store_label()} left unchanged"
        )
        _send_ack(conn, mac_key, salt, "rejected", "invalid credential blob")
        return 1

    # Parsing as JSON is not enough -- another agent's blob parses fine. Check
    # the shape against the resolved backend before overwriting the store. This
    # runs after the FORCE_WRITE assignment above so --force still relaxes the
    # backend's own write-time checks (codex expiry) exactly as before.
    try:
        creds.validate_blob(data)
    except creds.CredentialsError as e:
        _err(f"Error: {e}; {_store_label()} left unchanged")
        _send_ack(conn, mac_key, salt, "rejected", "blob failed backend validation")
        return 1

    creds.write(payload)
    _err(f"Received and imported {len(payload.encode())} bytes to {_store_label()}")
    if verbose:
        blob = creds.parse_blob(payload)
        tokens = creds.tokens_from_data(blob)
        if tokens:
            access_token, _refresh_token, expires_epoch = tokens
            _err(f"access_token:  {access_token}")
            _err(f"expires:       {_format_expiry_verbose(expires_epoch)}")
    _send_ack(conn, mac_key, salt, "ok", "")
    return 0


def _do_receive(
    port: int,
    *,
    verbose: bool = False,
    requested_agent: str | None = None,
    force: bool = False,
) -> int:
    passphrase = _get_passphrase()  # up front: prompt (if any) and fail fast before listening
    _err(f"Listening for one TCP connection on port {port}...")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        log.debug("receive: bound 0.0.0.0:%d, waiting for one connection", port)
        conn, addr = srv.accept()
        log.debug("receive: accepted connection from %s", addr)
        conn.settimeout(RECV_TIMEOUT)
        try:
            chunks = []
            total = 0
            while True:
                try:
                    block = conn.recv(65535)
                except socket.timeout:
                    _err(f"Error: connection idle for {RECV_TIMEOUT}s; aborting")
                    return 1
                if not block:
                    break
                total += len(block)
                if total > MAX_PAYLOAD:
                    _err(f"Error: payload exceeds {MAX_PAYLOAD} bytes; aborting")
                    return 1
                chunks.append(block)
            frame = b"".join(chunks).decode("utf-8", errors="replace")
            log.debug("receive: read %d bytes from the connection", len(frame.encode()))
            return _process_received_frame(
                conn,
                frame,
                passphrase,
                verbose=verbose,
                requested_agent=requested_agent,
                force=force,
            )
        finally:
            conn.close()
    finally:
        srv.close()


def _do_refresh(tokens: tuple[str, str, float]) -> int:
    _, refresh_token, _ = tokens
    if not refresh_token:
        _err("Error: No refresh token available")
        return 1
    refreshed = creds.refresh_tokens(refresh_token)
    if not refreshed:
        _err("Error: token refresh failed")
        return 1
    new_access, new_refresh, expires_in = refreshed
    new_expires_epoch = time.time() + expires_in

    data = creds.read_json()
    oauth = data.get("claudeAiOauth", {})
    oauth["accessToken"] = new_access
    oauth["refreshToken"] = new_refresh
    oauth["expiresAt"] = int(new_expires_epoch * 1000)
    data["claudeAiOauth"] = oauth
    creds.write(json.dumps(data))
    _err("Token refreshed successfully")

    _print_simple((new_access, new_refresh, new_expires_epoch))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --agent's default lives here, not in argparse: argparse's own
    # default="claude" could not distinguish "not specified" from an
    # explicit "--agent claude" (both produced args.agent == "claude"), and
    # --receive needs that distinction to know whether to auto-adopt the
    # sender's agent from the envelope. requested_agent stays None only
    # long enough for the --receive path to see it; _default_backend_for()
    # resolves the back-compat default (claude) for every other mode.
    requested_agent = args.agent  # None means "not specified on the command line"

    error = _validate(args)
    if error:
        _err(error)
        return 1

    # Validate before activation: `all` is a client-side operation, not a backend.
    # One-shot receive retains its provisional Claude default until unwrapping.
    if not (args.serve or args.request_host):
        creds.set_backend(_default_backend_for(requested_agent))

    # --force only bypasses Codex validation on modes that write the local auth
    # file. Send and refresh cannot run that validation, and Claude has no
    # FORCE_WRITE behavior. For --receive, the effective agent isn't
    # known until the payload is decrypted, so --force is applied *inside*
    # _do_receive instead of here (its "force" parameter, below); --import
    # is resolved now since its agent is already pinned. Reset in finally so
    # same-process callers never leak a forced state forward.
    force_codex_write = requested_agent == "codex" and bool(args.import_path)
    if args.force and force_codex_write:
        creds._backend.FORCE_WRITE = True
        _err("WARNING: --force set; skipping backend write-time safety checks")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    try:
        if args.serve:
            return request_daemon.serve(
                args.bind if args.bind is not None else "0.0.0.0",
                args.receive_port, _get_passphrase(), MAX_PAYLOAD
            )
        if args.request_host:
            return request_daemon.request_credentials(
                args.request_host, args.send_port, args.agent, _get_passphrase(),
                MAX_PAYLOAD, NC_BINARY, force=args.force,
            )
        if args.import_path:
            return _do_import(args.import_path)
        if args.send_host:
            return _do_send(args.send_host, args.send_port, args.oauth_only)
        if args.receive:
            return _do_receive(
                args.receive_port,
                verbose=args.verbose,
                requested_agent=requested_agent,
                force=args.force,
            )
        if args.raw:
            print(creds.read_raw())
            return 0
        if args.oauth_only:
            print(creds.oauth_only_json())
            return 0
        if args.simple or args.refresh:
            tokens = creds.extract_oauth_tokens()
            if not tokens:
                _err("Error: No OAuth token found in credentials")
                return 1
            if args.refresh:
                return _do_refresh(tokens)
            _print_simple(tokens)
            return 0
        # No mode selected (e.g. no arguments) → show help rather than dump the blob.
        parser.print_help()
        return 0
    except KeyboardInterrupt:
        if args.serve or args.request_host:
            return 0 if args.serve else 130
        raise
    except (creds.CredentialsError, OSError) as e:
        _err(f"Error: {e}")
        return 1
    finally:
        # Always reset FORCE_WRITE so a stale flag from this invocation can't
        # leak into the next same-process one (set_backend() also resets, but
        # this is the in-process safety net for back-to-back main() calls).
        if getattr(creds._backend, "FORCE_WRITE", None) is True:
            creds._backend.FORCE_WRITE = False


if __name__ == "__main__":
    sys.exit(main())
