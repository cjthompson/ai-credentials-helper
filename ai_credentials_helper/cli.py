"""CLI for managing Claude Code OAuth credentials in the macOS Keychain.

Installed as the ``credentials-helper`` console script (and runnable via
``python -m ai_credentials_helper.cli``). A pure-Python counterpart to
``credentials-helper.sh`` — same CLI surface, no bash/jq/xxd/curl. All keychain
and OAuth work is delegated to the shared ``ai_credentials_helper.credentials`` module.

Modes (mutually exclusive, except --oauth-only which may accompany --send).
With no arguments, prints help (it does not dump credentials by default).
  --agent <name>   Which agent's credentials to operate on: claude (default)
                   or codex.
  --raw            Print the raw stored blob, exactly as stored.
  --simple         Print access_token / refresh_token / expires_at / expires.
  --oauth-only     Print only the portable token subset as compact JSON.
  --refresh        Refresh the access token, write it back, print --simple form.
                   (Claude only; codex refreshes tokens itself on use.)
  --import <file|-> Write raw bytes (file or stdin) verbatim.
  --send <host>    Encrypt the blob and send it to <host> over TCP (the
                   receiver must be running --receive first). With --oauth-only,
                   send only the portable token subset.
  --receive        Accept one TCP connection, verify+decrypt it, and write the
                   result to the active agent's storage.

--send/--receive are end-to-end encrypted with a shared passphrase
(CLAUDE_CREDENTIALS_PASSPHRASE, or an interactive prompt). Both ends must use
the same passphrase. See ai_credentials_helper.transfer_crypto for the construction.
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
from ai_credentials_helper import transfer_crypto

log = logging.getLogger("ai_credentials_helper.cli")

DEFAULT_PORT = 47299
SEND_TIMEOUT = 10  # seconds to wait for the TCP connection to the receiver

# --send delegates the outbound TCP write to `nc`, an Apple platform binary that
# is exempt from macOS Local Network Privacy. A third-party (Homebrew/uv/etc.)
# venv python is blocked from LAN connect()s (EHOSTUNREACH); nc is not. Only the
# OUTBOUND hop is gated — --receive (bind/listen/accept) works natively in the
# venv python, so it is not delegated. Overridable via env for tests.
NC_BINARY = os.environ.get("CLAUDE_CREDENTIALS_NC", "/usr/bin/nc")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


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
        description="Manage Claude Code OAuth credentials in the macOS Keychain.",
        epilog=(
            "--send/--receive are end-to-end encrypted (AES-256-CBC + HMAC-SHA256) "
            "with a shared passphrase. Set CLAUDE_CREDENTIALS_PASSPHRASE on both "
            "ends, or you will be prompted. A wrong passphrase or tampered payload "
            "is rejected and the keychain is left untouched."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", "--verbose", action="store_true", help="log diagnostic detail to stderr")
    p.add_argument(
        "--agent",
        choices=("claude", "codex"),
        default="claude",
        help="which agent's credentials to operate on (default: claude)",
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
        help="only the claudeAiOauth section (alone, or as a --send modifier)",
    )
    p.add_argument("--import", dest="import_path", metavar="<file|->", help="write bytes verbatim")
    p.add_argument(
        "--send", dest="send_host", metavar="<host>", help="encrypt and send the blob over TCP"
    )
    p.add_argument(
        "--send-port",
        dest="send_port",
        type=int,
        default=DEFAULT_PORT,
        metavar="<port>",
        help=f"destination port for --send (default {DEFAULT_PORT})",
    )
    p.add_argument(
        "--receive", action="store_true", help="accept one TCP connection, decrypt, write it"
    )
    p.add_argument(
        "--port",
        dest="receive_port",
        type=int,
        default=DEFAULT_PORT,
        metavar="<port>",
        help=f"listening port for --receive (default {DEFAULT_PORT})",
    )
    return p


def _validate(args: argparse.Namespace) -> str | None:
    """Return an error message if the flag combination is invalid, else None."""
    primary = sum(
        [
            args.raw,
            args.simple,
            args.refresh,
            bool(args.import_path),
            bool(args.send_host),
            args.receive,
        ]
    )
    if primary > 1:
        return (
            "Error: --raw, --simple, --refresh, --import, --send, and --receive "
            "are mutually exclusive"
        )
    if args.oauth_only and (
        args.raw or args.simple or args.refresh or args.import_path or args.receive
    ):
        return "Error: --oauth-only can only be used by itself or with --send"
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
    frame = transfer_crypto.encrypt(plaintext, _get_passphrase()).encode()
    # Hand the encrypted frame to nc for the outbound TCP write (see NC_BINARY).
    # nc half-closes its write side on stdin EOF, so the receiver reads to EOF;
    # the send->receive roundtrip test pins this (it would hang otherwise).
    # Do NOT add `-N`: on macOS, nc is Apple's variant where `-N num_probes` is
    # --apple-tcp-adp-wtimo (needs a numeric arg), not OpenBSD's shutdown-on-EOF
    # flag — passing it errors with "invalid tcp adaptive write timeout value".
    log.debug("send: target %s:%d via %s, %d-byte frame", host, port, NC_BINARY, len(frame))
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [NC_BINARY, "-w", str(SEND_TIMEOUT), host, str(port)],
            input=frame,
            capture_output=True,
            timeout=SEND_TIMEOUT + 5,
        )
    except FileNotFoundError:
        _err(f"Error: {NC_BINARY} not found (needed to send)")
        return 1
    except subprocess.TimeoutExpired:
        _err(f"Error: send to {host}:{port} timed out after {SEND_TIMEOUT}s")
        return 1
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip() or f"nc exited {proc.returncode}"
        log.debug("send: nc failed after %.0f ms — %s", (time.monotonic() - started) * 1000, detail)
        _err(f"Error: could not send to {host}:{port} — {detail}")
        return 1
    log.debug("send: nc ok in %.0f ms", (time.monotonic() - started) * 1000)
    note = " (oauth-only)" if oauth_only else ""
    _err(f"Sent {len(frame)} encrypted bytes to {host}:{port} via TCP{note}")
    return 0


def _do_receive(port: int, verbose: bool = False) -> int:
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
        finally:
            conn.close()
    finally:
        srv.close()
    frame = b"".join(chunks).decode("utf-8", errors="replace")
    log.debug("receive: read %d bytes from the connection", len(frame.encode()))
    if not frame.strip():
        _err("Error: Received empty connection")
        return 1
    # Verify+decrypt BEFORE touching the keychain: a wrong passphrase or a
    # forged/tampered payload is rejected here, leaving credentials untouched.
    try:
        content = transfer_crypto.decrypt(frame, passphrase).strip()
    except transfer_crypto.DecryptionError as e:
        log.debug("receive: decryption/verification failed (%s)", e)
        _err(f"Error: {e}; keychain left unchanged")
        return 1
    log.debug("receive: verified + decrypted %d bytes", len(content.encode()))
    # The blob must be a credential document — raw JSON or hex-encoded JSON, the
    # two forms Claude Code stores (see creds.read_raw / a full --send). Reject
    # anything else before overwriting the keychain; an authentic HMAC alone
    # doesn't make a payload a valid blob, and writing garbage would corrupt it.
    try:
        creds.parse_blob(content)
    except ValueError:
        _err("Error: decrypted payload is not a valid credential blob; keychain left unchanged")
        return 1
    creds.write(content)
    _err(f"Received and imported {len(content.encode())} bytes to {_store_label()}")
    if verbose:
        blob = creds.parse_blob(content)
        oauth = blob.get("claudeAiOauth", {})
        access_token = oauth.get("accessToken", "")
        expires_ms = oauth.get("expiresAt", 0)
        if access_token and expires_ms:
            _err(f"access_token:  {access_token}")
            _err(f"expires:       {_format_expiry_verbose(expires_ms / 1000)}")
    return 0


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

    # Activate the chosen backend before any backend call. Unknown names
    # raise ValueError; argparse already restricts to the choices set.
    creds.set_backend(args.agent)

    error = _validate(args)
    if error:
        _err(error)
        return 1

    # --force only applies to write modes (import/send/receive/refresh) and
    # only after args validate cleanly. Always warn — bypassing safety should
    # be loud. Reset FORCE_WRITE in finally so a same-process caller (e.g.
    # tests, programmatic use) never leaks a forced state forward.
    is_write = bool(args.import_path or args.send_host or args.receive or args.refresh)
    if args.force and is_write:
        creds._backend.FORCE_WRITE = True
        _err("WARNING: --force set; skipping backend write-time safety checks")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    try:
        if args.import_path:
            return _do_import(args.import_path)
        if args.send_host:
            return _do_send(args.send_host, args.send_port, args.oauth_only)
        if args.receive:
            return _do_receive(args.receive_port, verbose=args.verbose)
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
