# Implementation plan: agent identity on the transfer wire

Source design: `docs/superpowers/specs/2026-07-29-agent-identity-transfer-design.md` (commit baseline `79f4cae`, worktree `/Users/chris/dev/personal/ai-credentials-helper/.claude/worktrees/opus-plan-sonnet-scout-haiku-impl`).

## Assumption spot-check (done before trusting the design doc)

I independently re-verified the assumptions this plan leans on hardest. **All held; nothing needed adjusting.**

1. Baseline suite green: ran `.venv/bin/python -m pytest -q` → **128 passed**. Confirmed.
2. `nc` reply-after-EOF behavior (assumption 2): reproduced live with a real Python listener + `/usr/bin/nc`. Client wrote `hello-payload` to stdin/EOF, server replied `ERR agent-mismatch\n` on the still-open connection; `nc` printed it to **stdout**, exit code **0**. Matches the doc exactly — the sender's exit status must come from parsing `nc`'s stdout, never its return code.
3. `argparse` can't distinguish `--agent claude` from the default (assumption 6): confirmed — both `parser.parse_args(["--raw"]).agent` and `parser.parse_args(["--agent","claude","--raw"]).agent` return `"claude"` today.
4. `credentials-helper.sh` has no crypto (assumption 3): `grep -n 'openssl\|pbkdf2\|encrypt' credentials-helper.sh` returns nothing; its `--send`/`--receive` (lines ~217-260) pipe raw keychain bytes through a bare `socket.connect()`/`sendall()` — no envelope, no encryption. Confirmed non-interoperable with the Python CLI already, independent of this change.
5. PBKDF2 timing (assumption 4): measured **0.227 s** for one `pbkdf2_hmac(..., 600000, dklen=80)` on this machine. Confirmed affordable.
6. Only two test files touch the CLI (assumption 5): confirmed via grep — `tests/test_cli_agent.py` and `tests/test_cli_live_transfer.py` only.

No contradictions found. Proceeding as designed.

## Decisions locked in (per the design doc's own recommendations — not open anymore)

1. **Unlabelled legacy payloads are rejected outright** (no `--allow-unlabeled` fallback). Both ends must be upgraded together.
2. **The sender exits non-zero on both `agent-mismatch` and `rejected` ACKs**, not just mismatch.
3. **The claude-side `validate_blob` hardening is explicitly OUT OF SCOPE for this change** — it's the design doc's "Optional companion hardening" section, sequenced separately. Do not touch `ai_credentials_helper/backends/claude.py` in this plan.

Also out of scope per the design doc's own "Explicitly out of scope" section (do not implement any of this): anti-replay for the credential frame, endpoint/host auth, a pre-send handshake, length padding, multi-agent/batched transfers, carrying `--oauth-only` on the wire, and any change to `credentials-helper.sh`'s transfer logic (only a documentation comment there, per step 4 below).

---

## Step 1 — New file: `ai_credentials_helper/transfer_envelope.py`

Create with exactly this content:

```python
"""Agent-identity envelope for credential transfers (``--send`` / ``--receive``).

Layered *inside* the encrypted frame that ``ai_credentials_helper.transfer_crypto``
produces/consumes: this module only deals with plaintext framing, so it has no
sockets and no crypto primitives of its own and is unit-testable in isolation.
See ``docs/superpowers/specs/2026-07-29-agent-identity-transfer-design.md``.

Envelope format -- one header line, then the payload verbatim, byte-for-byte
(a pretty-printed codex ``auth.json`` is multi-line, so "first line is the
header, everything after the first newline is payload" is required, not a
line-oriented format)::

    ai-credentials-helper/1 agent=<name>\\n<payload bytes, verbatim>

``MAGIC`` is ``"ai-credentials-helper/1"`` -- the trailing ``1`` is the
envelope's major version. Header tokens after the magic are whitespace-
separated ``key=value`` pairs; ``agent`` is required, unknown keys are
ignored (forward compatible), and an unrecognized major version is rejected
with its own message (distinct from "no envelope at all", which means an
old, unlabelled sender).

ACK format -- one line, receiver -> sender, authenticated by an HMAC tag the
caller (``ai_credentials_helper.cli``, using key material from
``transfer_crypto.mac_key_for_frame``/``frame_salt``) supplies::

    ai-credentials-helper/1 status=<ok|agent-mismatch|rejected> detail=<text> <hex-tag>

The three ACK header fields are fixed-order (unlike the wrap/unwrap
envelope) so that ``detail`` -- which may itself contain spaces, per
``_DETAIL_RE`` -- can be parsed unambiguously: everything between
``detail=`` and the final space-delimited token (the tag) belongs to
``detail``.
"""

import hashlib
import hmac
import re

MAGIC = "ai-credentials-helper/1"
_MAGIC_PREFIX = "ai-credentials-helper/"

_AGENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_DETAIL_RE = re.compile(r"^[A-Za-z0-9 _.:=-]{0,120}$")
_ACK_STATUSES = ("ok", "agent-mismatch", "rejected")


class EnvelopeError(Exception):
    """Envelope or ACK framing/validation failed."""


def _validate_agent_shape(agent: str) -> None:
    if not _AGENT_RE.match(agent):
        raise EnvelopeError(f"invalid agent name for envelope: {agent!r}")


def wrap(agent: str, payload: str) -> str:
    """Prefix ``payload`` with a header naming ``agent``; return the plaintext to encrypt.

    ``agent`` is validated by shape before being interpolated into the
    header (it should already be a real backend name from
    ``creds.backend_name()``, but this keeps wrap/unwrap symmetric and
    catches programmer error early rather than producing an envelope
    ``unwrap`` would reject anyway).
    """
    _validate_agent_shape(agent)
    return f"{MAGIC} agent={agent}\n{payload}"


def unwrap(text: str) -> tuple[str, str]:
    """Split enveloped ``text`` into ``(agent, payload)``; raise EnvelopeError on any defect.

    Order of checks: magic prefix present (else: "no agent label" -- an
    unupgraded sender) -> exact magic/version match (else: "unsupported
    envelope version") -> ``agent`` field present, shape-valid, and a
    registered backend name -> payload non-empty.
    """
    header, sep, payload = text.partition("\n")
    tokens = header.split()
    if not tokens or not tokens[0].startswith(_MAGIC_PREFIX):
        raise EnvelopeError(
            "payload has no agent label; the sender is running an older "
            "version — upgrade both ends"
        )
    if tokens[0] != MAGIC:
        raise EnvelopeError(
            f"unsupported envelope version {tokens[0]!r}; expected {MAGIC!r}"
        )
    fields: dict[str, str] = {}
    for tok in tokens[1:]:
        key, found_eq, value = tok.partition("=")
        if found_eq:
            fields[key] = value
    agent = fields.get("agent")
    if not agent:
        raise EnvelopeError("envelope header missing required 'agent' field")
    _validate_agent_shape(agent)
    # Deferred import: this keeps transfer_envelope's pure-framing logic from
    # depending on the storage backends at module-import time.
    from ai_credentials_helper.backends import get_backend

    try:
        get_backend(agent)
    except ValueError as e:
        raise EnvelopeError(str(e)) from e
    if not sep or not payload:
        raise EnvelopeError("envelope payload is empty")
    return agent, payload


def ack(mac_key: bytes, salt: bytes, status: str, detail: str = "") -> str:
    """Build a full authenticated ACK line: ``header + " " + hex-tag``.

    ``mac_key``/``salt`` are the ones tied to the transfer's own frame
    (``transfer_crypto.mac_key_for_frame`` / ``frame_salt``) -- binding the
    tag to that transfer's random salt is what makes a captured ACK from an
    earlier transfer fail to verify against a new one.
    """
    if status not in _ACK_STATUSES:
        raise EnvelopeError(f"invalid ack status: {status!r}")
    if not _DETAIL_RE.match(detail):
        raise EnvelopeError(f"invalid ack detail: {detail!r}")
    body = f"{MAGIC} status={status} detail={detail}"
    tag = hmac.new(
        mac_key, b"ack\x00" + salt + b"\x00" + body.encode(), hashlib.sha256
    ).hexdigest()
    return f"{body} {tag}"


def read_ack(line: str, mac_key: bytes, salt: bytes) -> tuple[str, str]:
    """Verify and parse an ACK ``line``; raise EnvelopeError on any failure.

    The tag is checked with ``hmac.compare_digest`` (constant-time) before
    anything in ``detail`` is trusted for display or logic. Returns
    ``(status, detail)``.
    """
    line = line.strip()
    head_and_tag = line.rsplit(" ", 1)
    if len(head_and_tag) != 2:
        raise EnvelopeError("malformed ack line")
    body, tag_hex = head_and_tag
    tag_hex = tag_hex.lower()
    if len(tag_hex) != 64 or not all(c in "0123456789abcdef" for c in tag_hex):
        raise EnvelopeError("malformed ack tag")
    expected = hmac.new(
        mac_key, b"ack\x00" + salt + b"\x00" + body.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, tag_hex):
        raise EnvelopeError("ack authentication failed")
    parts = body.split(" ", 2)
    if len(parts) != 3:
        raise EnvelopeError("malformed ack line")
    magic_tok, status_tok, detail_tok = parts
    if magic_tok != MAGIC:
        raise EnvelopeError(f"unsupported ack version {magic_tok!r}; expected {MAGIC!r}")
    if not status_tok.startswith("status="):
        raise EnvelopeError("malformed ack line: missing status field")
    if not detail_tok.startswith("detail="):
        raise EnvelopeError("malformed ack line: missing detail field")
    status = status_tok[len("status="):]
    detail = detail_tok[len("detail="):]
    if status not in _ACK_STATUSES:
        raise EnvelopeError(f"ack has invalid status: {status!r}")
    if not _DETAIL_RE.match(detail):
        raise EnvelopeError("ack detail failed charset validation")
    return status, detail
```

**Verify:** `.venv/bin/python -c "from ai_credentials_helper import transfer_envelope as te; print(te.unwrap(te.wrap('codex', 'x')))"` → prints `('codex', 'x')`.

---

## Step 2 — Modify `ai_credentials_helper/transfer_crypto.py`

### 2a. Fix the stale docstring (lines 1–9)

Replace:
```python
"""Authenticated encryption for credential transfer (``--send`` / ``--receive``).

The wire format is shared with the standalone ``claude-credentials.sh``, which
performs the AES step with the macOS ``openssl`` (LibreSSL) CLI and everything
else with the system ``python3`` stdlib. Both sides therefore agree on one
format — the same standard, two libraries.

Construction: **AES-256-CBC + HMAC-SHA256, encrypt-then-MAC.** GCM is avoided
because the ``openssl enc`` CLI cannot safely handle the AEAD tag.
```

With:
```python
"""Authenticated encryption for credential transfer (``--send`` / ``--receive``).

The KDF/AES *primitive* (PBKDF2-HMAC-SHA256 key schedule + AES-256-CBC) is
shared with the standalone ``credentials-helper.sh``, which performs the AES
step with the macOS ``openssl`` (LibreSSL) CLI and everything else with the
system ``python3`` stdlib -- both sides agree on that one construction. The
wire *framing* built on top of it (the agent-identity envelope in
``ai_credentials_helper.transfer_envelope``, and the authenticated ACK) is
specific to this Python CLI; ``credentials-helper.sh``'s own ``--send``/
``--receive`` use a different, unencrypted framing and do not interoperate
with this module's frame beyond that shared primitive.

Construction: **AES-256-CBC + HMAC-SHA256, encrypt-then-MAC.** GCM is avoided
because the ``openssl enc`` CLI cannot safely handle the AEAD tag.
```

(Leave the rest of the module docstring — key schedule, wire format diagram — unchanged; it's still accurate.)

### 2b. Factor out line-1 parsing, add `frame_salt` / `mac_key_for_frame`

Replace the entire `decrypt` function:

```python
def decrypt(frame: str, passphrase: str) -> str:
    """Verify+decrypt a wire ``frame``; raise :class:`DecryptionError` on any failure.

    The HMAC is checked (constant-time) **before** decryption, so a wrong
    passphrase or a forged/tampered frame is rejected without ever decrypting.
    """
    lines = [ln for ln in frame.splitlines() if ln.strip()]
    if len(lines) != 2:  # exactly base64-blob + hex-tag; reject extras
        raise DecryptionError("malformed transfer frame")
    try:
        blob = base64.b64decode(lines[0], validate=True)
    except (binascii.Error, ValueError) as e:
        raise DecryptionError("malformed transfer frame") from e
    if len(blob) <= SALT_LEN:
        raise DecryptionError("malformed transfer frame")

    tag_hex = lines[1].strip()
    if len(tag_hex) != 64 or not all(c in "0123456789abcdef" for c in tag_hex.lower()):
        raise DecryptionError("malformed transfer frame")
    salt, ciphertext = blob[:SALT_LEN], blob[SALT_LEN:]
    enc_key, iv, mac_key = _derive(passphrase, salt)

    expected = hmac.new(mac_key, blob, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, tag_hex):
        raise DecryptionError(
            "authentication failed (wrong passphrase or corrupted/forged data)"
        )

    # The HMAC gate above stops forgery, but a buggy or version-mismatched peer
    # that shares the passphrase can still produce a valid-tag frame whose
    # ciphertext won't decrypt (bad block length / padding) or whose plaintext
    # isn't UTF-8. Convert those to DecryptionError so the contract holds: any
    # failure raises DecryptionError, never a raw cryptography/codec exception.
    try:
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(_BLOCK_BITS).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()
    except (ValueError, UnicodeDecodeError) as e:
        raise DecryptionError("authenticated frame failed to decrypt") from e
```

With:

```python
def _parse_frame(frame: str) -> tuple[bytes, str]:
    """Parse+validate a wire frame's two lines; return ``(blob, tag_hex)``.

    ``blob`` is ``salt || ciphertext`` (undecoded). Raises DecryptionError on
    any malformed shape -- this is exactly the line-1/line-2 validation
    ``decrypt`` always did; it's factored out so ``frame_salt`` can reuse it
    without duplicating the rules or needing a passphrase.
    """
    lines = [ln for ln in frame.splitlines() if ln.strip()]
    if len(lines) != 2:  # exactly base64-blob + hex-tag; reject extras
        raise DecryptionError("malformed transfer frame")
    try:
        blob = base64.b64decode(lines[0], validate=True)
    except (binascii.Error, ValueError) as e:
        raise DecryptionError("malformed transfer frame") from e
    if len(blob) <= SALT_LEN:
        raise DecryptionError("malformed transfer frame")
    tag_hex = lines[1].strip()
    if len(tag_hex) != 64 or not all(c in "0123456789abcdef" for c in tag_hex.lower()):
        raise DecryptionError("malformed transfer frame")
    return blob, tag_hex


def frame_salt(frame: str) -> bytes:
    """Return the salt embedded in a wire ``frame`` (first ``SALT_LEN`` bytes of the blob).

    Raises DecryptionError if the frame's *shape* is malformed. Does **not**
    require or check the passphrase/HMAC -- it only needs the frame to be
    two well-formed lines, so it can succeed even when the frame's tag will
    later fail to verify under a given passphrase. Used to derive the ACK's
    mac_key on both ends without re-doing a full decrypt.
    """
    blob, _tag_hex = _parse_frame(frame)
    return blob[:SALT_LEN]


def mac_key_for_frame(frame: str, passphrase: str) -> bytes:
    """Return the HMAC key used for both the frame and its ACK.

    Same derivation as ``_derive(...)[2]``, applied to the frame's own salt,
    so the sender (who has passphrase + frame) and the receiver (who has
    passphrase + received frame) compute an identical mac_key with no extra
    round trip.
    """
    return _derive(passphrase, frame_salt(frame))[2]


def decrypt(frame: str, passphrase: str) -> str:
    """Verify+decrypt a wire ``frame``; raise :class:`DecryptionError` on any failure.

    The HMAC is checked (constant-time) **before** decryption, so a wrong
    passphrase or a forged/tampered frame is rejected without ever decrypting.
    """
    blob, tag_hex = _parse_frame(frame)
    salt, ciphertext = blob[:SALT_LEN], blob[SALT_LEN:]
    enc_key, iv, mac_key = _derive(passphrase, salt)

    expected = hmac.new(mac_key, blob, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, tag_hex):
        raise DecryptionError(
            "authentication failed (wrong passphrase or corrupted/forged data)"
        )

    # The HMAC gate above stops forgery, but a buggy or version-mismatched peer
    # that shares the passphrase can still produce a valid-tag frame whose
    # ciphertext won't decrypt (bad block length / padding) or whose plaintext
    # isn't UTF-8. Convert those to DecryptionError so the contract holds: any
    # failure raises DecryptionError, never a raw cryptography/codec exception.
    try:
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(_BLOCK_BITS).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()
    except (ValueError, UnicodeDecodeError) as e:
        raise DecryptionError("authenticated frame failed to decrypt") from e
```

This is a pure refactor: every message string `decrypt` raises is byte-for-byte identical to before. Do **not** touch `encrypt`, `_derive`, `PBKDF2_ITERATIONS`, `SALT_LEN`, or the wire format.

**Verify:** `.venv/bin/python -m pytest tests/test_transfer_crypto.py -q` → all existing tests still pass (no new tests yet — those come in step 6).

---

## Step 3 — Modify `ai_credentials_helper/cli.py`

### 3a. Module docstring (lines 1–27)

Replace:
```python
"""CLI for managing OAuth credentials for supported AI agents.

Installed as the ``credentials-helper`` console script (and runnable via
``python -m ai_credentials_helper.cli``). A pure-Python counterpart to
``credentials-helper.sh`` — same CLI surface, no bash/jq/xxd/curl. All storage
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
```

With:
```python
"""CLI for managing OAuth credentials for supported AI agents.

Installed as the ``credentials-helper`` console script (and runnable via
``python -m ai_credentials_helper.cli``). A pure-Python counterpart to
``credentials-helper.sh`` — same CLI surface, no bash/jq/xxd/curl. All storage
and OAuth work is delegated to the shared ``ai_credentials_helper.credentials`` module.

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
  --import <file|-> Write raw bytes (file or stdin) verbatim.
  --send <host>    Encrypt the blob and send it to <host> over TCP (the
                   receiver must be running --receive first). With --oauth-only,
                   send only the portable token subset. The transfer is labeled
                   with the sending agent; a receiver pinned to a different
                   agent (via --agent) rejects it on both ends.
  --receive        Accept one TCP connection, verify+decrypt it, and write the
                   result to the store named in the sender's label. Pass
                   --agent to require a specific sender agent; a mismatch is a
                   hard error on both ends and neither store is touched.

--send/--receive are end-to-end encrypted with a shared passphrase
(CLAUDE_CREDENTIALS_PASSPHRASE, or an interactive prompt). Both ends must use
the same passphrase, and both ends must run a version of this tool that
supports the agent-identity envelope (this version) — an older, unlabelled
payload is rejected. See ai_credentials_helper.transfer_crypto for the
encryption construction and ai_credentials_helper.transfer_envelope for the
agent-identity envelope.
"""
```

### 3b. Import (line 41 area)

Replace:
```python
from ai_credentials_helper import credentials as creds
from ai_credentials_helper import transfer_crypto
```
With:
```python
from ai_credentials_helper import credentials as creds
from ai_credentials_helper import transfer_crypto
from ai_credentials_helper import transfer_envelope
```

### 3c. Parser: `--agent` default and epilog

Replace:
```python
        epilog=(
            "--send/--receive are end-to-end encrypted (AES-256-CBC + HMAC-SHA256) "
            "with a shared passphrase. Set CLAUDE_CREDENTIALS_PASSPHRASE on both "
            "ends, or you will be prompted. A wrong passphrase or tampered payload "
            "is rejected and the active store is left unchanged."
        ),
```
With:
```python
        epilog=(
            "--send/--receive are end-to-end encrypted (AES-256-CBC + HMAC-SHA256) "
            "with a shared passphrase. Set CLAUDE_CREDENTIALS_PASSPHRASE on both "
            "ends, or you will be prompted. A wrong passphrase or tampered payload "
            "is rejected and the active store is left unchanged. The transfer is "
            "labeled with the sending agent; --receive without --agent adopts it, "
            "and a mismatched --agent is a hard error on both ends. Both ends must "
            "run a version of this tool that supports this agent label."
        ),
```

Replace:
```python
    p.add_argument(
        "--agent",
        choices=("claude", "codex"),
        default="claude",
        help="which agent's credentials to operate on (default: claude)",
    )
```
With:
```python
    p.add_argument(
        "--agent",
        choices=("claude", "codex"),
        default=None,
        help="which agent's credentials to operate on (default: claude; for "
             "--receive, omitting this adopts the sending agent named in the "
             "encrypted envelope)",
    )
```

### 3d. New helper: `_default_backend_for` (add just above `_do_import`, i.e. right before line `def _do_import(import_path: str) -> int:`)

```python
def _default_backend_for(requested_agent: str | None) -> str:
    """Resolve the backend name to activate: ``requested_agent``, or claude if unset.

    Centralizes the back-compat default (claude) in one place so both
    ``main()`` and tests have a single source of truth for "no --agent means
    claude" -- argparse's own ``default=`` can no longer express this (see
    the ``--agent`` parser entry: it must be ``None`` so ``--receive`` can
    tell "not specified" apart from an explicit ``--agent claude``).
    """
    return requested_agent or "claude"
```

### 3e. `_do_send`: wrap before encrypting, interpret the ACK on `nc`'s stdout

Replace the entire function:
```python
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
```

With:
```python
def _do_send(host: str, port: int, oauth_only: bool) -> int:
    plaintext = creds.oauth_only_json() if oauth_only else creds.read_raw()
    passphrase = _get_passphrase()
    enveloped = transfer_envelope.wrap(creds.backend_name(), plaintext)
    frame_text = transfer_crypto.encrypt(enveloped, passphrase)
    frame = frame_text.encode()
    # Hand the encrypted frame to nc for the outbound TCP write (see NC_BINARY).
    # nc half-closes its write side on stdin EOF, so the receiver reads to EOF;
    # the send->receive roundtrip test pins this (it would hang otherwise). nc
    # keeps its own read side open after that, so a receiver reply written
    # before it closes lands on nc's stdout -- that's the transport for the
    # ACK below (verified live against a real listener; see the design doc's
    # "Verified assumptions" #2). Do NOT add `-N`: on macOS, nc is Apple's
    # variant where `-N num_probes` is --apple-tcp-adp-wtimo (needs a numeric
    # arg), not OpenBSD's shutdown-on-EOF flag — passing it errors with
    # "invalid tcp adaptive write timeout value".
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
    sent_msg = f"Sent {len(frame)} encrypted bytes to {host}:{port} via TCP{note}"
    return _report_send_ack(proc.stdout, frame_text, passphrase, sent_msg)


def _report_send_ack(ack_bytes: bytes, frame_text: str, passphrase: str, sent_msg: str) -> int:
    """Interpret the receiver's ACK (captured on nc's stdout) and report the outcome.

    - Empty stdout: no ack was received (an older, un-upgraded receiver never
      writes one; or this one died before writing it). Back-compat: still
      print the send-success message and return 0.
    - A verified ``ok`` ack: print the send-success message, return 0.
    - A verified ``agent-mismatch`` or ``rejected`` ack: print the receiver's
      reason and return 1 -- the sender's exit code now reflects what
      actually happened to the store, not just whether bytes went out.
    - Anything that fails MAC verification or parsing (an on-path attacker,
      or an incompatible peer): print a warning and DO NOT print its
      contents, then fall back to the "no acknowledgement" behavior.
    """
    if not ack_bytes.strip():
        _err(sent_msg)
        _err(
            "Note: no acknowledgement received from the receiver "
            "(older version, or it did not respond)"
        )
        return 0
    try:
        mac_key = transfer_crypto.mac_key_for_frame(frame_text, passphrase)
        salt = transfer_crypto.frame_salt(frame_text)
        status, detail = transfer_envelope.read_ack(
            ack_bytes.decode("utf-8", errors="replace").strip(), mac_key, salt
        )
    except (transfer_crypto.DecryptionError, transfer_envelope.EnvelopeError) as e:
        log.debug("send: received an unverifiable acknowledgement (%s)", e)
        _err(sent_msg)
        _err("Note: received an unverifiable acknowledgement from the receiver; ignoring it")
        return 0
    if status == "ok":
        _err(sent_msg)
        return 0
    if status == "agent-mismatch":
        _err(f"Error: agent mismatch — receiver rejected the transfer ({detail})")
        return 1
    # status == "rejected"
    _err(f"Error: receiver rejected the transfer ({detail})")
    return 1
```

### 3f. `_do_receive`: unwrap, mismatch check, detected-agent notice, force, ACK

Replace the entire function:
```python
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
    # Verify+decrypt BEFORE touching the active store: a wrong passphrase or a
    # forged/tampered payload is rejected here, leaving credentials untouched.
    try:
        content = transfer_crypto.decrypt(frame, passphrase).strip()
    except transfer_crypto.DecryptionError as e:
        log.debug("receive: decryption/verification failed (%s)", e)
        _err(f"Error: {e}; {_store_label()} left unchanged")
        return 1
    log.debug("receive: verified + decrypted %d bytes", len(content.encode()))
    # The blob must be a credential document — raw JSON or hex-encoded JSON, the
    # two forms Claude Code stores (see creds.read_raw / a full --send). Reject
    # anything else before overwriting the active store; an authentic HMAC alone
    # doesn't make a payload a valid blob, and writing garbage would corrupt it.
    try:
        creds.parse_blob(content)
    except ValueError:
        _err(
            "Error: decrypted payload is not a valid credential blob; "
            f"{_store_label()} left unchanged"
        )
        return 1
    creds.write(content)
    _err(f"Received and imported {len(content.encode())} bytes to {_store_label()}")
    if verbose:
        blob = creds.parse_blob(content)
        tokens = creds.tokens_from_data(blob)
        if tokens:
            access_token, _refresh_token, expires_epoch = tokens
            _err(f"access_token:  {access_token}")
            _err(f"expires:       {_format_expiry_verbose(expires_epoch)}")
    return 0
```

With:
```python
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
        creds.parse_blob(payload)
    except ValueError:
        _err(
            "Error: decrypted payload is not a valid credential blob; "
            f"{_store_label()} left unchanged"
        )
        _send_ack(conn, mac_key, salt, "rejected", "invalid credential blob")
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
```

Note: `_do_receive`'s new signature makes `verbose`, `requested_agent`, and `force` **keyword-only** (the `*`). All existing call sites (`main()`, tests) already call it as `_do_receive(port, ...)` positionally for `port` only — this plan updates every call site in step 3g and step 6.

### 3g. `main()`

Replace:
```python
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

    # --force only bypasses Codex validation on modes that write the local auth
    # file. Send and refresh cannot run that validation, and Claude has no
    # FORCE_WRITE behavior. Reset in finally so same-process callers never
    # leak a forced state forward.
    force_codex_write = args.agent == "codex" and bool(args.import_path or args.receive)
    if args.force and force_codex_write:
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
```

With:
```python
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

    # Activate a backend before any backend call. For --receive with no
    # --agent, this is only a *provisional* activation (claude) that
    # _do_receive will switch away from once it learns the sender's agent
    # via the envelope; every other mode's backend is final here. Unknown
    # names raise ValueError; argparse already restricts --agent to the
    # choices set.
    creds.set_backend(_default_backend_for(requested_agent))

    error = _validate(args)
    if error:
        _err(error)
        return 1

    # --force only bypasses Codex validation on modes that write the local
    # auth file. Send and refresh cannot run that validation, and Claude has
    # no FORCE_WRITE behavior. For --receive, the effective agent isn't
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
```

(The rest of `main()` — `elif`/remaining branches, the `except`, and the `finally` block resetting `FORCE_WRITE` — is unchanged; leave it exactly as is. The `finally` block's comment is still accurate: it reads `creds._backend` at teardown time, which by then is whatever `_do_receive` switched it to.)

**Verify after 3a–3g:**
```
.venv/bin/python -c "import ai_credentials_helper.cli"
.venv/bin/python -m ai_credentials_helper.cli --help
```
Both must succeed with no traceback (the second should show the updated `--agent`/`--receive` help text). Do not run the full test suite yet — steps 3e/3f change signatures the existing tests call; that's expected and fixed in step 6.

---

## Step 4 — `credentials-helper.sh`: one-line documentation note (no behavioral change)

Replace:
```bash
#!/usr/bin/env bash
# Manage the Claude Code OAuth token in the macOS Keychain.
#
# This bash version only supports the ``claude`` agent (macOS Keychain).
# For ``codex`` or other agents, use the Python CLI:
#     credentials-helper --agent codex --simple
#
# Usage: ./credentials-helper.sh [--raw | --simple | --refresh | --oauth-only]
```
With:
```bash
#!/usr/bin/env bash
# Manage the Claude Code OAuth token in the macOS Keychain.
#
# This bash version only supports the ``claude`` agent (macOS Keychain).
# For ``codex`` or other agents, use the Python CLI:
#     credentials-helper --agent codex --simple
#
# Note: this script's --send/--receive use a plaintext, unencrypted wire
# format and do not interoperate with the Python CLI's --send/--receive
# (which are end-to-end encrypted and, as of this version, label the
# transfer with an agent name). Do not mix the two across a transfer.
#
# Usage: ./credentials-helper.sh [--raw | --simple | --refresh | --oauth-only]
```

Do not touch any other line of this file.

---

## Step 5 — `README.md`: document the new behavior

In the `## Encrypted transfer` section, after the paragraph ending `...Use --oauth-only with --send to transfer only the portable token subset.`, add a new paragraph:

```markdown
The receiver may omit `--agent` entirely — it adopts whichever agent the sender labeled the transfer with, and prints `Detected agent: <name> (from sender)` before writing. Passing a `--agent` that differs from the sender's is a hard error on both ends: the receiver's store is left untouched and the sender's exit code reflects the rejection. Both ends must be running a version of this tool that supports this agent label; an older, unlabelled payload is rejected outright.
```

---

## Step 6 — Tests

### 6a. New file: `tests/test_transfer_envelope.py`

```python
"""Unit tests for ai_credentials_helper.transfer_envelope.

Pure-function tests -- no sockets, no crypto beyond the HMAC primitive
already exercised by test_transfer_crypto.py.
"""

import pytest

from ai_credentials_helper import transfer_envelope as te

MAC_KEY = b"\x01" * 32
SALT = b"\x02" * 16
OTHER_SALT = b"\x03" * 16


def test_wrap_unwrap_round_trip():
    agent, payload = te.unwrap(te.wrap("codex", '{"tokens":{}}'))
    assert agent == "codex"
    assert payload == '{"tokens":{}}'


def test_wrap_unwrap_round_trip_multiline_payload():
    payload = '{\n  "tokens": {\n    "access_token": "a.b.c"\n  }\n}'
    agent, unwrapped = te.unwrap(te.wrap("codex", payload))
    assert agent == "codex"
    assert unwrapped == payload


def test_wrap_unwrap_round_trip_hex_claude_payload():
    payload = "7b22636c61756465416933223a317d"  # hex-looking, non-JSON-prefixed
    agent, unwrapped = te.unwrap(te.wrap("claude", payload))
    assert agent == "claude"
    assert unwrapped == payload


def test_payload_preserved_byte_for_byte():
    payload = "line one\nline two\n\ntrailing blank above"
    _agent, unwrapped = te.unwrap(te.wrap("claude", payload))
    assert unwrapped == payload


def test_unwrap_missing_magic_rejected():
    with pytest.raises(te.EnvelopeError, match="older version"):
        te.unwrap('{"claudeAiOauth":{}}')


def test_unwrap_unknown_major_version_rejected():
    with pytest.raises(te.EnvelopeError, match="unsupported envelope version"):
        te.unwrap("ai-credentials-helper/2 agent=claude\n{}")


def test_unwrap_unknown_header_keys_ignored():
    agent, payload = te.unwrap("ai-credentials-helper/1 oauth-only=true agent=codex\npayload")
    assert agent == "codex"
    assert payload == "payload"


@pytest.mark.parametrize(
    "header",
    [
        "ai-credentials-helper/1\npayload",                          # missing agent
        "ai-credentials-helper/1 agent=\npayload",                   # blank agent
        "ai-credentials-helper/1 agent=" + "a" * 40 + "\npayload",   # oversized
        "ai-credentials-helper/1 agent=Claude\npayload",             # illegal uppercase
        "ai-credentials-helper/1 agent=../etc\npayload",             # illegal characters
        "ai-credentials-helper/1 agent=bogus-agent\npayload",        # not a registered backend
    ],
)
def test_unwrap_bad_agent_rejected(header):
    with pytest.raises(te.EnvelopeError):
        te.unwrap(header)


def test_unwrap_empty_payload_rejected():
    with pytest.raises(te.EnvelopeError, match="empty"):
        te.unwrap("ai-credentials-helper/1 agent=claude\n")


def test_unwrap_no_newline_at_all_rejected_as_empty_payload():
    with pytest.raises(te.EnvelopeError, match="empty"):
        te.unwrap("ai-credentials-helper/1 agent=claude")


def test_wrap_rejects_invalid_agent_name():
    with pytest.raises(te.EnvelopeError):
        te.wrap("not valid", "payload")


def test_ack_round_trip():
    line = te.ack(MAC_KEY, SALT, "ok", "")
    status, detail = te.read_ack(line, MAC_KEY, SALT)
    assert (status, detail) == ("ok", "")


def test_ack_round_trip_with_detail_text():
    line = te.ack(MAC_KEY, SALT, "agent-mismatch", "sender=codex receiver=claude")
    status, detail = te.read_ack(line, MAC_KEY, SALT)
    assert status == "agent-mismatch"
    assert detail == "sender=codex receiver=claude"


def test_ack_flipped_tag_rejected():
    line = te.ack(MAC_KEY, SALT, "ok", "")
    body, tag = line.rsplit(" ", 1)
    flipped_tag = ("0" if tag[0] != "0" else "1") + tag[1:]
    with pytest.raises(te.EnvelopeError):
        te.read_ack(f"{body} {flipped_tag}", MAC_KEY, SALT)


def test_ack_under_different_salt_rejected():
    line = te.ack(MAC_KEY, SALT, "ok", "")
    with pytest.raises(te.EnvelopeError):
        te.read_ack(line, MAC_KEY, OTHER_SALT)


def test_ack_rejects_illegal_detail_charset():
    with pytest.raises(te.EnvelopeError):
        te.ack(MAC_KEY, SALT, "ok", "bad\x01char")


def test_ack_rejects_oversized_detail():
    with pytest.raises(te.EnvelopeError):
        te.ack(MAC_KEY, SALT, "ok", "x" * 121)


def test_ack_rejects_invalid_status():
    with pytest.raises(te.EnvelopeError):
        te.ack(MAC_KEY, SALT, "bogus", "")


def test_read_ack_rejects_malformed_line():
    with pytest.raises(te.EnvelopeError):
        te.read_ack("not-even-close-to-a-line", MAC_KEY, SALT)
```

**Verify:** `.venv/bin/python -m pytest tests/test_transfer_envelope.py -q` → all pass (this is a brand-new file with ~20 test functions).

### 6b. Additions to `tests/test_transfer_crypto.py`

Append at the end of the file:
```python
def test_frame_salt_matches_derive_salt():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    b64 = frame.splitlines()[0]
    blob = base64.b64decode(b64)
    assert tc.frame_salt(frame) == blob[: tc.SALT_LEN]


def test_mac_key_for_frame_matches_derive():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    salt = tc.frame_salt(frame)
    _enc_key, _iv, mac_key = tc._derive(PASSPHRASE, salt)
    assert tc.mac_key_for_frame(frame, PASSPHRASE) == mac_key


def test_frame_salt_rejects_malformed_frame():
    with pytest.raises(tc.DecryptionError):
        tc.frame_salt("not a valid frame")
```

No other lines in this file change.

**Verify:** `.venv/bin/python -m pytest tests/test_transfer_crypto.py -q` → previously-passing tests unchanged, plus 3 new ones, all pass.

### 6c. `tests/test_cli_agent.py` — imports

Replace:
```python
import json
import sys
import time

import pytest

from ai_credentials_helper import cli
from ai_credentials_helper import credentials as creds
```
With:
```python
import json
import subprocess
import sys
import time

import pytest

from ai_credentials_helper import cli
from ai_credentials_helper import credentials as creds
from ai_credentials_helper import transfer_crypto
from ai_credentials_helper import transfer_envelope as te
```

### 6d. `tests/test_cli_agent.py` — fake socket helpers

Replace:
```python
class _FakeConnection:
    def __init__(self, payload=b"encrypted-frame"):
        self._blocks = iter((payload, b""))

    def settimeout(self, _timeout):
        pass

    def recv(self, _size):
        return next(self._blocks)

    def close(self):
        pass


class _FakeServer:
    def __init__(self, payload=b"encrypted-frame"):
        self.connection = _FakeConnection(payload)

    def setsockopt(self, *_args):
        pass

    def bind(self, _address):
        pass

    def listen(self, _backlog):
        pass

    def accept(self):
        return self.connection, ("127.0.0.1", 12345)

    def close(self):
        pass


def _fake_receive_socket(monkeypatch):
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    monkeypatch.setattr(cli.socket, "socket", lambda *_args: _FakeServer())
```
With:
```python
class _FakeConnection:
    def __init__(self, payload=b"encrypted-frame"):
        self._blocks = iter((payload, b""))
        self.sent = b""  # bytes passed to sendall(), for ack assertions

    def settimeout(self, _timeout):
        pass

    def recv(self, _size):
        return next(self._blocks)

    def sendall(self, data):
        self.sent += data

    def close(self):
        pass


class _FakeServer:
    def __init__(self, payload=b"encrypted-frame"):
        self.connection = _FakeConnection(payload)

    def setsockopt(self, *_args):
        pass

    def bind(self, _address):
        pass

    def listen(self, _backlog):
        pass

    def accept(self):
        return self.connection, ("127.0.0.1", 12345)

    def close(self):
        pass


def _fake_receive_socket(monkeypatch, payload=b"encrypted-frame"):
    """Wire cli._do_receive up to a fake server; return the _FakeServer.

    Tests that need the raw ack bytes read ``server.connection.sent``.
    """
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    server = _FakeServer(payload)
    monkeypatch.setattr(cli.socket, "socket", lambda *_args: server)
    return server


def _wire_frame(agent: str, payload: str, passphrase: str = "test-passphrase") -> str:
    """Build a real encrypted, enveloped wire frame for the given agent/payload."""
    return transfer_crypto.encrypt(te.wrap(agent, payload), passphrase)
```

### 6e. `tests/test_cli_agent.py` — fix `test_cli_default_agent_is_claude`

Replace:
```python
def test_cli_default_agent_is_claude():
    parser = cli._build_parser()
    args = parser.parse_args(["--raw"])
    assert args.agent == "claude"
```
With:
```python
def test_cli_default_agent_is_claude():
    parser = cli._build_parser()
    args = parser.parse_args(["--raw"])
    assert args.agent is None
    # The back-compat default now resolves centrally, not in argparse --
    # this guards the property the original test was written for.
    assert cli._default_backend_for(args.agent) == "claude"
```

### 6f. `tests/test_cli_agent.py` — pin `requested_agent` in the two pre-unwrap error tests

Replace:
```python
def test_receive_decryption_failure_names_active_store(
    restore_backend, monkeypatch, capsys
):
    _fake_receive_socket(monkeypatch)
    creds.set_backend("codex")

    def fail_decrypt(_frame, _passphrase):
        raise cli.transfer_crypto.DecryptionError("authentication failed")

    monkeypatch.setattr(cli.transfer_crypto, "decrypt", fail_decrypt)

    assert cli._do_receive(0) == 1
    assert f"{cli._store_label()} left unchanged" in capsys.readouterr().err


def test_receive_invalid_blob_names_active_store(restore_backend, monkeypatch, capsys):
    _fake_receive_socket(monkeypatch)
    creds.set_backend("codex")
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: "not json")

    assert cli._do_receive(0) == 1
    assert f"{cli._store_label()} left unchanged" in capsys.readouterr().err
```
With:
```python
def test_receive_decryption_failure_names_active_store(
    restore_backend, monkeypatch, capsys
):
    _fake_receive_socket(monkeypatch)
    creds.set_backend("codex")

    def fail_decrypt(_frame, _passphrase):
        raise cli.transfer_crypto.DecryptionError("authentication failed")

    monkeypatch.setattr(cli.transfer_crypto, "decrypt", fail_decrypt)

    assert cli._do_receive(0, requested_agent="codex") == 1
    assert f"{cli._store_label()} left unchanged" in capsys.readouterr().err


def test_receive_invalid_blob_names_active_store(restore_backend, monkeypatch, capsys):
    _fake_receive_socket(monkeypatch)
    creds.set_backend("codex")
    enveloped = te.wrap("codex", "not json")
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: enveloped)

    assert cli._do_receive(0, requested_agent="codex") == 1
    assert f"{cli._store_label()} left unchanged" in capsys.readouterr().err
```
(Note: `"not json"` must now be enveloped, since `_process_received_frame` unwraps before calling `parse_blob` — otherwise this would fail at the unwrap step with the "no agent label" message instead of exercising the intended `parse_blob` failure path.)

### 6g. `tests/test_cli_agent.py` — wrap content in the two verbose-receive tests

Replace:
```python
def test_verbose_receive_prints_codex_access_token_and_expiry(
    restore_backend, tmp_path, monkeypatch, capsys
):
    import base64

    from ai_credentials_helper.backends import codex

    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    exp = int(time.time()) + 3600
    access = f"{b64({'alg': 'RS256'})}.{b64({'exp': exp})}.sig"
    content = json.dumps(
        {"tokens": {"access_token": access, "refresh_token": "rt", "account_id": "acct"}}
    )
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "auth.json")
    _fake_receive_socket(monkeypatch)
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: content)
    creds.set_backend("codex")

    assert cli._do_receive(0, verbose=True) == 0
    err = capsys.readouterr().err
    assert f"access_token:  {access}" in err
    assert "expires:" in err
```
With:
```python
def test_verbose_receive_prints_codex_access_token_and_expiry(
    restore_backend, tmp_path, monkeypatch, capsys
):
    import base64

    from ai_credentials_helper.backends import codex

    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    exp = int(time.time()) + 3600
    access = f"{b64({'alg': 'RS256'})}.{b64({'exp': exp})}.sig"
    content = json.dumps(
        {"tokens": {"access_token": access, "refresh_token": "rt", "account_id": "acct"}}
    )
    enveloped = te.wrap("codex", content)
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "auth.json")
    _fake_receive_socket(monkeypatch)
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: enveloped)
    creds.set_backend("codex")

    assert cli._do_receive(0, requested_agent="codex", verbose=True) == 0
    err = capsys.readouterr().err
    assert f"access_token:  {access}" in err
    assert "expires:" in err
```

Replace:
```python
def test_verbose_receive_keeps_claude_token_presentation(
    restore_backend, monkeypatch, capsys
):
    from ai_credentials_helper.backends import claude

    exp = int(time.time()) + 3600
    content = json.dumps(
        {
            "claudeAiOauth": {
                "accessToken": "claude-access",
                "refreshToken": "claude-refresh",
                "expiresAt": exp * 1000,
            }
        }
    )
    _fake_receive_socket(monkeypatch)
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: content)
    monkeypatch.setattr(claude, "write", lambda _content: None)
    creds.set_backend("claude")

    assert cli._do_receive(0, verbose=True) == 0
    err = capsys.readouterr().err
    assert "access_token:  claude-access" in err
    assert "expires:" in err
```
With:
```python
def test_verbose_receive_keeps_claude_token_presentation(
    restore_backend, monkeypatch, capsys
):
    from ai_credentials_helper.backends import claude

    exp = int(time.time()) + 3600
    content = json.dumps(
        {
            "claudeAiOauth": {
                "accessToken": "claude-access",
                "refreshToken": "claude-refresh",
                "expiresAt": exp * 1000,
            }
        }
    )
    enveloped = te.wrap("claude", content)
    _fake_receive_socket(monkeypatch)
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: enveloped)
    monkeypatch.setattr(claude, "write", lambda _content: None)
    creds.set_backend("claude")

    assert cli._do_receive(0, requested_agent="claude", verbose=True) == 0
    err = capsys.readouterr().err
    assert "access_token:  claude-access" in err
    assert "expires:" in err
```

### 6h. `tests/test_cli_agent.py` — rework the `--force`-on-receive test, add two more

Replace:
```python
def test_force_activates_for_codex_receive_and_resets(
    restore_backend, monkeypatch, capsys
):
    from ai_credentials_helper.backends import codex

    observed = {}

    def spy_receive(_port, verbose=False):
        observed["force_during_receive"] = codex.FORCE_WRITE
        observed["verbose"] = verbose
        return 0

    monkeypatch.setattr(cli, "_do_receive", spy_receive)

    assert cli.main(["--agent", "codex", "--force", "--receive"]) == 0
    assert observed == {"force_during_receive": True, "verbose": False}
    assert "WARNING: --force" in capsys.readouterr().err
    assert codex.FORCE_WRITE is False
```
With:
```python
def test_main_passes_force_and_requested_agent_through_to_do_receive(
    restore_backend, monkeypatch, capsys
):
    """main() no longer decides FORCE_WRITE for --receive itself (the wire
    agent isn't known yet) -- it just forwards --force and the resolved
    --agent to _do_receive, which applies force once it knows the backend
    (see test_force_activates_inside_do_receive_at_write_time for that).
    """
    observed = {}

    def spy_receive(_port, *, verbose=False, requested_agent=None, force=False):
        observed.update(verbose=verbose, requested_agent=requested_agent, force=force)
        return 0

    monkeypatch.setattr(cli, "_do_receive", spy_receive)

    assert cli.main(["--agent", "codex", "--force", "--receive"]) == 0
    assert observed == {"verbose": False, "requested_agent": "codex", "force": True}
    # The --force warning now fires inside _do_receive, not main() -- a
    # spied-out _do_receive means it never runs here.
    assert "WARNING: --force" not in capsys.readouterr().err


def test_main_bare_receive_passes_requested_agent_none(restore_backend, monkeypatch):
    observed = {}

    def spy_receive(_port, *, verbose=False, requested_agent=None, force=False):
        observed["requested_agent"] = requested_agent
        return 0

    monkeypatch.setattr(cli, "_do_receive", spy_receive)

    assert cli.main(["--receive"]) == 0
    assert observed["requested_agent"] is None


def test_force_activates_inside_do_receive_at_write_time(
    restore_backend, tmp_path, monkeypatch, capsys
):
    """The real (non-spied) --force contract: FORCE_WRITE flips only after
    _do_receive resolves the wire agent, and only for that backend.
    """
    from ai_credentials_helper.backends import codex

    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    creds.set_backend("claude")  # provisional, as main() would leave it pre-receive

    # An already-expired (but otherwise valid) codex token -- force is
    # required or codex's own expiry check in validate_blob would reject the
    # write regardless of this test's real point of interest.
    expired_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjF9.sig"  # exp=1 (1970)
    payload = json.dumps(
        {"tokens": {"access_token": expired_jwt, "refresh_token": "rt", "account_id": "z"}}
    )
    frame = _wire_frame("codex", payload)
    _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent=None, force=True)
    assert rc == 0
    assert "WARNING: --force" in capsys.readouterr().err
    assert json.loads(auth_file.read_text())["tokens"]["account_id"] == "z"
    codex.FORCE_WRITE = False  # this test bypasses main()'s finally reset
```

### 6i. `tests/test_cli_agent.py` — new end-to-end (fake-socket) tests for the core feature

Append these new tests to the file:

```python
def test_bare_receive_adopts_wire_agent_and_writes_codex_store(
    restore_backend, tmp_path, monkeypatch, capsys
):
    from ai_credentials_helper.backends import codex

    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    creds.set_backend("claude")  # provisional, as main() would leave it pre-receive

    payload = json.dumps(
        {"tokens": {"access_token": "eyJ.fake.token", "refresh_token": "rt", "account_id": "x"}}
    )
    frame = _wire_frame("codex", payload)
    server = _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent=None, force=False)
    assert rc == 0
    err = capsys.readouterr().err
    assert "Detected agent: codex (from sender)" in err
    assert "Received and imported" in err
    assert creds.backend_name() == "codex"
    written = json.loads(auth_file.read_text())
    assert written["tokens"]["account_id"] == "x"

    mac_key = transfer_crypto.mac_key_for_frame(frame, "test-passphrase")
    salt = transfer_crypto.frame_salt(frame)
    status, _detail = te.read_ack(server.connection.sent.decode().strip(), mac_key, salt)
    assert status == "ok"


def test_pinned_matching_agent_succeeds(restore_backend, tmp_path, monkeypatch, capsys):
    from ai_credentials_helper.backends import codex

    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    creds.set_backend("codex")

    payload = json.dumps(
        {"tokens": {"access_token": "eyJ.fake.token", "refresh_token": "rt", "account_id": "y"}}
    )
    frame = _wire_frame("codex", payload)
    _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent="codex", force=False)
    assert rc == 0
    assert json.loads(auth_file.read_text())["tokens"]["account_id"] == "y"


def test_pinned_mismatching_agent_rejected(restore_backend, tmp_path, monkeypatch, capsys):
    from ai_credentials_helper.backends import codex

    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps({"tokens": {"access_token": "orig", "refresh_token": "r", "account_id": "orig"}})
    )
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    creds.set_backend("codex")

    payload = json.dumps({"claudeAiOauth": {"accessToken": "a", "refreshToken": "r", "expiresAt": 1}})
    frame = _wire_frame("claude", payload)
    server = _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent="codex", force=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "agent mismatch" in err
    assert "sender sent 'claude'" in err
    assert "pinned to 'codex'" in err
    # store untouched
    assert json.loads(auth_file.read_text())["tokens"]["account_id"] == "orig"

    mac_key = transfer_crypto.mac_key_for_frame(frame, "test-passphrase")
    salt = transfer_crypto.frame_salt(frame)
    status, _detail = te.read_ack(server.connection.sent.decode().strip(), mac_key, salt)
    assert status == "agent-mismatch"


def test_unlabelled_legacy_payload_rejected(restore_backend, monkeypatch, capsys):
    creds.set_backend("codex")
    legacy_plaintext = json.dumps({"tokens": {"access_token": "a", "refresh_token": "r"}})
    frame = transfer_crypto.encrypt(legacy_plaintext, "test-passphrase")  # no envelope wrap
    _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent="codex", force=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "older version" in err
    assert "upgrade both ends" in err


def test_do_send_returns_1_on_verified_mismatch_ack(restore_backend, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    creds.set_backend("codex")
    monkeypatch.setattr(creds, "read_raw", lambda: '{"tokens":{}}')

    def fake_run(argv, input, capture_output, timeout):
        frame_text = input.decode()
        mac_key = transfer_crypto.mac_key_for_frame(frame_text, "test-passphrase")
        salt = transfer_crypto.frame_salt(frame_text)
        ack_line = te.ack(mac_key, salt, "agent-mismatch", "sender=codex receiver=claude")
        return subprocess.CompletedProcess(argv, 0, stdout=ack_line.encode(), stderr=b"")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._do_send("example.test", 47299, False)
    assert rc == 1
    assert "mismatch" in capsys.readouterr().err


def test_do_send_returns_0_with_note_on_empty_ack(restore_backend, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    creds.set_backend("codex")
    monkeypatch.setattr(creds, "read_raw", lambda: '{"tokens":{}}')

    def fake_run(argv, input, capture_output, timeout):
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._do_send("example.test", 47299, False)
    assert rc == 0
    err = capsys.readouterr().err
    assert "Sent" in err
    assert "no acknowledgement" in err


def test_do_send_ignores_unverifiable_ack(restore_backend, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    creds.set_backend("codex")
    monkeypatch.setattr(creds, "read_raw", lambda: '{"tokens":{}}')

    def fake_run(argv, input, capture_output, timeout):
        return subprocess.CompletedProcess(argv, 0, stdout=b"garbage not an ack\n", stderr=b"")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._do_send("example.test", 47299, False)
    assert rc == 0
    err = capsys.readouterr().err
    assert "unverifiable" in err
    assert "garbage not an ack" not in err
```

**Verify:** `.venv/bin/python -m pytest tests/test_cli_agent.py -q` → all pass (existing + new).

### 6j. `tests/test_cli_live_transfer.py` — add the mismatch round-trip case

The existing `test_codex_send_receive_round_trips_over_localhost_tcp` needs **no code change** — it exercises the real CLI end-to-end and the envelope/ACK machinery is transparent to it (receiver's stdout stays empty; it only writes ACKs to the socket, not stdout). Running it after steps 1–3 is the real regression check for the envelope + ACK over a genuine socket.

Append this new test to the file:

```python
def test_codex_send_claude_receive_mismatch_over_localhost_tcp(tmp_path):
    """Sender labels the transfer 'codex'; receiver is pinned to 'claude'.

    Both processes must exit 1, both stderrs must mention the mismatch, and
    neither store may be touched.
    """
    nc_binary = Path(os.environ.get("CLAUDE_CREDENTIALS_NC", "/usr/bin/nc"))
    if not nc_binary.exists():
        pytest.skip(f"{nc_binary} not available for CLI --send")

    send_home = tmp_path / "send-home"
    recv_home = tmp_path / "recv-home"
    send_auth = send_home / ".codex" / "auth.json"
    send_auth.parent.mkdir(parents=True)

    access_token = _jwt_with_exp(int(time.time()) + 3600)
    payload = {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": access_token,
            "refresh_token": "rt_live_mismatch",
            "account_id": "acct-live-mismatch",
        },
        "last_refresh": "2026-06-28T00:00:00Z",
    }
    send_auth.write_text(json.dumps(payload, separators=(",", ":")) + "\n")
    os.chmod(send_auth, 0o600)

    port = _free_localhost_port()
    env = os.environ.copy()
    env["CLAUDE_CREDENTIALS_PASSPHRASE"] = "pytest-localhost-mismatch"

    recv_env = env | {"HOME": str(recv_home)}
    send_env = env | {"HOME": str(send_home)}

    receiver = subprocess.Popen(
        [
            sys.executable, "-m", "ai_credentials_helper.cli",
            "--agent", "claude",
            "--receive", "--port", str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=recv_env,
    )
    send_result = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            send_result = subprocess.run(
                [
                    sys.executable, "-m", "ai_credentials_helper.cli",
                    "--agent", "codex",
                    "--send", "127.0.0.1", "--send-port", str(port),
                ],
                capture_output=True, text=True, env=send_env, timeout=10,
            )
            if receiver.poll() is not None:
                break
            if send_result.returncode != 0 and "mismatch" in (send_result.stderr or ""):
                break
            time.sleep(0.1)
        recv_stdout, recv_stderr = receiver.communicate(timeout=10)
    finally:
        if receiver.poll() is None:
            receiver.kill()
            receiver.communicate()

    assert send_result is not None
    assert send_result.returncode == 1, send_result.stdout
    assert receiver.returncode == 1, recv_stderr
    assert "mismatch" in send_result.stderr
    assert "mismatch" in recv_stderr
    assert not (recv_home / ".codex" / "auth.json").exists()
    # The sender's own store must also be untouched -- --send never writes.
    still_original = json.loads(send_auth.read_text())
    assert still_original["tokens"]["account_id"] == "acct-live-mismatch"
```

No new imports needed — `subprocess`, `json`, `os`, `sys`, `time`, `Path`, `pytest` are already imported at the top of this file.

**Verify:** `.venv/bin/python -m pytest tests/test_cli_live_transfer.py -q` → both tests pass (skips gracefully if `/usr/bin/nc` is unavailable, same as today).

---

## Verification commands, in order

Run each after the corresponding step; stop and fix before proceeding if any fail.

```bash
# after step 1
.venv/bin/python -c "from ai_credentials_helper import transfer_envelope as te; print(te.unwrap(te.wrap('codex', 'x')))"

# after step 2
.venv/bin/python -m pytest tests/test_transfer_crypto.py -q

# after step 3 (3a-3g)
.venv/bin/python -c "import ai_credentials_helper.cli"
.venv/bin/python -m ai_credentials_helper.cli --help

# after step 6a
.venv/bin/python -m pytest tests/test_transfer_envelope.py -q

# after step 6b
.venv/bin/python -m pytest tests/test_transfer_crypto.py -q

# after step 6c-6i
.venv/bin/python -m pytest tests/test_cli_agent.py -q

# after step 6j
.venv/bin/python -m pytest tests/test_cli_live_transfer.py -q

# final, full suite
.venv/bin/python -m pytest -q
```

---

## Definition of done

All of the following must pass, in this order, with no `xfail`/`skip` beyond the pre-existing `nc`-availability guard in `tests/test_cli_live_transfer.py`:

```bash
.venv/bin/python -m pytest tests/test_transfer_envelope.py -q
.venv/bin/python -m pytest tests/test_transfer_crypto.py -q
.venv/bin/python -m pytest tests/test_cli_agent.py -q
.venv/bin/python -m pytest tests/test_cli_live_transfer.py -q
.venv/bin/python -m pytest tests/test_claude_backend.py tests/test_codex_backend.py -q   # untouched by this change; confirm no regression
.venv/bin/python -m pytest -q   # full suite
```

**Expected final count:** baseline is **128 passed**. This plan adds:
- `tests/test_transfer_envelope.py`: 20 new tests.
- `tests/test_transfer_crypto.py`: +3 tests (frame_salt/mac_key_for_frame).
- `tests/test_cli_agent.py`: net +9 (removes 1 test — `test_force_activates_for_codex_receive_and_resets` — replaced by 3: `test_main_passes_force_and_requested_agent_through_to_do_receive`, `test_main_bare_receive_passes_requested_agent_none`, `test_force_activates_inside_do_receive_at_write_time`; adds 7 new: bare-receive-adopts, pinned-matching, pinned-mismatch, unlabelled-legacy-rejected, and 3 `_do_send` ack tests). Net: -1 +3 +7 = **+9**.
- `tests/test_cli_live_transfer.py`: +1 test (mismatch round trip).

**128 + 20 + 3 + 9 + 1 = 161 passed**, 0 failed, 0 unexpected skips (the two `test_cli_live_transfer.py` tests may legitimately skip together if `/usr/bin/nc` is absent on the CI machine — that's pre-existing behavior, not a regression).

### Critical files for implementation

- `ai_credentials_helper/transfer_envelope.py` (new)
- `ai_credentials_helper/cli.py`
- `ai_credentials_helper/transfer_crypto.py`
- `tests/test_cli_agent.py`
- `tests/test_cli_live_transfer.py`
