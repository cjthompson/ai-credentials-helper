"""Codex CLI credentials backend — JSON file at ``~/.codex/auth.json``.

Unlike Claude's macOS-only Keychain storage, Codex stores OAuth tokens in a
plain JSON file. We read/write it with ``0600`` permissions so the access
token isn't world-readable. The schema is::

    {
      "auth_mode": "chatgpt",
      "tokens": {
        "id_token": "...",
        "access_token": "...",
        "refresh_token": "...",
        "account_id": "..."
      },
      "last_refresh": "<ISO 8601 timestamp>"
    }

Refresh: per design plan, codex refreshes tokens itself on each CLI
invocation and the OAuth flow uses PKCE (a ``code_verifier`` may be required
that we don't have). ``refresh_tokens()`` is therefore not implemented in v1;
``--refresh`` from the CLI surfaces a clear ``CredentialsError`` for codex.

std-lib only — no third-party deps. JWT decode (signature unverified) for
expiry display uses ``base64.urlsafe_b64decode`` + ``json.loads``.
"""

import base64
import json
import os
import tempfile
import time
from datetime import datetime
from pathlib import Path

from ai_credentials_helper.backends.claude import CredentialsError as ClaudeCredentialsError

name = "codex"
label = "Codex CLI"

AUTH_PATH = Path.home() / ".codex" / "auth.json"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID: str | None = None  # codex uses PKCE; refresh not implemented in v1
KEYCHAIN_SERVICE = None  # codex doesn't use macOS Keychain; exposes for facade parity

# When True, codex.write() skips the expiry check in validate_blob() (shape
# checks still run, so a totally-garbage payload is still rejected). The CLI
# sets this when --force is passed; users shouldn't toggle it directly.
# Reset by ai_credentials_helper.credentials.set_backend() on every backend
# switch so a stale flag can't leak across invocations.
FORCE_WRITE = False


class CredentialsError(ClaudeCredentialsError):
    """Auth file missing, unreadable, unwriteable, or shape-invalid.

    Inherits from ``claude.CredentialsError`` so the facade and CLI can
    ``except CredentialsError`` uniformly across backends.
    """


def _read_path() -> str:
    """Return the verbatim file contents; raise CredentialsError on missing/unreadable."""
    try:
        text = AUTH_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CredentialsError(f"No credentials found at {AUTH_PATH}") from None
    except OSError as e:
        raise CredentialsError(f"Cannot read {AUTH_PATH}: {e}") from e
    return text.rstrip("\n")


def read_raw() -> str:
    """Return the verbatim ``auth.json`` blob (one trailing newline stripped)."""
    return _read_path()


def parse_blob(raw: str) -> dict:
    """Parse a codex auth blob — JSON only — into a dict. Raises ValueError on garbage.

    Used by ``--receive`` to validate a payload before writing the auth file.
    """
    return json.loads(raw)


def read_json() -> dict:
    """Read auth.json and parse it as JSON."""
    return json.loads(_read_path())


def oauth_only_json() -> str:
    """Return only the ``tokens`` subobject as compact JSON (no trailing newline).

    Drops ``last_refresh`` and ``auth_mode`` so the result is portable between
    machines but still in codex's native shape (same ``tokens`` keys).
    """
    data = read_json()
    return json.dumps({"tokens": data.get("tokens")}, separators=(",", ":"))


def find_account() -> str | None:
    """Return the Codex ``account_id``, or None if the file is missing/shape-invalid.

    Distinct from claude's keychain ``acct``: codex identifies the user by
    ``tokens.account_id`` (a UUID) inside the auth file itself.
    """
    try:
        data = read_json()
    except (CredentialsError, ValueError, json.JSONDecodeError):
        return None
    return (data.get("tokens") or {}).get("account_id")


def validate_blob(data) -> None:
    """Reject codex payloads that would clobber a real auth file with garbage.

    Defense-in-depth: ``write()`` (called by ``--import`` and ``--receive``)
    must not silently overwrite ``~/.codex/auth.json`` with a wrong-shaped or
    already-expired payload. A failed check raises :class:`CredentialsError`
    before the atomic-replace step, so the existing file stays put.

    With ``FORCE_WRITE`` set, the expiry check is skipped — useful for tests
    and for restoring a deliberately-saved near-expiry token. Shape checks
    still run, so a totally-garbage payload (non-dict, no ``tokens`` key,
    empty access_token, etc.) is rejected regardless of force.
    """
    if not isinstance(data, dict):
        raise CredentialsError(f"top-level value must be a JSON object, got {type(data).__name__}")

    tokens = data.get("tokens")
    if not isinstance(tokens, dict):
        raise CredentialsError("missing or non-dict 'tokens' object")

    access = tokens.get("access_token")
    if not isinstance(access, str) or not access:
        raise CredentialsError("tokens.access_token must be a non-empty string")
    if access.count(".") != 2:
        raise CredentialsError(
            "tokens.access_token is not a JWT (expected exactly two '.' separators)"
        )

    refresh = tokens.get("refresh_token")
    if not isinstance(refresh, str) or not refresh:
        raise CredentialsError("tokens.refresh_token must be a non-empty string")

    if not FORCE_WRITE:
        exp = _decode_jwt_exp(access)
        if exp is None:
            raise CredentialsError(
                "tokens.access_token JWT 'exp' claim could not be decoded; "
                "refusing to write a token we can't verify"
            )
        if exp <= int(time.time()):
            expiry_local = datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S %Z")
            raise CredentialsError(
                f"tokens.access_token expired at {expiry_local}; "
                "use --force to write an expired token anyway"
            )


def write(content: str) -> None:
    """Write ``content`` verbatim to ``~/.codex/auth.json`` with ``0600`` perms.

    Before touching the filesystem, parse and validate the payload: it must
    be valid JSON shaped like codex's auth file, with a non-empty access_token
    (JWT-shaped), non-empty refresh_token, and an unexpired ``exp`` claim
    unless ``FORCE_WRITE`` is set. A failed validation raises
    :class:`CredentialsError` and leaves the existing file untouched.

    Creates ``~/.codex/`` if missing. Writes to a temp file in the same
    directory (so the rename is atomic — cross-filesystem renames aren't),
    then ``os.replace``s it into place. A crash mid-write leaves the original
    auth.json untouched instead of producing a truncated file.
    """
    try:
        data = parse_blob(content)
    except ValueError as e:
        raise CredentialsError(f"payload is not valid JSON: {e}") from e
    validate_blob(data)
    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        # NamedTemporaryFile would default to /tmp (different filesystem, so
        # the replace isn't atomic). Build the path manually so the temp file
        # sits next to the final destination.
        fd, tmp_path = tempfile.mkstemp(
            prefix=".auth.json.", dir=str(AUTH_PATH.parent)
        )
    except OSError as e:
        raise CredentialsError(f"Cannot create temp file in {AUTH_PATH.parent}: {e}") from e
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, AUTH_PATH)
    except OSError as e:
        # Best-effort cleanup; the temp file may already be gone after a
        # successful replace.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise CredentialsError(f"Cannot write {AUTH_PATH}: {e}") from e


def _decode_jwt_exp(jwt: str) -> int | None:
    """Return the JWT's ``exp`` claim (seconds since epoch) with no signature check.

    Codex tokens are signed JWTs; we only use the ``exp`` field for display,
    not for trust decisions. Returns None if the JWT can't be parsed OR if
    ``exp`` is the wrong type (e.g. a string) — ``validate_blob`` then raises
    a clean :class:`CredentialsError` instead of letting ``int(time.time())``
    comparison raise ``TypeError`` further up.
    """
    if not jwt or jwt.count(".") != 2:
        return None
    # Take only the middle (payload) segment — splitting on "." once includes
    # everything after the first dot, which is "payload.sig" and breaks the
    # base64 decode below.
    payload_b64 = jwt.split(".")[1]
    # JWTs use URL-safe base64 without padding.
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    # JWT payload MUST be a JSON object (RFC 7519 §4). A list, string, or
    # number is well-formed JSON but not a valid JWT claim set — return None
    # so validate_blob() raises a clean CredentialsError instead of letting
    # ``payload.get(...)`` raise AttributeError further up.
    if not isinstance(payload, dict):
        return None
    exp = payload.get("exp")
    # RFC 7519 says NumericDate is a JSON number; some real-world issuers
    # occasionally emit a string. Either way, refuse to return a value
    # validate_blob() can't safely compare — let it raise CredentialsError
    # with a useful message rather than TypeError further up.
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return None
    return exp


def tokens_from_data(data: dict) -> tuple[str, str, float] | None:
    """Extract ``(access_token, refresh_token, expires_at_epoch)`` from a parsed blob."""
    tokens = data.get("tokens") or {}
    access = tokens.get("access_token")
    if not access:
        return None
    expires_at = _decode_jwt_exp(access)
    if expires_at is None:
        expires_at = int(time.time()) + 3600  # can't determine — fall back to now+1h
    return access, tokens.get("refresh_token") or "", float(expires_at)


def extract_oauth_tokens() -> tuple[str, str, float] | None:
    """Return ``(access_token, refresh_token, expires_at_epoch)`` or None on any error."""
    try:
        data = read_json()
    except (CredentialsError, ValueError, json.JSONDecodeError):
        return None
    return tokens_from_data(data)


def refresh_tokens(refresh_token: str) -> tuple[str, str, int] | None:
    """Refresh is not implemented for codex in v1 — codex refreshes itself on use.

    The OpenAI OAuth server uses PKCE: a refresh alone may not suffice without
    the original ``code_verifier`` that was exchanged at login. Until that's
    verified to work, callers should let codex manage refresh on its own
    (run any codex subcommand to trigger it).
    """
    raise CredentialsError(
        "--refresh is not supported for codex in this version; "
        "codex refreshes tokens automatically on use. Run any `codex` command "
        "to trigger a refresh."
    )
