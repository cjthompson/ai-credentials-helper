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
import time
from pathlib import Path

from ai_credentials_helper.backends.claude import CredentialsError as ClaudeCredentialsError

name = "codex"
label = "Codex CLI"

AUTH_PATH = Path.home() / ".codex" / "auth.json"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID: str | None = None  # codex uses PKCE; refresh not implemented in v1
KEYCHAIN_SERVICE = None  # codex doesn't use macOS Keychain; exposes for facade parity


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


def write(content: str) -> None:
    """Write ``content`` verbatim to ``~/.codex/auth.json`` with ``0600`` perms.

    Creates ``~/.codex/`` if missing. Replaces the existing file atomically
    via write-to-temp + rename, so a concurrent ``codex`` invocation cannot
    observe a partial file.
    """
    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(AUTH_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")
    except OSError as e:
        raise CredentialsError(f"Cannot write {AUTH_PATH}: {e}") from e


def _decode_jwt_exp(jwt: str) -> int | None:
    """Return the JWT's ``exp`` claim (seconds since epoch) with no signature check.

    Codex tokens are signed JWTs; we only use the ``exp`` field for display,
    not for trust decisions. Returns None if the JWT can't be parsed.
    """
    if not jwt or jwt.count(".") != 2:
        return None
    payload_b64 = jwt.split(".", 1)[1]
    # JWTs use URL-safe base64 without padding.
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload.get("exp")


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
