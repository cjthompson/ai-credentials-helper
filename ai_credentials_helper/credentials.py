"""Shared macOS Keychain + OAuth helpers for Claude Code credentials.

Single source of truth for reading/writing the ``Claude Code-credentials``
Keychain entry and refreshing OAuth tokens. Used by both the usage bar
(``usage.py``) and the ``claude-monitor-credentials`` CLI
(``claude_monitor.cli_credentials``).

stdlib only — shells out to the ``security`` binary (no ``keyring`` dependency),
matching the rest of the project.
"""

import json
import subprocess
import time
from urllib.request import Request, urlopen

KEYCHAIN_SERVICE = "Claude Code-credentials"
TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"


class CredentialsError(Exception):
    """Keychain entry missing, unreadable, or unwritable."""


def _security(args: list[str], *, timeout: int = 5) -> subprocess.CompletedProcess:
    return subprocess.run(["security", *args], capture_output=True, timeout=timeout)


def read_raw() -> str:
    """Return the verbatim ``security ... -w`` blob (one trailing newline stripped).

    This is the default-export form — exactly the bytes Claude Code stored,
    which may be raw JSON or hex-encoded depending on macOS version.
    """
    proc = _security(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"])
    if proc.returncode != 0 or not proc.stdout:
        raise CredentialsError("No credentials found in Keychain")
    return proc.stdout.decode("utf-8", errors="replace").rstrip("\n")


def parse_blob(raw: str) -> dict:
    """Parse a keychain blob — raw JSON, or hex-encoded JSON — into a dict.

    These are the two forms Claude Code stores (see :func:`read_raw`). Raises
    ``ValueError`` if ``raw`` is neither. Used to validate a *received* blob
    before writing it, so a garbage payload can't overwrite the keychain entry.
    """
    text = raw if raw.startswith("{") else bytes.fromhex(raw).decode("utf-8")
    return json.loads(text)


def read_json() -> dict:
    """Read the keychain blob and parse it as JSON, decoding hex if needed."""
    raw = read_raw()
    text = raw if raw.startswith("{") else bytes.fromhex(raw).decode("utf-8", errors="replace")
    return json.loads(text)


def oauth_only_json() -> str:
    """Return only the ``claudeAiOauth`` section as compact JSON (no trailing newline).

    Drops ``mcpOAuth`` and any other machine-specific keys — for sharing
    credentials between machines.
    """
    data = read_json()
    return json.dumps({"claudeAiOauth": data.get("claudeAiOauth")}, separators=(",", ":"))


def find_account() -> str | None:
    """Discover the account name of the existing keychain entry, or None."""
    proc = _security(["find-generic-password", "-s", KEYCHAIN_SERVICE])
    if proc.returncode != 0:
        return None
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if '"acct"' in line and "<blob>=" in line:
            return line.split("<blob>=")[1].strip().strip('"')
    return None


def write(content: str) -> None:
    """Write ``content`` verbatim to the keychain, replacing the existing entry.

    Requires an existing entry (so the account name can be discovered) — i.e.
    ``claude login`` must have run on this Mac at least once.
    """
    account = find_account()
    if not account:
        raise CredentialsError(
            f"No existing keychain entry for service '{KEYCHAIN_SERVICE}'. "
            "Run 'claude login' first."
        )
    proc = _security(
        ["add-generic-password", "-U", "-a", account, "-s", KEYCHAIN_SERVICE, "-w", content]
    )
    if proc.returncode != 0:
        raise CredentialsError(
            f"Keychain write failed: {proc.stderr.decode('utf-8', errors='replace').strip()}"
        )


def tokens_from_data(data: dict) -> tuple[str, str, float] | None:
    """Extract ``(access_token, refresh_token, expires_at_epoch)`` from a parsed blob, or None."""
    oauth = data.get("claudeAiOauth", {})
    token = oauth.get("accessToken")
    if not token:
        return None
    expires_at = oauth.get("expiresAt")
    expires_at = expires_at / 1000 if expires_at else time.time() + 3600
    return token, oauth.get("refreshToken") or "", expires_at


def extract_oauth_tokens() -> tuple[str, str, float] | None:
    """Return ``(access_token, refresh_token, expires_at_epoch)`` from the keychain, or None."""
    try:
        data = read_json()
    except (CredentialsError, ValueError, json.JSONDecodeError):
        return None
    return tokens_from_data(data)


def refresh_tokens(refresh_token: str) -> tuple[str, str, int] | None:
    """Exchange a refresh token for a new access token via the OAuth endpoint.

    Returns ``(access_token, refresh_token, expires_in_seconds)`` or None if no
    refresh token was given or the response lacked an access token. Network
    errors propagate to the caller.
    """
    if not refresh_token:
        return None
    payload = json.dumps(
        {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": CLIENT_ID}
    ).encode()
    req = Request(
        TOKEN_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    new_access = data.get("access_token")
    if not new_access:
        return None
    return new_access, data.get("refresh_token", refresh_token), data.get("expires_in", 3600)
