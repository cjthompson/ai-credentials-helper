"""Claude Code credentials backend with platform-native storage.

macOS uses the ``Claude Code-credentials`` Keychain entry. Linux and WSL use
Claude Code's ``.credentials.json`` under ``CLAUDE_CONFIG_DIR`` or ``~/.claude``.
Credential parsing and OAuth token handling are shared across both stores.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen

name = "claude"
label = "Claude Code"

TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"


class CredentialsError(Exception):
    """Credential data or its platform-native store is missing or inaccessible."""


def _linux_auth_path() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    config_dir = Path(configured).expanduser() if configured else Path.home() / ".claude"
    return config_dir / ".credentials.json"


if sys.platform == "darwin":
    KEYCHAIN_SERVICE: str | None = "Claude Code-credentials"
    AUTH_PATH: Path | None = None
elif sys.platform == "linux":
    KEYCHAIN_SERVICE = None
    AUTH_PATH = _linux_auth_path()
else:
    KEYCHAIN_SERVICE = None
    AUTH_PATH = None


def _require_auth_path() -> Path:
    if AUTH_PATH is None:
        raise CredentialsError(
            "Claude credential storage is supported only on macOS, Linux, and WSL"
        )
    return AUTH_PATH


def _security(args: list[str], *, timeout: int = 5) -> subprocess.CompletedProcess:
    return subprocess.run(["security", *args], capture_output=True, timeout=timeout)


def _read_raw_keychain() -> str:
    proc = _security(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"])
    if proc.returncode != 0 or not proc.stdout:
        raise CredentialsError("No credentials found in Keychain")
    return proc.stdout.decode("utf-8", errors="replace").rstrip("\n")


def _read_raw_file() -> str:
    path = _require_auth_path()
    try:
        return path.read_text(encoding="utf-8").rstrip("\n")
    except FileNotFoundError:
        raise CredentialsError(f"No credentials found at {path}") from None
    except OSError as exc:
        raise CredentialsError(f"Cannot read {path}: {exc}") from exc


def read_raw() -> str:
    """Return the credential blob, stripping one trailing newline."""
    return _read_raw_keychain() if KEYCHAIN_SERVICE else _read_raw_file()


def parse_blob(raw: str) -> dict:
    """Parse plain or hex-encoded credential JSON into an object."""
    text = raw.strip()
    if not text:
        raise ValueError("credential blob is empty")
    decoded = text if text.startswith("{") else bytes.fromhex(text).decode("utf-8")
    data = json.loads(decoded)
    if not isinstance(data, dict):
        raise ValueError("credential blob must be a JSON object")
    return data


def validate_blob(data: object) -> None:
    """Reject parsed data that is not a usable Claude OAuth credential document."""
    if not isinstance(data, dict):
        raise CredentialsError(
            f"top-level value must be a JSON object, got {type(data).__name__}"
        )
    oauth = data.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        raise CredentialsError("missing or non-dict 'claudeAiOauth' object")
    for field in ("accessToken", "refreshToken"):
        value = oauth.get(field)
        if not isinstance(value, str) or not value:
            raise CredentialsError(f"claudeAiOauth.{field} must be a non-empty string")


def read_json() -> dict:
    """Read and parse the credential blob, accepting plain or hex JSON."""
    return parse_blob(read_raw())


def oauth_only_json() -> str:
    """Return only the ``claudeAiOauth`` section as compact JSON (no trailing newline).

    Drops ``mcpOAuth`` and any other machine-specific keys — for sharing
    credentials between machines.
    """
    data = read_json()
    return json.dumps({"claudeAiOauth": data.get("claudeAiOauth")}, separators=(",", ":"))


def _find_account_keychain() -> str | None:
    proc = _security(["find-generic-password", "-s", KEYCHAIN_SERVICE])
    if proc.returncode != 0:
        return None
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if '"acct"' in line and "<blob>=" in line:
            return line.split("<blob>=")[1].strip().strip('"')
    return None


def find_account() -> str | None:
    """Discover the existing Keychain account name, or None for file storage."""
    return _find_account_keychain() if KEYCHAIN_SERVICE else None


def _write_keychain(content: str) -> None:
    account = _find_account_keychain()
    if not account:
        raise CredentialsError(
            f"No existing keychain entry for service '{KEYCHAIN_SERVICE}'. "
            "Run 'claude login' first."
        )
    proc = _security(
        ["add-generic-password", "-U", "-a", account, "-s", KEYCHAIN_SERVICE, "-w", content]
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise CredentialsError(f"Keychain write failed: {detail}")


def _write_file(content: str) -> None:
    path = _require_auth_path()
    parent_existed = path.parent.exists()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent_existed:
            os.chmod(path.parent, 0o700)
        fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    except OSError as exc:
        raise CredentialsError(f"Cannot prepare credential file at {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise CredentialsError(f"Cannot write {path}: {exc}") from exc


def write(content: str) -> None:
    """Replace the credential store, preserving Keychain writes verbatim on macOS."""
    if KEYCHAIN_SERVICE:
        _write_keychain(content)
        return
    try:
        data = parse_blob(content)
    except (ValueError, json.JSONDecodeError) as exc:
        raise CredentialsError(
            f"payload is not a valid Claude credential document: {exc}"
        ) from exc
    validate_blob(data)
    _write_file(json.dumps(data, separators=(",", ":")))


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
