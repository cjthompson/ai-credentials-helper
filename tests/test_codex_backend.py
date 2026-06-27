"""Unit tests for the Codex CLI backend (JSON file at ~/.codex/auth.json).

Tests redirect ``AUTH_PATH`` to a temp dir via monkeypatch so they don't
touch the real ``~/.codex/auth.json``. JWT decode is exercised with both a
realistic-shape JWT and malformed inputs.
"""

import base64
import json
import os
import time

import pytest

from ai_credentials_helper.backends import codex as creds


def _make_jwt(payload: dict) -> str:
    """Build a structurally valid JWT (header.payload.sig) with payload only.

    The signature segment is junk — we only test parsing, not verification.
    """
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64({'alg':'RS256','kid':'x'})}.{b64(payload)}.sig"


@pytest.fixture
def tmp_auth(tmp_path, monkeypatch):
    """Point ``AUTH_PATH`` at a temp file pre-populated with a codex-shaped blob."""
    access_jwt = _make_jwt({"sub": "user", "exp": int(time.time()) + 3600})
    refresh_jwt = _make_jwt({"sub": "user", "exp": int(time.time()) + 86400 * 30})
    full = {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": refresh_jwt,
            "access_token": access_jwt,
            "refresh_token": "rt_abc123",
            "account_id": "acct-uuid",
        },
        "last_refresh": "2026-06-26T17:26:26.595320Z",
    }
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps(full, indent=2))
    monkeypatch.setattr(creds, "AUTH_PATH", auth_file)
    return auth_file, access_jwt


# ── Read paths ─────────────────────────────────────────────────────────────


def test_read_raw_returns_verbatim_text(tmp_auth):
    auth_file, _ = tmp_auth
    assert creds.read_raw() == auth_file.read_text()


def test_read_raw_strips_trailing_newline(tmp_auth):
    auth_file, _ = tmp_auth
    auth_file.write_text(auth_file.read_text() + "\n")
    assert creds.read_raw() == auth_file.read_text().rstrip("\n")


def test_read_raw_raises_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(creds, "AUTH_PATH", tmp_path / "nope.json")
    with pytest.raises(creds.CredentialsError, match="No credentials found"):
        creds.read_raw()


def test_read_json_parses_blob(tmp_auth):
    auth_file, _ = tmp_auth
    data = creds.read_json()
    assert data["tokens"]["account_id"] == "acct-uuid"
    assert data["auth_mode"] == "chatgpt"


def test_read_json_raises_on_invalid_json(tmp_auth):
    auth_file, _ = tmp_auth
    auth_file.write_text("{ not json")
    with pytest.raises(json.JSONDecodeError):
        creds.read_json()


def test_oauth_only_json_drops_last_refresh_and_auth_mode(tmp_auth):
    out = creds.oauth_only_json()
    assert not out.endswith("\n")
    parsed = json.loads(out)
    assert "tokens" in parsed
    assert parsed["tokens"]["account_id"] == "acct-uuid"
    assert "last_refresh" not in parsed
    assert "auth_mode" not in parsed


# ── Account ───────────────────────────────────────────────────────────────


def test_find_account_returns_account_id(tmp_auth):
    assert creds.find_account() == "acct-uuid"


def test_find_account_returns_none_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(creds, "AUTH_PATH", tmp_path / "nope.json")
    assert creds.find_account() is None


def test_find_account_returns_none_when_shape_invalid(tmp_auth):
    auth_file, _ = tmp_auth
    auth_file.write_text(json.dumps({"tokens": {}}))
    assert creds.find_account() is None


# ── Write paths ────────────────────────────────────────────────────────────


def test_write_creates_file_with_0600_perms(tmp_path, monkeypatch):
    auth_file = tmp_path / "subdir" / "auth.json"  # parent doesn't exist yet
    monkeypatch.setattr(creds, "AUTH_PATH", auth_file)
    creds.write('{"tokens":{"access_token":"a"}}')
    assert auth_file.exists()
    mode = stat_mode(auth_file)
    # umask may further restrict; we only require owner write+read (no group/other bits).
    assert mode & 0o077 == 0


def test_write_replaces_existing(tmp_auth):
    auth_file, _ = tmp_auth
    creds.write('{"new": true}')
    assert json.loads(auth_file.read_text()) == {"new": True}


def test_write_appends_trailing_newline_if_missing(tmp_auth):
    auth_file, _ = tmp_auth
    creds.write('{"x": 1}')  # no trailing \n
    assert auth_file.read_text().endswith("\n")


# ── Token extraction ───────────────────────────────────────────────────────


def test_extract_oauth_tokens_returns_access_refresh_expiry(tmp_auth):
    _, access_jwt = tmp_auth
    access, refresh, expires_at = creds.extract_oauth_tokens()
    assert access == access_jwt
    assert refresh == "rt_abc123"
    # expires_at is the JWT exp (seconds since epoch); close to now+3600.
    assert pytest.approx(expires_at, abs=2) == time.time() + 3600


def test_extract_oauth_tokens_none_when_no_access_token(tmp_auth):
    auth_file, _ = tmp_auth
    auth_file.write_text(json.dumps({"tokens": {"refresh_token": "r"}}))
    assert creds.extract_oauth_tokens() is None


def test_extract_oauth_tokens_falls_back_when_jwt_invalid(tmp_auth):
    auth_file, _ = tmp_auth
    auth_file.write_text(json.dumps({
        "tokens": {"access_token": "not.a.jwt", "refresh_token": "rt_abc123"},
    }))
    access, refresh, expires_at = creds.extract_oauth_tokens()
    assert access == "not.a.jwt"
    assert refresh == "rt_abc123"
    # Falls back to now+3600 when JWT decode fails.
    assert expires_at > time.time()


# ── Refresh (not implemented for codex in v1) ─────────────────────────────


def test_refresh_tokens_raises_with_clear_message():
    with pytest.raises(creds.CredentialsError, match="not supported for codex"):
        creds.refresh_tokens("rt_anything")


# ── Helpers ───────────────────────────────────────────────────────────────


def stat_mode(path) -> int:
    """Return just the permission bits (mask off file-type)."""
    return os.stat(path).st_mode & 0o777