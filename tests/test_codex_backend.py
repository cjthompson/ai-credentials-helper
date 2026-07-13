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


def _make_jwt(payload: object) -> str:
    """Build a structurally valid JWT (header.payload.sig) with payload only.

    The signature segment is junk — we only test parsing, not verification.
    """
    def b64(d: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64({'alg':'RS256','kid':'x'})}.{b64(payload)}.sig"


def _valid_codex_payload(**overrides) -> str:
    """Build a JSON string that passes validate_blob with a 1h-future expiry.

    Pass overrides like ``access_token="..."`` or ``exp_offset=-10`` to
    construct variants for negative tests.
    """
    exp = int(time.time()) + overrides.pop("exp_offset", 3600)
    access = overrides.pop("access_token", _make_jwt({"sub": "u", "exp": exp}))
    payload = {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": access,
            "refresh_token": "rt_test",
            "account_id": "acct-test",
            **overrides,
        },
    }
    return json.dumps(payload)


@pytest.fixture
def restore_force():
    """Snapshot/restore codex.FORCE_WRITE so a test can't leak the flag."""
    from ai_credentials_helper.backends import codex
    original = codex.FORCE_WRITE
    yield
    codex.FORCE_WRITE = original


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


@pytest.mark.parametrize(
    "data",
    [[], "credentials", 42, None, {"tokens": []}, {"tokens": "credentials"}],
)
def test_find_account_returns_none_for_non_object_containers(tmp_auth, data):
    auth_file, _ = tmp_auth
    auth_file.write_text(json.dumps(data))
    assert creds.find_account() is None


# ── Write paths ────────────────────────────────────────────────────────────


def test_write_creates_file_with_0600_perms(tmp_path, monkeypatch):
    auth_file = tmp_path / "subdir" / "auth.json"  # parent doesn't exist yet
    monkeypatch.setattr(creds, "AUTH_PATH", auth_file)
    creds.write(_valid_codex_payload())
    assert auth_file.exists()
    mode = stat_mode(auth_file)
    # umask may further restrict; we only require owner write+read (no group/other bits).
    assert mode & 0o077 == 0


def test_write_replaces_existing(tmp_auth):
    auth_file, _ = tmp_auth
    creds.write(_valid_codex_payload())
    parsed = json.loads(auth_file.read_text())
    assert parsed["tokens"]["refresh_token"] == "rt_test"


def test_write_appends_trailing_newline_if_missing(tmp_auth):
    auth_file, _ = tmp_auth
    # Build a payload without trailing newline to exercise the append path.
    payload = _valid_codex_payload().rstrip("\n")
    creds.write(payload)
    assert auth_file.read_text().endswith("\n")


def test_write_does_not_leave_temp_files_behind(tmp_auth):
    """Atomic replace: any temp files in the parent dir get cleaned up."""
    auth_file, _ = tmp_auth
    creds.write(_valid_codex_payload())
    leftovers = [p for p in auth_file.parent.iterdir() if p.name.startswith(".auth.json.")]
    assert leftovers == [], f"temp files leaked: {leftovers}"


def test_write_is_atomic_preserves_existing_on_failure(tmp_auth, monkeypatch):
    """If os.replace fails mid-write, the original auth.json is untouched.

    Regression: the prior implementation opened auth.json with O_TRUNC, so a
    crash mid-write left an empty/partial file and clobbered the original.
    """
    auth_file, _ = tmp_auth
    original_content = auth_file.read_text()

    def boom(*_a, **_kw):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(creds.os, "replace", boom)
    with pytest.raises(creds.CredentialsError, match="Cannot write"):
        creds.write(_valid_codex_payload())

    assert auth_file.read_text() == original_content


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


@pytest.mark.parametrize(
    "data",
    [[], "credentials", 42, None, {"tokens": []}, {"tokens": "credentials"}],
)
def test_tokens_from_data_returns_none_for_non_object_containers(data):
    assert creds.tokens_from_data(data) is None


@pytest.mark.parametrize(
    "data",
    [[], "credentials", 42, None, {"tokens": []}, {"tokens": "credentials"}],
)
def test_extract_oauth_tokens_returns_none_for_non_object_containers(tmp_auth, data):
    auth_file, _ = tmp_auth
    auth_file.write_text(json.dumps(data))
    assert creds.extract_oauth_tokens() is None


def test_non_string_access_token_returns_none_instead_of_raising(tmp_auth):
    data = {"tokens": {"access_token": 123, "refresh_token": "refresh"}}
    assert creds.tokens_from_data(data) is None

    auth_file, _ = tmp_auth
    auth_file.write_text(json.dumps(data))
    assert creds.extract_oauth_tokens() is None


# ── Refresh (not implemented for codex in v1) ─────────────────────────────


def test_refresh_tokens_raises_with_clear_message():
    with pytest.raises(creds.CredentialsError, match="not supported for codex"):
        creds.refresh_tokens("rt_anything")


# ── Write-time validation (safety net against garbage overwrites) ──────────


@pytest.mark.parametrize("garbage", ["", "[]", '"a string"', "null", "{", "not json"])
def test_write_rejects_non_json_or_non_object_payload(garbage, tmp_auth, restore_force):
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError):
        creds.write(garbage)
    assert auth_file.read_text() == original, "failed validation must not touch disk"


def test_write_rejects_missing_tokens(tmp_auth, restore_force):
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError, match="tokens"):
        creds.write(json.dumps({"auth_mode": "chatgpt"}))
    assert auth_file.read_text() == original


def test_write_rejects_non_jwt_access_token(tmp_auth, restore_force):
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError, match="JWT"):
        creds.write(_valid_codex_payload(access_token="not.a.jwt"))
    assert auth_file.read_text() == original


def test_write_rejects_empty_refresh_token(tmp_auth, restore_force):
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError, match="refresh_token"):
        creds.write(_valid_codex_payload(refresh_token=""))
    assert auth_file.read_text() == original


def test_write_rejects_expired_token(tmp_auth, restore_force):
    """The headline protection: an expired access_token must be refused."""
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError, match="expired"):
        creds.write(_valid_codex_payload(exp_offset=-3600))
    assert auth_file.read_text() == original


def test_write_rejects_unparseable_jwt(tmp_auth, restore_force):
    """A non-decodable JWT must be rejected — we'd rather refuse than write
    something whose expiry we can't verify."""
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    # Three segments but the payload segment is not valid base64-encoded JSON.
    with pytest.raises(creds.CredentialsError, match="exp"):
        creds.write(_valid_codex_payload(access_token="aaa.!!!.bbb"))
    assert auth_file.read_text() == original


def test_write_rejects_string_exp_claim(tmp_auth, restore_force):
    """A JWT whose ``exp`` is a string must be rejected with a clean
    CredentialsError, not a TypeError.

    Regression: ``_decode_jwt_exp`` previously returned whatever
    ``payload.get('exp')`` was, so a JWT like ``{"exp": "1782635025"}`` made
    it past the decoder and crashed with TypeError in the ``<=`` comparison,
    leaving the CLI's exception handler the wrong error to format.
    """
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError, match="exp"):
        creds.write(_valid_codex_payload(access_token=_make_jwt({"sub": "u", "exp": "1782635025"})))
    assert auth_file.read_text() == original


def test_write_rejects_boolean_exp_claim(tmp_auth, restore_force):
    """Booleans are ints in Python — guard against JSON ``true`` slipping
    through isinstance(..., int)."""
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError, match="exp"):
        creds.write(_valid_codex_payload(access_token=_make_jwt({"exp": True})))
    assert auth_file.read_text() == original


def test_write_rejects_non_object_jwt_payload(tmp_auth, restore_force):
    """A JWT whose payload is valid JSON but not an object (e.g. ``[]``,
    ``"payload"``, ``42``) must be rejected with a clean CredentialsError.

    Regression: ``_decode_jwt_exp`` previously called ``payload.get("exp")``
    on whatever ``json.loads`` returned, so a list/str/int raised
    ``AttributeError`` instead of a clean rejection — the CLI's exception
    handler would then print the wrong error message.
    """
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError, match="exp"):
        creds.write(_valid_codex_payload(access_token=_make_jwt([])))
    with pytest.raises(creds.CredentialsError, match="exp"):
        creds.write(_valid_codex_payload(access_token=_make_jwt("payload")))
    with pytest.raises(creds.CredentialsError, match="exp"):
        creds.write(_valid_codex_payload(access_token=_make_jwt(42)))
    assert auth_file.read_text() == original


@pytest.mark.parametrize(
    "exp",
    [True, "1782635025", None, float("nan"), float("inf"), float("-inf"), 1e100, -1e100],
)
def test_decode_jwt_exp_rejects_unusable_values(exp):
    assert creds._decode_jwt_exp(_make_jwt({"exp": exp})) is None


@pytest.mark.parametrize("exp", [1e100, -1e100])
def test_validate_blob_rejects_out_of_range_exp_cleanly(exp, restore_force):
    data = json.loads(_valid_codex_payload(access_token=_make_jwt({"exp": exp})))
    with pytest.raises(creds.CredentialsError, match="exp"):
        creds.validate_blob(data)


def test_force_bypasses_expiry_check(tmp_auth, restore_force):
    """--force accepts expired tokens; tests/recovery use case."""
    creds.FORCE_WRITE = True
    auth_file, _ = tmp_auth
    creds.write(_valid_codex_payload(exp_offset=-3600))
    parsed = json.loads(auth_file.read_text())
    assert parsed["tokens"]["refresh_token"] == "rt_test"


def test_force_still_enforces_shape(tmp_auth, restore_force):
    """Shape checks run regardless of --force — '[]' must never reach disk."""
    creds.FORCE_WRITE = True
    auth_file, _ = tmp_auth
    original = auth_file.read_text()
    with pytest.raises(creds.CredentialsError):
        creds.write("[]")
    assert auth_file.read_text() == original


def test_set_backend_resets_force_write():
    """A stale FORCE_WRITE from a prior invocation must not leak forward."""
    from ai_credentials_helper import credentials as creds_facade
    original_backend = creds_facade._backend
    try:
        creds_facade.set_backend("codex")
        creds.FORCE_WRITE = True
        creds_facade.set_backend("claude")
        creds_facade.set_backend("codex")
        assert creds.FORCE_WRITE is False
    finally:
        creds_facade._backend = original_backend
        creds.FORCE_WRITE = False


# ── Helpers ───────────────────────────────────────────────────────────────


def stat_mode(path) -> int:
    """Return just the permission bits (mask off file-type)."""
    return os.stat(path).st_mode & 0o777
