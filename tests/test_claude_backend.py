"""Unit tests for the Claude backend (macOS Keychain + OAuth).

Tests import the backend module directly because they patch attributes
(``subprocess.run``, ``urlopen``) on the backend itself; the facade
dispatches via ``__getattr__`` so patches on the facade don't propagate.
"""

import json
from types import SimpleNamespace

import pytest

from ai_credentials_helper.backends import claude as creds

OAUTH = {
    "accessToken": "sk-ant-oat-abc",
    "refreshToken": "sk-ant-ort-xyz",
    "expiresAt": 1790000000000,
}
FULL = {"claudeAiOauth": OAUTH, "mcpOAuth": {"machine": "x"}, "other": "y"}
FULL_JSON = json.dumps(FULL, separators=(",", ":"))


def _proc(returncode=0, stdout=b"", stderr=b""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture
def fake_security(monkeypatch):
    """Mock the `security` CLI; tweak behavior via the returned state dict."""
    state = {
        "blob": FULL_JSON,  # what `find ... -w` returns (str), or None for "missing"
        "meta": '    "acct"<blob>="me@example.com"',  # what `find` (no -w) returns
        "writes": [],  # captured add-generic-password argv lists
        "add_rc": 0,
    }

    def fake_run(argv, **kwargs):
        assert argv[0] == "security"
        sub = argv[1]
        if sub == "find-generic-password":
            if "-w" in argv:
                if state["blob"] is None:
                    return _proc(returncode=1)
                return _proc(stdout=state["blob"].encode())
            return _proc(stdout=state["meta"].encode())
        if sub == "add-generic-password":
            state["writes"].append(argv)
            return _proc(returncode=state["add_rc"], stderr=b"boom" if state["add_rc"] else b"")
        raise AssertionError(f"unexpected security subcommand: {sub}")

    monkeypatch.setattr(creds.subprocess, "run", fake_run)
    return state


def _resp(payload: dict):
    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(payload).encode()

    return Resp()


def test_read_raw_returns_blob_without_trailing_newline(fake_security):
    fake_security["blob"] = FULL_JSON + "\n"
    assert creds.read_raw() == FULL_JSON


def test_read_raw_raises_when_missing(fake_security):
    fake_security["blob"] = None
    with pytest.raises(creds.CredentialsError):
        creds.read_raw()


def test_read_json_parses_plain_json(fake_security):
    assert creds.read_json() == FULL


def test_read_json_decodes_hex_blob(fake_security):
    fake_security["blob"] = FULL_JSON.encode().hex()
    assert creds.read_json() == FULL


def test_parse_blob_accepts_json_and_hex_and_rejects_garbage():
    # The blob Claude Code stores is JSON or hex-encoded JSON; parse_blob accepts
    # both and raises ValueError on anything else (used to validate received data).
    assert creds.parse_blob(FULL_JSON) == FULL
    assert creds.parse_blob(FULL_JSON.encode().hex()) == FULL
    for bad in ("", "   ", "not a blob", "zz", "{not json}"):
        with pytest.raises(ValueError):
            creds.parse_blob(bad)


def test_oauth_only_json_strips_other_keys_and_has_no_trailing_newline(fake_security):
    out = creds.oauth_only_json()
    assert not out.endswith("\n")
    assert json.loads(out) == {"claudeAiOauth": OAUTH}


def test_find_account_parses_blob_acct(fake_security):
    assert creds.find_account() == "me@example.com"


def test_write_discovers_account_and_calls_add_update(fake_security):
    creds.write(FULL_JSON)
    (argv,) = fake_security["writes"]
    assert argv[:2] == ["security", "add-generic-password"]
    assert "-U" in argv
    assert argv[argv.index("-a") + 1] == "me@example.com"
    assert argv[argv.index("-s") + 1] == creds.KEYCHAIN_SERVICE
    assert argv[argv.index("-w") + 1] == FULL_JSON


def test_write_raises_without_existing_account(fake_security):
    fake_security["meta"] = "no account here"
    with pytest.raises(creds.CredentialsError):
        creds.write(FULL_JSON)


def test_write_raises_on_security_failure(fake_security):
    fake_security["add_rc"] = 1
    with pytest.raises(creds.CredentialsError):
        creds.write(FULL_JSON)


def test_tokens_from_data_returns_none_without_access_token():
    assert creds.tokens_from_data({"claudeAiOauth": {}}) is None
    assert creds.tokens_from_data({}) is None


def test_tokens_from_data_defaults_expiry_when_absent():
    token, refresh, expires_at = creds.tokens_from_data({"claudeAiOauth": {"accessToken": "t"}})
    assert (token, refresh) == ("t", "")
    assert expires_at > 0  # falls back to now + 1h


def test_extract_oauth_tokens(fake_security):
    token, refresh, expires_at = creds.extract_oauth_tokens()
    assert token == "sk-ant-oat-abc"
    assert refresh == "sk-ant-ort-xyz"
    assert expires_at == 1790000000000 / 1000


def test_extract_oauth_tokens_none_when_missing(fake_security):
    fake_security["blob"] = None
    assert creds.extract_oauth_tokens() is None


def test_refresh_tokens_returns_new_tokens(monkeypatch):
    monkeypatch.setattr(
        creds, "urlopen",
        lambda req, **kw: _resp({"access_token": "new_a", "refresh_token": "new_r", "expires_in": 1234}),
    )
    assert creds.refresh_tokens("old_r") == ("new_a", "new_r", 1234)


def test_refresh_tokens_none_without_refresh_token():
    assert creds.refresh_tokens("") is None


def test_refresh_tokens_none_when_no_access_token(monkeypatch):
    monkeypatch.setattr(creds, "urlopen", lambda req, **kw: _resp({}))
    assert creds.refresh_tokens("old_r") is None


def test_refresh_tokens_defaults_refresh_and_expiry(monkeypatch):
    monkeypatch.setattr(creds, "urlopen", lambda req, **kw: _resp({"access_token": "new_a"}))
    assert creds.refresh_tokens("keep_r") == ("new_a", "keep_r", 3600)
