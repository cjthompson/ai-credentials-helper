"""Unit tests for Claude's platform-native credential storage and OAuth behavior.

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
    monkeypatch.setattr(creds, "KEYCHAIN_SERVICE", "Claude Code-credentials")
    monkeypatch.setattr(creds, "AUTH_PATH", None, raising=False)
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


def test_linux_auth_path_defaults_to_claude_directory(monkeypatch):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(creds.Path, "home", classmethod(lambda _cls: creds.Path("/home/tester")))
    assert creds._linux_auth_path() == creds.Path("/home/tester/.claude/.credentials.json")


def test_linux_auth_path_honors_claude_config_dir(monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/srv/claude-config")
    assert creds._linux_auth_path() == creds.Path("/srv/claude-config/.credentials.json")


def test_require_auth_path_rejects_unsupported_platform(monkeypatch):
    monkeypatch.setattr(creds, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(creds, "AUTH_PATH", None)
    with pytest.raises(creds.CredentialsError, match="supported only on macOS, Linux, and WSL"):
        creds._require_auth_path()


@pytest.mark.parametrize(
    "data, message",
    [
        ([], "top-level value must be a JSON object"),
        ({}, "missing or non-dict 'claudeAiOauth' object"),
        ({"claudeAiOauth": []}, "missing or non-dict 'claudeAiOauth' object"),
        ({"claudeAiOauth": {"accessToken": "", "refreshToken": "r"}}, "accessToken"),
        ({"claudeAiOauth": {"accessToken": "a", "refreshToken": ""}}, "refreshToken"),
    ],
)
def test_validate_blob_rejects_non_credentials(data, message):
    with pytest.raises(creds.CredentialsError, match=message):
        creds.validate_blob(data)


def test_validate_blob_accepts_oauth_credentials():
    creds.validate_blob(FULL)


def test_keychain_write_preserves_verbatim_non_oauth_document(fake_security):
    content = '{"customCredential":"preserve-verbatim"}'
    creds.write(content)
    (argv,) = fake_security["writes"]
    assert argv[argv.index("-w") + 1] == content


def test_keychain_write_accepts_linux_json(fake_security):
    creds.write(FULL_JSON)
    (argv,) = fake_security["writes"]
    assert argv[argv.index("-w") + 1] == FULL_JSON


@pytest.fixture
def linux_credentials(tmp_path, monkeypatch):
    auth_path = tmp_path / ".claude" / ".credentials.json"
    monkeypatch.setattr(creds, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(creds, "AUTH_PATH", auth_path)
    return auth_path


def test_linux_read_raw_reads_json_file(linux_credentials):
    linux_credentials.parent.mkdir(parents=True)
    linux_credentials.write_text(FULL_JSON + "\n")
    assert creds.read_raw() == FULL_JSON


def test_linux_read_raw_reports_missing_file(linux_credentials):
    with pytest.raises(creds.CredentialsError, match="No credentials found"):
        creds.read_raw()


def test_linux_write_creates_private_file_and_directory(linux_credentials):
    creds.write(FULL_JSON)
    assert json.loads(linux_credentials.read_text()) == FULL
    assert linux_credentials.stat().st_mode & 0o077 == 0
    assert linux_credentials.parent.stat().st_mode & 0o077 == 0


def test_linux_write_normalizes_hex_keychain_blob(linux_credentials):
    creds.write(FULL_JSON.encode().hex())
    assert json.loads(linux_credentials.read_text()) == FULL
    assert not linux_credentials.read_text().startswith(FULL_JSON.encode().hex()[:16])


def test_linux_write_validation_leaves_existing_file_unchanged(linux_credentials):
    linux_credentials.parent.mkdir(parents=True)
    linux_credentials.write_text(FULL_JSON + "\n")
    before = linux_credentials.read_bytes()
    with pytest.raises(creds.CredentialsError, match="accessToken"):
        creds.write('{"claudeAiOauth":{"accessToken":"","refreshToken":"r"}}')
    assert linux_credentials.read_bytes() == before


def test_linux_write_uses_atomic_replace(linux_credentials, monkeypatch):
    replaced = []
    real_replace = creds.os.replace

    def spy_replace(source, destination):
        replaced.append((creds.Path(source).parent, creds.Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr(creds.os, "replace", spy_replace)
    creds.write(FULL_JSON)
    assert replaced == [(linux_credentials.parent, linux_credentials)]


def test_linux_write_replace_failure_preserves_existing_and_cleans_temp(
    linux_credentials, monkeypatch
):
    linux_credentials.parent.mkdir(parents=True)
    linux_credentials.write_text(FULL_JSON + "\n")
    before = linux_credentials.read_bytes()

    def fail_replace(*_args):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(creds.os, "replace", fail_replace)

    with pytest.raises(creds.CredentialsError, match="Cannot write"):
        creds.write(FULL_JSON)

    assert linux_credentials.read_bytes() == before
    temp_prefix = f".{linux_credentials.name}."
    assert [p for p in linux_credentials.parent.iterdir() if p.name.startswith(temp_prefix)] == []


def test_linux_find_account_is_none(linux_credentials):
    assert creds.find_account() is None


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


def test_validate_blob_accepts_a_real_claude_document():
    creds.validate_blob({"claudeAiOauth": {"accessToken": "at", "refreshToken": "rt"}})


@pytest.mark.parametrize(
    "data, expected",
    [
        ([], "must be a JSON object"),
        ({}, "missing or non-dict 'claudeAiOauth'"),
        ({"claudeAiOauth": None}, "missing or non-dict 'claudeAiOauth'"),
        # A codex auth.json parses as JSON but is not claude credentials.
        ({"tokens": {"access_token": "a"}}, "missing or non-dict 'claudeAiOauth'"),
        ({"claudeAiOauth": {}}, "accessToken must be a non-empty string"),
        ({"claudeAiOauth": {"accessToken": ""}}, "accessToken must be a non-empty string"),
        ({"claudeAiOauth": {"accessToken": 7}}, "accessToken must be a non-empty string"),
    ],
)
def test_validate_blob_rejects_wrong_shapes(data, expected):
    with pytest.raises(creds.CredentialsError, match=expected):
        creds.validate_blob(data)
