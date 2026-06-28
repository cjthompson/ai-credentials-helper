"""Tests for the ``--agent`` flag and credentials-facade dispatch.

Verifies the CLI routes to the right backend based on ``--agent``, that the
default is claude (back-compat), that unknown agents error cleanly, and that
``--refresh --agent codex`` produces the documented "not supported" message.
"""

import json

import pytest

from ai_credentials_helper import cli
from ai_credentials_helper import credentials as creds


@pytest.fixture
def restore_backend():
    """Snapshot the active backend so a test can't pollute the next one.

    ``set_backend`` mutates module-level state — important to reset between
    tests since ordering is otherwise undefined.
    """
    original = creds._backend
    yield
    creds._backend = original


@pytest.fixture
def fake_codex_auth(tmp_path, monkeypatch):
    """Point codex backend at a temp auth.json with a realistic shape."""
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": "eyJ.fake.token",
            "refresh_token": "rt_x",
            "account_id": "acct-xyz",
        },
    }))
    monkeypatch.setattr(
        "ai_credentials_helper.backends.codex.AUTH_PATH", auth_file
    )
    return auth_file


def test_set_backend_dispatch_changes_active_backend(restore_backend):
    creds.set_backend("codex")
    assert creds.backend_name() == "codex"
    assert creds.TOKEN_URL == "https://auth.openai.com/oauth/token"
    creds.set_backend("claude")
    assert creds.backend_name() == "claude"


def test_set_backend_rejects_unknown(restore_backend):
    with pytest.raises(ValueError, match="unknown agent"):
        creds.set_backend("bogus-agent")


def test_default_backend_is_claude(restore_backend):
    creds.set_backend("codex")  # pollute
    creds.set_backend("claude")  # restore (also the default)
    assert creds.backend_name() == "claude"


def test_cli_agent_flag_accepted():
    parser = cli._build_parser()
    args = parser.parse_args(["--agent", "codex", "--raw"])
    assert args.agent == "codex"


def test_cli_default_agent_is_claude():
    parser = cli._build_parser()
    args = parser.parse_args(["--raw"])
    assert args.agent == "claude"


def test_cli_rejects_unknown_agent():
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--agent", "nope", "--raw"])


def test_cli_routes_to_codex_for_raw(fake_codex_auth, restore_backend, capsys):
    rc = cli.main(["--agent", "codex", "--raw"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert json.loads(out)["tokens"]["account_id"] == "acct-xyz"


def test_cli_routes_to_codex_for_simple(fake_codex_auth, restore_backend, capsys):
    # Build a JWT with a known exp so --simple prints a deterministic expiry.
    import base64

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    exp = 1790000000  # fixed for test stability
    jwt = f"{b64({'alg':'RS256'})}.{b64({'sub':'u','exp':exp})}.sig"

    fake_codex_auth.write_text(json.dumps({
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": jwt,
            "refresh_token": "rt_x",
            "account_id": "acct-xyz",
        },
    }))

    rc = cli.main(["--agent", "codex", "--simple"])
    assert rc == 0
    out = capsys.readouterr().out
    assert f"access_token:  {jwt}" in out
    assert "refresh_token: rt_x" in out


def test_cli_refresh_codex_returns_error(fake_codex_auth, restore_backend, capsys):
    rc = cli.main(["--agent", "codex", "--refresh"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not supported for codex" in err


def test_credentials_facade_re_exposes_known_constants(restore_backend):
    # The facade should expose claude's constants by default for back-compat.
    assert creds.KEYCHAIN_SERVICE == "Claude Code-credentials"
    assert creds.CLIENT_ID == "9d1c250a-e61b-44d9-88ed-5944d1962f5e"


def test_parse_blob_dispatches_for_both_backends(restore_backend):
    """Regression: --receive calls creds.parse_blob after decrypting. The facade
    must dispatch it for both backends, or AttributeError escapes main() and
    corrupts the receive path."""
    sample = '{"claudeAiOauth":{"accessToken":"a","refreshToken":"r","expiresAt":1}}'
    creds.set_backend("claude")
    assert creds.parse_blob(sample)["claudeAiOauth"]["accessToken"] == "a"

    creds.set_backend("codex")
    codex_sample = '{"tokens":{"access_token":"a","refresh_token":"r","account_id":"x"}}'
    assert creds.parse_blob(codex_sample)["tokens"]["account_id"] == "x"


def test_store_label_uses_backend_specific_noun(restore_backend):
    """Regression: --import/--receive used to print 'None' for codex because
    the messages referenced creds.KEYCHAIN_SERVICE, which codex doesn't have."""
    creds.set_backend("claude")
    assert "keychain service" in cli._store_label()
    assert "'Claude Code-credentials'" in cli._store_label()

    creds.set_backend("codex")
    assert "auth file" in cli._store_label()
    assert "None" not in cli._store_label()
