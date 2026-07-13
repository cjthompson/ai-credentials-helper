"""Tests for the ``--agent`` flag and credentials-facade dispatch.

Verifies the CLI routes to the right backend based on ``--agent``, that the
default is claude (back-compat), that unknown agents error cleanly, and that
``--refresh --agent codex`` produces the documented "not supported" message.
"""

import json
import sys
import time

import pytest

from ai_credentials_helper import cli
from ai_credentials_helper import credentials as creds


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


def test_cli_help_describes_backend_aware_storage_and_oauth_subset():
    help_text = cli._build_parser().format_help()
    normalized_help = " ".join(help_text.split())
    assert "Manage OAuth credentials for supported AI agents." in normalized_help
    assert "active store is left unchanged" in normalized_help
    assert "portable token subset for the selected backend" in normalized_help
    assert "only the claudeAiOauth section" not in normalized_help


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


def test_force_flag_prints_warning_and_sets_flag(restore_backend, tmp_path, monkeypatch, capsys):
    """--force emits a stderr warning AND toggles codex.FORCE_WRITE during the call.

    We can't assert ``codex.FORCE_WRITE is True`` after main() returns: a
    ``finally`` block resets it so a stale flag can't leak into the next
    same-process invocation. Instead, spy on ``codex.write`` directly — the
    facade re-fetches ``_backend`` at each call, so a module-level patch
    survives the set_backend() inside main().
    """
    import io

    from ai_credentials_helper.backends import codex

    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    # Feed --import - parseable JSON so _do_import reaches creds.write().
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"tokens": {}}'))

    observed = {}

    def spy_write(_content):
        observed["force_at_write"] = codex.FORCE_WRITE
        raise codex.CredentialsError("stop here")

    monkeypatch.setattr(codex, "write", spy_write)

    rc = cli.main(["--agent", "codex", "--force", "--import", "-"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "WARNING: --force" in err
    # Force was active while the write path ran; spy captured it.
    assert observed["force_at_write"] is True


def test_no_force_means_no_warning(restore_backend, tmp_path, monkeypatch, capsys):
    """Without --force, no WARNING line should appear in stderr."""
    from ai_credentials_helper.backends import codex
    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)

    cli.main(["--agent", "codex", "--simple"])  # read-only, won't error
    err = capsys.readouterr().err
    assert "WARNING" not in err


def test_force_is_noop_for_read_only_modes(restore_backend, tmp_path, monkeypatch, capsys):
    """--force on a read-only command (--simple) must not flip FORCE_WRITE.

    Defensive: --force is meaningless for reads, and toggling it would leave
    the backend in a forced state if a later same-process write was supposed
    to be safety-checked.
    """
    from ai_credentials_helper.backends import codex
    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)

    # Pre-write a fake but parseable blob so --simple doesn't blow up.
    auth_file.write_text(json.dumps({
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig",
            "refresh_token": "rt",
            "account_id": "a",
        },
    }))

    cli.main(["--agent", "codex", "--force", "--simple"])
    err = capsys.readouterr().err
    assert "WARNING" not in err
    assert codex.FORCE_WRITE is False


def test_force_is_noop_for_codex_send(restore_backend, monkeypatch, capsys):
    from ai_credentials_helper.backends import codex

    observed = {}

    def spy_send(_host, _port, _oauth_only):
        observed["force_during_send"] = codex.FORCE_WRITE
        return 0

    monkeypatch.setattr(cli, "_do_send", spy_send)

    assert cli.main(["--agent", "codex", "--force", "--send", "example.test"]) == 0
    assert observed["force_during_send"] is False
    assert "WARNING" not in capsys.readouterr().err


def test_force_is_noop_for_codex_refresh(restore_backend, monkeypatch, capsys):
    from ai_credentials_helper.backends import codex

    observed = {}
    monkeypatch.setattr(codex, "extract_oauth_tokens", lambda: ("access", "refresh", 1.0))

    def spy_refresh(_tokens):
        observed["force_during_refresh"] = codex.FORCE_WRITE
        return 0

    monkeypatch.setattr(cli, "_do_refresh", spy_refresh)

    assert cli.main(["--agent", "codex", "--force", "--refresh"]) == 0
    assert observed["force_during_refresh"] is False
    assert "WARNING" not in capsys.readouterr().err


def test_force_is_noop_for_claude_import(
    restore_backend, monkeypatch, capsys
):
    import io

    from ai_credentials_helper.backends import claude

    observed = {}
    monkeypatch.delattr(claude, "FORCE_WRITE", raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"claudeAiOauth": {}}'))

    def spy_write(_content):
        observed["force_during_write"] = getattr(claude, "FORCE_WRITE", False)

    monkeypatch.setattr(claude, "write", spy_write)

    try:
        assert cli.main(["--agent", "claude", "--force", "--import", "-"]) == 0
        assert observed["force_during_write"] is False
        assert "WARNING" not in capsys.readouterr().err
    finally:
        if hasattr(claude, "FORCE_WRITE"):
            del claude.FORCE_WRITE


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


def test_force_reset_after_main(restore_backend, tmp_path, monkeypatch):
    """main() must reset FORCE_WRITE in finally, even when write() raises.

    Regression: prior code only reset on backend-switch, so a same-process
    caller that hit a write error would leave the next write forced.
    """
    from ai_credentials_helper.backends import codex
    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)

    def boom(_content):
        raise codex.CredentialsError("simulated write failure")

    monkeypatch.setattr(codex, "write", boom)

    # Even though write() raises, FORCE_WRITE must end up False.
    cli.main(["--agent", "codex", "--force", "--import", "-"])
    assert codex.FORCE_WRITE is False
