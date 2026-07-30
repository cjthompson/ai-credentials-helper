"""Tests for the ``--agent`` flag and credentials-facade dispatch.

Verifies the CLI routes to the right backend based on ``--agent``, that the
default is claude (back-compat), that unknown agents error cleanly, and that
``--refresh --agent codex`` produces the documented "not supported" message.
"""

import json
import subprocess
import sys
import time

import pytest

from ai_credentials_helper import cli, transfer_crypto
from ai_credentials_helper import credentials as creds
from ai_credentials_helper import transfer_envelope as te


class _FakeConnection:
    def __init__(self, payload=b"encrypted-frame"):
        self._blocks = iter((payload, b""))
        self.sent = b""  # bytes passed to sendall(), for ack assertions

    def settimeout(self, _timeout):
        pass

    def recv(self, _size):
        return next(self._blocks)

    def sendall(self, data):
        self.sent += data

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


def _fake_receive_socket(monkeypatch, payload=b"encrypted-frame"):
    """Wire cli._do_receive up to a fake server; return the _FakeServer.

    Tests that need the raw ack bytes read ``server.connection.sent``.
    """
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    server = _FakeServer(payload)
    monkeypatch.setattr(cli.socket, "socket", lambda *_args: server)
    return server


def _wire_frame(agent: str, payload: str, passphrase: str = "test-passphrase") -> str:
    """Build a real encrypted, enveloped wire frame for the given agent/payload."""
    return transfer_crypto.encrypt(te.wrap(agent, payload), passphrase)


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
    assert args.agent is None
    # The back-compat default now resolves centrally, not in argparse --
    # this guards the property the original test was written for.
    assert cli._default_backend_for(args.agent) == "claude"


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
    from ai_credentials_helper.backends import claude

    assert creds.CLIENT_ID == "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    if sys.platform == "darwin":
        assert creds.KEYCHAIN_SERVICE == "Claude Code-credentials"
        assert claude.AUTH_PATH is None
    elif sys.platform == "linux":
        assert creds.KEYCHAIN_SERVICE is None
        assert claude.AUTH_PATH is not None
        assert claude.AUTH_PATH.name == ".credentials.json"


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


def test_store_label_uses_backend_specific_noun(restore_backend, monkeypatch):
    """Regression: --import/--receive used to print 'None' for codex because
    the messages referenced creds.KEYCHAIN_SERVICE, which codex doesn't have."""
    from ai_credentials_helper.backends import claude

    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", "Claude Code-credentials")
    monkeypatch.setattr(claude, "AUTH_PATH", None)
    creds.set_backend("claude")
    assert "keychain service" in cli._store_label()
    assert "'Claude Code-credentials'" in cli._store_label()

    creds.set_backend("codex")
    assert "auth file" in cli._store_label()
    assert "None" not in cli._store_label()


def test_store_label_uses_linux_claude_auth_path(restore_backend, tmp_path, monkeypatch):
    from ai_credentials_helper.backends import claude

    auth_path = tmp_path / ".claude" / ".credentials.json"
    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(claude, "AUTH_PATH", auth_path)
    creds.set_backend("claude")

    assert cli._store_label() == f"auth file {str(auth_path)!r}"


def test_receive_decryption_failure_names_active_store(
    restore_backend, monkeypatch, capsys
):
    _fake_receive_socket(monkeypatch)
    creds.set_backend("codex")

    def fail_decrypt(_frame, _passphrase):
        raise cli.transfer_crypto.DecryptionError("authentication failed")

    monkeypatch.setattr(cli.transfer_crypto, "decrypt", fail_decrypt)

    assert cli._do_receive(0, requested_agent="codex") == 1
    assert f"{cli._store_label()} left unchanged" in capsys.readouterr().err


def test_receive_invalid_blob_names_active_store(restore_backend, monkeypatch, capsys):
    _fake_receive_socket(monkeypatch)
    creds.set_backend("codex")
    enveloped = te.wrap("codex", "not json")
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: enveloped)

    assert cli._do_receive(0, requested_agent="codex") == 1
    assert f"{cli._store_label()} left unchanged" in capsys.readouterr().err


def test_receive_rejects_wrong_claude_shape_before_write(
    restore_backend, monkeypatch, capsys
):
    from ai_credentials_helper.backends import claude

    _fake_receive_socket(monkeypatch)
    monkeypatch.setattr(
        cli.transfer_crypto,
        "decrypt",
        lambda *_args: '{"notClaudeCredentials":true}',
    )
    writes = []
    monkeypatch.setattr(claude, "write", writes.append)
    creds.set_backend("claude")

    assert cli._do_receive(0) == 1
    assert writes == []
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
    enveloped = te.wrap("codex", content)
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "auth.json")
    _fake_receive_socket(monkeypatch)
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: enveloped)
    creds.set_backend("codex")

    assert cli._do_receive(0, requested_agent="codex", verbose=True) == 0
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
    enveloped = te.wrap("claude", content)
    _fake_receive_socket(monkeypatch)
    monkeypatch.setattr(cli.transfer_crypto, "decrypt", lambda *_args: enveloped)
    monkeypatch.setattr(claude, "write", lambda _content: None)
    creds.set_backend("claude")

    assert cli._do_receive(0, requested_agent="claude", verbose=True) == 0
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


def test_main_passes_force_and_requested_agent_through_to_do_receive(
    restore_backend, monkeypatch, capsys
):
    """main() no longer decides FORCE_WRITE for --receive itself (the wire
    agent isn't known yet) -- it just forwards --force and the resolved
    --agent to _do_receive, which applies force once it knows the backend
    (see test_force_activates_inside_do_receive_at_write_time for that).
    """
    observed = {}

    def spy_receive(_port, *, verbose=False, requested_agent=None, force=False):
        observed.update(verbose=verbose, requested_agent=requested_agent, force=force)
        return 0

    monkeypatch.setattr(cli, "_do_receive", spy_receive)

    assert cli.main(["--agent", "codex", "--force", "--receive"]) == 0
    assert observed == {"verbose": False, "requested_agent": "codex", "force": True}
    # The --force warning now fires inside _do_receive, not main() -- a
    # spied-out _do_receive means it never runs here.
    assert "WARNING: --force" not in capsys.readouterr().err


def test_main_bare_receive_passes_requested_agent_none(restore_backend, monkeypatch):
    observed = {}

    def spy_receive(_port, *, verbose=False, requested_agent=None, force=False):
        observed["requested_agent"] = requested_agent
        return 0

    monkeypatch.setattr(cli, "_do_receive", spy_receive)

    assert cli.main(["--receive"]) == 0
    assert observed["requested_agent"] is None


def test_force_activates_inside_do_receive_at_write_time(
    restore_backend, tmp_path, monkeypatch, capsys
):
    """The real (non-spied) --force contract: FORCE_WRITE flips only after
    _do_receive resolves the wire agent, and only for that backend.
    """
    from ai_credentials_helper.backends import codex

    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    creds.set_backend("claude")  # provisional, as main() would leave it pre-receive

    # An already-expired (but otherwise valid) codex token -- force is
    # required or codex's own expiry check in validate_blob would reject the
    # write regardless of this test's real point of interest.
    expired_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjF9.sig"  # exp=1 (1970)
    payload = json.dumps(
        {"tokens": {"access_token": expired_jwt, "refresh_token": "rt", "account_id": "z"}}
    )
    frame = _wire_frame("codex", payload)
    _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent=None, force=True)
    assert rc == 0
    assert "WARNING: --force" in capsys.readouterr().err
    assert json.loads(auth_file.read_text())["tokens"]["account_id"] == "z"
    codex.FORCE_WRITE = False  # this test bypasses main()'s finally reset


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


def test_bare_receive_adopts_wire_agent_and_writes_codex_store(
    restore_backend, tmp_path, monkeypatch, capsys
):
    import base64

    from ai_credentials_helper.backends import codex

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    exp = int(time.time()) + 3600
    access = f"{b64({'alg': 'RS256'})}.{b64({'exp': exp})}.sig"

    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    creds.set_backend("claude")  # provisional, as main() would leave it pre-receive

    payload = json.dumps(
        {"tokens": {"access_token": access, "refresh_token": "rt", "account_id": "x"}}
    )
    frame = _wire_frame("codex", payload)
    server = _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent=None, force=False)
    assert rc == 0
    err = capsys.readouterr().err
    assert "Detected agent: codex (from sender)" in err
    assert "Received and imported" in err
    assert creds.backend_name() == "codex"
    written = json.loads(auth_file.read_text())
    assert written["tokens"]["account_id"] == "x"

    mac_key = transfer_crypto.mac_key_for_frame(frame, "test-passphrase")
    salt = transfer_crypto.frame_salt(frame)
    status, _detail = te.read_ack(server.connection.sent.decode().strip(), mac_key, salt)
    assert status == "ok"


def test_pinned_matching_agent_succeeds(restore_backend, tmp_path, monkeypatch, capsys):
    import base64

    from ai_credentials_helper.backends import codex

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    exp = int(time.time()) + 3600
    access = f"{b64({'alg': 'RS256'})}.{b64({'exp': exp})}.sig"

    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    creds.set_backend("codex")

    payload = json.dumps(
        {"tokens": {"access_token": access, "refresh_token": "rt", "account_id": "y"}}
    )
    frame = _wire_frame("codex", payload)
    _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent="codex", force=False)
    assert rc == 0
    assert json.loads(auth_file.read_text())["tokens"]["account_id"] == "y"


def test_pinned_mismatching_agent_rejected(restore_backend, tmp_path, monkeypatch, capsys):
    from ai_credentials_helper.backends import codex

    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps({"tokens": {"access_token": "orig", "refresh_token": "r", "account_id": "orig"}})
    )
    monkeypatch.setattr(codex, "AUTH_PATH", auth_file)
    creds.set_backend("codex")

    payload = json.dumps({"claudeAiOauth": {"accessToken": "a", "refreshToken": "r", "expiresAt": 1}})
    frame = _wire_frame("claude", payload)
    server = _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent="codex", force=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "agent mismatch" in err
    assert "sender sent 'claude'" in err
    assert "pinned to 'codex'" in err
    # store untouched
    assert json.loads(auth_file.read_text())["tokens"]["account_id"] == "orig"

    mac_key = transfer_crypto.mac_key_for_frame(frame, "test-passphrase")
    salt = transfer_crypto.frame_salt(frame)
    status, _detail = te.read_ack(server.connection.sent.decode().strip(), mac_key, salt)
    assert status == "agent-mismatch"


def test_unlabelled_legacy_payload_rejected(restore_backend, monkeypatch, capsys):
    creds.set_backend("codex")
    legacy_plaintext = json.dumps({"tokens": {"access_token": "a", "refresh_token": "r"}})
    frame = transfer_crypto.encrypt(legacy_plaintext, "test-passphrase")  # no envelope wrap
    _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent="codex", force=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "older version" in err
    assert "upgrade both ends" in err


def test_do_send_returns_1_on_verified_mismatch_ack(restore_backend, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    creds.set_backend("codex")
    monkeypatch.setattr(creds, "read_raw", lambda: '{"tokens":{}}')

    def fake_run(argv, input, capture_output, timeout):
        frame_text = input.decode()
        mac_key = transfer_crypto.mac_key_for_frame(frame_text, "test-passphrase")
        salt = transfer_crypto.frame_salt(frame_text)
        ack_line = te.ack(mac_key, salt, "agent-mismatch", "sender=codex receiver=claude")
        return subprocess.CompletedProcess(argv, 0, stdout=ack_line.encode(), stderr=b"")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._do_send("example.test", 47299, False)
    assert rc == 1
    assert "mismatch" in capsys.readouterr().err


def test_do_send_fails_closed_on_empty_ack(restore_backend, monkeypatch, capsys):
    """No ack means the outcome is unknown, so --send must not report success.

    An on-path attacker can suppress the reply; treating silence as success
    would let it manufacture "delivered". There is no back-compat cost: a
    receiver too old to send an ack also rejects this sender's labelled
    payload, so the transfer fails at the receiver anyway.
    """
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    creds.set_backend("codex")
    monkeypatch.setattr(creds, "read_raw", lambda: '{"tokens":{}}')

    def fake_run(argv, input, capture_output, timeout):
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._do_send("example.test", 47299, False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "Sent" in err  # the bytes did leave; that part is still true
    assert "no acknowledgement" in err
    assert "outcome of the transfer is unknown" in err


def test_do_send_fails_closed_on_unverifiable_ack(restore_backend, monkeypatch, capsys):
    """An ack that fails MAC verification is an unknown outcome, not a success.

    The peer's bytes must never be echoed -- they are attacker-controlled and
    would otherwise land on the sender's terminal.
    """
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    creds.set_backend("codex")
    monkeypatch.setattr(creds, "read_raw", lambda: '{"tokens":{}}')

    def fake_run(argv, input, capture_output, timeout):
        return subprocess.CompletedProcess(argv, 0, stdout=b"garbage not an ack\n", stderr=b"")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._do_send("example.test", 47299, False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "could not be verified" in err
    assert "outcome of the transfer is unknown" in err
    assert "garbage not an ack" not in err


def test_receive_rejects_codex_shaped_blob_labelled_claude(
    restore_backend, monkeypatch, capsys
):
    """A codex blob that declares agent=claude must not reach the Keychain.

    On the baseline this was a real corruption path: claude.parse_blob is
    bare json.loads, so a codex auth.json parsed fine and was written
    verbatim over the Claude Code keychain entry. The label being authentic
    is not enough -- a peer holding the passphrase can mislabel a frame, so
    the backend shape check is the defence in depth that catches it.
    """
    from ai_credentials_helper.backends import claude

    wrote = []
    monkeypatch.setattr(claude, "write", lambda content: wrote.append(content))
    creds.set_backend("claude")

    codex_payload = json.dumps(
        {"tokens": {"access_token": "eyJ.fake.token", "refresh_token": "rt"}}
    )
    frame = _wire_frame("claude", codex_payload)
    server = _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent=None, force=False)
    assert rc == 1
    assert wrote == []  # the keychain was never touched
    err = capsys.readouterr().err
    assert "claudeAiOauth" in err
    assert "left unchanged" in err

    mac_key = transfer_crypto.mac_key_for_frame(frame, "test-passphrase")
    salt = transfer_crypto.frame_salt(frame)
    status, _detail = te.read_ack(server.connection.sent.decode().strip(), mac_key, salt)
    assert status == "rejected"


def test_receive_accepts_well_formed_claude_blob(restore_backend, monkeypatch, capsys):
    """The companion to the test above: a real claude blob still writes."""
    from ai_credentials_helper.backends import claude

    wrote = []
    monkeypatch.setattr(claude, "write", lambda content: wrote.append(content))
    creds.set_backend("claude")

    payload = json.dumps(
        {"claudeAiOauth": {"accessToken": "at", "refreshToken": "rt", "expiresAt": 1}}
    )
    frame = _wire_frame("claude", payload)
    _fake_receive_socket(monkeypatch, payload=frame.encode())

    rc = cli._do_receive(0, requested_agent=None, force=False)
    assert rc == 0
    assert wrote == [payload]
    assert "Received and imported" in capsys.readouterr().err
