"""Daemon authorization, bounded transport, and failure containment."""

import json
import socket
import subprocess
import sys
import threading
import time

import pytest

from ai_credentials_helper import cli
from ai_credentials_helper import request_daemon as d
from ai_credentials_helper import request_protocol as p
from ai_credentials_helper import transfer_crypto as crypto
from ai_credentials_helper.backends import claude, codex

PW = "synthetic-test-passphrase"
NONCE = "a" * 64
CLAUDE = json.dumps({"claudeAiOauth": {"accessToken": "secret-at", "refreshToken": "secret-rt"}})


@pytest.fixture(autouse=True)
def fast_crypto(monkeypatch):
    monkeypatch.setattr(crypto, "PBKDF2_ITERATIONS", 1000)


class Connection:
    def __init__(self, blocks):
        self.blocks = iter(blocks)
        self.sent = b""
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, _size):
        return next(self.blocks)

    def sendall(self, data):
        self.sent += data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True


def request_connection(text=None, pw=PW):
    frame = crypto.encrypt(text or p.request("claude", NONCE), pw).encode()
    return Connection([frame[:12], frame[12:], b""])


def test_server_reads_after_authentication_and_never_writes(monkeypatch):
    reads = []
    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(claude, "read_raw", lambda: reads.append(True) or CLAUDE)
    monkeypatch.setattr(claude, "write", lambda _: pytest.fail("server wrote credentials"))
    for conn in (request_connection(pw="wrong"), request_connection('{"agent":"claude"}')):
        with pytest.raises((crypto.DecryptionError, p.ProtocolError)):
            d.process_connection(conn, PW, 1024 * 1024, time.monotonic() + 5)
    assert reads == []
    conn = request_connection()
    d.process_connection(conn, PW, 1024 * 1024, time.monotonic() + 5)
    assert p.read_response(crypto.decrypt(conn.sent.decode(), PW), "claude", NONCE) == (
        CLAUDE, None
    )
    assert reads == [True]


@pytest.mark.parametrize("exc,code", [
    (claude.CredentialsError("secret-at"), "credentials-unavailable"),
    (OSError("secret-at"), "backend-failure"),
    (subprocess.TimeoutExpired("secret-at", 5), "backend-failure"),
])
def test_backend_errors_are_authenticated_and_sanitized(monkeypatch, caplog, exc, code):
    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", None)

    def fail():
        raise exc

    monkeypatch.setattr(claude, "read_raw", fail)
    conn = request_connection()
    with caplog.at_level("INFO", logger=d.__name__):
        d.process_connection(conn, PW, 1024 * 1024, time.monotonic() + 5,
                             peer="127.0.0.1:12345")
    text = crypto.decrypt(conn.sent.decode(), PW)
    assert p.read_response(text, "claude", NONCE) == (None, code)
    assert f"peer=127.0.0.1:12345 agent=claude code={code}" in caplog.text
    assert f"status=error code={code}" in caplog.text
    for secret in ("secret-at", PW, NONCE):
        assert secret not in caplog.text
    assert "secret-at" not in text


def test_keychain_timeout_uses_remaining_budget(monkeypatch):
    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", "synthetic-keychain")
    observed = []
    monkeypatch.setattr(claude, "_read_raw_keychain",
                        lambda *, timeout: observed.append(timeout) or CLAUDE)
    d.process_connection(request_connection(), PW, 1024 * 1024, time.monotonic() + 1)
    assert 0 < observed[0] <= 1


def test_fragmented_large_frame_and_size_bound():
    conn = Connection([b"a" * 40000, b"b" * 40000, b""])
    assert len(d.read_frame(conn, 80000, time.monotonic() + 1)) == 80000
    with pytest.raises(p.ProtocolError):
        d.read_frame(Connection([b"abcd", b"e"]), 4, time.monotonic() + 1)


def test_trickled_bytes_do_not_reset_deadline(monkeypatch):
    ticks = iter([0, 0.4, 1.1])
    monkeypatch.setattr(d.time, "monotonic", lambda: next(ticks))
    conn = Connection([b"a", b"b", b""])
    with pytest.raises(TimeoutError):
        d.read_frame(conn, 100, 1)
    assert conn.timeouts == [1, 0.6]


def test_deadline_checked_before_backend_read(monkeypatch):
    # Supply a complete valid frame; expiry must still gate the backend read.
    monkeypatch.setattr(d, "read_frame", lambda *_: crypto.encrypt(
        p.request("claude", NONCE), PW).encode())
    monkeypatch.setattr(claude, "read_raw", lambda: pytest.fail("read after deadline"))
    with pytest.raises(TimeoutError):
        d.process_connection(Connection([]), PW, 1024 * 1024, time.monotonic() - 1)


def test_requester_rejects_replay_before_write(monkeypatch, capsys):
    monkeypatch.setattr(claude, "write", lambda _: pytest.fail("replay imported"))
    replay = crypto.encrypt(p.response("claude", "b" * 64, payload=CLAUDE), PW).encode()
    monkeypatch.setattr(d, "exchange", lambda *_: replay)
    assert d.request_credentials("host", 123, "claude", PW, 10000, "nc") == 1
    assert "secret-at" not in capsys.readouterr().err


@pytest.mark.parametrize("first_failure", ["request", "import"])
def test_all_attempts_second_agent_after_failure(monkeypatch, capsys, first_failure):
    calls, writes = [], []

    def exchange(frame, *_args):
        agent, nonce = p.read_request(crypto.decrypt(frame.decode(), PW))
        calls.append((agent, nonce))
        if agent == "claude" and first_failure == "request":
            raise OSError("secret-at")
        return crypto.encrypt(p.response(agent, nonce, payload=CLAUDE), PW).encode()

    def fail_import(_):
        raise claude.CredentialsError("secret-at")

    monkeypatch.setattr(d, "exchange", exchange)
    monkeypatch.setattr(claude, "write", fail_import)
    monkeypatch.setattr(codex, "validate_blob", lambda _: None)
    monkeypatch.setattr(codex, "write", lambda payload: writes.append(payload))
    assert d.request_credentials("host", 123, "all", PW, 10000, "nc") == 1
    assert [agent for agent, _ in calls] == ["claude", "codex"]
    assert calls[0][1] != calls[1][1]
    assert writes == [CLAUDE]
    assert "secret-at" not in capsys.readouterr().err


def test_native_exchange_half_closes_and_accumulates_response():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        observed = []

        def peer():
            with listener.accept()[0] as conn:
                observed.append(d.read_frame(conn, 100, time.monotonic() + 2))
                conn.sendall(b"a" * 70000)
                conn.sendall(b"b" * 30000)

        thread = threading.Thread(target=peer)
        thread.start()
        try:
            reply = d.exchange_native(b"request", "127.0.0.1", listener.getsockname()[1], 100000)
        finally:
            thread.join(timeout=3)
        assert observed == [b"request"]
        assert reply == b"a" * 70000 + b"b" * 30000


@pytest.mark.parametrize("args", [
    ["--request", "host"], ["--agent", "all", "--raw"],
    ["--serve", "--agent", "claude"], ["--serve", "--send", "host"],
    ["--serve", "--oauth-only"], ["--request", "host", "--agent", "codex", "--receive"],
    ["--bind", "127.0.0.1", "--receive"], ["--serve", "--force"],
    ["--serve", "--port", "65536"],
    ["--request", "", "--agent", "claude"],
])
def test_cli_rejects_invalid_modes_before_backend_activation(monkeypatch, args):
    monkeypatch.setattr(cli.creds, "set_backend", lambda _: pytest.fail("backend activated"))
    assert cli.main(args) == 1


def test_cli_dispatch_and_single_passphrase(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_get_passphrase", lambda: calls.append("passphrase") or PW)
    monkeypatch.setattr(d, "serve", lambda *args: calls.append(args) or 0)
    assert cli.main(["--serve", "--bind", "127.0.0.1", "--port", "1234"]) == 0
    assert calls == ["passphrase", ("127.0.0.1", 1234, PW, cli.MAX_PAYLOAD)]
    calls.clear()
    monkeypatch.setattr(d, "request_credentials", lambda *args, **kw: calls.append(args) or 0)
    assert cli.main(["--request", "host", "--agent", "all"]) == 0
    assert calls[0] == "passphrase"
    assert calls[1][:4] == ("host", cli.DEFAULT_PORT, "all", PW)


def test_missing_passphrase_never_listens(monkeypatch):
    monkeypatch.delenv("CLAUDE_CREDENTIALS_PASSPHRASE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(d, "serve", lambda *_: pytest.fail("started without passphrase"))
    assert cli.main(["--serve"]) == 1


@pytest.mark.parametrize("mode", ["ok", "oversize", "timeout", "nonzero"])
def test_nc_bounded_output_and_subprocess_cleanup(tmp_path, monkeypatch, mode):
    script = tmp_path / "fake-nc"
    script.write_text(
        f"#!{sys.executable}\n"
        "import sys, time\n"
        "assert sys.argv[1:5] == ['-G', '10', '-w', '30']\n"
        "assert sys.stdin.buffer.read() == b'request'\n"
        + {
            "ok": "sys.stdout.buffer.write(b'a' * 70000 + b'b' * 30000)\n",
            "oversize": "sys.stdout.buffer.write(b'a' * 100001)\n"
                        "sys.stdout.buffer.flush()\ntime.sleep(30)\n",
            "timeout": "time.sleep(30)\n",
            "nonzero": "sys.exit(1)\n",
        }[mode]
    )
    script.chmod(0o700)
    processes = []
    popen = subprocess.Popen

    def track(*args, **kwargs):
        proc = popen(*args, **kwargs)
        processes.append(proc)
        return proc

    monkeypatch.setattr(d.subprocess, "Popen", track)
    if mode == "timeout":
        monkeypatch.setattr(d, "CONNECT_TIMEOUT", 0.05)
        monkeypatch.setattr(d, "EXCHANGE_TIMEOUT", 0.05)
        # For the short timeout case the stub must accept the tuned arguments.
        script.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
    if mode == "ok":
        assert d.exchange_nc(b"request", "host", 123, 100000, str(script)) == (
            b"a" * 70000 + b"b" * 30000
        )
    else:
        with pytest.raises((p.ProtocolError, TimeoutError, OSError)):
            d.exchange_nc(b"request", "host", 123, 100000, str(script))
    assert processes[0].poll() is not None
    assert processes[0].stdin.closed and processes[0].stdout.closed


def test_nc_subprocess_cleanup_on_interrupt(tmp_path, monkeypatch):
    script = tmp_path / "fake-nc"
    script.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
    script.chmod(0o700)
    processes = []
    popen = subprocess.Popen

    def track(*args, **kwargs):
        proc = popen(*args, **kwargs)
        processes.append(proc)
        return proc

    def interrupt(*_):
        raise KeyboardInterrupt

    monkeypatch.setattr(d.subprocess, "Popen", track)
    monkeypatch.setattr(d.selectors.DefaultSelector, "select", interrupt)
    with pytest.raises(KeyboardInterrupt):
        d.exchange_nc(b"request", "host", 123, 1000, str(script))
    assert processes[0].poll() is not None
    assert processes[0].stdin.closed and processes[0].stdout.closed


def test_listener_recovers_from_invalid_timeout_and_disconnect(monkeypatch, caplog):
    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(claude, "read_raw", lambda: CLAUDE)

    class Idle(Connection):
        def recv(self, _):
            raise TimeoutError("secret-at")

    class Disconnected(Connection):
        def sendall(self, _):
            raise ConnectionResetError("secret-at")

    valid = request_connection()
    disconnected = Disconnected(request_connection().blocks)
    connections = [Connection([b"garbage", b""]), Idle([]), disconnected, valid]

    class Listener(Connection):
        def setsockopt(self, *_):
            pass

        def bind(self, address):
            assert address == ("127.0.0.1", 1234)

        def listen(self, _):
            pass

        def getsockname(self):
            return ("127.0.0.1", 1234)

        def accept(self):
            if self.blocks:
                return self.blocks.pop(0), ("127.0.0.1", 50000)
            raise KeyboardInterrupt

    listener = Listener([])
    listener.blocks = list(connections)
    monkeypatch.setattr(d.socket, "socket", lambda *_: listener)
    with caplog.at_level("DEBUG"):
        assert d.serve("127.0.0.1", 1234, PW, 10000) == 0
    assert all(conn.closed for conn in connections)
    assert listener.closed
    assert p.read_response(crypto.decrypt(valid.sent.decode(), PW), "claude", NONCE)[0] == CLAUDE
    assert "secret-at" not in caplog.text
    assert "credential request connected: peer=127.0.0.1:50000" in caplog.text
    for code in ("invalid-encrypted-frame", "timeout", "transport-error"):
        assert f"code={code}" in caplog.text


def test_listener_interrupt_closes_active_connection(monkeypatch):
    class Interrupt(Connection):
        def recv(self, _):
            raise KeyboardInterrupt

    conn = Interrupt([])

    class Listener(Connection):
        def setsockopt(self, *_):
            pass

        def bind(self, _):
            pass

        def listen(self, _):
            pass

        def getsockname(self):
            return ("127.0.0.1", 1234)

        def accept(self):
            return conn, ("127.0.0.1", 50000)

    listener = Listener([])
    monkeypatch.setattr(d.socket, "socket", lambda *_: listener)
    assert d.serve("127.0.0.1", 1234, PW, 10000) == 0
    assert conn.closed and listener.closed


def test_write_uses_remaining_deadline():
    conn = Connection([])
    deadline = time.monotonic() + 0.1
    d.send_frame(conn, b"response", deadline)
    assert 0 < conn.timeouts[0] <= 0.1
    with pytest.raises(TimeoutError):
        d.send_frame(conn, b"response", time.monotonic() - 1)


@pytest.mark.parametrize("reply", [b"", b"truncated", b"wrong\xff"])
def test_invalid_reply_never_imports(monkeypatch, reply):
    monkeypatch.setattr(d, "exchange", lambda *_: reply)
    monkeypatch.setattr(claude, "write", lambda _: pytest.fail("invalid reply imported"))
    assert d.request_credentials("host", 123, "claude", PW, 10000, "nc") == 1


def test_request_force_is_scoped_to_codex_write(tmp_path, monkeypatch):
    auth = tmp_path / "auth.json"
    auth.write_text("original")
    expired = json.dumps({"tokens": {"access_token": "e30.eyJleHAiOjF9.sig",
                                     "refresh_token": "synthetic-refresh"}})

    def exchange(frame, *_):
        agent, nonce = p.read_request(crypto.decrypt(frame.decode(), PW))
        return crypto.encrypt(p.response(agent, nonce, payload=expired), PW).encode()

    monkeypatch.setattr(d, "exchange", exchange)
    monkeypatch.setattr(codex, "AUTH_PATH", auth)
    assert d.request_credentials("host", 123, "codex", PW, 10000, "nc") == 1
    assert auth.read_text() == "original"
    assert d.request_credentials("host", 123, "codex", PW, 10000, "nc", force=True) == 0
    assert json.loads(auth.read_text()) == json.loads(expired)
    assert codex.FORCE_WRITE is False


@pytest.mark.parametrize("platform,transport", [("darwin", "exchange_nc"),
                                                ("linux", "exchange_native")])
def test_request_transport_dispatch(monkeypatch, platform, transport):
    calls = []
    monkeypatch.setattr(d.sys, "platform", platform)
    monkeypatch.setattr(d, transport, lambda *args: calls.append(args) or b"reply")
    assert d.exchange(b"frame", "host", 123, 10000, "apple-nc") == b"reply"
    assert calls[0][:4] == (b"frame", "host", 123, 10000)


def test_server_logs_request_and_response_without_secrets(monkeypatch, caplog):
    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(claude, "read_raw", lambda: CLAUDE)
    with caplog.at_level("INFO", logger=d.__name__):
        d.process_connection(request_connection(), PW, 10000, time.monotonic() + 5,
                             peer="127.0.0.1:12345")
    assert "credential request received: peer=127.0.0.1:12345 agent=claude bytes=" in caplog.text
    assert "credential response sent: peer=127.0.0.1:12345 agent=claude status=ok" in caplog.text
    assert "bytes=" in caplog.text and "elapsed_ms=" in caplog.text
    for secret in ("secret-at", "secret-rt", PW, NONCE, CLAUDE):
        assert secret not in caplog.text


def test_server_logs_oversized_response_as_error(monkeypatch, caplog):
    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(claude, "read_raw", lambda: CLAUDE * 100)
    conn = request_connection()
    with caplog.at_level("INFO", logger=d.__name__):
        d.process_connection(conn, PW, 1000, time.monotonic() + 5)
    assert p.read_response(crypto.decrypt(conn.sent.decode(), PW), "claude", NONCE) == (
        None, "backend-failure"
    )
    assert "code=response-too-large" in caplog.text
    assert "status=error code=backend-failure" in caplog.text
    assert "secret-at" not in caplog.text


@pytest.mark.parametrize("exc,code", [
    (d.FrameTooLarge("secret-at"), "frame-too-large"),
    (p.ProtocolError("secret-at"), "invalid-request"),
    (UnicodeDecodeError("utf-8", b"secret-at", 0, 1, "secret-at"), "invalid-request"),
])
def test_connection_error_codes_do_not_include_peer_data(exc, code):
    assert d._connection_error_code(exc) == code
