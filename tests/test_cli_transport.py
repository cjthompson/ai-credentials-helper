from types import SimpleNamespace

from ai_credentials_helper import cli


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.shutdown_calls = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def sendall(self, data):
        self.sent.append(data)

    def shutdown(self, how):
        self.shutdown_calls.append(how)


def test_linux_sender_uses_native_socket_and_half_closes(monkeypatch):
    conn = FakeSocket()
    calls = []
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(
        cli.socket,
        "create_connection",
        lambda address, timeout: calls.append((address, timeout)) or conn,
    )
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("nc used on Linux")),
    )

    error, transport = cli._send_frame(b"encrypted", "example.test", 47299)

    assert error is None
    assert transport == "native socket"
    assert calls == [(('example.test', 47299), cli.SEND_TIMEOUT)]
    assert conn.sent == [b"encrypted"]
    assert conn.shutdown_calls == [cli.socket.SHUT_WR]
    assert conn.closed


def test_darwin_sender_keeps_apple_nc(monkeypatch):
    observed = {}
    monkeypatch.setattr(cli.sys, "platform", "darwin")

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    error, transport = cli._send_frame(b"encrypted", "example.test", 47299)

    assert error is None
    assert transport == cli.NC_BINARY
    assert observed["argv"] == [cli.NC_BINARY, "-w", str(cli.SEND_TIMEOUT), "example.test", "47299"]
    assert observed["kwargs"]["input"] == b"encrypted"


def test_native_sender_returns_connection_error(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "linux")

    def refuse(*_args, **_kwargs):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(cli.socket, "create_connection", refuse)
    error, transport = cli._send_frame(b"encrypted", "127.0.0.1", 47299)
    assert transport == "native socket"
    assert error == "connection refused"


def test_native_sender_describes_empty_os_error(monkeypatch):
    """An OSError without a message must not look like a successful send."""
    monkeypatch.setattr(cli.sys, "platform", "linux")

    def fail_without_message(*_args, **_kwargs):
        raise OSError()

    monkeypatch.setattr(cli.socket, "create_connection", fail_without_message)

    error, transport = cli._send_frame(b"encrypted", "127.0.0.1", 47299)

    assert transport == "native socket"
    assert error == "native socket error"


def test_do_send_rejects_empty_error_result(monkeypatch, capsys):
    """A non-None transport error is a failed send even when its text is empty."""
    monkeypatch.setattr(cli.creds, "read_raw", lambda: "credential blob")
    monkeypatch.setattr(cli, "_get_passphrase", lambda: "test-passphrase")
    monkeypatch.setattr(cli.transfer_crypto, "encrypt", lambda *_args: "encrypted-frame")
    monkeypatch.setattr(cli, "_send_frame", lambda *_args: ("", "native socket"))

    assert cli._do_send("example.test", 47299, oauth_only=False) == 1
    assert "Error: could not send to example.test:47299" in capsys.readouterr().err


def test_native_sender_returns_timeout_error(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(
        cli.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(cli.socket.timeout()),
    )
    error, transport = cli._send_frame(b"encrypted", "127.0.0.1", 47299)
    assert transport == "native socket"
    assert error == f"timed out after {cli.SEND_TIMEOUT}s"


def test_sender_rejects_unsupported_platform(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "win32")
    error, transport = cli._send_frame(b"encrypted", "example.test", 47299)
    assert transport == "unsupported platform"
    assert error == "credential transfer is supported only on macOS, Linux, and WSL"
