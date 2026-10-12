"""Real daemon/request CLI exchanges using only temporary credential stores."""

import base64
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ai_credentials_helper import request_protocol, transfer_crypto


@pytest.mark.timeout(60)
def test_daemon_repeated_requests_errors_and_partial_success(tmp_path):
    if sys.platform != "linux":
        pytest.skip("both isolated file backends are available on Linux/WSL")
    server_home = tmp_path / "server"
    client_home = tmp_path / "client"
    claude_file = server_home / ".claude" / ".credentials.json"
    codex_file = server_home / ".codex" / "auth.json"
    claude_file.parent.mkdir(parents=True)
    codex_file.parent.mkdir(parents=True)
    payload_b64 = base64.urlsafe_b64encode(json.dumps({"exp": time.time() + 3600}).encode())
    codex_payload = {"tokens": {"access_token": "header." + payload_b64.decode() + ".sig",
                                "refresh_token": "synthetic-codex-refresh"}}
    claude_payload = {"claudeAiOauth": {"accessToken": "synthetic-claude-access",
                                        "refreshToken": "synthetic-claude-refresh"}}
    claude_file.write_text(json.dumps(claude_payload))
    codex_file.write_text(json.dumps(codex_payload))
    original_codex = codex_file.read_bytes()
    original_claude = claude_file.read_bytes()
    passphrase = "synthetic-daemon-passphrase"
    env = os.environ | {"CLAUDE_CREDENTIALS_PASSPHRASE": passphrase}
    command = [sys.executable, "-m", "ai_credentials_helper.cli"]
    # Reserve a port for startup; readiness comes from stderr after successful bind.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    daemon = subprocess.Popen(
        command + ["--serve", "--bind", "127.0.0.1", "--port", str(port), "--verbose"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env | {"HOME": str(server_home), "CLAUDE_CONFIG_DIR": str(claude_file.parent)},
    )

    def request(agent):
        return subprocess.run(
            command + ["--request", "127.0.0.1", "--agent", agent,
                       "--send-port", str(port), "--verbose"],
            capture_output=True, timeout=20,
            env=env | {"HOME": str(client_home),
                       "CLAUDE_CONFIG_DIR": str(client_home / ".claude")},
        )

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(daemon.stderr, selectors.EVENT_READ)
            assert selector.select(5), "daemon failed to announce readiness"
            ready = daemon.stderr.readline()
        assert b"Serving credential requests" in ready
        # Authentication failure, malformed plaintext, oversized frame, and reset.
        invalid_frames = [
            transfer_crypto.encrypt(request_protocol.request("claude", "a" * 64), "wrong"),
            transfer_crypto.encrypt("{}", passphrase),
            "x" * (16 * 1024 + 1),
        ]
        for frame in invalid_frames:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
                conn.sendall(frame.encode())
                conn.shutdown(socket.SHUT_WR)
                try:
                    assert conn.recv(1024) == b""
                except ConnectionResetError:
                    pass
        assert claude_file.read_bytes() == original_claude
        assert codex_file.read_bytes() == original_codex
        result = request("all")
        assert result.returncode == 0, result.stderr
        assert json.loads((client_home / ".claude" / ".credentials.json").read_text()) == (
            claude_payload
        )
        assert json.loads((client_home / ".codex" / "auth.json").read_text()) == codex_payload
        assert request("codex").returncode == 0
        assert claude_file.read_bytes() == original_claude
        assert codex_file.read_bytes() == original_codex
        # Remove only a synthetic test store; Claude failure must not prevent Codex import.
        claude_file.unlink()
        result = request("all")
        assert result.returncode == 1
        assert b"claude: request failed (credentials-unavailable)" in result.stderr
        assert b"codex: credentials imported" in result.stderr
        assert request("codex").returncode == 0
        daemon.send_signal(signal.SIGINT)
        stdout, stderr = daemon.communicate(timeout=5)
        assert daemon.returncode == 0
        assert stdout == b""
        for secret in (passphrase, "synthetic-claude-access", "synthetic-codex-refresh"):
            assert secret.encode() not in ready + stderr + result.stderr
        for path in (client_home / ".claude" / ".credentials.json",
                     client_home / ".codex" / "auth.json"):
            assert path.stat().st_mode & 0o077 == 0
    finally:
        if daemon.poll() is None:
            daemon.kill()
        daemon.communicate()


@pytest.mark.timeout(30)
def test_large_codex_request_uses_platform_transport(tmp_path):
    if sys.platform not in ("darwin", "linux"):
        pytest.skip("supported request platforms only")
    if sys.platform == "darwin" and not Path(
        os.environ.get("CLAUDE_CREDENTIALS_NC", "/usr/bin/nc")
    ).exists():
        pytest.skip("Apple nc unavailable")
    server_home = tmp_path / "server"
    client_home = tmp_path / "client"
    auth = server_home / ".codex" / "auth.json"
    auth.parent.mkdir(parents=True)
    claims = base64.urlsafe_b64encode(json.dumps({"exp": time.time() + 3600}).encode()).decode()
    payload = {"tokens": {"access_token": f"header.{claims}.sig",
                          "refresh_token": "synthetic-refresh"}, "padding": "x" * 90000}
    auth.write_text(json.dumps(payload))
    original = auth.read_bytes()
    env = os.environ | {"CLAUDE_CREDENTIALS_PASSPHRASE": "synthetic-large-request"}
    command = [sys.executable, "-m", "ai_credentials_helper.cli"]
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    daemon = subprocess.Popen(
        command + ["--serve", "--bind", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env | {"HOME": str(server_home)},
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(daemon.stderr, selectors.EVENT_READ)
            assert selector.select(5)
            assert b"Serving credential requests" in daemon.stderr.readline()
        result = subprocess.run(
            command + ["--request", "127.0.0.1", "--agent", "codex",
                       "--send-port", str(port)],
            capture_output=True, timeout=20, env=env | {"HOME": str(client_home)},
        )
        assert result.returncode == 0, result.stderr
        assert json.loads((client_home / ".codex" / "auth.json").read_text()) == payload
        assert auth.read_bytes() == original
        daemon.send_signal(signal.SIGINT)
        _stdout, stderr = daemon.communicate(timeout=5)
        assert daemon.returncode == 0
        assert b"[INFO] credential request connected: peer=127.0.0.1:" in stderr
        assert b"credential request received: peer=127.0.0.1:" in stderr
        assert b"agent=codex status=ok" in stderr
        assert b"synthetic-refresh" not in stderr
        assert b"synthetic-large-request" not in stderr
    finally:
        if daemon.poll() is None:
            daemon.kill()
        daemon.communicate()
