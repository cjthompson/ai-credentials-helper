"""Integration smoke tests for real CLI send/receive over localhost TCP."""

import base64
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


def _b64_json(data: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


def _jwt_with_exp(exp: int) -> str:
    return f"{_b64_json({'alg': 'none', 'typ': 'JWT'})}.{_b64_json({'sub': 'live-test', 'exp': exp})}.sig"


def _free_localhost_port() -> int:
    try:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
    except OSError as e:
        pytest.skip(f"localhost TCP sockets unavailable: {e}")
    try:
        return sock.getsockname()[1]
    finally:
        sock.close()


def test_codex_send_receive_round_trips_over_localhost_tcp(tmp_path):
    """Exercise real CLI subprocesses, encryption, nc send, and socket receive.

    The test uses two temporary HOME directories so it never reads or writes the
    developer's real ``~/.codex/auth.json``.
    """
    nc_binary = Path(os.environ.get("CLAUDE_CREDENTIALS_NC", "/usr/bin/nc"))
    if not nc_binary.exists():
        pytest.skip(f"{nc_binary} not available for CLI --send")

    send_home = tmp_path / "send-home"
    recv_home = tmp_path / "recv-home"
    send_auth = send_home / ".codex" / "auth.json"
    recv_auth = recv_home / ".codex" / "auth.json"
    send_auth.parent.mkdir(parents=True)

    access_token = _jwt_with_exp(int(time.time()) + 3600)
    payload = {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": access_token,
            "refresh_token": "rt_live_test",
            "account_id": "acct-live-test",
        },
        "last_refresh": "2026-06-28T00:00:00Z",
    }
    send_auth.write_text(json.dumps(payload, separators=(",", ":")) + "\n")
    os.chmod(send_auth, 0o600)

    port = _free_localhost_port()
    env = os.environ.copy()
    env["CLAUDE_CREDENTIALS_PASSPHRASE"] = "pytest-localhost-live-transfer"

    recv_env = env | {"HOME": str(recv_home)}
    send_env = env | {"HOME": str(send_home)}

    receiver = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ai_credentials_helper.cli",
            "--agent",
            "codex",
            "--receive",
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=recv_env,
    )
    send_result = None
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            send_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ai_credentials_helper.cli",
                    "--agent",
                    "codex",
                    "--send",
                    "127.0.0.1",
                    "--send-port",
                    str(port),
                ],
                capture_output=True,
                text=True,
                env=send_env,
                timeout=10,
            )
            if send_result.returncode == 0:
                break
            if receiver.poll() is not None:
                break
            time.sleep(0.1)

        recv_stdout, recv_stderr = receiver.communicate(timeout=10)
    finally:
        if receiver.poll() is None:
            receiver.kill()
            receiver.communicate()

    assert send_result is not None
    assert send_result.returncode == 0, send_result.stderr
    assert receiver.returncode == 0, recv_stderr
    assert recv_stdout == ""
    assert "Sent" in send_result.stderr
    assert "Received and imported" in recv_stderr

    received = json.loads(recv_auth.read_text())
    assert received["tokens"]["account_id"] == "acct-live-test"
    assert received["tokens"]["access_token"] == access_token
    assert received["tokens"]["refresh_token"] == "rt_live_test"
    assert recv_auth.stat().st_mode & 0o077 == 0
