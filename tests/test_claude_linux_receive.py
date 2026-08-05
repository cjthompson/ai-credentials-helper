import json
import os
import socket
import subprocess
import sys
import time

import pytest

from ai_credentials_helper import transfer_crypto

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux storage integration")

PAYLOAD = {
    "claudeAiOauth": {
        "accessToken": "sk-ant-oat-linux-test",
        "refreshToken": "sk-ant-ort-linux-test",
        "expiresAt": 1900000000000,
    }
}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_linux_receive_writes_configured_claude_credentials(tmp_path):
    config_dir = tmp_path / "claude-config"
    auth_path = config_dir / ".credentials.json"
    passphrase = "pytest-linux-claude-transfer"
    port = _free_port()
    env = os.environ | {
        "CLAUDE_CONFIG_DIR": str(config_dir),
        "CLAUDE_CREDENTIALS_PASSPHRASE": passphrase,
    }
    receiver = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ai_credentials_helper.cli",
            "--agent",
            "claude",
            "--receive",
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        deadline = time.monotonic() + 3
        while True:
            try:
                conn = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if time.monotonic() >= deadline or receiver.poll() is not None:
                    raise
                time.sleep(0.05)
        frame = transfer_crypto.encrypt(json.dumps(PAYLOAD), passphrase).encode()
        with conn:
            conn.sendall(frame)
            conn.shutdown(socket.SHUT_WR)
        _stdout, stderr = receiver.communicate(timeout=10)
    finally:
        if receiver.poll() is None:
            receiver.kill()
            receiver.communicate()

    assert receiver.returncode == 0, stderr
    assert json.loads(auth_path.read_text()) == PAYLOAD
    assert auth_path.stat().st_mode & 0o077 == 0
