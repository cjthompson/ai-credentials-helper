import os
import subprocess
from pathlib import Path


def test_legacy_shell_rejects_non_darwin(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uname = fake_bin / "uname"
    uname.write_text("#!/bin/sh\nprintf 'Linux\\n'\n")
    uname.chmod(0o755)
    script = Path(__file__).parents[1] / "credentials-helper.sh"

    result = subprocess.run(
        ["bash", str(script), "--help"],
        capture_output=True,
        text=True,
        env=os.environ | {"PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )

    assert result.returncode == 1
    assert "macOS-only" in result.stderr
    assert "Use the Python CLI" in result.stderr
