#!/usr/bin/env python3
"""Setup script for ai-credentials-helper.

Creates a venv, installs the package, and symlinks credentials-helper to ~/.local/bin/.
"""

import subprocess
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
VENV_DIR = REPO_DIR / ".venv"
LOCAL_BIN = Path.home() / ".local" / "bin"

MIN_PYTHON = (3, 12)


def run(cmd, **kwargs):
    print(f"  $ {' '.join(cmd)}")
    subprocess.check_call(cmd, **kwargs)


def has_uv():
    import shutil
    return shutil.which("uv") is not None


def python_meets_minimum() -> bool:
    return tuple(sys.version_info[:2]) >= MIN_PYTHON


def setup_venv():
    venv_python = VENV_DIR / "bin" / "python"

    if has_uv():
        if not VENV_DIR.exists():
            print(f"Creating venv at {VENV_DIR} (using uv) ...")
            run(["uv", "venv", str(VENV_DIR), "--python", ">=3.12"])
        elif not venv_python.exists():
            print(f"venv at {VENV_DIR} is broken, recreating (using uv) ...")
            import shutil
            shutil.rmtree(VENV_DIR)
            run(["uv", "venv", str(VENV_DIR), "--python", ">=3.12"])
        else:
            print(f"venv already exists at {VENV_DIR}")

        print("Installing ai-credentials-helper in editable mode (using uv) ...")
        run(["uv", "pip", "install", "-e", str(REPO_DIR), "--python", str(venv_python)])
    else:
        if not python_meets_minimum():
            print(
                f"Error: Python {sys.version_info.major}.{sys.version_info.minor} "
                "detected, but 3.12+ is required."
            )
            print()
            print("Install uv (recommended) and re-run — it will fetch the right Python:")
            print("  Install with Homebrew:  brew install uv")
            print("  Or install from shell:  curl -LsSf https://astral.sh/uv/install.sh | sh")
            sys.exit(1)

        if VENV_DIR.exists():
            try:
                subprocess.check_call(
                    [str(venv_python), "-c", "import pip"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                print(f"venv already exists at {VENV_DIR}")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"venv at {VENV_DIR} is broken, recreating ...")
                import shutil
                shutil.rmtree(VENV_DIR)
                run([sys.executable, "-m", "venv", str(VENV_DIR)])
        else:
            print(f"Creating venv at {VENV_DIR} ...")
            run([sys.executable, "-m", "venv", str(VENV_DIR)])

        print("Installing ai-credentials-helper in editable mode ...")
        run([str(venv_python), "-m", "pip", "install", "-e", str(REPO_DIR)])


def symlink_to_path():
    print()
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    src = VENV_DIR / "bin" / "credentials-helper"
    dst = LOCAL_BIN / "credentials-helper"
    if dst.is_symlink() or dst.exists():
        dst.unlink()
    dst.symlink_to(src)
    print(f"  {dst} → {src}")
    print(f"Symlinked to {LOCAL_BIN} (ensure it is on PATH)")


def main():
    print("=== ai-credentials-helper setup ===")
    print()
    setup_venv()
    symlink_to_path()
    print()
    print("Done! Run `credentials-helper --help` to get started.")


if __name__ == "__main__":
    main()
