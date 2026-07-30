# AI Credentials Helper

`ai-credentials-helper` securely copies OAuth credentials used by AI coding agents between computers. It supports Claude Code credentials in the macOS Keychain or Linux/WSL `${CLAUDE_CONFIG_DIR:-~/.claude}/.credentials.json`, plus Codex CLI credentials in `~/.codex/auth.json`.

Claude is the default backend. Pass `--agent codex` to work with Codex credentials.

## Requirements

- macOS, native Linux, or WSL
- Python 3.12 or newer
- [`uv`](https://docs.astral.sh/uv/) is recommended but optional

## Install

```bash
git clone git@github.com:cjthompson/ai-credentials-helper.git
cd ai-credentials-helper
python3 install.py
```

The installer creates `.venv`, installs the package, and links `credentials-helper` into `~/.local/bin`. Ensure that directory is on your `PATH`.

## Usage

Claude Code uses the macOS Keychain on macOS and `${CLAUDE_CONFIG_DIR:-~/.claude}/.credentials.json` on Linux and WSL. The helper selects the correct store automatically; continue to use `--agent claude` or omit `--agent`, since Claude is the default.

```bash
credentials-helper --simple
credentials-helper --raw
credentials-helper --oauth-only
credentials-helper --refresh
```

Codex CLI uses `~/.codex/auth.json`:

```bash
credentials-helper --agent codex --simple
credentials-helper --agent codex --raw
credentials-helper --agent codex --oauth-only
credentials-helper --agent codex --import ./auth-backup.json
```

Codex refreshes its own tokens, so `--refresh` is not supported for that backend. Codex imports and receives reject expired tokens by default; use `--force` only when deliberately restoring one:

```bash
credentials-helper --agent codex --force --import ./expired-auth.json
```

Run `credentials-helper --help` for all options.

## Encrypted transfer

Transfers use authenticated encryption over a one-shot TCP connection and work macOS ↔ Linux/WSL and Linux/WSL ↔ Linux/WSL for both Claude and Codex. Start the receiver first, then run the sender with the same `--agent` value and passphrase. Use `--agent claude` for Claude Code or `--agent codex` for Codex CLI.

`credentials-helper.sh` is a legacy, macOS-only Claude implementation. It is not wire-compatible with the authenticated Python transfer protocol. Use the installed `credentials-helper` Python CLI for all cross-computer copying.

The Python CLI uses Apple's `/usr/bin/nc` for outbound connections on macOS and native Python sockets on Linux and WSL. No Linux `netcat` package is required. The receiving machine must be reachable at the host and port supplied by the sender; WSL firewall or NAT configuration remains the responsibility of the host environment.

On the receiving machine:

```bash
export CLAUDE_CREDENTIALS_PASSPHRASE='same-secret-on-both-machines'
credentials-helper --agent codex --receive
```

On the sending machine:

```bash
export CLAUDE_CREDENTIALS_PASSPHRASE='same-secret-on-both-machines'
credentials-helper --agent codex --send 192.168.1.42
```

Omit `--agent codex` to select Claude. Omit the environment variable to enter the passphrase interactively. The default port is `47299`; override it with `--port` on the receiver and `--send-port` on the sender. Use `--oauth-only` with `--send` to transfer only the portable token subset.

For Claude transfers from macOS to Linux/WSL, the receiver converts a hex-encoded Keychain blob to Claude Code's JSON credential-file format automatically. Linux/WSL writes use an atomic replacement and `0600` file permissions. A malformed or unauthenticated payload is rejected before replacement.

The receiver may omit `--agent` entirely — it adopts whichever agent the sender labeled the transfer with, and prints `Detected agent: <name> (from sender)` before writing. Passing a `--agent` that differs from the sender's is a hard error on both ends: the receiver's store is left untouched and the sender's exit code reflects the rejection. Both ends must be running a version of this tool that supports this agent label; an older, unlabelled payload is rejected outright.

## Security

- `--raw`, `--simple`, and verbose receive output can expose credentials in the terminal.
- Transfer security depends on choosing and protecting a strong shared passphrase.
- A failed authentication or malformed payload leaves the destination store unchanged.
- Codex credential files written by the helper use `0600` permissions.
- Tests use synthetic credentials and temporary home directories; they do not access real Keychain or Codex credentials.

## Development

Install development dependencies, then run the checks:

```bash
uv pip install -e '.[dev]' --python .venv/bin/python
.venv/bin/pytest -q
.venv/bin/ruff check .
```

The localhost integration test starts real sender and receiver subprocesses. It skips automatically where loopback sockets or the configured `nc` binary are unavailable.
