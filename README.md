# AI Credentials Helper

`ai-credentials-helper` reads, inspects, imports, and securely transfers OAuth credentials used by AI coding agents. It supports Claude Code credentials in the macOS Keychain and Codex CLI credentials in `~/.codex/auth.json`.

Claude is the default backend. Pass `--agent codex` to work with Codex credentials.

## Requirements

- macOS
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

Claude Code uses the macOS Keychain and is selected by default:

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

Transfers use authenticated encryption over a one-shot TCP connection. Start the receiver first, then run the sender with the same agent and passphrase.

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

Omit the environment variable to enter the passphrase interactively. The default port is `47299`; override it with `--port` on the receiver and `--send-port` on the sender. Use `--oauth-only` with `--send` to transfer only the portable token subset.

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
