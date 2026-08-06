# Linux and WSL Credential Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Copy Claude Code and Codex CLI credentials securely in every direction among macOS, native Linux, and WSL machines.

**Architecture:** Preserve the current agent-level backend registry. The Claude backend selects macOS Keychain or Claude Code's Linux/WSL `.credentials.json` store internally, while the CLI selects Apple's `nc` sender on macOS and a dependency-free Python socket sender on Linux/WSL. The authenticated wire format remains unchanged, and the one-shot Python receiver adds backend-specific shape validation immediately before storage dispatch.

**Tech Stack:** Python 3.12+, stdlib (`json`, `os`, `pathlib`, `socket`, `subprocess`, `sys`, `tempfile`), `cryptography`, pytest, Ruff, GitHub Actions.

## Global Constraints

- The feature is credential copying only. Do not add new login, account-management, or refresh behavior.
- Support `darwin` and `linux` explicitly. WSL follows the `linux` branch because Python reports `sys.platform == "linux"` inside WSL.
- Support both `--agent claude` and `--agent codex` in all macOS/Linux/WSL directions.
- Preserve macOS Claude Keychain behavior and Apple's `/usr/bin/nc` outbound workaround.
- On Linux/WSL, read and write `${CLAUDE_CONFIG_DIR:-~/.claude}/.credentials.json`.
- Linux/WSL credential writes must be atomic JSON-file replacements with mode `0600`; a newly created credential directory must use mode `0700`.
- Normalize macOS hex-encoded Claude Keychain blobs into JSON before writing the Linux/WSL credential file.
- Validate decrypted Claude payload shape before replacing either destination store.
- Preserve direct macOS Claude `--import` behavior; receive-only validation belongs in the CLI before it calls the storage backend.
- Preserve the AES-256-CBC + HMAC-SHA256 authenticated wire format. Do not add a new runtime dependency or protocol version.
- A failed connection, decryption, validation, or write must leave the destination credential store unchanged.
- Preserve the user's existing untracked `uv.lock`; do not stage or modify it unless separately authorized.
- Work will be done sequentially on `ct/linux-native-transfer`, with one commit per task and one pull request after all stages are complete.

## Sources of Truth

- Anthropic credential management: <https://code.claude.com/docs/en/authentication#credential-management>
- Existing Claude backend: `ai_credentials_helper/backends/claude.py`
- Existing Codex atomic writer: `ai_credentials_helper/backends/codex.py`
- Existing transfer sender and receiver: `ai_credentials_helper/cli.py`
- Existing live transfer test: `tests/test_cli_live_transfer.py`

## File and Stage Map

### BRANCH: `ct/linux-native-transfer`

Load `superpowers:using-git-worktrees` and fetch the default branch. Before creating the worktree, run `git check-ignore .Codex/worktrees`; if it is not already ignored, add `.Codex/worktrees/` to `.git/info/exclude` as a local-only rule and do not modify the shared `.gitignore`. Create the worktree under `.Codex/worktrees/ct/linux-native-transfer`.

### STAGE 1: Portable outbound transport

Independently enables Linux/WSL sending for the already-portable Codex backend while preserving macOS sending.

- Modify `ai_credentials_helper/cli.py`: platform-dispatched outbound transport.
- Create `tests/test_cli_transport.py`: focused transport unit tests without touching backend tests.
- Modify `tests/test_cli_live_transfer.py`: only require `nc` on Darwin and exercise the native sender on Linux.
- Create `.github/workflows/test.yml`: macOS/Linux Python 3.12 test matrix.
- Modify `README.md`: platform requirements and transport behavior.

### STAGE 2: Linux/WSL Claude storage

Builds on Stage 1 and enables Linux/WSL machines to receive and store Claude credentials using the already-native Python receiver.

- Modify `ai_credentials_helper/backends/claude.py`: platform selection, Linux file storage, normalization, and validation.
- Modify `ai_credentials_helper/backends/__init__.py`: add `validate_blob` to the backend protocol and make its storage description platform-neutral.
- Modify `ai_credentials_helper/credentials.py`: dispatch `validate_blob` through the facade and make its default-backend description platform-neutral.
- Modify `ai_credentials_helper/cli.py`: validate decrypted data through the active backend before storage dispatch.
- Modify `tests/test_claude_backend.py`: Linux/WSL storage, validation, permissions, atomicity, and cross-platform normalization tests.
- Modify `tests/test_cli_agent.py`: Linux Claude store-label coverage.
- Create `tests/test_claude_linux_receive.py`: real Linux subprocess receive into `CLAUDE_CONFIG_DIR`.
- Modify `README.md`: Claude Linux/WSL storage and cross-platform copy examples.
- Modify `pyproject.toml`: remove the macOS-only package description.

### STAGE 3: Legacy script guard and documentation

Builds on Stages 1 and 2, prevents Linux/WSL users from invoking the macOS-only legacy Bash implementation, and corrects stale transfer documentation.

- Modify `credentials-helper.sh`: fail immediately outside Darwin.
- Modify `ai_credentials_helper/transfer_crypto.py`: describe the actual Python implementation and stop claiming wire compatibility with the plaintext shell script.
- Modify `tests/test_transfer_crypto.py`: describe OpenSSL primitive interoperability without claiming legacy-script compatibility.
- Modify `README.md`: label the Bash script as legacy and macOS-only.
- Create `tests/test_legacy_shell.py`: verify the platform guard without executing Keychain operations.

---

### Task 1: Add the Linux/WSL native socket sender

**Files:**

- Modify: `ai_credentials_helper/cli.py:31-53`
- Modify: `ai_credentials_helper/cli.py:223-255`
- Create: `tests/test_cli_transport.py`

**Interfaces:**

- Consumes: encrypted `frame: bytes`, destination `host: str`, and `port: int` from `_do_send`.
- Produces: `_send_frame_native(frame: bytes, host: str, port: int) -> str | None` and `_send_frame_nc(frame: bytes, host: str, port: int) -> str | None`. A `None` result means success; a string is the user-facing failure detail.
- Selection: `_send_frame(frame: bytes, host: str, port: int) -> tuple[str | None, str]` returns `(error, transport_name)` and selects only `darwin` or `linux`.

- [ ] **Step 1: Create focused failing transport tests**

Create `tests/test_cli_transport.py` with fake sockets and subprocesses. The tests must pin native send, half-close, Darwin `nc`, timeout/error formatting, and unsupported-platform behavior:

```python
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
```

- [ ] **Step 2: Run the transport tests and verify they fail**

Run:

```bash
.venv/bin/pytest tests/test_cli_transport.py -q
```

Expected: failures because `_send_frame`, `_send_frame_native`, and `_send_frame_nc` do not exist.

- [ ] **Step 3: Extract the Darwin sender and implement the Linux/WSL sender**

In `ai_credentials_helper/cli.py`, retain `NC_BINARY`, add the native sender, and make the selection explicit:

```python
def _send_frame_native(frame: bytes, host: str, port: int) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=SEND_TIMEOUT) as conn:
            conn.sendall(frame)
            conn.shutdown(socket.SHUT_WR)
    except socket.timeout:
        return f"timed out after {SEND_TIMEOUT}s"
    except OSError as exc:
        return str(exc)
    return None


def _send_frame_nc(frame: bytes, host: str, port: int) -> str | None:
    try:
        proc = subprocess.run(
            [NC_BINARY, "-w", str(SEND_TIMEOUT), host, str(port)],
            input=frame,
            capture_output=True,
            timeout=SEND_TIMEOUT + 5,
        )
    except FileNotFoundError:
        return f"{NC_BINARY} not found"
    except subprocess.TimeoutExpired:
        return f"timed out after {SEND_TIMEOUT}s"
    if proc.returncode != 0:
        return proc.stderr.decode(errors="replace").strip() or f"nc exited {proc.returncode}"
    return None


def _send_frame(frame: bytes, host: str, port: int) -> tuple[str | None, str]:
    if sys.platform == "darwin":
        return _send_frame_nc(frame, host, port), NC_BINARY
    if sys.platform == "linux":
        return _send_frame_native(frame, host, port), "native socket"
    return (
        "credential transfer is supported only on macOS, Linux, and WSL",
        "unsupported platform",
    )
```

Refactor `_do_send` so encryption remains unchanged, it calls `_send_frame`, logs the selected transport, prints one error, and reports success only after the sender returns `None`:

```python
def _do_send(host: str, port: int, oauth_only: bool) -> int:
    plaintext = creds.oauth_only_json() if oauth_only else creds.read_raw()
    frame = transfer_crypto.encrypt(plaintext, _get_passphrase()).encode()
    started = time.monotonic()
    error, transport = _send_frame(frame, host, port)
    if error:
        elapsed_ms = (time.monotonic() - started) * 1000
        log.debug("send: %s failed after %.0f ms — %s", transport, elapsed_ms, error)
        _err(f"Error: could not send to {host}:{port} — {error}")
        return 1
    log.debug("send: %s ok in %.0f ms", transport, (time.monotonic() - started) * 1000)
    note = " (oauth-only)" if oauth_only else ""
    _err(f"Sent {len(frame)} encrypted bytes to {host}:{port} via TCP{note}")
    return 0
```

- [ ] **Step 4: Run focused transport and existing CLI tests**

Run:

```bash
.venv/bin/pytest tests/test_cli_transport.py tests/test_cli_agent.py -q
```

Expected: all tests pass; existing CLI output remains stable.

- [ ] **Step 5: Commit the transport implementation**

```bash
git add ai_credentials_helper/cli.py tests/test_cli_transport.py
git commit -m "feat: add native Linux credential transfer"
```

### Task 2: Exercise the selected sender on macOS and Linux CI

**Files:**

- Modify: `tests/test_cli_live_transfer.py:37-45`
- Create: `.github/workflows/test.yml`

**Interfaces:**

- Consumes: platform-dispatched `_send_frame` from Task 1.
- Produces: a live encrypted Codex round trip on both GitHub-hosted operating systems.

- [ ] **Step 1: Make the live test's `nc` prerequisite Darwin-only**

Change the unconditional check to:

```python
if sys.platform == "darwin":
    nc_binary = Path(os.environ.get("CLAUDE_CREDENTIALS_NC", "/usr/bin/nc"))
    if not nc_binary.exists():
        pytest.skip(f"{nc_binary} not available for CLI --send")
```

Update the test docstring from `encryption, nc send, and socket receive` to `encryption, platform-selected send, and socket receive`.

- [ ] **Step 2: Run the live test locally**

```bash
.venv/bin/pytest tests/test_cli_live_transfer.py -q
```

Expected: one passing localhost round trip. A sandbox that forbids loopback may report the existing explicit skip.

- [ ] **Step 3: Add the macOS/Linux workflow**

Create `.github/workflows/test.yml`:

```yaml
name: test

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, ubuntu-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
          cache: pip
      - run: python -m pip install -e '.[dev]'
      - run: pytest -q
      - run: ruff check .
```

- [ ] **Step 4: Run the complete local verification surface**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
```

Expected: the complete test suite and Ruff pass.

- [ ] **Step 5: Commit CI and live coverage**

```bash
git add .github/workflows/test.yml tests/test_cli_live_transfer.py
git commit -m "test: verify transfers on macOS and Linux"
```

### Task 3: Document portable transport and finish Stage 1

**Files:**

- Modify: `README.md:7-21`
- Modify: `README.md:51-69`

**Interfaces:**

- Consumes: Task 1's platform-selected sender and Task 2's CI coverage.
- Produces: user instructions for Codex copying between supported platforms.

- [ ] **Step 1: Update requirements and transfer text**

Replace the macOS-only requirement with:

```markdown
- macOS, native Linux, or WSL
- Python 3.12 or newer
- [`uv`](https://docs.astral.sh/uv/) is recommended but optional
```

Add this paragraph after the encrypted-transfer introduction:

```markdown
The Python CLI uses Apple's `/usr/bin/nc` for outbound connections on macOS and native Python sockets on Linux and WSL. No Linux `netcat` package is required. The receiving machine must be reachable at the host and port supplied by the sender; WSL firewall or NAT configuration remains the responsibility of the host environment.
```

- [ ] **Step 2: Verify README commands and CLI help agree**

```bash
.venv/bin/credentials-helper --help
rg -n "macOS|Linux|WSL|netcat|/usr/bin/nc|--send|--receive" README.md ai_credentials_helper/cli.py
```

Expected: README flags match help output and no text claims that Python transfer is macOS-only.

- [ ] **Step 3: Commit documentation**

```bash
git add README.md
git commit -m "docs: describe Linux credential transfer"
```

- [ ] **Step 4: Complete the Stage 1 checkpoint**

Rerun:

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
```

Expected: Stage 1 is complete on `ct/linux-native-transfer`; do not push or open a pull request yet.

---

### Task 4: Select the Claude credential store by platform

**Files:**

- Modify: `ai_credentials_helper/backends/claude.py:1-29`
- Modify: `tests/test_claude_backend.py`

**Interfaces:**

- Produces: `KEYCHAIN_SERVICE: str | None`, `AUTH_PATH: Path | None`, and `_require_auth_path() -> Path`.
- Darwin uses Keychain; Linux/WSL uses `.credentials.json`; other platforms fail before storage access.

- [ ] **Step 1: Add failing platform and config-directory tests**

First make the existing Keychain fixture host-independent. At the start of `fake_security`, explicitly select Keychain storage so the same tests still exercise macOS behavior on an Ubuntu runner:

```python
monkeypatch.setattr(creds, "KEYCHAIN_SERVICE", "Claude Code-credentials")
monkeypatch.setattr(creds, "AUTH_PATH", None, raising=False)
```

Then append tests that isolate module constants with monkeypatching:

```python
def test_linux_auth_path_defaults_to_claude_directory(monkeypatch):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(creds.Path, "home", classmethod(lambda _cls: creds.Path("/home/tester")))
    assert creds._linux_auth_path() == creds.Path("/home/tester/.claude/.credentials.json")


def test_linux_auth_path_honors_claude_config_dir(monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/srv/claude-config")
    assert creds._linux_auth_path() == creds.Path("/srv/claude-config/.credentials.json")


def test_require_auth_path_rejects_unsupported_platform(monkeypatch):
    monkeypatch.setattr(creds, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(creds, "AUTH_PATH", None)
    with pytest.raises(creds.CredentialsError, match="supported only on macOS, Linux, and WSL"):
        creds._require_auth_path()
```

- [ ] **Step 2: Run the platform tests and verify they fail**

```bash
.venv/bin/pytest tests/test_claude_backend.py -q
```

Expected: failures because `_linux_auth_path`, `AUTH_PATH`, and `_require_auth_path` do not exist.

- [ ] **Step 3: Add explicit platform constants and path resolution**

Add `os`, `sys`, `tempfile`, and `Path` imports and define:

```python
def _linux_auth_path() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    config_dir = Path(configured).expanduser() if configured else Path.home() / ".claude"
    return config_dir / ".credentials.json"


if sys.platform == "darwin":
    KEYCHAIN_SERVICE: str | None = "Claude Code-credentials"
    AUTH_PATH: Path | None = None
elif sys.platform == "linux":
    KEYCHAIN_SERVICE = None
    AUTH_PATH = _linux_auth_path()
else:
    KEYCHAIN_SERVICE = None
    AUTH_PATH = None


def _require_auth_path() -> Path:
    if AUTH_PATH is None:
        raise CredentialsError(
            "Claude credential storage is supported only on macOS, Linux, and WSL"
        )
    return AUTH_PATH
```

Replace the module and exception docstrings with platform-neutral text:

```python
"""Claude Code credentials backend with platform-native storage.

macOS uses the ``Claude Code-credentials`` Keychain entry. Linux and WSL use
Claude Code's ``.credentials.json`` under ``CLAUDE_CONFIG_DIR`` or ``~/.claude``.
Credential parsing and OAuth token handling are shared across both stores.
"""


class CredentialsError(Exception):
    """Credential data or its platform-native store is missing or inaccessible."""
```

- [ ] **Step 4: Run focused tests**

```bash
.venv/bin/pytest tests/test_claude_backend.py -q
```

Expected: new platform tests pass and existing fake-Keychain tests remain green.

- [ ] **Step 5: Commit platform selection**

```bash
git add ai_credentials_helper/backends/claude.py tests/test_claude_backend.py
git commit -m "feat: select Claude storage by platform"
```

### Task 5: Validate and atomically write Linux/WSL Claude credentials

**Files:**

- Modify: `ai_credentials_helper/backends/claude.py:31-120`
- Modify: `ai_credentials_helper/backends/__init__.py:15-64`
- Modify: `ai_credentials_helper/credentials.py:35-73`
- Modify: `ai_credentials_helper/cli.py:295-317`
- Modify: `tests/test_claude_backend.py`
- Modify: `tests/test_cli_agent.py`

**Interfaces:**

- Produces: `validate_blob(data: object) -> None` on every backend and through the facade.
- `_do_receive(...)` parses and validates decrypted data through the active backend before calling `write`.
- `claude.write(content: str) -> None` preserves existing verbatim macOS Keychain writes without adding import-time validation, but validates and writes normalized compact JSON on Linux/WSL.
- `_write_file(content: str) -> None` performs same-directory atomic replacement.

- [ ] **Step 1: Add Claude validation, receive-boundary, and macOS preservation tests**

Add parameterized coverage:

```python
@pytest.mark.parametrize(
    "data, message",
    [
        ([], "top-level value must be a JSON object"),
        ({}, "missing or non-dict 'claudeAiOauth' object"),
        ({"claudeAiOauth": []}, "missing or non-dict 'claudeAiOauth' object"),
        ({"claudeAiOauth": {"accessToken": "", "refreshToken": "r"}}, "accessToken"),
        ({"claudeAiOauth": {"accessToken": "a", "refreshToken": ""}}, "refreshToken"),
    ],
)
def test_validate_blob_rejects_non_credentials(data, message):
    with pytest.raises(creds.CredentialsError, match=message):
        creds.validate_blob(data)


def test_validate_blob_accepts_oauth_credentials():
    creds.validate_blob(FULL)


def test_keychain_write_preserves_verbatim_non_oauth_document(fake_security):
    content = '{"customCredential":"preserve-verbatim"}'
    creds.write(content)
    (argv,) = fake_security["writes"]
    assert argv[argv.index("-w") + 1] == content
```

In `tests/test_cli_agent.py`, add a receive-path regression proving that valid JSON with the wrong Claude shape is rejected before the backend writer is called:

```python
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
```

- [ ] **Step 2: Add failing Linux file tests**

Use a fixture that patches the storage signal without pretending the test host itself is Linux:

```python
@pytest.fixture
def linux_credentials(tmp_path, monkeypatch):
    auth_path = tmp_path / ".claude" / ".credentials.json"
    monkeypatch.setattr(creds, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(creds, "AUTH_PATH", auth_path)
    return auth_path


def test_linux_read_raw_reads_json_file(linux_credentials):
    linux_credentials.parent.mkdir(parents=True)
    linux_credentials.write_text(FULL_JSON + "\n")
    assert creds.read_raw() == FULL_JSON


def test_linux_read_raw_reports_missing_file(linux_credentials):
    with pytest.raises(creds.CredentialsError, match="No credentials found"):
        creds.read_raw()


def test_linux_write_creates_private_file_and_directory(linux_credentials):
    creds.write(FULL_JSON)
    assert json.loads(linux_credentials.read_text()) == FULL
    assert linux_credentials.stat().st_mode & 0o077 == 0
    assert linux_credentials.parent.stat().st_mode & 0o077 == 0


def test_linux_write_normalizes_hex_keychain_blob(linux_credentials):
    creds.write(FULL_JSON.encode().hex())
    assert json.loads(linux_credentials.read_text()) == FULL
    assert not linux_credentials.read_text().startswith(FULL_JSON.encode().hex()[:16])


def test_linux_write_validation_leaves_existing_file_unchanged(linux_credentials):
    linux_credentials.parent.mkdir(parents=True)
    linux_credentials.write_text(FULL_JSON + "\n")
    before = linux_credentials.read_bytes()
    with pytest.raises(creds.CredentialsError, match="accessToken"):
        creds.write('{"claudeAiOauth":{"accessToken":"","refreshToken":"r"}}')
    assert linux_credentials.read_bytes() == before


def test_linux_write_uses_atomic_replace(linux_credentials, monkeypatch):
    replaced = []
    real_replace = creds.os.replace

    def spy_replace(source, destination):
        replaced.append((creds.Path(source).parent, creds.Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr(creds.os, "replace", spy_replace)
    creds.write(FULL_JSON)
    assert replaced == [(linux_credentials.parent, linux_credentials)]


def test_linux_write_replace_failure_preserves_existing_and_cleans_temp(
    linux_credentials, monkeypatch
):
    linux_credentials.parent.mkdir(parents=True)
    linux_credentials.write_text(FULL_JSON + "\n")
    before = linux_credentials.read_bytes()

    def fail_replace(*_args):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(creds.os, "replace", fail_replace)

    with pytest.raises(creds.CredentialsError, match="Cannot write"):
        creds.write(FULL_JSON)

    assert linux_credentials.read_bytes() == before
    temp_prefix = f".{linux_credentials.name}."
    assert [p for p in linux_credentials.parent.iterdir() if p.name.startswith(temp_prefix)] == []


def test_linux_find_account_is_none(linux_credentials):
    assert creds.find_account() is None
```

- [ ] **Step 3: Run the new tests and verify they fail**

```bash
.venv/bin/pytest tests/test_claude_backend.py tests/test_cli_agent.py -q
```

Expected: validation, receive-boundary, and Linux storage tests fail while the macOS preservation test passes against the existing Keychain behavior.

- [ ] **Step 4: Implement Claude shape validation**

Add:

```python
def validate_blob(data: object) -> None:
    if not isinstance(data, dict):
        raise CredentialsError(
            f"top-level value must be a JSON object, got {type(data).__name__}"
        )
    oauth = data.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        raise CredentialsError("missing or non-dict 'claudeAiOauth' object")
    for field in ("accessToken", "refreshToken"):
        value = oauth.get(field)
        if not isinstance(value, str) or not value:
            raise CredentialsError(f"claudeAiOauth.{field} must be a non-empty string")
```

Make `parse_blob` strip surrounding whitespace, decode plain or hex JSON, and reject non-object JSON with `ValueError`:

```python
def parse_blob(raw: str) -> dict:
    text = raw.strip()
    if not text:
        raise ValueError("credential blob is empty")
    decoded = text if text.startswith("{") else bytes.fromhex(text).decode("utf-8")
    data = json.loads(decoded)
    if not isinstance(data, dict):
        raise ValueError("credential blob must be a JSON object")
    return data
```

Change `read_json()` to `return parse_blob(read_raw())` so every read supports the same representations.

- [ ] **Step 5: Implement file reads and atomic normalized writes**

Extract the current Keychain behavior without changing its subprocess contract:

```python
def _read_raw_keychain() -> str:
    proc = _security(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"])
    if proc.returncode != 0 or not proc.stdout:
        raise CredentialsError("No credentials found in Keychain")
    return proc.stdout.decode("utf-8", errors="replace").rstrip("\n")


def _find_account_keychain() -> str | None:
    proc = _security(["find-generic-password", "-s", KEYCHAIN_SERVICE])
    if proc.returncode != 0:
        return None
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if '"acct"' in line and "<blob>=" in line:
            return line.split("<blob>=")[1].strip().strip('"')
    return None


def _write_keychain(content: str) -> None:
    account = _find_account_keychain()
    if not account:
        raise CredentialsError(
            f"No existing keychain entry for service '{KEYCHAIN_SERVICE}'. "
            "Run 'claude login' first."
        )
    proc = _security(
        [
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
            content,
        ]
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise CredentialsError(f"Keychain write failed: {detail}")
```

Then add the Linux/WSL file functions:

```python
def _read_raw_file() -> str:
    path = _require_auth_path()
    try:
        return path.read_text(encoding="utf-8").rstrip("\n")
    except FileNotFoundError:
        raise CredentialsError(f"No credentials found at {path}") from None
    except OSError as exc:
        raise CredentialsError(f"Cannot read {path}: {exc}") from exc


def _write_file(content: str) -> None:
    path = _require_auth_path()
    parent_existed = path.parent.exists()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent_existed:
            os.chmod(path.parent, 0o700)
        fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    except OSError as exc:
        raise CredentialsError(f"Cannot prepare credential file at {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise CredentialsError(f"Cannot write {path}: {exc}") from exc
```

Dispatch public storage calls and normalize only for file storage:

```python
def read_raw() -> str:
    return _read_raw_keychain() if KEYCHAIN_SERVICE else _read_raw_file()


def find_account() -> str | None:
    return _find_account_keychain() if KEYCHAIN_SERVICE else None


def write(content: str) -> None:
    if KEYCHAIN_SERVICE:
        _write_keychain(content)
        return
    try:
        data = parse_blob(content)
    except (ValueError, json.JSONDecodeError) as exc:
        raise CredentialsError(f"payload is not a valid Claude credential document: {exc}") from exc
    validate_blob(data)
    _write_file(json.dumps(data, separators=(",", ":")))
```

Do not change permissions on a pre-existing `CLAUDE_CONFIG_DIR`; only enforce `0700` when this code creates the directory.

- [ ] **Step 6: Add `validate_blob` to the backend contract and enforce it in the receiver**

In `ai_credentials_helper/backends/__init__.py`, add to `Backend`:

```python
def validate_blob(self, data: object) -> None:
    """Reject parsed data that is not safe to write to this backend."""
    ...
```

In `ai_credentials_helper/credentials.py`, add `"validate_blob"` to `__all__`. Codex already implements this exact function name, so no Codex implementation change is needed.

In `ai_credentials_helper/cli.py`, replace the parse-only receive check with backend-specific validation while retaining the existing unchanged-store error:

```python
try:
    data = creds.parse_blob(content)
    creds.validate_blob(data)
except (ValueError, creds.CredentialsError):
    _err(
        "Error: decrypted payload is not a valid credential blob; "
        f"{_store_label()} left unchanged"
    )
    return 1
creds.write(content)
```

Update the module descriptions while these files are already being modified:

```python
# ai_credentials_helper/backends/__init__.py
"""Storage backends for supported AI agents.

Claude uses the macOS Keychain on macOS and a JSON credential file on Linux
and WSL. Codex uses a JSON credential file on every supported platform.
"""
```

```python
# ai_credentials_helper/credentials.py
"""Backend facade for AI-agent credential storage.

The default backend is Claude for compatibility. Each backend selects and
owns its platform-appropriate storage adapter.
"""
```

Replace the `tests/test_claude_backend.py` module docstring with:

```python
"""Unit tests for Claude's platform-native credential storage and OAuth behavior."""
```

- [ ] **Step 7: Run backend and facade tests**

```bash
.venv/bin/pytest tests/test_claude_backend.py tests/test_codex_backend.py tests/test_cli_agent.py -q
```

Expected: all tests pass, including unchanged macOS Keychain behavior and Codex validation.

- [ ] **Step 8: Commit validated Linux storage**

```bash
git add ai_credentials_helper/backends/claude.py ai_credentials_helper/backends/__init__.py ai_credentials_helper/credentials.py ai_credentials_helper/cli.py tests/test_claude_backend.py tests/test_cli_agent.py
git commit -m "feat: store Claude credentials on Linux"
```

### Task 6: Verify CLI labels and the cross-platform Claude representations

**Files:**

- Modify: `tests/test_cli_agent.py:192-201`
- Modify: `tests/test_claude_backend.py`
- Create: `tests/test_claude_linux_receive.py`

**Interfaces:**

- Consumes: Task 5's `AUTH_PATH`, normalization, and facade dispatch.
- Produces: regression coverage for Linux labels, both cross-platform representations, and a real Linux receive into `CLAUDE_CONFIG_DIR`.

- [ ] **Step 1: Add a real Linux Claude receive test**

Create `tests/test_claude_linux_receive.py`. The test launches the actual CLI receiver with an isolated config directory, sends an authenticated frame over localhost, and inspects the real file selected by `sys.platform == "linux"`:

```python
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
```

- [ ] **Step 2: Run the Linux receive test**

On macOS it should skip; the Ubuntu CI job added in Stage 1 must run and pass it:

```bash
.venv/bin/pytest tests/test_claude_linux_receive.py -q
```

- [ ] **Step 3: Make existing facade and Keychain-label tests platform-aware**

Replace the macOS-only constant assertion with:

```python
def test_credentials_facade_re_exposes_known_constants(restore_backend):
    from ai_credentials_helper.backends import claude

    assert creds.CLIENT_ID == "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    if sys.platform == "darwin":
        assert creds.KEYCHAIN_SERVICE == "Claude Code-credentials"
        assert claude.AUTH_PATH is None
    elif sys.platform == "linux":
        assert creds.KEYCHAIN_SERVICE is None
        assert claude.AUTH_PATH is not None
        assert claude.AUTH_PATH.name == ".credentials.json"
```

Update the existing Keychain-label test so it tests Keychain presentation explicitly on every host, rather than assuming the host is macOS:

```python
def test_store_label_uses_backend_specific_noun(restore_backend, monkeypatch):
    from ai_credentials_helper.backends import claude

    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", "Claude Code-credentials")
    monkeypatch.setattr(claude, "AUTH_PATH", None)
    creds.set_backend("claude")
    assert "keychain service" in cli._store_label()
    assert "'Claude Code-credentials'" in cli._store_label()

    creds.set_backend("codex")
    assert "auth file" in cli._store_label()
    assert "None" not in cli._store_label()
```

- [ ] **Step 4: Add a Linux Claude label test**

```python
def test_store_label_uses_linux_claude_auth_path(restore_backend, tmp_path, monkeypatch):
    from ai_credentials_helper.backends import claude

    auth_path = tmp_path / ".claude" / ".credentials.json"
    monkeypatch.setattr(claude, "KEYCHAIN_SERVICE", None)
    monkeypatch.setattr(claude, "AUTH_PATH", auth_path)
    creds.set_backend("claude")

    assert cli._store_label() == f"auth file {str(auth_path)!r}"
```

- [ ] **Step 5: Pin Linux-to-macOS JSON preservation**

Use the existing `fake_security` fixture to ensure a normalized Linux JSON payload remains valid when written to Keychain:

```python
def test_keychain_write_accepts_linux_json(fake_security):
    creds.write(FULL_JSON)
    (argv,) = fake_security["writes"]
    assert argv[argv.index("-w") + 1] == FULL_JSON
```

The reciprocal macOS-hex-to-Linux-JSON direction is pinned by `test_linux_write_normalizes_hex_keychain_blob` in Task 5.

- [ ] **Step 6: Run the representation and CLI tests**

```bash
.venv/bin/pytest tests/test_claude_backend.py tests/test_cli_agent.py tests/test_claude_linux_receive.py -q
```

Expected: all tests pass.

- [ ] **Step 7: Commit cross-platform regression coverage**

```bash
git add tests/test_claude_backend.py tests/test_cli_agent.py tests/test_claude_linux_receive.py
git commit -m "test: cover cross-platform Claude copies"
```

### Task 7: Document Claude copying and finish Stage 2

**Files:**

- Modify: `README.md:1-77`
- Modify: `pyproject.toml:1-5`
- Modify: `ai_credentials_helper/backends/codex.py:1-5`

**Interfaces:**

- Consumes: Tasks 4-6.
- Produces: exact receiver-first workflow and accurate storage/security documentation.

- [ ] **Step 1: Make package and backend metadata platform-neutral**

Change the project description to:

```toml
description = "Securely copy OAuth credentials between AI coding agents"
```

In `ai_credentials_helper/backends/codex.py`, replace the module docstring's storage-comparison paragraph with:

```text
Codex stores OAuth tokens in a plain JSON file on every supported platform.
Claude uses the macOS Keychain on macOS and a JSON credential file on Linux
and WSL.
```

- [ ] **Step 2: Document Claude storage on each supported platform**

Replace the introductory storage text with:

```markdown
`ai-credentials-helper` securely copies OAuth credentials used by AI coding agents between computers. It supports Claude Code credentials in the macOS Keychain or Linux/WSL `${CLAUDE_CONFIG_DIR:-~/.claude}/.credentials.json`, plus Codex CLI credentials in `~/.codex/auth.json`.
```

Add under Usage:

```markdown
Claude Code uses the macOS Keychain on macOS and `${CLAUDE_CONFIG_DIR:-~/.claude}/.credentials.json` on Linux and WSL. The helper selects the correct store automatically; continue to use `--agent claude` or omit `--agent`, since Claude is the default.
```

- [ ] **Step 3: Document every requested copy direction without duplicating commands**

Replace the encrypted-transfer lead-in with:

```markdown
Transfers use authenticated encryption over a one-shot TCP connection and work macOS ↔ Linux/WSL and Linux/WSL ↔ Linux/WSL for both Claude and Codex. Start the receiver first, then run the sender with the same `--agent` value and passphrase. Use `--agent claude` for Claude Code or `--agent codex` for Codex CLI.
```

Keep the existing receiver and sender examples, but state that omitting `--agent codex` selects Claude. Add:

```markdown
For Claude transfers from macOS to Linux/WSL, the receiver converts a hex-encoded Keychain blob to Claude Code's JSON credential-file format automatically. Linux/WSL writes use an atomic replacement and `0600` file permissions. A malformed or unauthenticated payload is rejected before replacement.
```

- [ ] **Step 4: Verify documentation and metadata**

```bash
.venv/bin/credentials-helper --help
rg -n "macOS-only|macOS Keychain|Linux|WSL|CLAUDE_CONFIG_DIR|0600|--agent" README.md pyproject.toml ai_credentials_helper/backends ai_credentials_helper/credentials.py
```

Expected: no package-level statement calls the Python helper macOS-only; platform-specific Keychain statements remain accurate.

- [ ] **Step 5: Run complete local verification**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
```

Expected: all tests and Ruff pass.

- [ ] **Step 6: Commit documentation**

```bash
git add README.md pyproject.toml ai_credentials_helper/backends/codex.py
git commit -m "docs: explain Claude copies on Linux and WSL"
```

- [ ] **Step 7: Complete the Stage 2 checkpoint**

Rerun the complete verification commands. Expected: Stage 2 is complete on `ct/linux-native-transfer`; do not push or open a pull request yet.

---

### Task 8: Guard the legacy Bash implementation

**Files:**

- Modify: `credentials-helper.sh:1-16`
- Create: `tests/test_legacy_shell.py`

**Interfaces:**

- Produces: a clear nonzero exit on Linux/WSL before `security`, `jq`, `xxd`, `curl`, or BSD `date` is invoked.
- Does not change the supported Python CLI or its encrypted wire format.

- [ ] **Step 1: Add a failing shell-guard test**

```python
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
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
.venv/bin/pytest tests/test_legacy_shell.py -q
```

Expected: failure because `credentials-helper.sh --help` currently exits successfully on the host instead of honoring the fake Linux `uname`.

- [ ] **Step 3: Add the guard immediately after strict mode**

```bash
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Error: credentials-helper.sh is macOS-only. Use the Python CLI on Linux or WSL: credentials-helper --help" >&2
  exit 1
fi
```

Keep the shell script explicitly Claude-only. Do not port its plaintext transfer implementation or imply wire compatibility with the authenticated Python CLI.

- [ ] **Step 4: Run the shell test**

```bash
.venv/bin/pytest tests/test_legacy_shell.py -q
```

Expected: pass.

- [ ] **Step 5: Commit the guard**

```bash
git add credentials-helper.sh tests/test_legacy_shell.py
git commit -m "fix: reject Linux in legacy shell helper"
```

### Task 9: Correct stale crypto documentation and finish the branch

**Files:**

- Modify: `ai_credentials_helper/transfer_crypto.py:1-10`
- Modify: `tests/test_transfer_crypto.py:1-22`
- Modify: `tests/test_transfer_crypto.py:138-145`
- Modify: `README.md`

**Interfaces:**

- Produces: documentation that distinguishes the authenticated Python CLI from the plaintext legacy shell script.

- [ ] **Step 1: Replace the stale module introduction**

Use:

```python
"""Authenticated encryption for credential transfer (``--send`` / ``--receive``).

The Python CLI owns this wire format. Encryption and authentication are
implemented with ``cryptography`` plus Python's standard library and work the
same way on macOS, Linux, and WSL. The legacy ``credentials-helper.sh`` script
is not wire-compatible and is outside this module's contract.

Construction: **AES-256-CBC + HMAC-SHA256, encrypt-then-MAC.**
"""
```

Retain the existing key-schedule and wire-format documentation below it.

- [ ] **Step 2: Correct the OpenSSL interoperability test descriptions**

Replace the `tests/test_transfer_crypto.py` module docstring with:

```python
"""Unit and OpenSSL interoperability tests for credential-transfer crypto.

The interoperability tests exercise AES-256-CBC through the local ``openssl``
binary while Python owns the authenticated frame construction. They verify the
cryptographic primitive boundary without modeling or claiming compatibility
with the legacy ``credentials-helper.sh`` script.
"""
```

Replace the KDF comment with:

```python
# Known-answer vector: PBKDF2-HMAC-SHA256(PASSPHRASE, salt, 600000, dklen=80).
# Locks the derivation so independent crypto implementations cannot silently drift.
```

Rename the interop section comment to `Interop with the local openssl AES primitive`, change `_openssl_frame`'s docstring to `Produce an authenticated frame using openssl for the AES step.`, and remove the comment that says the helper mirrors `credentials-helper.sh`.

- [ ] **Step 3: Add the legacy script note to README**

```markdown
`credentials-helper.sh` is a legacy, macOS-only Claude implementation. It is not wire-compatible with the authenticated Python transfer protocol. Use the installed `credentials-helper` Python CLI for all cross-computer copying.
```

- [ ] **Step 4: Run documentation consistency checks**

```bash
rg -n "credentials-helper\.sh|claude-credentials\.sh|wire.compat|openssl|macOS-only" README.md ai_credentials_helper/transfer_crypto.py ai_credentials_helper/backends ai_credentials_helper/credentials.py tests/test_transfer_crypto.py credentials-helper.sh
```

Expected: no claim says the Python crypto format is shared with the legacy shell script.

- [ ] **Step 5: Run complete local verification**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
```

Expected: all tests and Ruff pass.

- [ ] **Step 6: Commit documentation**

```bash
git add ai_credentials_helper/transfer_crypto.py tests/test_transfer_crypto.py README.md
git commit -m "docs: clarify legacy transfer limitations"
```

- [ ] **Step 7: Run pre-push review and open the pull request**

Load `pre-push-check`, follow its local Fresh Eyes process, fix valid findings, and rerun the complete verification commands. Push `ct/linux-native-transfer`, load `concise-pr`, create one pull request against the default branch, and load `pre-push-check` again for its post-PR Fresh Eyes watch.

---

## Final Branch Acceptance

After all three stages are complete on `ct/linux-native-transfer` and before merging its pull request:

- [ ] Run the complete suite and lint:

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
```

- [ ] Confirm GitHub Actions passes on both `macos-latest` and `ubuntu-latest`.
- [ ] On WSL, set `CLAUDE_CONFIG_DIR` to a temporary directory, complete a localhost Claude send/receive, and confirm `.credentials.json` is JSON with mode `0600`.
- [ ] On separate reachable machines, manually smoke-test one Claude macOS → Linux/WSL copy and one Linux/WSL → macOS copy using synthetic or deliberately replaceable credentials.
- [ ] Confirm both directions use the same passphrase and reject a wrong passphrase without changing the receiver's original credential bytes.
- [ ] Confirm Codex still round-trips through `~/.codex/auth.json` and preserves mode `0600`.
- [ ] Confirm `git status --short` contains no credential files, temporary auth files, or accidental changes to the user's untracked `uv.lock`.

## Plan Self-Review

- Every requested platform direction is covered by the single implementation branch and final acceptance matrix.
- Linux/WSL Claude storage follows Anthropic's documented default and `CLAUDE_CONFIG_DIR` override.
- macOS hex-to-Linux JSON normalization is an explicit implementation and regression test, not an assumption.
- Unsupported native Windows does not silently use Linux paths.
- Native Linux transport is exercised on an actual Linux CI runner; Darwin preserves the Apple `nc` workaround.
- Receiver validation precedes storage dispatch without changing direct macOS Keychain import semantics.
- Validation and simulated `os.replace` failure tests pin the unchanged-destination guarantee and temporary-file cleanup.
- The legacy shell script remains outside the supported encrypted transfer path and fails clearly on Linux/WSL.
- Production and test documentation describe OpenSSL interoperability without claiming wire compatibility with the legacy shell script.
- No placeholder steps, unspecified interfaces, or dependency additions remain.
