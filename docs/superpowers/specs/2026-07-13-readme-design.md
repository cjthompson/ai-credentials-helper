# README Design

## Goal

Add a concise, user-facing `README.md` that lets a new user understand and install the credential helper, use it with Claude Code or Codex CLI, transfer credentials safely, and run the test suite.

## Audience

People using the repository directly on macOS. Readers should not need knowledge of the internal backend architecture.

## Structure

The README will contain these short sections:

1. Project overview and supported credential stores.
2. Requirements and installation with `install.py`.
3. Common commands for Claude and Codex.
4. Encrypted sender/receiver examples.
5. Security notes explaining runtime credential access and temporary test credentials.
6. Development setup and test/lint commands.

## Constraints

- Keep the document concise and task-oriented.
- Use commands supported by the current CLI.
- State that Claude is the default backend and Codex requires `--agent codex`.
- Explain that `--send` and `--receive` require the same passphrase.
- Do not include real credentials, personal information, badges, screenshots, or speculative features.
- Avoid duplicating detailed implementation documentation.

## Validation

- Compare every documented option with `credentials-helper --help`.
- Check Markdown structure and links manually.
- Run the existing test and lint commands shown in the README.
