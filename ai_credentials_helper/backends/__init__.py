"""Storage backends for different AI agents (claude, codex, ...).

Each backend owns its own storage adapter — macOS Keychain for claude, JSON
file for codex, etc. The ``Backend`` protocol is the contract the CLI and
``credentials`` facade dispatch against. New agents add one file in this
directory and one entry in ``BACKENDS`` — nothing else changes.
"""

from typing import Protocol

from ai_credentials_helper.backends import claude, codex


class Backend(Protocol):
    """Storage adapter for one AI agent's OAuth credentials.

    All read methods raise :class:`CredentialsError` (re-exported from
    ``ai_credentials_helper.backends.claude``) when the backing store is
    missing or unreadable. ``write`` is idempotent — replacing an existing
    entry, not appending.
    """

    name: str
    label: str  # human-readable, for error messages and CLI help

    def read_raw(self) -> str:
        """Return the verbatim backing-store blob (one trailing newline stripped)."""
        ...

    def read_json(self) -> dict:
        """Return the parsed JSON form of :meth:`read_raw`."""
        ...

    def write(self, content: str) -> None:
        """Replace the existing entry with ``content`` verbatim."""
        ...

    def find_account(self) -> str | None:
        """Return an account-like identifier (keychain acct, account_id, ...) or None."""
        ...

    def tokens_from_data(self, data: dict) -> tuple[str, str, float] | None:
        """Extract ``(access_token, refresh_token, expires_at_epoch)`` from parsed data."""
        ...

    def extract_oauth_tokens(self) -> tuple[str, str, float] | None:
        """Return ``(access_token, refresh_token, expires_at_epoch)`` or None."""
        ...

    def refresh_tokens(self, refresh_token: str) -> tuple[str, str, int] | None:
        """Exchange ``refresh_token`` for a new ``(access, refresh, expires_in)`` or None."""
        ...

    def oauth_only_json(self) -> str:
        """Return a compact JSON string with only the agent-portable token subset."""
        ...


BACKENDS: dict[str, Backend] = {
    "claude": claude,  # type: ignore[dict-item]
    "codex": codex,  # type: ignore[dict-item]
}


def get_backend(name: str) -> Backend:
    """Return the backend registered under ``name``; raise ValueError for unknowns.

    Backends are imported as modules — instances are stateless and cheap — so we
    expose the module itself; ``Backend`` is a Protocol describing that module's
    call surface. Module-level ``read_raw()`` etc. are looked up dynamically by
    the ``credentials`` facade.
    """
    if name not in BACKENDS:
        raise ValueError(
            f"unknown agent '{name}'; supported: {', '.join(sorted(BACKENDS))}"
        )
    return BACKENDS[name]  # type: ignore[return-value]
