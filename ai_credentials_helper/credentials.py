"""Backend facade for AI-agent credential storage.

The default backend is Claude for compatibility. Each backend selects and
owns its platform-appropriate storage adapter.
"""

from ai_credentials_helper.backends import claude, get_backend

# Public alias for callers that want to catch the same error regardless of
# backend — both backends define their own ``CredentialsError``, but they
# share this name and semantics, so we re-export claude's.
CredentialsError = claude.CredentialsError

_DEFAULT_BACKEND = "claude"
_backend = claude


def set_backend(name: str) -> None:
    """Switch the active backend to ``name`` (``claude`` or ``codex``).

    Subsequent module-level calls (``read_raw``, ``write``, ``refresh_tokens``,
    etc.) dispatch to the chosen backend. Raises ``ValueError`` if ``name`` is
    not a registered backend.

    Always resets backend-specific flags (e.g. ``codex.FORCE_WRITE``) so a
    prior ``--force`` invocation can't leak into a fresh one.
    """
    global _backend
    _backend = get_backend(name)
    # Reset any backend-level flags that affect write semantics. New backends
    # should reset their own here too (or live on the facade as constants).
    if hasattr(_backend, "FORCE_WRITE"):
        _backend.FORCE_WRITE = False


def backend_name() -> str:
    """Return the active backend's name (``claude`` / ``codex``)."""
    return _backend.name  # type: ignore[no-any-return]


def backend_label() -> str:
    """Return the active backend's human label for error messages."""
    return _backend.label  # type: ignore[no-any-return]


# Dynamic dispatch — every name in __all__ resolves to the active backend.
# The implementation is per-call so callers don't need to remember which
# backend is active; the facade handles it transparently.
__all__ = [  # noqa: F822 - names dispatched dynamically via __getattr__
    "CredentialsError",
    "KEYCHAIN_SERVICE",
    "TOKEN_URL",
    "CLIENT_ID",
    "set_backend",
    "backend_name",
    "backend_label",
    "read_raw",
    "read_json",
    "write",
    "validate_blob",
    "find_account",
    "tokens_from_data",
    "extract_oauth_tokens",
    "refresh_tokens",
    "oauth_only_json",
    "parse_blob",
    "validate_blob",
]


def __getattr__(name: str):
    """Module-level __getattr__ dispatches unknown names to the active backend.

    This is how ``creds.read_raw()`` resolves to whichever backend's
    ``read_raw`` was set by the most recent ``set_backend`` call. Names in
    ``__all__`` are documented above; everything else raises ``AttributeError``
    so typos surface immediately rather than silently dispatching.
    """
    if name in __all__ and name not in globals():
        return getattr(_backend, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
