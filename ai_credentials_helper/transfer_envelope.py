"""Agent-identity envelope for credential transfers (``--send`` / ``--receive``).

Layered *inside* the encrypted frame that ``ai_credentials_helper.transfer_crypto``
produces/consumes: this module only deals with plaintext framing, so it has no
sockets and no crypto primitives of its own and is unit-testable in isolation.
See ``docs/superpowers/specs/2026-07-29-agent-identity-transfer-design.md``.

Envelope format -- one header line, then the payload verbatim, byte-for-byte
(a pretty-printed codex ``auth.json`` is multi-line, so "first line is the
header, everything after the first newline is payload" is required, not a
line-oriented format)::

    ai-credentials-helper/1 agent=<name>\n<payload bytes, verbatim>

``MAGIC`` is ``"ai-credentials-helper/1"`` -- the trailing ``1`` is the
envelope's major version. Header tokens after the magic are whitespace-
separated ``key=value`` pairs; ``agent`` is required, unknown keys are
ignored (forward compatible), and an unrecognized major version is rejected
with its own message (distinct from "no envelope at all", which means an
old, unlabelled sender).

ACK format -- one line, receiver -> sender, authenticated by an HMAC tag the
caller (``ai_credentials_helper.cli``, using key material from
``transfer_crypto.mac_key_for_frame``/``frame_salt``) supplies::

    ai-credentials-helper/1 status=<ok|agent-mismatch|rejected> detail=<text> <hex-tag>

The three ACK header fields are fixed-order (unlike the wrap/unwrap
envelope) so that ``detail`` -- which may itself contain spaces, per
``_DETAIL_RE`` -- can be parsed unambiguously: everything between
``detail=`` and the final space-delimited token (the tag) belongs to
``detail``.
"""

import hashlib
import hmac
import re

MAGIC = "ai-credentials-helper/1"
_MAGIC_PREFIX = "ai-credentials-helper/"

_AGENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_DETAIL_RE = re.compile(r"^[A-Za-z0-9 _.:=-]{0,120}$")
_ACK_STATUSES = ("ok", "agent-mismatch", "rejected")


class EnvelopeError(Exception):
    """Envelope or ACK framing/validation failed."""


def _validate_agent_shape(agent: str) -> None:
    if not _AGENT_RE.match(agent):
        raise EnvelopeError(f"invalid agent name for envelope: {agent!r}")


def wrap(agent: str, payload: str) -> str:
    """Prefix ``payload`` with a header naming ``agent``; return the plaintext to encrypt.

    ``agent`` is validated by shape before being interpolated into the
    header (it should already be a real backend name from
    ``creds.backend_name()``, but this keeps wrap/unwrap symmetric and
    catches programmer error early rather than producing an envelope
    ``unwrap`` would reject anyway).
    """
    _validate_agent_shape(agent)
    return f"{MAGIC} agent={agent}\n{payload}"


def unwrap(text: str) -> tuple[str, str]:
    """Split enveloped ``text`` into ``(agent, payload)``; raise EnvelopeError on any defect.

    Order of checks: magic prefix present (else: "no agent label" -- an
    unupgraded sender) -> exact magic/version match (else: "unsupported
    envelope version") -> ``agent`` field present, shape-valid, and a
    registered backend name -> payload non-empty.
    """
    header, sep, payload = text.partition("\n")
    tokens = header.split()
    if not tokens or not tokens[0].startswith(_MAGIC_PREFIX):
        raise EnvelopeError(
            "payload has no agent label; the sender is running an older "
            "version — upgrade both ends"
        )
    if tokens[0] != MAGIC:
        raise EnvelopeError(
            f"unsupported envelope version {tokens[0]!r}; expected {MAGIC!r}"
        )
    fields: dict[str, str] = {}
    for tok in tokens[1:]:
        key, found_eq, value = tok.partition("=")
        if found_eq:
            fields[key] = value
    agent = fields.get("agent")
    if not agent:
        raise EnvelopeError("envelope header missing required 'agent' field")
    _validate_agent_shape(agent)
    # Deferred import: this keeps transfer_envelope's pure-framing logic from
    # depending on the storage backends at module-import time.
    from ai_credentials_helper.backends import get_backend

    try:
        get_backend(agent)
    except ValueError as e:
        raise EnvelopeError(str(e)) from e
    if not sep or not payload:
        raise EnvelopeError("envelope payload is empty")
    return agent, payload


def ack(mac_key: bytes, salt: bytes, status: str, detail: str = "") -> str:
    """Build a full authenticated ACK line: ``header + " " + hex-tag``.

    ``mac_key``/``salt`` are the ones tied to the transfer's own frame
    (``transfer_crypto.mac_key_for_frame`` / ``frame_salt``) -- binding the
    tag to that transfer's random salt is what makes a captured ACK from an
    earlier transfer fail to verify against a new one.
    """
    if status not in _ACK_STATUSES:
        raise EnvelopeError(f"invalid ack status: {status!r}")
    if not _DETAIL_RE.match(detail):
        raise EnvelopeError(f"invalid ack detail: {detail!r}")
    body = f"{MAGIC} status={status} detail={detail}"
    tag = hmac.new(
        mac_key, b"ack\x00" + salt + b"\x00" + body.encode(), hashlib.sha256
    ).hexdigest()
    return f"{body} {tag}"


def read_ack(line: str, mac_key: bytes, salt: bytes) -> tuple[str, str]:
    """Verify and parse an ACK ``line``; raise EnvelopeError on any failure.

    The tag is checked with ``hmac.compare_digest`` (constant-time) before
    anything in ``detail`` is trusted for display or logic. Returns
    ``(status, detail)``.
    """
    line = line.strip()
    head_and_tag = line.rsplit(" ", 1)
    if len(head_and_tag) != 2:
        raise EnvelopeError("malformed ack line")
    body, tag_hex = head_and_tag
    tag_hex = tag_hex.lower()
    if len(tag_hex) != 64 or not all(c in "0123456789abcdef" for c in tag_hex):
        raise EnvelopeError("malformed ack tag")
    expected = hmac.new(
        mac_key, b"ack\x00" + salt + b"\x00" + body.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, tag_hex):
        raise EnvelopeError("ack authentication failed")
    parts = body.split(" ", 2)
    if len(parts) != 3:
        raise EnvelopeError("malformed ack line")
    magic_tok, status_tok, detail_tok = parts
    if magic_tok != MAGIC:
        raise EnvelopeError(f"unsupported ack version {magic_tok!r}; expected {MAGIC!r}")
    if not status_tok.startswith("status="):
        raise EnvelopeError("malformed ack line: missing status field")
    if not detail_tok.startswith("detail="):
        raise EnvelopeError("malformed ack line: missing detail field")
    status = status_tok[len("status="):]
    detail = detail_tok[len("detail="):]
    if status not in _ACK_STATUSES:
        raise EnvelopeError(f"ack has invalid status: {status!r}")
    if not _DETAIL_RE.match(detail):
        raise EnvelopeError("ack detail failed charset validation")
    return status, detail
