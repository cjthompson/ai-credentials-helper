"""Strict plaintext messages for the encrypted credential request protocol."""

import json
import re
import secrets

from ai_credentials_helper import transfer_envelope

AGENTS = ("claude", "codex")
ERRORS = ("credentials-unavailable", "backend-failure")
_NONCE = re.compile(r"[0-9a-f]{64}\Z")


class ProtocolError(ValueError):
    """A request or response is invalid; messages never contain peer data."""


def new_nonce() -> str:
    return secrets.token_hex(32)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate protocol field")
        result[key] = value
    return result


def _parse(text: str, kind: str) -> dict:
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as exc:
        raise ProtocolError("invalid protocol document") from exc
    if not isinstance(data, dict):
        raise ProtocolError("invalid protocol document")
    if data.get("type") != kind or type(data.get("version")) is not int or data["version"] != 1:
        raise ProtocolError("unsupported protocol type or version")
    if data.get("agent") not in AGENTS:
        raise ProtocolError("unsupported requested agent")
    nonce = data.get("nonce")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ProtocolError("invalid request nonce")
    return data


def request(agent: str, nonce: str) -> str:
    text = json.dumps(dict(type="credential-request", version=1, agent=agent, nonce=nonce))
    read_request(text)
    return text


def read_request(text: str) -> tuple[str, str]:
    data = _parse(text, "credential-request")
    if set(data) != {"type", "version", "agent", "nonce"}:
        raise ProtocolError("invalid request fields")
    return data["agent"], data["nonce"]


def response(agent: str, nonce: str, *, payload: str | None = None,
             error: str | None = None) -> str:
    data = dict(type="credential-response", version=1, agent=agent, nonce=nonce)
    if error is not None:
        if error not in ERRORS or payload is not None:
            raise ProtocolError("invalid response error")
        data.update(status="error", error=error)
    else:
        if not isinstance(payload, str) or not payload:
            raise ProtocolError("empty credential response")
        data.update(status="ok", envelope=transfer_envelope.wrap(agent, payload))
    return json.dumps(data)


def read_response(text: str, agent: str, nonce: str) -> tuple[str | None, str | None]:
    data = _parse(text, "credential-response")
    if data["agent"] != agent or data["nonce"] != nonce:
        raise ProtocolError("response does not match the outstanding request")
    fields = {"type", "version", "agent", "nonce", "status"}
    if data.get("status") == "error":
        if set(data) != fields | {"error"} or data["error"] not in ERRORS:
            raise ProtocolError("invalid response error")
        return None, data["error"]
    if data.get("status") != "ok" or set(data) != fields | {"envelope"}:
        raise ProtocolError("invalid response status or fields")
    if not isinstance(data["envelope"], str):
        raise ProtocolError("invalid response envelope")
    try:
        wire_agent, payload = transfer_envelope.unwrap(data["envelope"])
    except transfer_envelope.EnvelopeError as exc:
        raise ProtocolError("invalid response envelope") from exc
    if wire_agent != agent:
        raise ProtocolError("response envelope agent mismatch")
    return payload, None
