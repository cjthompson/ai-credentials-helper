"""Request binding, strict schemas, and one-shot protocol separation."""

import json

import pytest

from ai_credentials_helper import request_protocol as p
from ai_credentials_helper import transfer_envelope

NONCE = "a" * 64


def test_request_and_success_response_round_trip():
    assert p.read_request(p.request("claude", NONCE)) == ("claude", NONCE)
    assert p.read_response(p.response("claude", NONCE, payload="blob"), "claude", NONCE) == (
        "blob", None
    )
    assert len(p.new_nonce()) == 64
    assert p.new_nonce() != p.new_nonce()


def test_error_response_round_trip():
    text = p.response("codex", NONCE, error="credentials-unavailable")
    assert p.read_response(text, "codex", NONCE) == (None, "credentials-unavailable")


@pytest.mark.parametrize("changes", [
    {"version": True}, {"version": 2}, {"type": "credential-response"},
    {"agent": "all"}, {"agent": []}, {"nonce": "a"}, {"nonce": "A" * 64},
    {"nonce": None}, {"extra": 1},
])
def test_invalid_requests(changes):
    data = json.loads(p.request("claude", NONCE)) | changes
    with pytest.raises(p.ProtocolError):
        p.read_request(json.dumps(data))


@pytest.mark.parametrize("text", ['[]', 'null', '{', '{}',
    '{"type":"credential-request","version":1,"agent":"claude",'
    '"nonce":"' + NONCE + '","agent":"codex"}',
])
def test_malformed_requests(text):
    with pytest.raises(p.ProtocolError):
        p.read_request(text)


@pytest.mark.parametrize("changes", [
    {"nonce": "b" * 64}, {"agent": "codex"}, {"status": "unknown"},
    {"envelope": 12}, {"error": "backend-failure"}, {"version": 2},
    {"envelope": transfer_envelope.wrap("codex", "blob")},
])
def test_replayed_or_invalid_response(changes):
    data = json.loads(p.response("claude", NONCE, payload="blob")) | changes
    with pytest.raises(p.ProtocolError):
        p.read_response(json.dumps(data), "claude", NONCE)


def test_reject_unknown_error_and_duplicate_response_fields():
    data = json.loads(p.response("claude", NONCE, error="backend-failure"))
    data["error"] = "untrusted terminal bytes"
    with pytest.raises(p.ProtocolError):
        p.read_response(json.dumps(data), "claude", NONCE)
    text = p.response("claude", NONCE, payload="blob")
    with pytest.raises(p.ProtocolError):
        p.read_response(text[:-1] + ',"status":"ok"}', "claude", NONCE)


def test_one_shot_envelope_rejects_new_protocol():
    for text in (p.request("claude", NONCE), p.response("claude", NONCE, payload="blob")):
        with pytest.raises(transfer_envelope.EnvelopeError):
            transfer_envelope.unwrap(text)
