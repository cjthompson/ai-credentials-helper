"""Unit tests for ai_credentials_helper.transfer_envelope.

Pure-function tests -- no sockets, no crypto beyond the HMAC primitive
already exercised by test_transfer_crypto.py.
"""

import pytest

from ai_credentials_helper import transfer_envelope as te

MAC_KEY = b"\x01" * 32
SALT = b"\x02" * 16
OTHER_SALT = b"\x03" * 16


def test_wrap_unwrap_round_trip():
    agent, payload = te.unwrap(te.wrap("codex", '{"tokens":{}}'))
    assert agent == "codex"
    assert payload == '{"tokens":{}}'


def test_wrap_unwrap_round_trip_multiline_payload():
    payload = '{\n  "tokens": {\n    "access_token": "a.b.c"\n  }\n}'
    agent, unwrapped = te.unwrap(te.wrap("codex", payload))
    assert agent == "codex"
    assert unwrapped == payload


def test_wrap_unwrap_round_trip_hex_claude_payload():
    payload = "7b22636c61756465416933223a317d"  # hex-looking, non-JSON-prefixed
    agent, unwrapped = te.unwrap(te.wrap("claude", payload))
    assert agent == "claude"
    assert unwrapped == payload


def test_payload_preserved_byte_for_byte():
    payload = "line one\nline two\n\ntrailing blank above"
    _agent, unwrapped = te.unwrap(te.wrap("claude", payload))
    assert unwrapped == payload


def test_unwrap_missing_magic_rejected():
    with pytest.raises(te.EnvelopeError, match="older version"):
        te.unwrap('{"claudeAiOauth":{}}')


def test_unwrap_unknown_major_version_rejected():
    with pytest.raises(te.EnvelopeError, match="unsupported envelope version"):
        te.unwrap("ai-credentials-helper/2 agent=claude\n{}")


def test_unwrap_unknown_header_keys_ignored():
    agent, payload = te.unwrap("ai-credentials-helper/1 oauth-only=true agent=codex\npayload")
    assert agent == "codex"
    assert payload == "payload"


@pytest.mark.parametrize(
    "header",
    [
        "ai-credentials-helper/1\npayload",                          # missing agent
        "ai-credentials-helper/1 agent=\npayload",                   # blank agent
        "ai-credentials-helper/1 agent=" + "a" * 40 + "\npayload",   # oversized
        "ai-credentials-helper/1 agent=Claude\npayload",             # illegal uppercase
        "ai-credentials-helper/1 agent=../etc\npayload",             # illegal characters
        "ai-credentials-helper/1 agent=bogus-agent\npayload",        # not a registered backend
    ],
)
def test_unwrap_bad_agent_rejected(header):
    with pytest.raises(te.EnvelopeError):
        te.unwrap(header)


def test_unwrap_empty_payload_rejected():
    with pytest.raises(te.EnvelopeError, match="empty"):
        te.unwrap("ai-credentials-helper/1 agent=claude\n")


def test_unwrap_no_newline_at_all_rejected_as_empty_payload():
    with pytest.raises(te.EnvelopeError, match="empty"):
        te.unwrap("ai-credentials-helper/1 agent=claude")


def test_wrap_rejects_invalid_agent_name():
    with pytest.raises(te.EnvelopeError):
        te.wrap("not valid", "payload")


def test_ack_round_trip():
    line = te.ack(MAC_KEY, SALT, "ok", "")
    status, detail = te.read_ack(line, MAC_KEY, SALT)
    assert (status, detail) == ("ok", "")


def test_ack_round_trip_with_detail_text():
    line = te.ack(MAC_KEY, SALT, "agent-mismatch", "sender=codex receiver=claude")
    status, detail = te.read_ack(line, MAC_KEY, SALT)
    assert status == "agent-mismatch"
    assert detail == "sender=codex receiver=claude"


def test_ack_flipped_tag_rejected():
    line = te.ack(MAC_KEY, SALT, "ok", "")
    body, tag = line.rsplit(" ", 1)
    flipped_tag = ("0" if tag[0] != "0" else "1") + tag[1:]
    with pytest.raises(te.EnvelopeError):
        te.read_ack(f"{body} {flipped_tag}", MAC_KEY, SALT)


def test_ack_under_different_salt_rejected():
    line = te.ack(MAC_KEY, SALT, "ok", "")
    with pytest.raises(te.EnvelopeError):
        te.read_ack(line, MAC_KEY, OTHER_SALT)


def test_ack_rejects_illegal_detail_charset():
    with pytest.raises(te.EnvelopeError):
        te.ack(MAC_KEY, SALT, "ok", "bad\x01char")


def test_ack_rejects_oversized_detail():
    with pytest.raises(te.EnvelopeError):
        te.ack(MAC_KEY, SALT, "ok", "x" * 121)


def test_ack_rejects_invalid_status():
    with pytest.raises(te.EnvelopeError):
        te.ack(MAC_KEY, SALT, "bogus", "")


def test_read_ack_rejects_malformed_line():
    with pytest.raises(te.EnvelopeError):
        te.read_ack("not-even-close-to-a-line", MAC_KEY, SALT)
