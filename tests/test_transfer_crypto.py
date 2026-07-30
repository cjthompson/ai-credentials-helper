"""Unit and OpenSSL interoperability tests for credential-transfer crypto.

The interoperability tests exercise AES-256-CBC through the local ``openssl``
binary while Python owns the authenticated frame construction. They verify the
cryptographic primitive boundary without modeling or claiming compatibility
with the legacy ``credentials-helper.sh`` script.
"""

import base64
import hashlib
import hmac
import subprocess

import pytest

from ai_credentials_helper import transfer_crypto as tc

PASSPHRASE = "correct horse battery staple"
PLAINTEXT = '{"claudeAiOauth":{"accessToken":"abc","refreshToken":"def"},"mcpOAuth":{"x":1}}'

# Known-answer vector: PBKDF2-HMAC-SHA256(PASSPHRASE, salt, 600000, dklen=80).
# Locks the derivation so independent crypto implementations cannot silently drift.
KDF_SALT_HEX = "00112233445566778899aabbccddeeff"
KDF_MATERIAL_HEX = (
    "7c0123695eb46911838d4c16fa259d7280c59060c6031130b8269b624faacd02"
    "4716eebebfd5ce3877cdda8f18760233fab78d93b320fa43bfe50eb9b61ce3cf"
    "6796f247244c01ac157121190c5e31ca"
)


def test_kdf_known_answer_vector():
    salt = bytes.fromhex(KDF_SALT_HEX)
    enc_key, iv, mac_key = tc._derive(PASSPHRASE, salt)
    assert (enc_key + iv + mac_key).hex() == KDF_MATERIAL_HEX
    assert len(enc_key) == 32 and len(iv) == 16 and len(mac_key) == 32


def test_round_trip():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    assert tc.decrypt(frame, PASSPHRASE) == PLAINTEXT


def test_frame_is_two_text_lines():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    lines = frame.splitlines()
    assert len(lines) == 2
    base64.b64decode(lines[0], validate=True)  # line 1 is valid base64
    assert len(lines[1]) == 64 and int(lines[1], 16) >= 0  # line 2 is a sha256 hex tag


def test_distinct_salt_per_encrypt():
    # Random salt → different ciphertext for the same input each time.
    assert tc.encrypt(PLAINTEXT, PASSPHRASE) != tc.encrypt(PLAINTEXT, PASSPHRASE)


def test_wrong_passphrase_rejected():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    with pytest.raises(tc.DecryptionError, match="authentication failed"):
        tc.decrypt(frame, "wrong passphrase")


def test_tampered_ciphertext_rejected():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    b64, tag = frame.splitlines()
    blob = bytearray(base64.b64decode(b64))
    blob[-1] ^= 0x01  # flip a ciphertext bit
    tampered = f"{base64.b64encode(bytes(blob)).decode()}\n{tag}\n"
    with pytest.raises(tc.DecryptionError, match="authentication failed"):
        tc.decrypt(tampered, PASSPHRASE)


def test_tampered_tag_rejected():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    b64, tag = frame.splitlines()
    flipped = ("0" if tag[0] != "0" else "1") + tag[1:]
    with pytest.raises(tc.DecryptionError, match="authentication failed"):
        tc.decrypt(f"{b64}\n{flipped}\n", PASSPHRASE)


@pytest.mark.parametrize("bad", ["", "onlyoneline", "not!base64!\nabcd", "\n\n"])
def test_malformed_frame_rejected(bad):
    with pytest.raises(tc.DecryptionError):
        tc.decrypt(bad, PASSPHRASE)


def test_extra_lines_rejected():
    # The wire format is exactly two lines; a third line must be rejected, not ignored.
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    with pytest.raises(tc.DecryptionError, match="malformed"):
        tc.decrypt(frame.rstrip("\n") + "\nextra-line\n", PASSPHRASE)


@pytest.mark.parametrize("bad_tag", ["z" * 64, "abc", "a" * 63, "a" * 65])
def test_malformed_tag_shape_rejected(bad_tag):
    b64 = tc.encrypt(PLAINTEXT, PASSPHRASE).splitlines()[0]
    with pytest.raises(tc.DecryptionError, match="malformed"):
        tc.decrypt(f"{b64}\n{bad_tag}\n", PASSPHRASE)


def _authenticated_frame(passphrase: str, salt: bytes, ciphertext: bytes) -> str:
    """Build a frame with a VALID HMAC over arbitrary ``ciphertext`` bytes.

    Simulates a buggy/mismatched peer that shares the passphrase (so the tag
    verifies) yet emits a payload Python cannot actually decrypt. Such a frame
    passes the HMAC gate and reaches the decrypt path.
    """
    _enc_key, _iv, mac_key = tc._derive(passphrase, salt)
    blob = salt + ciphertext
    tag = hmac.new(mac_key, blob, hashlib.sha256).hexdigest()
    return f"{base64.b64encode(blob).decode()}\n{tag}\n"


def test_authenticated_frame_with_bad_cipher_length_rejected():
    # Valid HMAC, but the ciphertext is not a multiple of the AES block size —
    # the cipher raises ValueError, which must surface as DecryptionError.
    frame = _authenticated_frame(PASSPHRASE, bytes.fromhex(KDF_SALT_HEX), b"short")
    with pytest.raises(tc.DecryptionError):
        tc.decrypt(frame, PASSPHRASE)


def test_authenticated_frame_with_non_utf8_plaintext_rejected():
    # Valid HMAC and valid PKCS7, but the plaintext is not UTF-8 — the final
    # .decode() raises UnicodeDecodeError, which must surface as DecryptionError.
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    salt = bytes.fromhex(KDF_SALT_HEX)
    enc_key, iv, _mac_key = tc._derive(PASSPHRASE, salt)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(b"\xff\xfe\xfd\xfc") + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    frame = _authenticated_frame(PASSPHRASE, salt, ciphertext)
    with pytest.raises(tc.DecryptionError):
        tc.decrypt(frame, PASSPHRASE)


# ── Interop with the local openssl AES primitive ───────────────────────────────


def _openssl_frame(plaintext: str, passphrase: str, salt: bytes) -> str:
    """Produce an authenticated frame using openssl for the AES step."""
    material = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, tc.PBKDF2_ITERATIONS, 80)
    enc_key, iv, mac_key = material[0:32], material[32:48], material[48:80]
    ciphertext = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-K", enc_key.hex(), "-iv", iv.hex(), "-nosalt"],
        input=plaintext.encode(),
        capture_output=True,
        check=True,
    ).stdout
    blob = salt + ciphertext
    tag = hmac.new(mac_key, blob, hashlib.sha256).hexdigest()
    return f"{base64.b64encode(blob).decode()}\n{tag}\n"


def test_interop_openssl_encrypt_python_decrypt():
    frame = _openssl_frame(PLAINTEXT, PASSPHRASE, salt=bytes.fromhex(KDF_SALT_HEX))
    assert tc.decrypt(frame, PASSPHRASE) == PLAINTEXT


def test_interop_python_encrypt_openssl_decrypt():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    b64, _tag = frame.splitlines()
    blob = base64.b64decode(b64)
    salt, ciphertext = blob[: tc.SALT_LEN], blob[tc.SALT_LEN :]
    material = hashlib.pbkdf2_hmac("sha256", PASSPHRASE.encode(), salt, tc.PBKDF2_ITERATIONS, 80)
    enc_key, iv = material[0:32], material[32:48]
    recovered = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", enc_key.hex(), "-iv", iv.hex(), "-nosalt"],
        input=ciphertext,
        capture_output=True,
        check=True,
    ).stdout
    assert recovered.decode() == PLAINTEXT


def test_frame_salt_matches_derive_salt():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    b64 = frame.splitlines()[0]
    blob = base64.b64decode(b64)
    assert tc.frame_salt(frame) == blob[: tc.SALT_LEN]


def test_mac_key_for_frame_matches_derive():
    frame = tc.encrypt(PLAINTEXT, PASSPHRASE)
    salt = tc.frame_salt(frame)
    _enc_key, _iv, mac_key = tc._derive(PASSPHRASE, salt)
    assert tc.mac_key_for_frame(frame, PASSPHRASE) == mac_key


def test_frame_salt_rejects_malformed_frame():
    with pytest.raises(tc.DecryptionError):
        tc.frame_salt("not a valid frame")
