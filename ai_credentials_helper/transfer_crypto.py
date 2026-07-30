"""Authenticated encryption for credential transfer (``--send`` / ``--receive``).

The KDF/AES *primitive* (PBKDF2-HMAC-SHA256 key schedule + AES-256-CBC) is a
standard construction, cross-checked against the macOS ``openssl`` (LibreSSL)
CLI by the interop tests in ``tests/test_transfer_crypto.py``. Those build the
same frame with an entirely separate implementation, so a change here that
stays self-consistent but drifts off the standard fails there rather than
shipping silently. The wire *framing* built on top of the primitive -- the
agent-identity envelope in ``ai_credentials_helper.transfer_envelope`` and the
authenticated ACK -- is specific to this CLI and is not a shared format.

Construction: **AES-256-CBC + HMAC-SHA256, encrypt-then-MAC.**

Key schedule (identical on both sides)::

    salt     = 16 random bytes
    material = PBKDF2-HMAC-SHA256(passphrase, salt, 600000, dklen=80)
    enc_key  = material[0:32]   # AES-256 key
    iv       = material[32:48]  # AES-CBC IV
    mac_key  = material[48:80]  # HMAC-SHA256 key

Wire format (two newline-separated text lines)::

    line 1:  base64( salt(16) || ciphertext )
    line 2:  hex( HMAC-SHA256(mac_key, salt || ciphertext) )
"""

import base64
import binascii
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PBKDF2_ITERATIONS = 600_000
SALT_LEN = 16
_BLOCK_BITS = 128  # AES block size


class DecryptionError(Exception):
    """Authentication or parsing failed (wrong passphrase, or corrupt/forged data)."""


def _derive(passphrase: str, salt: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (enc_key, iv, mac_key) from one PBKDF2 derivation, split by position."""
    material = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(), salt, PBKDF2_ITERATIONS, dklen=80
    )
    return material[0:32], material[32:48], material[48:80]


def encrypt(plaintext: str, passphrase: str) -> str:
    """Encrypt+authenticate ``plaintext`` under ``passphrase``; return the wire frame."""
    salt = os.urandom(SALT_LEN)
    enc_key, iv, mac_key = _derive(passphrase, salt)

    padder = padding.PKCS7(_BLOCK_BITS).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    blob = salt + ciphertext
    tag = hmac.new(mac_key, blob, hashlib.sha256).hexdigest()
    return f"{base64.b64encode(blob).decode()}\n{tag}\n"


def _parse_frame(frame: str) -> tuple[bytes, str]:
    """Parse+validate a wire frame's two lines; return ``(blob, tag_hex)``.

    ``blob`` is ``salt || ciphertext`` (undecoded). Raises DecryptionError on
    any malformed shape -- this is exactly the line-1/line-2 validation
    ``decrypt`` always did; it's factored out so ``frame_salt`` can reuse it
    without duplicating the rules or needing a passphrase.
    """
    lines = [ln for ln in frame.splitlines() if ln.strip()]
    if len(lines) != 2:  # exactly base64-blob + hex-tag; reject extras
        raise DecryptionError("malformed transfer frame")
    try:
        blob = base64.b64decode(lines[0], validate=True)
    except (binascii.Error, ValueError) as e:
        raise DecryptionError("malformed transfer frame") from e
    if len(blob) <= SALT_LEN:
        raise DecryptionError("malformed transfer frame")
    tag_hex = lines[1].strip()
    if len(tag_hex) != 64 or not all(c in "0123456789abcdef" for c in tag_hex.lower()):
        raise DecryptionError("malformed transfer frame")
    return blob, tag_hex


def frame_salt(frame: str) -> bytes:
    """Return the salt embedded in a wire ``frame`` (first ``SALT_LEN`` bytes of the blob).

    Raises DecryptionError if the frame's *shape* is malformed. Does **not**
    require or check the passphrase/HMAC -- it only needs the frame to be
    two well-formed lines, so it can succeed even when the frame's tag will
    later fail to verify under a given passphrase. Used to derive the ACK's
    mac_key on both ends without re-doing a full decrypt.
    """
    blob, _tag_hex = _parse_frame(frame)
    return blob[:SALT_LEN]


def mac_key_for_frame(frame: str, passphrase: str) -> bytes:
    """Return the HMAC key used for both the frame and its ACK.

    Same derivation as ``_derive(...)[2]``, applied to the frame's own salt,
    so the sender (who has passphrase + frame) and the receiver (who has
    passphrase + received frame) compute an identical mac_key with no extra
    round trip.
    """
    return _derive(passphrase, frame_salt(frame))[2]


def decrypt(frame: str, passphrase: str) -> str:
    """Verify+decrypt a wire ``frame``; raise :class:`DecryptionError` on any failure.

    The HMAC is checked (constant-time) **before** decryption, so a wrong
    passphrase or a forged/tampered frame is rejected without ever decrypting.
    """
    blob, tag_hex = _parse_frame(frame)
    salt, ciphertext = blob[:SALT_LEN], blob[SALT_LEN:]
    enc_key, iv, mac_key = _derive(passphrase, salt)

    expected = hmac.new(mac_key, blob, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, tag_hex):
        raise DecryptionError(
            "authentication failed (wrong passphrase or corrupted/forged data)"
        )

    # The HMAC gate above stops forgery, but a buggy or version-mismatched peer
    # that shares the passphrase can still produce a valid-tag frame whose
    # ciphertext won't decrypt (bad block length / padding) or whose plaintext
    # isn't UTF-8. Convert those to DecryptionError so the contract holds: any
    # failure raises DecryptionError, never a raw cryptography/codec exception.
    try:
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(_BLOCK_BITS).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()
    except (ValueError, UnicodeDecodeError) as e:
        raise DecryptionError("authenticated frame failed to decrypt") from e
