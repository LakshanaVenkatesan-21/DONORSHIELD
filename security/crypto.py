"""
security/crypto.py — DonorShield Stage 2 cryptographic utilities.

Provides:
  - AES-256-GCM authenticated encryption / decryption
  - SHA-256 file integrity hashing

AES-256-GCM overview
--------------------
AES-GCM is an authenticated encryption with associated data (AEAD) scheme.
It simultaneously encrypts the plaintext and produces an authentication tag
that covers both the ciphertext and any additional associated data.
Decryption fails with an InvalidTag exception if the ciphertext, tag, or
nonce has been altered, providing both confidentiality and integrity.

Key management
--------------
The 32-byte (256-bit) key is loaded exclusively from the DS_AES_KEY
environment variable, which must be a 64-character hex string.
The key is NEVER written to the database, log files, or HTTP responses.
See .env.example for generation instructions.

Stored token format (version 1)
--------------------------------
Tokens are base64url-encoded (no padding) strings with the structure:

    v1:<base64url(nonce)>:<base64url(ciphertext+tag)>

  - "v1"                  version prefix for future algorithm agility
  - nonce                 12 random bytes (96 bits), unique per encryption
  - ciphertext+tag        AES-GCM output; the 16-byte tag is appended by
                          the cryptography library automatically

The version prefix allows a future migration to a different algorithm
without breaking existing stored tokens.

SHA-256 integrity note
----------------------
sha256_file() returns the hex digest of a file's contents.  A plain hash
detects accidental or deliberate changes ONLY when the expected digest is
stored or transmitted through a separate, trusted channel (e.g. signed
manifest, separate database column, out-of-band comparison).  Storing the
hash in the same location as the file it protects does not provide
tamper-evidence.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NONCE_BYTES = 12          # 96-bit nonce — recommended for AES-GCM
_KEY_BYTES   = 32          # 256-bit key
_VERSION     = "v1"
_ENV_VAR     = "DS_AES_KEY"


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

class KeyNotConfiguredError(RuntimeError):
    """Raised when DS_AES_KEY is absent or malformed."""


def _load_key() -> bytes:
    """
    Load the AES-256 key from the DS_AES_KEY environment variable.

    The variable must be a 64-character lowercase hex string representing
    32 bytes.  Raises KeyNotConfiguredError if it is missing or the wrong
    length; this surfaces as a clear configuration error rather than a
    silent cryptographic failure.
    """
    raw = os.environ.get(_ENV_VAR, "")
    if not raw:
        raise KeyNotConfiguredError(
            f"{_ENV_VAR} environment variable is not set. "
            "Generate a key with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise KeyNotConfiguredError(
            f"{_ENV_VAR} must be a 64-character hex string (got {len(raw)} chars)."
        )
    if len(key) != _KEY_BYTES:
        raise KeyNotConfiguredError(
            f"{_ENV_VAR} must decode to exactly {_KEY_BYTES} bytes "
            f"(got {len(key)} bytes from {len(raw)}-char hex string)."
        )
    return key


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def encrypt(plaintext: str | bytes) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM using a fresh random nonce.

    Parameters
    ----------
    plaintext : str or bytes
        The data to encrypt.  Strings are UTF-8 encoded before encryption.

    Returns
    -------
    str
        A versioned token: ``v1:<nonce_b64>:<ciphertext_and_tag_b64>``
        Safe to store in a TEXT database column.

    Raises
    ------
    KeyNotConfiguredError
        If DS_AES_KEY is not set or is malformed.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    key   = _load_key()
    nonce = os.urandom(_NONCE_BYTES)          # fresh random nonce every call
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)

    nonce_b64 = base64.urlsafe_b64encode(nonce).rstrip(b"=").decode()
    ct_b64    = base64.urlsafe_b64encode(ciphertext_and_tag).rstrip(b"=").decode()
    return f"{_VERSION}:{nonce_b64}:{ct_b64}"


def decrypt(token: str) -> bytes:
    """
    Decrypt and authenticate a token produced by :func:`encrypt`.

    Parameters
    ----------
    token : str
        A versioned token in the format ``v1:<nonce_b64>:<ct_b64>``.

    Returns
    -------
    bytes
        The original plaintext bytes.

    Raises
    ------
    KeyNotConfiguredError
        If DS_AES_KEY is not set or is malformed.
    ValueError
        If the token format is unrecognised or the version is unsupported.
    cryptography.exceptions.InvalidTag
        If the ciphertext or tag has been tampered with, or the wrong key
        is used.  The caller should treat this as an integrity failure.
    """
    parts = token.split(":")
    if len(parts) != 3 or parts[0] != _VERSION:
        raise ValueError(
            f"Unrecognised token format. Expected '{_VERSION}:<nonce>:<ciphertext>'."
        )

    _, nonce_b64, ct_b64 = parts

    def _b64_decode(s: str) -> bytes:
        # Restore stripped padding before decoding.
        padding = 4 - len(s) % 4
        return base64.urlsafe_b64decode(s + "=" * (padding % 4))

    nonce              = _b64_decode(nonce_b64)
    ciphertext_and_tag = _b64_decode(ct_b64)

    key    = _load_key()
    aesgcm = AESGCM(key)
    # Raises InvalidTag automatically if authentication fails.
    return aesgcm.decrypt(nonce, ciphertext_and_tag, None)


def decrypt_str(token: str) -> str:
    """Convenience wrapper — returns the plaintext as a UTF-8 string."""
    return decrypt(token).decode("utf-8")


# ---------------------------------------------------------------------------
# SHA-256 file integrity
# ---------------------------------------------------------------------------

def sha256_file(path: str) -> str:
    """
    Compute the SHA-256 hex digest of the file at *path*.

    This is suitable for verifying that an exported report or backup file
    has not been altered, provided the expected digest is stored or
    communicated through a separate trusted channel.

    A hash stored alongside the file it protects does NOT provide
    tamper-evidence on its own — an attacker who can replace the file can
    also replace the hash.

    Parameters
    ----------
    path : str
        Absolute or relative path to the file.

    Returns
    -------
    str
        64-character lowercase hex digest.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of an in-memory byte string."""
    return hashlib.sha256(data).hexdigest()
