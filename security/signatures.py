"""
security/signatures.py — DonorShield Stage 4 digital signature utilities.

Provides RSA-2048 key-pair generation, PEM serialisation, RSA-PSS/SHA-256
signing, and verification for exported audit reports.

Algorithm choice
----------------
RSA-PSS (Probabilistic Signature Scheme) with SHA-256 is used.  PSS is the
modern, provably-secure RSA padding scheme recommended over the older PKCS#1
v1.5 padding.  A 2048-bit key provides ~112 bits of security, which is
adequate for this project.  The salt length is set to the digest size (32
bytes) as recommended by RFC 8017.

Key management
--------------
Private key  — loaded from the path in DS_RSA_PRIVATE_KEY_PATH.
               Never stored in SQLite, never logged, never sent in responses.
               The file must be readable only by the application user.

Public key   — loaded from the path in DS_RSA_PUBLIC_KEY_PATH.
               Safe to distribute; used for verification only.

Both paths default to keys/ inside the project root when the environment
variables are not set, so local development works without extra configuration
after running `flask generate-keys`.

Signature format
----------------
sign_bytes() returns raw bytes (the RSA-PSS signature over the SHA-256 digest
of the input).  Callers are responsible for encoding/storing the signature
alongside the signed data.  The export route in app.py stores both as
separate files inside a ZIP archive:

    audit_report_<timestamp>.zip
    ├── report.json      — the exact bytes that were signed
    └── report.sig       — the raw RSA-PSS signature (binary)

Verification
------------
verify_bytes(report_bytes, signature_bytes, public_key) returns True/False.
It never raises on a bad signature — it catches InvalidSignature and returns
False so callers always get a clear boolean result.

The `flask verify-report` CLI command performs offline verification using
only the public key.
"""

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_PROJECT_ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_KEY_DIR = os.path.join(_PROJECT_ROOT, "keys")

_PRIVATE_KEY_PATH_ENV = "DS_RSA_PRIVATE_KEY_PATH"
_PUBLIC_KEY_PATH_ENV  = "DS_RSA_PUBLIC_KEY_PATH"


def _default_private_path() -> str:
    return os.path.join(_DEFAULT_KEY_DIR, "private.pem")


def _default_public_path() -> str:
    return os.path.join(_DEFAULT_KEY_DIR, "public.pem")


def get_private_key_path() -> str:
    return os.environ.get(_PRIVATE_KEY_PATH_ENV) or _default_private_path()


def get_public_key_path() -> str:
    return os.environ.get(_PUBLIC_KEY_PATH_ENV) or _default_public_path()


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SigningKeyNotFoundError(RuntimeError):
    """Raised when the private key file cannot be found or read."""


class VerificationKeyNotFoundError(RuntimeError):
    """Raised when the public key file cannot be found or read."""


# ---------------------------------------------------------------------------
# Key generation and serialisation
# ---------------------------------------------------------------------------

def generate_key_pair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generate a fresh RSA-2048 key pair.

    Returns
    -------
    (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def save_private_key(private_key: RSAPrivateKey, path: str) -> None:
    """
    Serialise *private_key* to a PEM file at *path*.

    The file is written with no password protection.  Restrict access with
    filesystem permissions (chmod 600 on Unix; restrict ACL on Windows).
    Never commit this file to version control.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_key(public_key: RSAPublicKey, path: str) -> None:
    """Serialise *public_key* to a PEM file at *path*."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str | None = None) -> RSAPrivateKey:
    """
    Load an RSA private key from *path* (defaults to DS_RSA_PRIVATE_KEY_PATH
    or keys/private.pem).

    Raises
    ------
    SigningKeyNotFoundError
        If the file does not exist or cannot be read.
    """
    resolved = path or get_private_key_path()
    if not os.path.isfile(resolved):
        raise SigningKeyNotFoundError(
            f"RSA private key not found at '{resolved}'. "
            "Run `flask generate-keys` to create a key pair."
        )
    with open(resolved, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str | None = None) -> RSAPublicKey:
    """
    Load an RSA public key from *path* (defaults to DS_RSA_PUBLIC_KEY_PATH
    or keys/public.pem).

    Raises
    ------
    VerificationKeyNotFoundError
        If the file does not exist or cannot be read.
    """
    resolved = path or get_public_key_path()
    if not os.path.isfile(resolved):
        raise VerificationKeyNotFoundError(
            f"RSA public key not found at '{resolved}'. "
            "Run `flask generate-keys` to create a key pair."
        )
    with open(resolved, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

def sign_bytes(data: bytes, private_key: RSAPrivateKey | None = None) -> bytes:
    """
    Sign *data* with RSA-PSS/SHA-256.

    Parameters
    ----------
    data : bytes
        The exact bytes to sign (e.g. the UTF-8 encoded JSON report).
    private_key : RSAPrivateKey, optional
        If omitted, the key is loaded from the configured path.

    Returns
    -------
    bytes
        The raw RSA-PSS signature.  Store this alongside *data* for later
        verification.  The signature covers the SHA-256 digest of *data*.

    Raises
    ------
    SigningKeyNotFoundError
        If the private key file cannot be found.
    """
    key = private_key or load_private_key()
    return key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256.digest_size,
        ),
        hashes.SHA256(),
    )


def verify_bytes(
    data: bytes,
    signature: bytes,
    public_key: RSAPublicKey | None = None,
) -> bool:
    """
    Verify an RSA-PSS/SHA-256 signature over *data*.

    Parameters
    ----------
    data : bytes
        The exact bytes that were signed.
    signature : bytes
        The raw signature produced by :func:`sign_bytes`.
    public_key : RSAPublicKey, optional
        If omitted, the key is loaded from the configured path.

    Returns
    -------
    bool
        True  — signature is valid; *data* has not been modified.
        False — signature is invalid, *data* was modified, wrong key used,
                or the signature bytes are malformed.

    This function never raises on a bad signature.  It only raises
    VerificationKeyNotFoundError if the public key file is missing.
    """
    key = public_key or load_public_key()
    try:
        key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256.digest_size,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, Exception):
        return False
