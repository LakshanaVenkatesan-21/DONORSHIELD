"""
DonorShield - Stage 2 cryptographic utility tests.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import hashlib
import os
import tempfile

import pytest
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_KEY_HEX = "a" * 64   # 32 bytes of 0xaa — valid length, never used in prod


def _set_key(monkeypatch, hex_key=VALID_KEY_HEX):
    monkeypatch.setenv("DS_AES_KEY", hex_key)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_key(monkeypatch):
    """
    Remove DS_AES_KEY from the environment before every test so tests that
    expect KeyNotConfiguredError are not accidentally satisfied by a key set
    in the developer's shell.
    """
    monkeypatch.delenv("DS_AES_KEY", raising=False)


# ---------------------------------------------------------------------------
# 1. Key loading
# ---------------------------------------------------------------------------

class TestKeyLoading:
    def test_missing_key_raises(self):
        from security.crypto import encrypt, KeyNotConfiguredError
        with pytest.raises(KeyNotConfiguredError, match="DS_AES_KEY"):
            encrypt("hello")

    def test_short_key_raises(self, monkeypatch):
        monkeypatch.setenv("DS_AES_KEY", "deadbeef")   # only 4 bytes
        from security.crypto import encrypt, KeyNotConfiguredError
        with pytest.raises(KeyNotConfiguredError):
            encrypt("hello")

    def test_non_hex_key_raises(self, monkeypatch):
        monkeypatch.setenv("DS_AES_KEY", "z" * 64)    # not valid hex
        from security.crypto import encrypt, KeyNotConfiguredError
        with pytest.raises(KeyNotConfiguredError):
            encrypt("hello")

    def test_valid_key_accepted(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt
        token = encrypt("test")
        assert token.startswith("v1:")


# ---------------------------------------------------------------------------
# 2. Encryption output format
# ---------------------------------------------------------------------------

class TestEncryptFormat:
    def test_token_has_three_parts(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt
        token = encrypt("hello world")
        parts = token.split(":")
        assert len(parts) == 3

    def test_token_starts_with_version(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt
        token = encrypt("hello world")
        assert token.startswith("v1:")

    def test_ciphertext_differs_from_plaintext(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt
        plaintext = "sensitive donor data"
        token = encrypt(plaintext)
        assert plaintext not in token
        assert plaintext.encode() not in token.encode()

    def test_bytes_input_accepted(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt
        token = encrypt(b"\x00\x01\x02\x03")
        assert decrypt(token) == b"\x00\x01\x02\x03"


# ---------------------------------------------------------------------------
# 3. Successful round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_string_roundtrip(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt_str
        plaintext = "John Doe, O+, contact: 9876543210"
        assert decrypt_str(encrypt(plaintext)) == plaintext

    def test_unicode_roundtrip(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt_str
        plaintext = "Aarav Singh — रक्त समूह A+"
        assert decrypt_str(encrypt(plaintext)) == plaintext

    def test_empty_string_roundtrip(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt_str
        assert decrypt_str(encrypt("")) == ""

    def test_long_plaintext_roundtrip(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt_str
        plaintext = "x" * 10_000
        assert decrypt_str(encrypt(plaintext)) == plaintext


# ---------------------------------------------------------------------------
# 4. Wrong key rejection
# ---------------------------------------------------------------------------

class TestWrongKey:
    def test_wrong_key_raises_invalid_tag(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt

        token = encrypt("secret data")

        # Switch to a different key before decrypting.
        monkeypatch.setenv("DS_AES_KEY", "b" * 64)
        from security.crypto import decrypt
        with pytest.raises(InvalidTag):
            decrypt(token)

    def test_wrong_key_does_not_return_plaintext(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt

        plaintext = "confidential"
        token = encrypt(plaintext)

        monkeypatch.setenv("DS_AES_KEY", "c" * 64)
        from security.crypto import decrypt
        try:
            result = decrypt(token)
            # If no exception, result must not be the original plaintext.
            assert result != plaintext.encode()
        except InvalidTag:
            pass   # expected path


# ---------------------------------------------------------------------------
# 5. Tampered ciphertext rejection
# ---------------------------------------------------------------------------

class TestTampering:
    def _flip_last_byte(self, b64_segment: str) -> str:
        """Decode, flip the last byte, re-encode."""
        import base64
        padding = 4 - len(b64_segment) % 4
        raw = bytearray(base64.urlsafe_b64decode(b64_segment + "=" * (padding % 4)))
        raw[-1] ^= 0xFF
        return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

    def test_tampered_ciphertext_rejected(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt

        token = encrypt("integrity check")
        version, nonce_b64, ct_b64 = token.split(":")
        bad_token = f"{version}:{nonce_b64}:{self._flip_last_byte(ct_b64)}"

        with pytest.raises(InvalidTag):
            decrypt(bad_token)

    def test_tampered_nonce_rejected(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt

        token = encrypt("integrity check")
        version, nonce_b64, ct_b64 = token.split(":")
        bad_token = f"{version}:{self._flip_last_byte(nonce_b64)}:{ct_b64}"

        with pytest.raises(InvalidTag):
            decrypt(bad_token)

    def test_truncated_token_rejected(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt

        token = encrypt("data")
        # Remove the last 8 characters to truncate the tag.
        with pytest.raises((InvalidTag, ValueError)):
            decrypt(token[:-8])

    def test_malformed_token_rejected(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import decrypt
        with pytest.raises(ValueError, match="Unrecognised token format"):
            decrypt("notavalidtoken")

    def test_wrong_version_rejected(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt, decrypt
        token = encrypt("data")
        bad = "v2:" + token[3:]   # change version prefix
        with pytest.raises(ValueError, match="Unrecognised token format"):
            decrypt(bad)


# ---------------------------------------------------------------------------
# 6. Nonce uniqueness
# ---------------------------------------------------------------------------

class TestNonceUniqueness:
    def test_same_plaintext_produces_different_tokens(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt
        plaintext = "repeated value"
        tokens = {encrypt(plaintext) for _ in range(50)}
        # All 50 tokens must be distinct (different nonces).
        assert len(tokens) == 50

    def test_nonces_are_all_unique(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt
        import base64

        def _extract_nonce(token):
            nonce_b64 = token.split(":")[1]
            padding = 4 - len(nonce_b64) % 4
            return base64.urlsafe_b64decode(nonce_b64 + "=" * (padding % 4))

        nonces = [_extract_nonce(encrypt("x")) for _ in range(100)]
        assert len(set(nonces)) == 100, "Duplicate nonce detected — RNG may be broken"

    def test_nonce_is_12_bytes(self, monkeypatch):
        _set_key(monkeypatch)
        from security.crypto import encrypt
        import base64

        token = encrypt("check nonce length")
        nonce_b64 = token.split(":")[1]
        padding = 4 - len(nonce_b64) % 4
        nonce = base64.urlsafe_b64decode(nonce_b64 + "=" * (padding % 4))
        assert len(nonce) == 12


# ---------------------------------------------------------------------------
# 7. SHA-256 integrity
# ---------------------------------------------------------------------------

class TestSHA256Integrity:
    def test_known_digest(self):
        from security.crypto import sha256_bytes
        # SHA-256("") is a well-known constant.
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_bytes(b"") == expected

    def test_digest_changes_with_content(self):
        from security.crypto import sha256_bytes
        assert sha256_bytes(b"abc") != sha256_bytes(b"abd")

    def test_file_digest_matches_bytes_digest(self):
        from security.crypto import sha256_file, sha256_bytes
        content = b"DonorShield export report\nline 2\n"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            path = f.name
        try:
            assert sha256_file(path) == sha256_bytes(content)
        finally:
            os.unlink(path)

    def test_file_digest_detects_modification(self):
        from security.crypto import sha256_file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"original content")
            path = f.name
        try:
            original_digest = sha256_file(path)
            with open(path, "ab") as f:
                f.write(b" modified")
            assert sha256_file(path) != original_digest
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        from security.crypto import sha256_file
        with pytest.raises(FileNotFoundError):
            sha256_file("/nonexistent/path/report.csv")

    def test_digest_is_64_hex_chars(self):
        from security.crypto import sha256_bytes
        digest = sha256_bytes(b"test data")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)
