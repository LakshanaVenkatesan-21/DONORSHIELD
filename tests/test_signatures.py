"""
DonorShield - Stage 4 digital signature unit tests.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import os
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def key_pair():
    """Generate one RSA-2048 key pair shared across all unit tests."""
    from security.signatures import generate_key_pair
    return generate_key_pair()


@pytest.fixture(scope="module")
def private_key(key_pair):
    return key_pair[0]


@pytest.fixture(scope="module")
def public_key(key_pair):
    return key_pair[1]


# ---------------------------------------------------------------------------
# 1. Key generation
# ---------------------------------------------------------------------------

class TestKeyGeneration:
    def test_generates_rsa_private_key(self, private_key):
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        assert isinstance(private_key, RSAPrivateKey)

    def test_key_size_is_2048(self, private_key):
        assert private_key.key_size == 2048

    def test_generates_rsa_public_key(self, public_key):
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        assert isinstance(public_key, RSAPublicKey)

    def test_public_key_matches_private_key(self, private_key, public_key):
        # The public key derived from the private key must equal the generated one.
        assert (
            private_key.public_key().public_numbers()
            == public_key.public_numbers()
        )

    def test_two_key_pairs_are_different(self):
        from security.signatures import generate_key_pair
        _, pub1 = generate_key_pair()
        _, pub2 = generate_key_pair()
        assert pub1.public_numbers() != pub2.public_numbers()


# ---------------------------------------------------------------------------
# 2. Key serialisation (save / load)
# ---------------------------------------------------------------------------

class TestKeySerialization:
    def test_save_and_load_private_key(self, private_key):
        from security.signatures import save_private_key, load_private_key
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "private.pem")
            save_private_key(private_key, path)
            loaded = load_private_key(path)
            assert loaded.private_numbers() == private_key.private_numbers()

    def test_save_and_load_public_key(self, public_key):
        from security.signatures import save_public_key, load_public_key
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "public.pem")
            save_public_key(public_key, path)
            loaded = load_public_key(path)
            assert loaded.public_numbers() == public_key.public_numbers()

    def test_load_missing_private_key_raises(self):
        from security.signatures import load_private_key, SigningKeyNotFoundError
        with pytest.raises(SigningKeyNotFoundError):
            load_private_key("/nonexistent/path/private.pem")

    def test_load_missing_public_key_raises(self):
        from security.signatures import load_public_key, VerificationKeyNotFoundError
        with pytest.raises(VerificationKeyNotFoundError):
            load_public_key("/nonexistent/path/public.pem")

    def test_private_key_pem_not_in_public_file(self, private_key, public_key):
        """Public PEM file must not contain the private key material."""
        from security.signatures import save_public_key
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "public.pem")
            save_public_key(public_key, path)
            content = open(path, "rb").read()
            assert b"PRIVATE" not in content


# ---------------------------------------------------------------------------
# 3. Valid signature round-trip
# ---------------------------------------------------------------------------

class TestValidSignature:
    def test_sign_returns_bytes(self, private_key):
        from security.signatures import sign_bytes
        sig = sign_bytes(b"test report data", private_key)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_valid_signature_verifies(self, private_key, public_key):
        from security.signatures import sign_bytes, verify_bytes
        data = b'{"event": "LOGIN", "user": "admin"}'
        sig = sign_bytes(data, private_key)
        assert verify_bytes(data, sig, public_key) is True

    def test_different_data_same_key_different_sig(self, private_key):
        """RSA-PSS uses random salt so two signatures of the same data differ."""
        from security.signatures import sign_bytes
        data = b"report content"
        sig1 = sign_bytes(data, private_key)
        sig2 = sign_bytes(data, private_key)
        assert sig1 != sig2

    def test_both_sigs_verify_correctly(self, private_key, public_key):
        from security.signatures import sign_bytes, verify_bytes
        data = b"report content"
        sig1 = sign_bytes(data, private_key)
        sig2 = sign_bytes(data, private_key)
        assert verify_bytes(data, sig1, public_key) is True
        assert verify_bytes(data, sig2, public_key) is True

    def test_large_report_signs_and_verifies(self, private_key, public_key):
        from security.signatures import sign_bytes, verify_bytes
        data = b'{"events": [' + b'{"id": 1},' * 500 + b'{"id": 501}]}'
        sig = sign_bytes(data, private_key)
        assert verify_bytes(data, sig, public_key) is True


# ---------------------------------------------------------------------------
# 4. Modified report is rejected
# ---------------------------------------------------------------------------

class TestModifiedReportRejected:
    def test_appended_byte_fails_verification(self, private_key, public_key):
        from security.signatures import sign_bytes, verify_bytes
        data = b'{"report": "original"}'
        sig = sign_bytes(data, private_key)
        assert verify_bytes(data + b"x", sig, public_key) is False

    def test_truncated_data_fails_verification(self, private_key, public_key):
        from security.signatures import sign_bytes, verify_bytes
        data = b'{"report": "original content here"}'
        sig = sign_bytes(data, private_key)
        assert verify_bytes(data[:-1], sig, public_key) is False

    def test_single_bit_flip_fails_verification(self, private_key, public_key):
        from security.signatures import sign_bytes, verify_bytes
        data = bytearray(b'{"event_type": "LOGIN", "user": "admin"}')
        sig = sign_bytes(bytes(data), private_key)
        data[5] ^= 0x01   # flip one bit
        assert verify_bytes(bytes(data), sig, public_key) is False

    def test_whitespace_change_fails_verification(self, private_key, public_key):
        """Even a whitespace change in the JSON must invalidate the signature."""
        from security.signatures import sign_bytes, verify_bytes
        data = b'{"key":"value"}'
        sig = sign_bytes(data, private_key)
        assert verify_bytes(b'{"key": "value"}', sig, public_key) is False


# ---------------------------------------------------------------------------
# 5. Wrong public key is rejected
# ---------------------------------------------------------------------------

class TestWrongKeyRejected:
    def test_different_public_key_fails(self, private_key):
        from security.signatures import sign_bytes, verify_bytes, generate_key_pair
        data = b"audit report bytes"
        sig = sign_bytes(data, private_key)
        _, other_pub = generate_key_pair()
        assert verify_bytes(data, sig, other_pub) is False

    def test_correct_key_still_verifies_after_wrong_key_attempt(
        self, private_key, public_key
    ):
        from security.signatures import sign_bytes, verify_bytes, generate_key_pair
        data = b"audit report bytes"
        sig = sign_bytes(data, private_key)
        _, other_pub = generate_key_pair()
        verify_bytes(data, sig, other_pub)   # should return False, not raise
        assert verify_bytes(data, sig, public_key) is True


# ---------------------------------------------------------------------------
# 6. Malformed signature is rejected safely
# ---------------------------------------------------------------------------

class TestMalformedSignature:
    def test_empty_signature_returns_false(self, public_key):
        from security.signatures import verify_bytes
        assert verify_bytes(b"some data", b"", public_key) is False

    def test_random_bytes_signature_returns_false(self, public_key):
        from security.signatures import verify_bytes
        assert verify_bytes(b"some data", os.urandom(256), public_key) is False

    def test_truncated_signature_returns_false(self, private_key, public_key):
        from security.signatures import sign_bytes, verify_bytes
        data = b"report"
        sig = sign_bytes(data, private_key)
        assert verify_bytes(data, sig[:64], public_key) is False

    def test_flipped_signature_byte_returns_false(self, private_key, public_key):
        from security.signatures import sign_bytes, verify_bytes
        data = b"report"
        sig = bytearray(sign_bytes(data, private_key))
        sig[0] ^= 0xFF
        assert verify_bytes(data, bytes(sig), public_key) is False

    def test_verify_never_raises_on_bad_sig(self, public_key):
        """verify_bytes must return False, never raise, for any garbage input."""
        from security.signatures import verify_bytes
        for bad_sig in [b"", b"\x00" * 256, b"not-a-signature", os.urandom(128)]:
            result = verify_bytes(b"data", bad_sig, public_key)
            assert result is False
