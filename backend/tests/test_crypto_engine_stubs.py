"""Tests verifying cryptographic exception hierarchy and baseline contract types."""

import pytest
from backend.app.services.crypto_engine import (
    CryptoEngineError,
    InvalidKeyMaterialError,
    MalformedPackageError,
    UnsupportedPackageVersionError,
    FileSizeLimitExceededError,
    SignatureVerificationError,
    DecryptionAuthenticationError,
    KeyPairPEM,
    generate_rsa_keypair,
)


def test_exception_hierarchy():
    """Verify that all crypto errors subclass CryptoEngineError."""
    assert issubclass(InvalidKeyMaterialError, CryptoEngineError)
    assert issubclass(MalformedPackageError, CryptoEngineError)
    assert issubclass(UnsupportedPackageVersionError, CryptoEngineError)
    assert issubclass(FileSizeLimitExceededError, CryptoEngineError)
    assert issubclass(SignatureVerificationError, CryptoEngineError)
    assert issubclass(DecryptionAuthenticationError, CryptoEngineError)


def test_keypair_pem_namedtuple():
    """Verify KeyPairPEM structure."""
    kp = KeyPairPEM(public_pem="pub", private_pem="priv")
    assert kp.public_pem == "pub"
    assert kp.private_pem == "priv"


def test_rsa_key_generation_minimum_size():
    """Verify key generation rejects bit sizes under 2048."""
    with pytest.raises(ValueError, match="at least 2048 bits"):
        generate_rsa_keypair(key_size_bits=1024)
