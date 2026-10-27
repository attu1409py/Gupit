"""Tests verifying cryptographic function stubs and exception hierarchy.

Ensures that:
1. All Phase 1 crypto functions raise NotImplementedError rather than mock or fake crypto.
2. The exception hierarchy matches specification.
"""

import pytest
from backend.app.services.crypto_engine import (
    CryptoEngineError,
    InvalidKeyMaterialError,
    MalformedPackageError,
    UnsupportedPackageVersionError,
    FileSizeLimitExceededError,
    SignatureVerificationError,
    DecryptionAuthenticationError,
    generate_rsa_keypair,
    compute_public_key_fingerprint,
    protect_private_key,
    unprotect_private_key,
    validate_file_metadata,
    create_encrypted_package,
    verify_and_decrypt_package,
)


def test_exception_hierarchy():
    """Verify that all crypto errors subclass CryptoEngineError."""
    assert issubclass(InvalidKeyMaterialError, CryptoEngineError)
    assert issubclass(MalformedPackageError, CryptoEngineError)
    assert issubclass(UnsupportedPackageVersionError, CryptoEngineError)
    assert issubclass(FileSizeLimitExceededError, CryptoEngineError)
    assert issubclass(SignatureVerificationError, CryptoEngineError)
    assert issubclass(DecryptionAuthenticationError, CryptoEngineError)


def test_crypto_stubs_raise_not_implemented():
    """Verify that placeholder functions raise NotImplementedError in Phase 1."""
    with pytest.raises(NotImplementedError):
        generate_rsa_keypair()

    with pytest.raises(NotImplementedError):
        compute_public_key_fingerprint("dummy_pem")

    with pytest.raises(NotImplementedError):
        protect_private_key("dummy_pem", b"0" * 32)

    with pytest.raises(NotImplementedError):
        unprotect_private_key(b"blob", b"0" * 32)

    with pytest.raises(NotImplementedError):
        validate_file_metadata("test.txt", b"content")

    with pytest.raises(NotImplementedError):
        create_encrypted_package(
            file_bytes=b"test",
            original_filename="test.txt",
            content_type="text/plain",
            sender_signing_private_pem="pem",
            recipient_encryption_public_pem="pem",
            sender_user_id="usr_1",
            recipient_user_id="usr_2",
        )

    with pytest.raises(NotImplementedError):
        verify_and_decrypt_package(
            package_bytes=b"GUPIT...",
            sender_signing_public_pem="pem",
            recipient_encryption_private_pem="pem",
        )
