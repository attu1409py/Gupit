"""Gupit backend services module."""

from backend.app.services.file_storage import (
    BaseStorageService,
    LocalFileSystemStorage,
    StorageError,
    StorageNotFoundError,
)
from backend.app.services.crypto_engine import (
    CryptoEngineError,
    InvalidKeyMaterialError,
    MalformedPackageError,
    SignatureVerificationError,
    DecryptionAuthenticationError,
    KeyPairPEM,
    generate_rsa_keypair,
    compute_public_key_fingerprint,
    protect_private_key,
    unprotect_private_key,
    create_encrypted_package,
    verify_and_decrypt_package,
)

__all__ = [
    "BaseStorageService",
    "LocalFileSystemStorage",
    "StorageError",
    "StorageNotFoundError",
    "CryptoEngineError",
    "InvalidKeyMaterialError",
    "MalformedPackageError",
    "SignatureVerificationError",
    "DecryptionAuthenticationError",
    "KeyPairPEM",
    "generate_rsa_keypair",
    "compute_public_key_fingerprint",
    "protect_private_key",
    "unprotect_private_key",
    "create_encrypted_package",
    "verify_and_decrypt_package",
]
