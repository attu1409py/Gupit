"""Gupit Cryptographic Engine.

Provides secure hybrid cryptography combining:
- AES-256-GCM for authenticated symmetric file encryption
- RSA-OAEP (SHA-256, MGF1-SHA-256) for session key encapsulation
- RSA-PSS (SHA-256, MGF1-SHA-256, salt_length=MAX_LENGTH) for digital signatures
- At-rest private key protection using AES-256-GCM and a server master key
- Optional PKCS#8 passphrase-protected private key serialization
- Binary package serialization (.pkg) with strict validation and safe error handling
"""

import base64
from dataclasses import dataclass
import hashlib
import json
import os
import struct
from typing import NamedTuple, Optional
import uuid

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==============================================================================
# 1. Cryptographic Error Hierarchy
# ==============================================================================

class CryptoEngineError(Exception):
    """Base exception for all cryptographic failures in Gupit."""
    pass


class InvalidKeyMaterialError(CryptoEngineError):
    """Raised when PEM/DER key encoding is corrupt or has unexpected format."""
    pass


class UnsupportedPackageVersionError(CryptoEngineError):
    """Raised when an encrypted package has an unrecognized version identifier."""
    pass


class MalformedPackageError(CryptoEngineError):
    """Raised when the package header, magic bytes, or framing is structurally corrupt."""
    pass


class FileSizeLimitExceededError(CryptoEngineError):
    """Raised when file size exceeds server policy."""
    pass


class SignatureVerificationError(CryptoEngineError):
    """Raised when RSA-PSS signature verification fails against sender public key."""
    pass


class DecryptionAuthenticationError(CryptoEngineError):
    """Raised when AES-GCM authentication tag check or RSA-OAEP unwrapping fails."""
    pass


# ==============================================================================
# 2. Data Types & Structures
# ==============================================================================

class KeyPairPEM(NamedTuple):
    """Pair of public and private keys in PEM format."""
    public_pem: str
    private_pem: str


@dataclass(frozen=True)
class IdentityKeyMaterial:
    """Public key bundle and computed fingerprints for a user identity."""
    identity_id: str
    user_id: str
    encryption_public_pem: str
    signing_public_pem: str
    encryption_fingerprint: str
    signing_fingerprint: str


@dataclass(frozen=True)
class ProtectedPrivateKeyMaterial:
    """Encrypted private keys at rest, protected by the server master key."""
    identity_id: str
    encrypted_encryption_private_blob: bytes
    encrypted_signing_private_blob: bytes


@dataclass(frozen=True)
class PackageMetadata:
    """Structured header metadata for an encrypted file package."""
    version: int
    package_id: str
    original_filename: str
    content_type: str
    file_size_bytes: int
    sender_user_id: str
    recipient_user_id: str
    sender_signing_fingerprint: str
    recipient_encryption_fingerprint: str


@dataclass(frozen=True)
class EncryptedPackageResult:
    """Result of an encryption and signing operation."""
    package_id: str
    package_bytes: bytes
    metadata: PackageMetadata


@dataclass(frozen=True)
class DecryptedFileResult:
    """Result of a verified signature and authenticated decryption operation."""
    original_filename: str
    content_type: str
    file_bytes: bytes
    file_size_bytes: int
    sender_signing_fingerprint: str


# ==============================================================================
# 3. Constants & Specifications
# ==============================================================================

PACKAGE_MAGIC: bytes = b"GUPIT"
CURRENT_PACKAGE_VERSION: int = 1
MIN_RSA_KEY_SIZE_BITS: int = 2048
DEFAULT_RSA_KEY_SIZE_BITS: int = 3072
AES_KEY_SIZE_BYTES: int = 32        # 256 bits
AES_GCM_NONCE_SIZE_BYTES: int = 12  # 96 bits
AES_GCM_TAG_SIZE_BYTES: int = 16    # 128 bits
MASTER_KEY_SIZE_BYTES: int = 32     # 256 bits
DEFAULT_MAX_FILE_SIZE: int = 25 * 1024 * 1024  # 25 MiB (26,214,400 bytes)
MAX_HEADER_JSON_BYTES: int = 65536     # 64 KB safety limit for header framing
MIN_SIGNATURE_BYTES: int = 256         # 2048-bit RSA signature length
MAX_SIGNATURE_BYTES: int = 512         # 4096-bit RSA signature length
MAX_PACKAGE_OVERHEAD_BYTES: int = 65536  # Extra framing margin allowance for packages

WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})


# ==============================================================================
# 4. Key Management & Helper Functions
# ==============================================================================

def generate_rsa_keypair(key_size_bits: int = DEFAULT_RSA_KEY_SIZE_BITS) -> KeyPairPEM:
    """Generate an RSA key pair suitable for either OAEP encryption or PSS signing.

    Args:
        key_size_bits: Bit length of RSA modulus (must be >= 2048, default 3072).

    Returns:
        KeyPairPEM with public_pem and private_pem in PKCS#8 / SPKI PEM format.

    Raises:
        ValueError: If key_size_bits < 2048.
    """
    if key_size_bits < MIN_RSA_KEY_SIZE_BITS:
        raise ValueError(
            f"RSA key size must be at least {MIN_RSA_KEY_SIZE_BITS} bits, got {key_size_bits}."
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size_bits,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return KeyPairPEM(public_pem=public_pem, private_pem=private_pem)


def compute_public_key_fingerprint(public_pem: str) -> str:
    """Compute a SHA-256 hexadecimal fingerprint from a PEM-encoded public key.

    Args:
        public_pem: Public key in SubjectPublicKeyInfo PEM format.

    Returns:
        64-character lowercase hex string of SHA-256 digest of DER bytes.

    Raises:
        InvalidKeyMaterialError: If PEM decoding fails or key format is invalid.
    """
    if not isinstance(public_pem, str) or not public_pem.strip():
        raise InvalidKeyMaterialError("Public key PEM must be a non-empty string.")

    try:
        pub_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        der_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der_bytes).hexdigest()
    except Exception as e:
        raise InvalidKeyMaterialError(f"Failed to parse public key PEM: {e}") from e


def serialize_public_key(public_key_obj: object) -> str:
    """Serialize an RSA public key object to SPKI PEM string.

    Args:
        public_key_obj: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.

    Returns:
        PEM-formatted string.

    Raises:
        InvalidKeyMaterialError: If key object is invalid.
    """
    if not isinstance(public_key_obj, rsa.RSAPublicKey):
        raise InvalidKeyMaterialError("Provided object is not an RSAPublicKey instance.")
    try:
        pem_bytes = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")
    except Exception as e:
        raise InvalidKeyMaterialError(f"Failed to serialize public key: {e}") from e


def load_public_key(public_pem: str) -> rsa.RSAPublicKey:
    """Load an RSA public key object from an SPKI PEM string.

    Args:
        public_pem: PEM-formatted public key string.

    Returns:
        RSAPublicKey object.

    Raises:
        InvalidKeyMaterialError: If PEM parsing fails or key modulus < 2048.
    """
    if not isinstance(public_pem, str) or not public_pem.strip():
        raise InvalidKeyMaterialError("Public key PEM must be a non-empty string.")
    try:
        pub_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        if not isinstance(pub_key, rsa.RSAPublicKey):
            raise InvalidKeyMaterialError("Loaded key is not an RSA public key.")
        if pub_key.key_size < MIN_RSA_KEY_SIZE_BITS:
            raise InvalidKeyMaterialError(
                f"RSA key size must be at least {MIN_RSA_KEY_SIZE_BITS} bits, got {pub_key.key_size}."
            )
        return pub_key
    except InvalidKeyMaterialError:
        raise
    except Exception as e:
        raise InvalidKeyMaterialError(f"Failed to parse public key PEM: {e}") from e


def serialize_private_key(
    private_key_obj: object,
    password: Optional[bytes] = None,
) -> str:
    """Serialize an RSA private key object to PKCS#8 PEM string with optional passphrase.

    Args:
        private_key_obj: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.
        password: Optional passphrase bytes for encrypting the private key at export.

    Returns:
        PEM-formatted string.

    Raises:
        InvalidKeyMaterialError: If key object is invalid.
        ValueError: If password is empty or wrong type.
    """
    if not isinstance(private_key_obj, rsa.RSAPrivateKey):
        raise InvalidKeyMaterialError("Provided object is not an RSAPrivateKey instance.")
    try:
        if password is not None:
            if not isinstance(password, (bytes, bytearray)) or len(password) == 0:
                raise ValueError("Passphrase must be non-empty bytes.")
            enc_alg: serialization.KeySerializationEncryption = (
                serialization.BestAvailableEncryption(bytes(password))
            )
        else:
            enc_alg = serialization.NoEncryption()

        pem_bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg,
        )
        return pem_bytes.decode("utf-8")
    except ValueError:
        raise
    except Exception as e:
        raise InvalidKeyMaterialError(f"Failed to serialize private key: {e}") from e


def load_private_key(
    private_pem: str,
    password: Optional[bytes] = None,
) -> rsa.RSAPrivateKey:
    """Load an RSA private key object from a PKCS#8 PEM string.

    Args:
        private_pem: PEM-formatted private key string.
        password: Optional passphrase bytes if the PEM is encrypted.

    Returns:
        RSAPrivateKey object.

    Raises:
        DecryptionAuthenticationError: If passphrase is incorrect or missing.
        InvalidKeyMaterialError: If PEM parsing fails or key is not RSA with size >= 2048.
    """
    if not isinstance(private_pem, str) or not private_pem.strip():
        raise InvalidKeyMaterialError("Private key PEM must be a non-empty string.")
    try:
        priv_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"),
            password=password,
        )
        if not isinstance(priv_key, rsa.RSAPrivateKey):
            raise InvalidKeyMaterialError("Loaded key is not an RSA private key.")
        if priv_key.key_size < MIN_RSA_KEY_SIZE_BITS:
            raise InvalidKeyMaterialError(
                f"RSA private key size must be at least {MIN_RSA_KEY_SIZE_BITS} bits, got {priv_key.key_size}."
            )
        return priv_key
    except TypeError as e:
        raise DecryptionAuthenticationError(f"Encrypted private key requires a passphrase: {e}") from e
    except ValueError as e:
        err_msg = str(e).lower()
        if "incorrect password" in err_msg or "bad decrypt" in err_msg:
            raise DecryptionAuthenticationError(f"Incorrect private key passphrase: {e}") from e
        raise InvalidKeyMaterialError(f"Failed to parse private key PEM: {e}") from e
    except InvalidKeyMaterialError:
        raise
    except Exception as e:
        raise InvalidKeyMaterialError(f"Failed to parse private key PEM: {e}") from e


def _load_private_key(private_pem: str) -> rsa.RSAPrivateKey:
    """Internal helper to load an unencrypted RSA private key."""
    return load_private_key(private_pem, password=None)


def protect_private_key(private_pem: str, master_key_bytes: bytes) -> bytes:
    """Encrypt a private key PEM string at rest using AES-256-GCM and the server master key.

    Args:
        private_pem: Unprotected private key in PEM format.
        master_key_bytes: 32-byte server master key from environment.

    Returns:
        Encrypted binary blob containing nonce (12B) + auth tag (16B) + ciphertext.

    Raises:
        ValueError: If master_key_bytes is not exactly 32 bytes.
        InvalidKeyMaterialError: If private_pem is malformed.
        CryptoEngineError: On encryption failure.
    """
    if not isinstance(master_key_bytes, (bytes, bytearray)) or len(master_key_bytes) != MASTER_KEY_SIZE_BYTES:
        raise ValueError(f"Server master key must be exactly {MASTER_KEY_SIZE_BYTES} bytes.")

    # Validate that the private key is valid RSA before protecting
    _load_private_key(private_pem)

    try:
        nonce = os.urandom(AES_GCM_NONCE_SIZE_BYTES)
        aesgcm = AESGCM(bytes(master_key_bytes))
        # AESGCM.encrypt appends 16-byte auth tag to the ciphertext
        encrypted_output = aesgcm.encrypt(nonce, private_pem.encode("utf-8"), associated_data=None)
        raw_ciphertext = encrypted_output[:-AES_GCM_TAG_SIZE_BYTES]
        auth_tag = encrypted_output[-AES_GCM_TAG_SIZE_BYTES:]

        # Wire layout: nonce (12B) + auth tag (16B) + ciphertext
        return nonce + auth_tag + raw_ciphertext
    except Exception as e:
        raise CryptoEngineError(f"Private key protection failed: {e}") from e


def unprotect_private_key(encrypted_blob: bytes, master_key_bytes: bytes) -> str:
    """Decrypt a stored private key blob using the server master key and AES-256-GCM.

    Args:
        encrypted_blob: Binary blob created by protect_private_key.
        master_key_bytes: 32-byte server master key.

    Returns:
        Decrypted PEM string.

    Raises:
        ValueError: If master_key_bytes is not exactly 32 bytes.
        DecryptionAuthenticationError: If master key is incorrect or blob is corrupted.
    """
    if not isinstance(master_key_bytes, (bytes, bytearray)) or len(master_key_bytes) != MASTER_KEY_SIZE_BYTES:
        raise ValueError(f"Server master key must be exactly {MASTER_KEY_SIZE_BYTES} bytes.")

    min_required_len = AES_GCM_NONCE_SIZE_BYTES + AES_GCM_TAG_SIZE_BYTES
    if not isinstance(encrypted_blob, (bytes, bytearray)) or len(encrypted_blob) < min_required_len:
        raise DecryptionAuthenticationError("Encrypted private key blob is truncated or corrupted.")

    nonce = encrypted_blob[:AES_GCM_NONCE_SIZE_BYTES]
    auth_tag = encrypted_blob[AES_GCM_NONCE_SIZE_BYTES:min_required_len]
    raw_ciphertext = encrypted_blob[min_required_len:]

    try:
        aesgcm = AESGCM(bytes(master_key_bytes))
        # AESGCM.decrypt expects ciphertext + auth_tag
        decrypted_bytes = aesgcm.decrypt(nonce, raw_ciphertext + auth_tag, associated_data=None)
        return decrypted_bytes.decode("utf-8")
    except InvalidTag as e:
        raise DecryptionAuthenticationError(
            "Failed to decrypt private key: master key is incorrect or blob was tampered with."
        ) from e
    except Exception as e:
        raise DecryptionAuthenticationError(f"Private key decryption error: {e}") from e


def _validate_filename(filename: str) -> None:
    """Internal helper strictly validating filename safety against path traversal and device injection.

    Raises:
        ValueError: If filename contains invalid, dangerous, or traversal characters.
    """
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Filename must be a non-empty string.")

    if "\x00" in filename:
        raise ValueError("Filename contains null byte.")

    # Disallow path separators, directory traversal, Windows drive colons, and control characters
    if "/" in filename or "\\" in filename or ".." in filename or ":" in filename:
        raise ValueError("Filename contains path separator, drive letter, or directory traversal sequences.")

    if any(c in filename for c in ("\r", "\n", "\t", "\x0b", "\x0c")):
        raise ValueError("Filename contains control characters.")

    stripped = filename.strip()
    if stripped in (".", ".."):
        raise ValueError("Filename cannot be a relative directory indicator.")

    # Check against Windows reserved device names
    base = stripped.split(".")[0].upper()
    if base in WINDOWS_RESERVED_NAMES:
        raise ValueError(f"Filename '{filename}' uses a reserved system device name.")


def validate_file_metadata(
    filename: str,
    file_bytes: bytes,
    max_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
) -> None:
    """Sanitize filename and enforce file size policy.

    Args:
        filename: Original filename submitted by client.
        file_bytes: Raw bytes of uploaded file.
        max_size_bytes: Max permissible file size (default 25 MiB: 26,214,400 bytes).

    Raises:
        FileSizeLimitExceededError: If len(file_bytes) > max_size_bytes.
        ValueError: If filename contains dangerous directory traversal patterns.
        TypeError: If file_bytes is not bytes or bytearray.
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("file_bytes must be bytes or bytearray.")

    if len(file_bytes) > max_size_bytes:
        raise FileSizeLimitExceededError(
            f"File size ({len(file_bytes)} bytes) exceeds maximum permitted limit ({max_size_bytes} bytes)."
        )

    _validate_filename(filename)


# ==============================================================================
# 5. Package Creation & Encryption (Hybrid Encryption + RSA-PSS Signing)
# ==============================================================================

def create_encrypted_package(
    file_bytes: bytes,
    original_filename: str,
    content_type: str,
    sender_signing_private_pem: str,
    recipient_encryption_public_pem: str,
    sender_user_id: str,
    recipient_user_id: str,
    max_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
) -> EncryptedPackageResult:
    """Execute hybrid encryption and digital signing to build a tamper-evident package.

    Steps:
      1. Enforce size and filename checks via validate_file_metadata.
      2. Validate and load keys (ensuring RSA modulus >= 2048 bits).
      3. Generate fresh 256-bit AES key and fresh 96-bit nonce.
      4. Wrap AES key using recipient's RSA-OAEP public key.
      5. Construct header metadata JSON with base64-encoded wrapped key and nonce.
      6. Encrypt file_bytes using AES-256-GCM with header_bytes as Associated Data (AAD).
      7. Sign (header_bytes || SHA-256(ciphertext)) using sender's RSA-PSS private key.
      8. Assemble into binary .pkg wire format.

    Returns:
        EncryptedPackageResult containing package ID, serialized binary, and metadata.

    Raises:
        FileSizeLimitExceededError: If file exceeds limit.
        ValueError: If filename is invalid or contains path traversal.
        InvalidKeyMaterialError: If provided keys are invalid or < 2048 bits.
        CryptoEngineError: For internal cryptographic failures.
    """
    # 1. Metadata and size validation
    validate_file_metadata(original_filename, file_bytes, max_size_bytes=max_size_bytes)

    if not isinstance(sender_user_id, str) or not sender_user_id.strip():
        raise ValueError("sender_user_id must be a non-empty string.")
    if not isinstance(recipient_user_id, str) or not recipient_user_id.strip():
        raise ValueError("recipient_user_id must be a non-empty string.")

    # 2. Key validation and fingerprinting
    sender_signing_priv_key = _load_private_key(sender_signing_private_pem)
    recipient_enc_pub_key = load_public_key(recipient_encryption_public_pem)

    sender_signing_pub_pem = sender_signing_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    sender_signing_fingerprint = compute_public_key_fingerprint(sender_signing_pub_pem)
    recipient_enc_fingerprint = compute_public_key_fingerprint(recipient_encryption_public_pem)

    # 3. Generate fresh symmetric key material
    aes_key = os.urandom(AES_KEY_SIZE_BYTES)
    nonce = os.urandom(AES_GCM_NONCE_SIZE_BYTES)

    # 4. Wrap AES key using RSA-OAEP (SHA-256, MGF1-SHA-256)
    try:
        wrapped_aes_key = recipient_enc_pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise CryptoEngineError(f"RSA-OAEP key wrapping failed: {e}") from e

    package_id = f"pkg_{uuid.uuid4().hex}"

    # 5. Construct Header Metadata Dictionary and deterministic JSON bytes
    header_dict = {
        "version": CURRENT_PACKAGE_VERSION,
        "package_id": package_id,
        "original_filename": original_filename,
        "content_type": content_type or "application/octet-stream",
        "file_size": len(file_bytes),
        "sender_user_id": sender_user_id,
        "recipient_user_id": recipient_user_id,
        "sender_signing_fingerprint": sender_signing_fingerprint,
        "recipient_encryption_fingerprint": recipient_enc_fingerprint,
        "encrypted_aes_key_b64": base64.b64encode(wrapped_aes_key).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
    }
    # Deterministic JSON serialization
    header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # 6. Encrypt file using AES-256-GCM with header_bytes as AAD
    try:
        aesgcm = AESGCM(aes_key)
        encrypted_data = aesgcm.encrypt(nonce, bytes(file_bytes), associated_data=header_bytes)
        ciphertext = encrypted_data[:-AES_GCM_TAG_SIZE_BYTES]
        auth_tag = encrypted_data[-AES_GCM_TAG_SIZE_BYTES:]
    except Exception as e:
        raise CryptoEngineError(f"AES-GCM encryption failed: {e}") from e
    finally:
        del aes_key

    # 7. Digitally sign (header_bytes || SHA-256(ciphertext)) using RSA-PSS
    ciphertext_digest = hashlib.sha256(ciphertext).digest()
    signature_payload = header_bytes + ciphertext_digest

    try:
        signature = sender_signing_priv_key.sign(
            signature_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception as e:
        raise CryptoEngineError(f"RSA-PSS signing failed: {e}") from e

    # 8. Assemble package binary wire format:
    # Magic (5B) | Version (2B) | Header Length (4B) | Header Bytes | Sig Length (2B) | Sig Bytes | Tag (16B) | Ciphertext
    package_bytes = (
        PACKAGE_MAGIC
        + struct.pack(">H", CURRENT_PACKAGE_VERSION)
        + struct.pack(">I", len(header_bytes))
        + header_bytes
        + struct.pack(">H", len(signature))
        + signature
        + auth_tag
        + ciphertext
    )

    metadata = PackageMetadata(
        version=CURRENT_PACKAGE_VERSION,
        package_id=package_id,
        original_filename=original_filename,
        content_type=content_type or "application/octet-stream",
        file_size_bytes=len(file_bytes),
        sender_user_id=sender_user_id,
        recipient_user_id=recipient_user_id,
        sender_signing_fingerprint=sender_signing_fingerprint,
        recipient_encryption_fingerprint=recipient_enc_fingerprint,
    )

    return EncryptedPackageResult(
        package_id=package_id,
        package_bytes=package_bytes,
        metadata=metadata,
    )


# ==============================================================================
# 6. Package Verification & Decryption
# ==============================================================================

def verify_and_decrypt_package(
    package_bytes: bytes,
    sender_signing_public_pem: str,
    recipient_encryption_private_pem: str,
    max_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
) -> DecryptedFileResult:
    """Verify signature, authenticate, and decrypt a Gupit package.

    Security Guarantee:
      No plaintext bytes are produced or yielded if signature verification
      fails or if AES-GCM authentication tag check fails.

    Steps:
      1. Parse package framing, magic bytes, version, and enforce size limits.
      2. Parse and validate header JSON structure, field types, and safe filename.
      3. Verify RSA-PSS signature against sender_signing_public_pem.
         -> On failure: raise SignatureVerificationError immediately.
      4. Unwrap AES key using recipient_encryption_private_pem (RSA-OAEP).
         -> On failure: raise DecryptionAuthenticationError.
      5. Decrypt ciphertext using AES-256-GCM with header_bytes as AAD and verify tag.
         -> On failure: raise DecryptionAuthenticationError.
      6. Return DecryptedFileResult with verified plaintext bytes and safe metadata.

    Returns:
        DecryptedFileResult with verified plaintext bytes and safe filename.

    Raises:
        MalformedPackageError: If binary format, magic bytes, or framing is invalid.
        UnsupportedPackageVersionError: If version is unrecognized.
        FileSizeLimitExceededError: If package size or decrypted content exceeds limit.
        InvalidKeyMaterialError: If public or private key PEM is invalid.
        SignatureVerificationError: If sender digital signature fails or fingerprint mismatches.
        DecryptionAuthenticationError: If tag check fails or key cannot be unwrapped.
    """
    if not isinstance(package_bytes, (bytes, bytearray)):
        raise MalformedPackageError("Package data must be bytes or bytearray.")

    # Enforce maximum allowable package size (file limit + header allowance)
    max_allowed_package_len = max_size_bytes + MAX_PACKAGE_OVERHEAD_BYTES
    if len(package_bytes) > max_allowed_package_len:
        raise FileSizeLimitExceededError(
            f"Package binary size ({len(package_bytes)} bytes) exceeds maximum allowable limit ({max_allowed_package_len} bytes)."
        )

    # 1. Check minimum framing header: Magic(5) + Version(2) + HeaderLength(4) = 11 bytes
    min_framing_len = len(PACKAGE_MAGIC) + 2 + 4
    if len(package_bytes) < min_framing_len:
        raise MalformedPackageError("Package is truncated: insufficient header framing.")

    magic = package_bytes[:5]
    if magic != PACKAGE_MAGIC:
        raise MalformedPackageError(f"Invalid package magic bytes: expected {PACKAGE_MAGIC!r}, got {magic!r}.")

    (version,) = struct.unpack(">H", package_bytes[5:7])
    if version != CURRENT_PACKAGE_VERSION:
        raise UnsupportedPackageVersionError(
            f"Unsupported package version: {version}. Only version {CURRENT_PACKAGE_VERSION} is supported."
        )

    (header_len,) = struct.unpack(">I", package_bytes[7:11])
    if header_len == 0 or header_len > MAX_HEADER_JSON_BYTES:
        raise MalformedPackageError(f"Invalid header length: {header_len} bytes.")

    offset = 11

    # Check that header bytes + signature length uint16 can be read
    if len(package_bytes) < offset + header_len + 2:
        raise MalformedPackageError("Package is truncated: incomplete header or signature length.")

    header_bytes = package_bytes[offset : offset + header_len]
    offset += header_len

    (sig_len,) = struct.unpack(">H", package_bytes[offset : offset + 2])
    if sig_len < MIN_SIGNATURE_BYTES or sig_len > MAX_SIGNATURE_BYTES:
        raise MalformedPackageError(f"Invalid signature length: {sig_len} bytes.")

    offset += 2

    # Check that signature bytes + auth tag (16B) can be read
    if len(package_bytes) < offset + sig_len + AES_GCM_TAG_SIZE_BYTES:
        raise MalformedPackageError("Package is truncated: incomplete signature or authentication tag.")

    signature_bytes = package_bytes[offset : offset + sig_len]
    offset += sig_len

    auth_tag = package_bytes[offset : offset + AES_GCM_TAG_SIZE_BYTES]
    offset += AES_GCM_TAG_SIZE_BYTES

    ciphertext = package_bytes[offset:]

    # 2. Parse and validate JSON header metadata
    try:
        header_json_str = header_bytes.decode("utf-8")
        header_dict = json.loads(header_json_str)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise MalformedPackageError("Package header is not valid UTF-8 JSON.") from e

    required_fields = [
        "version",
        "package_id",
        "original_filename",
        "content_type",
        "file_size",
        "sender_user_id",
        "recipient_user_id",
        "sender_signing_fingerprint",
        "recipient_encryption_fingerprint",
        "encrypted_aes_key_b64",
        "nonce_b64",
    ]
    for field in required_fields:
        if field not in header_dict:
            raise MalformedPackageError(f"Missing required header field: '{field}'.")

    if header_dict["version"] != version:
        raise MalformedPackageError("Header version field does not match binary envelope version.")

    # Validate filename inside header using strict sanitization
    original_filename = header_dict["original_filename"]
    try:
        _validate_filename(original_filename)
    except ValueError as e:
        raise MalformedPackageError(f"Header original_filename validation failed: {e}") from e

    # Validate expected file size and ciphertext length
    expected_file_size = header_dict["file_size"]
    if not isinstance(expected_file_size, int) or expected_file_size < 0:
        raise MalformedPackageError("Header file_size must be a non-negative integer.")

    if expected_file_size > max_size_bytes:
        raise FileSizeLimitExceededError(
            f"Package declared file size ({expected_file_size} bytes) exceeds maximum limit ({max_size_bytes} bytes)."
        )

    if len(ciphertext) != expected_file_size:
        raise MalformedPackageError(
            f"Package ciphertext size mismatch: expected {expected_file_size} bytes, got {len(ciphertext)}."
        )

    # 3. Load Keys (validates format and minimum 2048-bit modulus)
    sender_signing_pub_key = load_public_key(sender_signing_public_pem)
    recipient_enc_priv_key = _load_private_key(recipient_encryption_private_pem)

    # Verify recipient key matches the envelope's target recipient fingerprint
    recipient_pub_pem = recipient_enc_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    actual_recipient_fp = compute_public_key_fingerprint(recipient_pub_pem)
    if header_dict["recipient_encryption_fingerprint"] != actual_recipient_fp:
        raise DecryptionAuthenticationError(
            f"Recipient key mismatch: package was encrypted for key {header_dict['recipient_encryption_fingerprint']}, "
            f"provided key is {actual_recipient_fp}."
        )

    # 4. Strict Signature Verification (BEFORE Decryption)
    # The signature covers header_bytes || SHA-256(ciphertext)
    ciphertext_digest = hashlib.sha256(ciphertext).digest()
    signature_payload = header_bytes + ciphertext_digest

    try:
        sender_signing_pub_key.verify(
            signature_bytes,
            signature_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as e:
        raise SignatureVerificationError(
            "RSA-PSS signature verification failed against sender signing public key."
        ) from e
    except Exception as e:
        raise SignatureVerificationError(f"Signature verification failure: {e}") from e

    # Check sender fingerprint in header matches sender public key provided
    expected_sender_fp = compute_public_key_fingerprint(sender_signing_public_pem)
    if header_dict["sender_signing_fingerprint"] != expected_sender_fp:
        raise SignatureVerificationError(
            f"Sender fingerprint mismatch: package claims {header_dict['sender_signing_fingerprint']}, "
            f"provided key is {expected_sender_fp}."
        )

    # 5. Unwrap AES session key using RSA-OAEP
    try:
        wrapped_aes_key = base64.b64decode(header_dict["encrypted_aes_key_b64"])
    except Exception as e:
        raise MalformedPackageError("Failed to decode base64 wrapped AES key.") from e

    try:
        aes_key = recipient_enc_priv_key.decrypt(
            wrapped_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise DecryptionAuthenticationError(
            "Failed to unwrap AES session key: recipient private key is incorrect or key material was corrupted."
        ) from e

    if len(aes_key) != AES_KEY_SIZE_BYTES:
        raise DecryptionAuthenticationError("Recovered session key has invalid length.")

    # 6. Authenticated Decryption with AES-256-GCM
    try:
        nonce = base64.b64decode(header_dict["nonce_b64"])
    except Exception as e:
        raise MalformedPackageError("Failed to decode base64 nonce.") from e

    if len(nonce) != AES_GCM_NONCE_SIZE_BYTES:
        raise MalformedPackageError(f"Nonce must be {AES_GCM_NONCE_SIZE_BYTES} bytes, got {len(nonce)}.")

    try:
        aesgcm = AESGCM(aes_key)
        # AESGCM decrypt expects ciphertext + auth_tag, authenticated against AAD (header_bytes)
        plaintext = aesgcm.decrypt(nonce, ciphertext + auth_tag, associated_data=header_bytes)
    except InvalidTag as e:
        raise DecryptionAuthenticationError(
            "AES-GCM tag verification failed: ciphertext or header has been modified."
        ) from e
    except Exception as e:
        raise DecryptionAuthenticationError(f"Decryption failed: {e}") from e
    finally:
        del aes_key

    # Validate recovered file size against manifest
    if len(plaintext) != header_dict["file_size"]:
        raise DecryptionAuthenticationError(
            f"Decrypted payload length ({len(plaintext)}) does not match manifest file_size ({header_dict['file_size']})."
        )

    return DecryptedFileResult(
        original_filename=original_filename,
        content_type=header_dict["content_type"],
        file_bytes=plaintext,
        file_size_bytes=len(plaintext),
        sender_signing_fingerprint=header_dict["sender_signing_fingerprint"],
    )
