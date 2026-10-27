# Gupit Cryptographic Interface Specification

**Module:** `backend.app.services.crypto_engine`  
**Standard:** NIST / RFC 8017 / FIPS 186-4  
**Implementation Library:** Python `cryptography` (hazmat & high-level primitives)  
**Status:** Frozen Interface (Phase 1 Foundation)  

---

## 1. Overview & Primitives

Gupit applies **hybrid cryptography** with an authenticated, signed envelope architecture.

### Selected Algorithms:
1. **Symmetric Encryption:** AES-256 in Galois/Counter Mode (**AES-GCM**)
   - Key length: 256 bits (32 bytes), securely sampled from CSPRNG (`os.urandom(32)`).
   - Nonce length: 96 bits (12 bytes), fresh per encryption operation (`os.urandom(12)`).
   - Authentication Tag: 128 bits (16 bytes).
   - Associated Data (AAD): Versioned package header JSON bytes.
2. **Asymmetric Key Wrapping:** RSA-OAEP
   - Key length: 3072-bit or 4096-bit RSA (minimum 2048-bit; default 3072-bit).
   - Hash: SHA-256.
   - Mask Generation Function: MGF1 with SHA-256.
3. **Digital Signatures:** RSA-PSS
   - Hash: SHA-256.
   - Salt length: MGF1 with SHA-256, `salt_length=PSS.MAX_LENGTH` or `hashes.SHA256().digest_size`.
4. **Key Fingerprinting:**
   - Format: SHA-256 hex digest of the DER-encoded (SubjectPublicKeyInfo) public key.
5. **Private Key Storage Protection (Server-Side Prototype):**
   - AES-256-GCM encryption of private keys at rest using a 256-bit server master key.

---

## 2. Package Binary / Wire Format

A Gupit Encrypted Package (`.pkg`) is structured into explicit fields:

```
+--------------------------------------------------------------------------------+
| Magic Bytes: "GUPIT" (5 bytes: 0x47 0x55 0x50 0x49 0x54)                       |
+--------------------------------------------------------------------------------+
| Package Version: uint16 big-endian (0x00 0x01 = version 1)                     |
+--------------------------------------------------------------------------------+
| Header Length: uint32 big-endian                                              |
+--------------------------------------------------------------------------------+
| Header JSON (UTF-8 bytes):                                                     |
| {                                                                              |
|   "version": 1,                                                                |
|   "package_id": "pkg_...",                                                     |
|   "original_filename": "...",                                                  |
|   "content_type": "...",                                                       |
|   "file_size": 1048576,                                                        |
|   "sender_signing_fingerprint": "...",                                         |
|   "recipient_encryption_fingerprint": "...",                                   |
|   "encrypted_aes_key_b64": "...",                                              |
|   "nonce_b64": "..."                                                           |
| }                                                                              |
+--------------------------------------------------------------------------------+
| RSA-PSS Signature Length: uint16 big-endian (e.g. 384 bytes for 3072-bit RSA)   |
+--------------------------------------------------------------------------------+
| Signature Bytes: RSA-PSS(Header bytes || SHA-256(Ciphertext bytes))            |
+--------------------------------------------------------------------------------+
| AES-GCM Authentication Tag: 16 bytes                                           |
+--------------------------------------------------------------------------------+
| Ciphertext Bytes (AES-256-GCM encrypted file body)                             |
+--------------------------------------------------------------------------------+
```

---

## 3. Exception Hierarchy

All cryptographic errors derive from a base `CryptoEngineError`:

```python
class CryptoEngineError(Exception):
    """Base exception for all cryptographic failures in Gupit."""
    pass

class InvalidKeyMaterialError(CryptoEngineError):
    """Raised when PEM/DER key encoding is corrupt or unexpected algorithm/format."""
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
    """Raised when AES-GCM authentication tag verification or OAEP unwrapping fails."""
    pass
```

---

## 4. Data Types and Schemas

```python
from dataclasses import dataclass
from typing import NamedTuple

class KeyPairPEM(NamedTuple):
    public_pem: str
    private_pem: str

@dataclass(frozen=True)
class IdentityKeyMaterial:
    identity_id: str
    user_id: str
    encryption_public_pem: str
    signing_public_pem: str
    encryption_fingerprint: str
    signing_fingerprint: str

@dataclass(frozen=True)
class ProtectedPrivateKeyMaterial:
    identity_id: str
    encrypted_encryption_private_blob: bytes
    encrypted_signing_private_blob: bytes

@dataclass(frozen=True)
class PackageMetadata:
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
    package_id: str
    package_bytes: bytes
    metadata: PackageMetadata

@dataclass(frozen=True)
class DecryptedFileResult:
    original_filename: str
    content_type: str
    file_bytes: bytes
    file_size_bytes: int
    sender_signing_fingerprint: str
```

---

## 5. Python Function Signatures

The following interfaces are defined in `backend.app.services.crypto_engine`.  
*During foundation stage, these functions raise `NotImplementedError`.*

```python
def generate_rsa_keypair(key_size_bits: int = 3072) -> KeyPairPEM:
    """
    Generate an RSA key pair suitable for either OAEP encryption or PSS signing.
    
    Args:
        key_size_bits: Bit length of RSA modulus (must be >= 2048, default 3072).
        
    Returns:
        KeyPairPEM with public_pem and private_pem in PKCS#8 / SPKI PEM format.
        
    Raises:
        ValueError: If key_size_bits < 2048.
    """
    raise NotImplementedError("generate_rsa_keypair will be implemented in Phase 2.")


def compute_public_key_fingerprint(public_pem: str) -> str:
    """
    Compute a SHA-256 hexadecimal fingerprint from a PEM-encoded public key.
    
    Args:
        public_pem: Public key in SubjectPublicKeyInfo PEM format.
        
    Returns:
        64-character lowercase hex string of SHA-256 digest of DER bytes.
        
    Raises:
        InvalidKeyMaterialError: If PEM decoding fails or key format is invalid.
    """
    raise NotImplementedError("compute_public_key_fingerprint will be implemented in Phase 2.")


def protect_private_key(private_pem: str, master_key_bytes: bytes) -> bytes:
    """
    Encrypt a private key PEM string at rest using AES-256-GCM and the server master key.
    
    Args:
        private_pem: Unprotected private key in PEM format.
        master_key_bytes: 32-byte server master key from environment.
        
    Returns:
        Encrypted binary blob containing nonce (12B) + auth tag (16B) + ciphertext.
        
    Raises:
        ValueError: If master_key_bytes is not exactly 32 bytes.
        CryptoEngineError: On encryption failure.
    """
    raise NotImplementedError("protect_private_key will be implemented in Phase 2.")


def unprotect_private_key(encrypted_blob: bytes, master_key_bytes: bytes) -> str:
    """
    Decrypt a stored private key blob using the server master key and AES-256-GCM.
    
    Args:
        encrypted_blob: Binary blob created by protect_private_key.
        master_key_bytes: 32-byte server master key.
        
    Returns:
        Decrypted PEM string.
        
    Raises:
        DecryptionAuthenticationError: If master key is incorrect or blob is corrupted.
    """
    raise NotImplementedError("unprotect_private_key will be implemented in Phase 2.")


def validate_file_metadata(
    filename: str,
    file_bytes: bytes,
    max_size_bytes: int = 52428800
) -> None:
    """
    Sanitize filename and enforce file size policy.
    
    Args:
        filename: Original filename submitted by client.
        file_bytes: Raw bytes of uploaded file.
        max_size_bytes: Max permissible file size (default 50MB).
        
    Raises:
        FileSizeLimitExceededError: If len(file_bytes) > max_size_bytes.
        ValueError: If filename contains dangerous directory traversal patterns.
    """
    raise NotImplementedError("validate_file_metadata will be implemented in Phase 2.")


def create_encrypted_package(
    file_bytes: bytes,
    original_filename: str,
    content_type: str,
    sender_signing_private_pem: str,
    recipient_encryption_public_pem: str,
    sender_user_id: str,
    recipient_user_id: str,
    max_size_bytes: int = 52428800,
) -> EncryptedPackageResult:
    """
    Execute hybrid encryption and digital signing to build a tamper-evident package.
    
    Steps:
      1. Enforce size and filename checks via validate_file_metadata.
      2. Generate fresh 256-bit AES key and 96-bit nonce.
      3. Wrap AES key using recipient's RSA-OAEP public key.
      4. Encrypt file_bytes using AES-256-GCM; produce ciphertext and 128-bit tag.
      5. Construct header metadata JSON with fingerprints.
      6. Sign (header || SHA-256(ciphertext)) using sender's RSA-PSS private key.
      7. Assemble into binary .pkg wire format.
      
    Returns:
        EncryptedPackageResult containing package ID, serialized binary, and metadata.
        
    Raises:
        FileSizeLimitExceededError: If file exceeds limit.
        InvalidKeyMaterialError: If provided keys are invalid.
        CryptoEngineError: For internal cryptographic failures.
    """
    raise NotImplementedError("create_encrypted_package will be implemented in Phase 2.")


def verify_and_decrypt_package(
    package_bytes: bytes,
    sender_signing_public_pem: str,
    recipient_encryption_private_pem: str,
) -> DecryptedFileResult:
    """
    Verify signature, authenticate, and decrypt a Gupit package.
    
    Security Guarantee:
      No plaintext bytes are produced or yielded if signature verification
      fails or if AES-GCM authentication tag check fails.
      
    Steps:
      1. Parse package framing, magic bytes, and version.
      2. Validate version support (reject unknown versions).
      3. Verify RSA-PSS signature against sender_signing_public_pem.
         -> On failure: raise SignatureVerificationError immediately.
      4. Unwrap AES key using recipient_encryption_private_pem (RSA-OAEP).
         -> On failure: raise DecryptionAuthenticationError.
      5. Decrypt ciphertext using AES-256-GCM with header as AAD and verify tag.
         -> On failure: raise DecryptionAuthenticationError.
      6. Return DecryptedFileResult with verified plaintext bytes and metadata.
      
    Returns:
        DecryptedFileResult with verified plaintext bytes and safe filename.
        
    Raises:
        MalformedPackageError: If binary format or magic bytes are invalid.
        UnsupportedPackageVersionError: If version is unrecognized.
        SignatureVerificationError: If sender digital signature fails.
        DecryptionAuthenticationError: If tag check fails or key cannot be unwrapped.
    """
    raise NotImplementedError("verify_and_decrypt_package will be implemented in Phase 2.")
```
