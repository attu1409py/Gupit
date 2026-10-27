"""Comprehensive unit tests for Gupit Cryptographic Engine.

Tests:
1. RSA key generation (2048, 3072-bit), SPKI/PKCS#8 serialization, and key separation.
2. Public key fingerprint generation, determinism, and loading validation.
3. Private key at-rest protection with AES-256-GCM and server master key.
4. File metadata and size limit validation with directory traversal protection.
5. End-to-end hybrid encryption and authenticated decryption (text, binary, empty files).
6. Nonce and AES session key freshness across repeated operations.
7. Package binary wire framing (.pkg) conformance.
8. Tampering, bit-flip, and forgery rejection across ciphertext, tag, header, nonce, wrapped key, and signature.
9. Cross-user rejection (wrong sender public key, wrong recipient private key).
10. Malformed, truncated, and unsupported package version rejection.
11. Safe failure behavior with zero plaintext leakage.
"""

import base64
import json
import os
import struct
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
    compute_public_key_fingerprint,
    serialize_public_key,
    load_public_key,
    serialize_private_key,
    load_private_key,
    protect_private_key,
    unprotect_private_key,
    validate_file_metadata,
    create_encrypted_package,
    verify_and_decrypt_package,
    PACKAGE_MAGIC,
    CURRENT_PACKAGE_VERSION,
    DEFAULT_MAX_FILE_SIZE,
    MAX_PACKAGE_OVERHEAD_BYTES,
)


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture(scope="module")
def sender_keys():
    """Generate a 2048-bit keypair for fast test execution."""
    return generate_rsa_keypair(key_size_bits=2048)


@pytest.fixture(scope="module")
def recipient_keys():
    """Generate a separate 2048-bit keypair for recipient."""
    return generate_rsa_keypair(key_size_bits=2048)


@pytest.fixture(scope="module")
def third_party_keys():
    """Generate an unauthorized third party keypair."""
    return generate_rsa_keypair(key_size_bits=2048)


@pytest.fixture
def master_key():
    """32-byte server master key."""
    return os.urandom(32)


# ==============================================================================
# 1. Key Management Tests
# ==============================================================================

def test_rsa_key_generation():
    """Verify RSA key pair generation with correct PEM headers."""
    kp = generate_rsa_keypair(key_size_bits=2048)
    assert "-----BEGIN PUBLIC KEY-----" in kp.public_pem
    assert "-----END PUBLIC KEY-----" in kp.public_pem
    assert "-----BEGIN PRIVATE KEY-----" in kp.private_pem
    assert "-----END PRIVATE KEY-----" in kp.private_pem


def test_rsa_key_separation(sender_keys, recipient_keys):
    """Confirm separate key pairs produce distinct public and private keys."""
    assert sender_keys.public_pem != recipient_keys.public_pem
    assert sender_keys.private_pem != recipient_keys.private_pem


def test_public_key_serialization_and_reloading(sender_keys):
    """Test loading and re-serializing RSA public keys."""
    pub_key_obj = load_public_key(sender_keys.public_pem)
    serialized = serialize_public_key(pub_key_obj)
    assert serialized.strip() == sender_keys.public_pem.strip()


def test_load_public_key_malformed():
    """Ensure malformed or non-PEM public keys raise InvalidKeyMaterialError."""
    with pytest.raises(InvalidKeyMaterialError):
        load_public_key("NOT_A_VALID_PEM")

    with pytest.raises(InvalidKeyMaterialError):
        load_public_key("")

    with pytest.raises(InvalidKeyMaterialError):
        # Passing private key to load_public_key
        kp = generate_rsa_keypair(2048)
        load_public_key(kp.private_pem)


def test_serialize_public_key_invalid_object():
    """Ensure serializing non-RSAPublicKey raises InvalidKeyMaterialError."""
    with pytest.raises(InvalidKeyMaterialError):
        serialize_public_key("string_not_key")


def test_public_key_fingerprint(sender_keys, recipient_keys):
    """Verify SHA-256 public key fingerprinting is consistent and distinct."""
    fp1 = compute_public_key_fingerprint(sender_keys.public_pem)
    fp2 = compute_public_key_fingerprint(sender_keys.public_pem)
    assert fp1 == fp2
    assert len(fp1) == 64
    assert all(c in "0123456789abcdef" for c in fp1)

    fp_recipient = compute_public_key_fingerprint(recipient_keys.public_pem)
    assert fp1 != fp_recipient


def test_compute_fingerprint_invalid_key():
    """Verify invalid public key raises InvalidKeyMaterialError."""
    with pytest.raises(InvalidKeyMaterialError):
        compute_public_key_fingerprint("corrupt_key_content")


# ==============================================================================
# 2. Private Key Protection Tests
# ==============================================================================

def test_protect_and_unprotect_private_key(sender_keys, master_key):
    """Verify at-rest private key encryption and decryption using master key."""
    blob = protect_private_key(sender_keys.private_pem, master_key)
    assert isinstance(blob, bytes)
    assert len(blob) > 28  # Nonce(12) + Tag(16) + Ciphertext

    # Decrypt and verify exact match
    recovered_pem = unprotect_private_key(blob, master_key)
    assert recovered_pem == sender_keys.private_pem


def test_unprotect_private_key_wrong_master_key(sender_keys, master_key):
    """Verify decryption fails when supplied wrong master key."""
    blob = protect_private_key(sender_keys.private_pem, master_key)
    wrong_key = os.urandom(32)

    with pytest.raises(DecryptionAuthenticationError):
        unprotect_private_key(blob, wrong_key)


def test_unprotect_private_key_tampered_blob(sender_keys, master_key):
    """Verify tampering with private key blob raises DecryptionAuthenticationError."""
    blob = bytearray(protect_private_key(sender_keys.private_pem, master_key))
    blob[-1] ^= 0xFF  # Flip bit in ciphertext

    with pytest.raises(DecryptionAuthenticationError):
        unprotect_private_key(bytes(blob), master_key)


def test_protect_private_key_invalid_master_key_length(sender_keys):
    """Verify master key of wrong length raises ValueError."""
    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        protect_private_key(sender_keys.private_pem, b"too_short")

    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        unprotect_private_key(b"blob", b"too_short")


def test_protect_private_key_invalid_pem(master_key):
    """Verify invalid private key PEM raises InvalidKeyMaterialError."""
    with pytest.raises(InvalidKeyMaterialError):
        protect_private_key("INVALID_PRIVATE_KEY", master_key)


# ==============================================================================
# 3. File Metadata Validation Tests
# ==============================================================================

def test_validate_file_metadata_exact_limit_and_one_byte_over():
    """Verify that a file exactly at the limit is accepted and one byte over is rejected."""
    # Custom limit check (e.g. 100 bytes)
    validate_file_metadata("limit.bin", b"0" * 100, max_size_bytes=100)
    with pytest.raises(FileSizeLimitExceededError):
        validate_file_metadata("over.bin", b"0" * 101, max_size_bytes=100)

    # 25 MiB standard contract limit (26,214,400 bytes)
    assert DEFAULT_MAX_FILE_SIZE == 25 * 1024 * 1024

    exact_25mib = b"X" * DEFAULT_MAX_FILE_SIZE
    validate_file_metadata("exact_25mib.bin", exact_25mib)

    over_25mib = b"X" * (DEFAULT_MAX_FILE_SIZE + 1)
    with pytest.raises(FileSizeLimitExceededError):
        validate_file_metadata("over_25mib.bin", over_25mib)


def test_validate_file_metadata_dangerous_filenames():
    """Verify path traversal and dangerous filename characters raise ValueError."""
    dangerous_names = [
        "../secret.txt",
        "..\\secret.txt",
        "/etc/passwd",
        "C:\\Windows\\System32\\cmd.exe",
        "path/to/file.txt",
        "file\x00.txt",
        "",
        "   ",
        ".",
        "..",
    ]
    for name in dangerous_names:
        with pytest.raises(ValueError):
            validate_file_metadata(name, b"test")


# ==============================================================================
# 4. End-to-End Encryption & Decryption Tests
# ==============================================================================

def test_encrypt_and_decrypt_text_file(sender_keys, recipient_keys):
    """Verify encrypting and decrypting a UTF-8 text file."""
    plaintext = "Confidential Gupit Document: Hybrid Cryptography in action! 🚀".encode("utf-8")
    filename = "report.txt"

    pkg_result = create_encrypted_package(
        file_bytes=plaintext,
        original_filename=filename,
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    assert pkg_result.package_id.startswith("pkg_")
    assert pkg_result.metadata.original_filename == filename
    assert pkg_result.metadata.file_size_bytes == len(plaintext)

    dec_result = verify_and_decrypt_package(
        package_bytes=pkg_result.package_bytes,
        sender_signing_public_pem=sender_keys.public_pem,
        recipient_encryption_private_pem=recipient_keys.private_pem,
    )

    assert dec_result.file_bytes == plaintext
    assert dec_result.original_filename == filename
    assert dec_result.content_type == "text/plain"
    assert dec_result.file_size_bytes == len(plaintext)
    assert dec_result.sender_signing_fingerprint == compute_public_key_fingerprint(sender_keys.public_pem)


def test_encrypt_and_decrypt_binary_file(sender_keys, recipient_keys):
    """Verify encrypting and recovering arbitrary binary data."""
    # 64 KB random binary payload
    payload = os.urandom(65536)
    filename = "binary_archive.bin"

    pkg_result = create_encrypted_package(
        file_bytes=payload,
        original_filename=filename,
        content_type="application/octet-stream",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    dec_result = verify_and_decrypt_package(
        package_bytes=pkg_result.package_bytes,
        sender_signing_public_pem=sender_keys.public_pem,
        recipient_encryption_private_pem=recipient_keys.private_pem,
    )

    assert dec_result.file_bytes == payload
    assert dec_result.file_size_bytes == len(payload)


def test_encrypt_and_decrypt_empty_file(sender_keys, recipient_keys):
    """Verify encryption and authenticated recovery of a zero-byte file."""
    empty_bytes = b""
    filename = "empty.txt"

    pkg_result = create_encrypted_package(
        file_bytes=empty_bytes,
        original_filename=filename,
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    dec_result = verify_and_decrypt_package(
        package_bytes=pkg_result.package_bytes,
        sender_signing_public_pem=sender_keys.public_pem,
        recipient_encryption_private_pem=recipient_keys.private_pem,
    )

    assert dec_result.file_bytes == b""
    assert dec_result.file_size_bytes == 0


def test_fresh_aes_keys_and_nonces_per_operation(sender_keys, recipient_keys):
    """Verify repeated encryption of identical payload generates unique ciphertexts and nonces."""
    file_bytes = b"Identical plain text data"

    pkg1 = create_encrypted_package(
        file_bytes=file_bytes,
        original_filename="test.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    pkg2 = create_encrypted_package(
        file_bytes=file_bytes,
        original_filename="test.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    assert pkg1.package_bytes != pkg2.package_bytes
    assert pkg1.package_id != pkg2.package_id


def test_encrypt_and_decrypt_25mib_exact_limit(sender_keys, recipient_keys):
    """Verify encrypting and decrypting a file exactly at the 25 MiB limit (26,214,400 bytes)."""
    exact_payload = b"Z" * (25 * 1024 * 1024)
    filename = "exact_25mib.bin"

    pkg_result = create_encrypted_package(
        file_bytes=exact_payload,
        original_filename=filename,
        content_type="application/octet-stream",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    # Package must be larger than plaintext due to framing overhead, but within allowable package margin
    assert len(pkg_result.package_bytes) > len(exact_payload)
    assert len(pkg_result.package_bytes) <= DEFAULT_MAX_FILE_SIZE + MAX_PACKAGE_OVERHEAD_BYTES

    dec_result = verify_and_decrypt_package(
        package_bytes=pkg_result.package_bytes,
        sender_signing_public_pem=sender_keys.public_pem,
        recipient_encryption_private_pem=recipient_keys.private_pem,
    )

    assert dec_result.file_bytes == exact_payload
    assert dec_result.file_size_bytes == 25 * 1024 * 1024
    assert dec_result.original_filename == filename


def test_package_binary_wire_format(sender_keys, recipient_keys):
    """Verify the binary .pkg layout matches the exact specification."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Hello Gupit wire format",
        original_filename="hello.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    data = pkg_result.package_bytes
    assert data[:5] == PACKAGE_MAGIC
    (version,) = struct.unpack(">H", data[5:7])
    assert version == CURRENT_PACKAGE_VERSION

    (header_len,) = struct.unpack(">I", data[7:11])
    assert header_len > 0

    header_bytes = data[11 : 11 + header_len]
    header = json.loads(header_bytes.decode("utf-8"))
    assert header["original_filename"] == "hello.txt"
    assert "encrypted_aes_key_b64" in header
    assert "nonce_b64" in header

    offset = 11 + header_len
    (sig_len,) = struct.unpack(">H", data[offset : offset + 2])
    assert sig_len > 0


# ==============================================================================
# 5. Tampering, Bit-Flipping & Forgery Tests
# ==============================================================================

def test_tampered_ciphertext_fails(sender_keys, recipient_keys):
    """Altering any bit of ciphertext must cause signature verification or decryption failure."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Important secret document contents",
        original_filename="doc.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    tampered_bytes = bytearray(pkg_result.package_bytes)
    # Flip the very last byte (part of ciphertext)
    tampered_bytes[-1] ^= 0x01

    with pytest.raises((SignatureVerificationError, DecryptionAuthenticationError)):
        verify_and_decrypt_package(
            package_bytes=bytes(tampered_bytes),
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_tampered_signature_fails(sender_keys, recipient_keys):
    """Altering signature bytes must raise SignatureVerificationError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Signed message",
        original_filename="signed.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    data = pkg_result.package_bytes
    (header_len,) = struct.unpack(">I", data[7:11])
    sig_offset = 11 + header_len + 2  # start of signature bytes

    tampered_bytes = bytearray(data)
    tampered_bytes[sig_offset] ^= 0xFF

    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt_package(
            package_bytes=bytes(tampered_bytes),
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_tampered_header_fails(sender_keys, recipient_keys):
    """Altering header metadata must trigger SignatureVerificationError immediately."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Secret data",
        original_filename="secret.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    data = bytearray(pkg_result.package_bytes)
    # Tamper with byte inside the JSON header (e.g. index 15)
    data[15] ^= 0x01

    with pytest.raises((SignatureVerificationError, MalformedPackageError)):
        verify_and_decrypt_package(
            package_bytes=bytes(data),
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_tampered_auth_tag_fails(sender_keys, recipient_keys):
    """Altering authentication tag must trigger DecryptionAuthenticationError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Data with tag",
        original_filename="tag.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    data = pkg_result.package_bytes
    (header_len,) = struct.unpack(">I", data[7:11])
    sig_len_offset = 11 + header_len
    (sig_len,) = struct.unpack(">H", data[sig_len_offset : sig_len_offset + 2])
    tag_offset = sig_len_offset + 2 + sig_len

    tampered_bytes = bytearray(data)
    tampered_bytes[tag_offset] ^= 0xFF  # Flip bit in auth tag

    with pytest.raises(DecryptionAuthenticationError):
        verify_and_decrypt_package(
            package_bytes=bytes(tampered_bytes),
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_wrong_sender_public_key_fails(sender_keys, recipient_keys, third_party_keys):
    """Attempting verification with wrong sender public key must raise SignatureVerificationError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Sender verification test",
        original_filename="sender.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt_package(
            package_bytes=pkg_result.package_bytes,
            sender_signing_public_pem=third_party_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_wrong_recipient_private_key_fails(sender_keys, recipient_keys, third_party_keys):
    """Attempting decryption with wrong recipient private key must raise DecryptionAuthenticationError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Recipient authorization test",
        original_filename="recip.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    with pytest.raises(DecryptionAuthenticationError):
        verify_and_decrypt_package(
            package_bytes=pkg_result.package_bytes,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=third_party_keys.private_pem,
        )


# ==============================================================================
# 6. Malformed & Truncated Package Tests
# ==============================================================================

def test_truncated_packages(sender_keys, recipient_keys):
    """Truncated package slices must raise MalformedPackageError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Truncation test",
        original_filename="trunc.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )
    full_data = pkg_result.package_bytes

    truncation_points = [0, 4, 10, 20, 50, len(full_data) - 5]
    for pt in truncation_points:
        with pytest.raises(MalformedPackageError):
            verify_and_decrypt_package(
                package_bytes=full_data[:pt],
                sender_signing_public_pem=sender_keys.public_pem,
                recipient_encryption_private_pem=recipient_keys.private_pem,
            )


def test_invalid_magic_bytes(sender_keys, recipient_keys):
    """Corrupt magic bytes must raise MalformedPackageError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Magic bytes test",
        original_filename="magic.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )
    corrupted = b"BADMG" + pkg_result.package_bytes[5:]

    with pytest.raises(MalformedPackageError, match="Invalid package magic bytes"):
        verify_and_decrypt_package(
            package_bytes=corrupted,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_unsupported_package_version(sender_keys, recipient_keys):
    """Package with unsupported version number must raise UnsupportedPackageVersionError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Version test",
        original_filename="ver.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    # Set version to 99 (0x0063)
    corrupted = pkg_result.package_bytes[:5] + struct.pack(">H", 99) + pkg_result.package_bytes[7:]

    with pytest.raises(UnsupportedPackageVersionError, match="Unsupported package version"):
        verify_and_decrypt_package(
            package_bytes=corrupted,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_no_plaintext_leakage_on_failure(sender_keys, recipient_keys):
    """Verify that failed decryption never leaks usable plaintext."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Top Secret Zero Leakage",
        original_filename="secret.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    tampered = bytearray(pkg_result.package_bytes)
    tampered[-1] ^= 0x01

    try:
        verify_and_decrypt_package(
            package_bytes=bytes(tampered),
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )
        pytest.fail("Decryption should have raised an exception")
    except CryptoEngineError:
        # Expected failure: verify no plaintext is produced
        pass


def test_tampered_nonce_fails(sender_keys, recipient_keys):
    """Modifying the nonce in the package header must cause verification or tag failure."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Nonce test",
        original_filename="nonce.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    data = pkg_result.package_bytes
    (header_len,) = struct.unpack(">I", data[7:11])
    header_bytes = data[11 : 11 + header_len]
    header_dict = json.loads(header_bytes.decode("utf-8"))

    # Tamper with the nonce in the header
    raw_nonce = bytearray(base64.b64decode(header_dict["nonce_b64"]))
    raw_nonce[0] ^= 0xFF
    header_dict["nonce_b64"] = base64.b64encode(bytes(raw_nonce)).decode("ascii")

    new_header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tampered_package = (
        data[:7]
        + struct.pack(">I", len(new_header_bytes))
        + new_header_bytes
        + data[11 + header_len :]
    )

    with pytest.raises((SignatureVerificationError, DecryptionAuthenticationError, MalformedPackageError)):
        verify_and_decrypt_package(
            package_bytes=tampered_package,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_tampered_wrapped_aes_key_fails(sender_keys, recipient_keys):
    """Modifying the wrapped AES key in the package header must cause verification or unwrapping failure."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Wrapped key test",
        original_filename="key.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    data = pkg_result.package_bytes
    (header_len,) = struct.unpack(">I", data[7:11])
    header_bytes = data[11 : 11 + header_len]
    header_dict = json.loads(header_bytes.decode("utf-8"))

    # Tamper with the wrapped AES key
    raw_key = bytearray(base64.b64decode(header_dict["encrypted_aes_key_b64"]))
    raw_key[0] ^= 0xFF
    header_dict["encrypted_aes_key_b64"] = base64.b64encode(bytes(raw_key)).decode("ascii")

    new_header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tampered_package = (
        data[:7]
        + struct.pack(">I", len(new_header_bytes))
        + new_header_bytes
        + data[11 + header_len :]
    )

    with pytest.raises((SignatureVerificationError, DecryptionAuthenticationError, MalformedPackageError)):
        verify_and_decrypt_package(
            package_bytes=tampered_package,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_missing_header_fields_fail(sender_keys, recipient_keys):
    """Header with missing mandatory fields must raise MalformedPackageError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Field test",
        original_filename="fields.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    data = pkg_result.package_bytes
    (header_len,) = struct.unpack(">I", data[7:11])
    header_bytes = data[11 : 11 + header_len]
    header_dict = json.loads(header_bytes.decode("utf-8"))

    # Remove required field
    del header_dict["content_type"]

    new_header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tampered_package = (
        data[:7]
        + struct.pack(">I", len(new_header_bytes))
        + new_header_bytes
        + data[11 + header_len :]
    )

    with pytest.raises((MalformedPackageError, SignatureVerificationError)):
        verify_and_decrypt_package(
            package_bytes=tampered_package,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_create_package_size_limit_exceeded(sender_keys, recipient_keys):
    """Package creation exceeding max_size_bytes must raise FileSizeLimitExceededError."""
    # 1. Custom limit: 100 bytes succeeds, 101 bytes rejected
    pkg_at_limit = create_encrypted_package(
        file_bytes=b"0" * 100,
        original_filename="limit.bin",
        content_type="application/octet-stream",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
        max_size_bytes=100,
    )
    assert pkg_at_limit.metadata.file_size_bytes == 100

    with pytest.raises(FileSizeLimitExceededError):
        create_encrypted_package(
            file_bytes=b"0" * 101,
            original_filename="overflow.bin",
            content_type="application/octet-stream",
            sender_signing_private_pem=sender_keys.private_pem,
            recipient_encryption_public_pem=recipient_keys.public_pem,
            sender_user_id="usr_alice",
            recipient_user_id="usr_bob",
            max_size_bytes=100,
        )

    # 2. Default 25 MiB limit: 25 MiB + 1 byte rejected
    with pytest.raises(FileSizeLimitExceededError):
        create_encrypted_package(
            file_bytes=b"0" * (DEFAULT_MAX_FILE_SIZE + 1),
            original_filename="overflow_25mib.bin",
            content_type="application/octet-stream",
            sender_signing_private_pem=sender_keys.private_pem,
            recipient_encryption_public_pem=recipient_keys.public_pem,
            sender_user_id="usr_alice",
            recipient_user_id="usr_bob",
        )


def test_create_package_invalid_keys(recipient_keys):
    """Passing invalid key PEMs to package creation must raise InvalidKeyMaterialError."""
    with pytest.raises(InvalidKeyMaterialError):
        create_encrypted_package(
            file_bytes=b"test",
            original_filename="file.txt",
            content_type="text/plain",
            sender_signing_private_pem="INVALID_PRIVATE_KEY",
            recipient_encryption_public_pem=recipient_keys.public_pem,
            sender_user_id="usr_alice",
            recipient_user_id="usr_bob",
        )

    kp = generate_rsa_keypair(2048)
    with pytest.raises(InvalidKeyMaterialError):
        create_encrypted_package(
            file_bytes=b"test",
            original_filename="file.txt",
            content_type="text/plain",
            sender_signing_private_pem=kp.private_pem,
            recipient_encryption_public_pem="INVALID_PUBLIC_KEY",
            sender_user_id="usr_alice",
            recipient_user_id="usr_bob",
        )


def test_verify_package_invalid_keys(sender_keys, recipient_keys):
    """Passing invalid key PEMs to package verification must raise InvalidKeyMaterialError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"test",
        original_filename="file.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    with pytest.raises(InvalidKeyMaterialError):
        verify_and_decrypt_package(
            package_bytes=pkg_result.package_bytes,
            sender_signing_public_pem="INVALID_PUBLIC_KEY",
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )

    with pytest.raises(InvalidKeyMaterialError):
        verify_and_decrypt_package(
            package_bytes=pkg_result.package_bytes,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem="INVALID_PRIVATE_KEY",
        )


def test_default_3072_bit_key_lifecycle():
    """Verify that default 3072-bit keys function end-to-end for encryption and decryption."""
    keys_sender_3072 = generate_rsa_keypair(key_size_bits=3072)
    keys_recip_3072 = generate_rsa_keypair(key_size_bits=3072)

    payload = b"Testing 3072-bit standard RSA key pairs with Gupit"
    pkg = create_encrypted_package(
        file_bytes=payload,
        original_filename="doc_3072.txt",
        content_type="text/plain",
        sender_signing_private_pem=keys_sender_3072.private_pem,
        recipient_encryption_public_pem=keys_recip_3072.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    res = verify_and_decrypt_package(
        package_bytes=pkg.package_bytes,
        sender_signing_public_pem=keys_sender_3072.public_pem,
        recipient_encryption_private_pem=keys_recip_3072.private_pem,
    )

    assert res.file_bytes == payload
    assert res.file_size_bytes == len(payload)


# ==============================================================================
# 7. Additional Hardening & Passphrase Tests
# ==============================================================================

def test_private_key_passphrase_encryption_and_loading(sender_keys):
    """Verify standard PKCS#8 passphrase-protected private key export and import."""
    priv_obj = load_private_key(sender_keys.private_pem)
    passphrase = b"SuperSecretPassphrase123!"

    # Export encrypted PKCS#8
    encrypted_pem = serialize_private_key(priv_obj, password=passphrase)
    assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in encrypted_pem

    # Reload with correct passphrase
    reloaded_priv = load_private_key(encrypted_pem, password=passphrase)
    assert reloaded_priv.key_size == priv_obj.key_size

    # Reload unencrypted fails with require passphrase
    with pytest.raises(DecryptionAuthenticationError):
        load_private_key(encrypted_pem, password=None)

    # Reload with wrong passphrase fails
    with pytest.raises(DecryptionAuthenticationError):
        load_private_key(encrypted_pem, password=b"WrongPassphrase!")


def test_weak_rsa_key_rejection():
    """Verify that RSA keys under 2048 bits are rejected across all functions."""
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    from cryptography.hazmat.primitives import serialization as crypto_ser

    # Generate a weak 1024-bit RSA key for testing rejection
    weak_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak_priv_pem = weak_key.private_bytes(
        encoding=crypto_ser.Encoding.PEM,
        format=crypto_ser.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_ser.NoEncryption(),
    ).decode("utf-8")
    weak_pub_pem = weak_key.public_key().public_bytes(
        encoding=crypto_ser.Encoding.PEM,
        format=crypto_ser.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Rejection in load_public_key
    with pytest.raises(InvalidKeyMaterialError, match="at least 2048 bits"):
        load_public_key(weak_pub_pem)

    # Rejection in load_private_key
    with pytest.raises(InvalidKeyMaterialError, match="at least 2048 bits"):
        load_private_key(weak_priv_pem)


def test_validate_file_metadata_advanced_traversal_and_device_names():
    """Verify filename checks reject Windows drive letters, reserved device names, and control characters."""
    bad_filenames = [
        "C:autoexec.bat",
        "D:file.txt",
        "CON",
        "con.txt",
        "NUL",
        "PRN.pdf",
        "COM1",
        "LPT1.doc",
        "file\rname.txt",
        "file\nname.txt",
        "file\tname.txt",
    ]
    for bad_name in bad_filenames:
        with pytest.raises(ValueError):
            validate_file_metadata(bad_name, b"test")


def test_verify_package_oversized_rejection(sender_keys, recipient_keys):
    """Verify that packages claiming or containing data exceeding size limits raise FileSizeLimitExceededError."""
    payload = b"Payload within normal limits"
    pkg_result = create_encrypted_package(
        file_bytes=payload,
        original_filename="normal.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    # 1. Declared size / max_size_bytes restriction: payload exceeds custom limit of 10 bytes
    with pytest.raises(FileSizeLimitExceededError):
        verify_and_decrypt_package(
            package_bytes=pkg_result.package_bytes,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
            max_size_bytes=10,  # lower than payload (28 bytes)
        )

    # 2. Package wire bytes exceeding allowable package length (max_size_bytes + MAX_PACKAGE_OVERHEAD_BYTES)
    artificially_bloated_package = pkg_result.package_bytes + b"\x00" * (MAX_PACKAGE_OVERHEAD_BYTES + 10)
    with pytest.raises(FileSizeLimitExceededError, match="exceeds maximum allowable limit"):
        verify_and_decrypt_package(
            package_bytes=artificially_bloated_package,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
            max_size_bytes=len(payload),
        )


def test_verify_package_invalid_framing_lengths(sender_keys, recipient_keys):
    """Verify that abnormal header or signature lengths in package wire format raise MalformedPackageError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Test framing",
        original_filename="frame.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )
    data = pkg_result.package_bytes

    # 1. Header length zero
    corrupted_hdr_zero = data[:7] + struct.pack(">I", 0) + data[11:]
    with pytest.raises(MalformedPackageError, match="Invalid header length"):
        verify_and_decrypt_package(
            package_bytes=corrupted_hdr_zero,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )

    # 2. Header length > 64KB
    corrupted_hdr_huge = data[:7] + struct.pack(">I", 70000) + data[11:]
    with pytest.raises(MalformedPackageError, match="Invalid header length"):
        verify_and_decrypt_package(
            package_bytes=corrupted_hdr_huge,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=recipient_keys.private_pem,
        )


def test_verify_package_recipient_fingerprint_mismatch(sender_keys, recipient_keys, third_party_keys):
    """Verify that attempting decryption with a recipient key whose fingerprint differs from the envelope raises DecryptionAuthenticationError."""
    pkg_result = create_encrypted_package(
        file_bytes=b"Fingerprint mismatch test",
        original_filename="mismatch.txt",
        content_type="text/plain",
        sender_signing_private_pem=sender_keys.private_pem,
        recipient_encryption_public_pem=recipient_keys.public_pem,
        sender_user_id="usr_alice",
        recipient_user_id="usr_bob",
    )

    with pytest.raises(DecryptionAuthenticationError, match="Recipient key mismatch"):
        verify_and_decrypt_package(
            package_bytes=pkg_result.package_bytes,
            sender_signing_public_pem=sender_keys.public_pem,
            recipient_encryption_private_pem=third_party_keys.private_pem,
        )


