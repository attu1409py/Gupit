"""Database entity definitions and metadata models for SQLite."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class UserModel:
    id: str
    username: str
    email: str
    password_hash: str
    created_at: datetime
    is_active: bool = True


@dataclass
class SessionModel:
    id: str
    user_id: str
    token_hash: str  # SHA-256 of opaque token
    created_at: datetime
    expires_at: datetime
    is_revoked: bool = False


@dataclass
class IdentityModel:
    id: str
    user_id: str
    encryption_public_pem: str
    signing_public_pem: str
    encryption_fingerprint: str
    signing_fingerprint: str
    encrypted_encryption_private_blob: bytes
    encrypted_signing_private_blob: bytes
    created_at: datetime
    is_active: bool = True


@dataclass
class PackageModel:
    id: str
    sender_user_id: str
    recipient_user_id: str
    original_filename: str
    content_type: str
    file_size_bytes: int
    ciphertext_size_bytes: int
    storage_path: str
    package_version: int
    created_at: datetime


@dataclass
class ShareModel:
    id: str
    package_id: str
    sender_user_id: str
    recipient_user_id: str
    token_hash: str  # SHA-256 of share URL token
    created_at: datetime
    expires_at: datetime
    max_downloads: int
    downloads_count: int = 0
    is_revoked: bool = False
    revoked_at: Optional[datetime] = None
