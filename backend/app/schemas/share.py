"""File encryption and restricted share schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class FileEncryptResponse(BaseModel):
    package_id: str
    original_filename: str
    file_size_bytes: int
    ciphertext_size_bytes: int
    recipient_user_id: str
    sender_user_id: str
    package_version: int = 1
    created_at: datetime


class ShareCreateRequest(BaseModel):
    package_id: str
    recipient_user_id: str
    expires_in_hours: int = Field(default=72, ge=1, le=720)
    max_downloads: int = Field(default=5, ge=1, le=100)


class ShareCreateResponse(BaseModel):
    share_id: str
    share_url: str
    recipient_user_id: str
    expires_at: datetime
    max_downloads: int
    downloads_remaining: int
    is_revoked: bool = False


class ShareSummaryResponse(BaseModel):
    share_id: str
    package_id: Optional[str] = None
    original_filename: str
    recipient_username: Optional[str] = None
    sender_username: Optional[str] = None
    file_size_bytes: Optional[int] = None
    created_at: datetime
    expires_at: datetime
    downloads_count: Optional[int] = None
    downloads_remaining: Optional[int] = None
    max_downloads: Optional[int] = None
    is_revoked: bool


class ShareDetailResponse(BaseModel):
    share_id: str
    original_filename: str
    sender_username: str
    file_size_bytes: int
    expires_at: datetime
    downloads_remaining: int
    package_version: int
    sender_signing_fingerprint: str


class ShareDownloadRequest(BaseModel):
    token: str


class ShareRevokeResponse(BaseModel):
    share_id: str
    is_revoked: bool
    revoked_at: datetime
