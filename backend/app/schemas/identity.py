"""Cryptographic identity schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class IdentityCreateRequest(BaseModel):
    label: Optional[str] = None


class IdentitySummary(BaseModel):
    identity_id: str
    user_id: str
    encryption_key_fingerprint: str
    signing_key_fingerprint: str
    created_at: datetime
    is_active: bool = True


class IdentityPublicKeysResponse(BaseModel):
    identity_id: str
    user_id: str
    encryption_public_key_pem: str
    signing_public_key_pem: str
    encryption_key_fingerprint: str
    signing_key_fingerprint: str
