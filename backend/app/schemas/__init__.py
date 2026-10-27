"""Pydantic schemas matching the Gupit API Contract."""

from backend.app.schemas.common import HealthResponse, StandardErrorResponse
from backend.app.schemas.auth import (
    UserRegisterRequest,
    UserRegisterResponse,
    UserLoginRequest,
    UserLoginResponse,
    UserSummary,
    UserSearchResponse,
)
from backend.app.schemas.identity import (
    IdentityCreateRequest,
    IdentitySummary,
    IdentityPublicKeysResponse,
)
from backend.app.schemas.share import (
    FileEncryptResponse,
    ShareCreateRequest,
    ShareCreateResponse,
    ShareSummaryResponse,
    ShareDetailResponse,
    ShareDownloadRequest,
    ShareRevokeResponse,
)

__all__ = [
    "HealthResponse",
    "StandardErrorResponse",
    "UserRegisterRequest",
    "UserRegisterResponse",
    "UserLoginRequest",
    "UserLoginResponse",
    "UserSummary",
    "UserSearchResponse",
    "IdentityCreateRequest",
    "IdentitySummary",
    "IdentityPublicKeysResponse",
    "FileEncryptResponse",
    "ShareCreateRequest",
    "ShareCreateResponse",
    "ShareSummaryResponse",
    "ShareDetailResponse",
    "ShareDownloadRequest",
    "ShareRevokeResponse",
]
