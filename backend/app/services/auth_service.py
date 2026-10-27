"""Authentication service interface and Argon2 / session stubs.

Assigned to Developer 3 for Phase 2 implementation.
"""

from typing import Optional
from backend.app.schemas.auth import UserRegisterRequest, UserLoginRequest, UserSummary


class AuthService:
    """Service managing user registration, Argon2 hashing, and opaque session tokens."""

    def register_user(self, request: UserRegisterRequest) -> UserSummary:
        """Register a new user account with Argon2 password hashing."""
        raise NotImplementedError("register_user will be implemented by Developer 3 in Phase 2.")

    def authenticate_user(self, request: UserLoginRequest) -> tuple[UserSummary, str, str]:
        """Verify credentials, create session, and return (user, session_token, csrf_token)."""
        raise NotImplementedError("authenticate_user will be implemented by Developer 3 in Phase 2.")

    def validate_session(self, raw_session_token: str) -> Optional[UserSummary]:
        """Hash raw_session_token and check SQLite session validity."""
        raise NotImplementedError("validate_session will be implemented by Developer 3 in Phase 2.")

    def invalidate_session(self, raw_session_token: str) -> bool:
        """Mark session as revoked/deleted in SQLite."""
        raise NotImplementedError("invalidate_session will be implemented by Developer 3 in Phase 2.")
