"""Authentication and user management route definitions.

Endpoints defined according to docs/API_CONTRACT.md.
Assigned to Developer 3 for Phase 2 implementation.
"""

from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.auth import (
    UserRegisterRequest,
    UserRegisterResponse,
    UserLoginRequest,
    UserLoginResponse,
    UserSummary,
    UserSearchResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
users_router = APIRouter(prefix="/users", tags=["Users"])


@router.post("/register", response_model=UserRegisterResponse, status_code=status.HTTP_201_CREATED)
def register_user(request: UserRegisterRequest):
    """Register a new user account."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Registration endpoint will be implemented by Developer 3 in Phase 2.",
    )


@router.post("/login", response_model=UserLoginResponse)
def login_user(request: UserLoginRequest):
    """Authenticate user credentials and set HttpOnly session cookie."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Login endpoint will be implemented by Developer 3 in Phase 2.",
    )


@router.post("/logout")
def logout_user():
    """Revoke active session and clear cookie."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Logout endpoint will be implemented by Developer 3 in Phase 2.",
    )


@router.get("/me", response_model=UserSummary)
def get_current_user():
    """Retrieve authenticated caller profile."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Session introspection will be implemented by Developer 3 in Phase 2.",
    )


@users_router.get("/search", response_model=list[UserSearchResponse])
def search_users(q: str):
    """Search registered users to select as file sharing recipients."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="User search will be implemented by Developer 3 in Phase 2.",
    )
