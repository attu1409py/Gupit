"""Authentication and user management schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserRegisterResponse(BaseModel):
    id: str
    username: str
    email: EmailStr
    created_at: datetime


class UserLoginRequest(BaseModel):
    username_or_email: str
    password: str


class UserSummary(BaseModel):
    id: str
    username: str
    email: EmailStr
    primary_identity_id: Optional[str] = None
    created_at: Optional[datetime] = None


class UserLoginResponse(BaseModel):
    user: UserSummary
    csrf_token: str


class UserSearchResponse(BaseModel):
    id: str
    username: str
    email: EmailStr
    has_identity: bool
