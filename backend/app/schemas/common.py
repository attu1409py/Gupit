"""Common and system schemas."""

from typing import Any, Optional
from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    storage_backend: str

    model_config = ConfigDict(extra="ignore")


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class StandardErrorResponse(BaseModel):
    error: ErrorDetail
