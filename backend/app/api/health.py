"""System Health & Status Endpoint."""

from fastapi import APIRouter
from backend.app.core.config import settings
from backend.app.schemas.common import HealthResponse

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return current API operational status and configuration summary."""
    return HealthResponse(
        status="ok",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        storage_backend=settings.STORAGE_BACKEND,
    )
