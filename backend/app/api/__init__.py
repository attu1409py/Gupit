"""API Router aggregation module."""

from fastapi import APIRouter
from backend.app.api.health import router as health_router
from backend.app.api.auth import router as auth_router, users_router
from backend.app.api.identities import router as identities_router
from backend.app.api.files import router as files_router
from backend.app.api.shares import router as shares_router

api_router = APIRouter(prefix="/api")

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(identities_router)
api_router.include_router(files_router)
api_router.include_router(shares_router)

__all__ = ["api_router"]
