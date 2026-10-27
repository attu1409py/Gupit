"""File encryption routes.

Endpoints defined according to docs/API_CONTRACT.md.
Assigned to Developers 1 & 3 for Phase 2 implementation.
"""

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from backend.app.schemas.share import FileEncryptResponse

router = APIRouter(prefix="/files", tags=["Files"])


@router.post("/encrypt", response_model=FileEncryptResponse, status_code=status.HTTP_201_CREATED)
async def encrypt_file(
    file: UploadFile = File(...),
    recipient_user_id: str = Form(...),
):
    """Upload plaintext file, execute hybrid encryption, and store package."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Hybrid file encryption will be implemented in Phase 2.",
    )
