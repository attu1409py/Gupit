"""Restricted file sharing routes.

Endpoints defined according to docs/API_CONTRACT.md.
Assigned to Developer 3 for Phase 2 implementation.
"""

from fastapi import APIRouter, HTTPException, Query, status
from backend.app.schemas.share import (
    ShareCreateRequest,
    ShareCreateResponse,
    ShareSummaryResponse,
    ShareDetailResponse,
    ShareDownloadRequest,
    ShareRevokeResponse,
)

router = APIRouter(prefix="/shares", tags=["Shares"])


@router.post("", response_model=ShareCreateResponse, status_code=status.HTTP_201_CREATED)
def create_share(request: ShareCreateRequest):
    """Create restricted share link with high-entropy token and limits."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Share creation will be implemented by Developer 3 in Phase 2.",
    )


@router.get("/sent", response_model=list[ShareSummaryResponse])
def list_sent_shares():
    """List shares created by authenticated caller."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Listing sent shares will be implemented in Phase 2.",
    )


@router.get("/received", response_model=list[ShareSummaryResponse])
def list_received_shares():
    """List shares targeted to authenticated caller."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Listing received shares will be implemented in Phase 2.",
    )


@router.get("/{share_id}", response_model=ShareDetailResponse)
def get_share_details(share_id: str, token: str = Query(...)):
    """Inspect share details, verifying recipient ID and token validity."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Share inspection will be implemented in Phase 2.",
    )


@router.post("/{share_id}/download")
def download_shared_file(share_id: str, request: ShareDownloadRequest):
    """Verify authorization, verify signature, decrypt, and stream file."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Authenticated decryption and download will be implemented in Phase 2.",
    )


@router.delete("/{share_id}", response_model=ShareRevokeResponse)
def revoke_share(share_id: str):
    """Revoke an active share link."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Share revocation will be implemented in Phase 2.",
    )
