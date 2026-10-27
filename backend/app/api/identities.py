"""Identity management routes.

Endpoints defined according to docs/API_CONTRACT.md.
Assigned to Developers 1 & 3 for Phase 2 implementation.
"""

from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.identity import (
    IdentityCreateRequest,
    IdentitySummary,
    IdentityPublicKeysResponse,
)

router = APIRouter(prefix="/identities", tags=["Identities"])


@router.get("", response_model=list[IdentitySummary])
def list_identities():
    """List caller's cryptographic identities and key fingerprints."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Identity listing will be implemented in Phase 2.",
    )


@router.post("", response_model=IdentitySummary, status_code=status.HTTP_201_CREATED)
def create_identity(request: IdentityCreateRequest = IdentityCreateRequest()):
    """Generate fresh RSA keypairs and register a new identity for the caller."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Identity generation will be implemented in Phase 2.",
    )


@router.get("/{identity_id}/public-keys", response_model=IdentityPublicKeysResponse)
def get_identity_public_keys(identity_id: str):
    """Retrieve public keys and fingerprints for preparing hybrid encryption."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Public key retrieval will be implemented in Phase 2.",
    )
