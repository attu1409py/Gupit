"""Identity store interface for managing public/private key material.

Assigned to Developer 3 (in collaboration with Developer 1) for Phase 2 implementation.
"""

from typing import Optional
from backend.app.schemas.identity import IdentitySummary, IdentityPublicKeysResponse


class IdentityStore:
    """Service managing user cryptographic identities, public keys, and protected private keys."""

    def create_identity_for_user(self, user_id: str) -> IdentitySummary:
        """Coordinate with crypto_engine to generate and persist key pairs for a user."""
        raise NotImplementedError("create_identity_for_user will be implemented in Phase 2.")

    def get_public_keys(self, identity_id: str) -> Optional[IdentityPublicKeysResponse]:
        """Fetch PEM-encoded public keys and fingerprints for encryption/verification."""
        raise NotImplementedError("get_public_keys will be implemented in Phase 2.")

    def get_user_active_identity(self, user_id: str) -> Optional[IdentitySummary]:
        """Fetch the active identity for a user."""
        raise NotImplementedError("get_user_active_identity will be implemented in Phase 2.")
