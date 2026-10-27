"""Share management service interface for restricted share links.

Assigned to Developer 3 for Phase 2 implementation.
"""

from typing import List, Optional
from backend.app.schemas.share import (
    ShareCreateRequest,
    ShareCreateResponse,
    ShareSummaryResponse,
    ShareDetailResponse,
)


class ShareService:
    """Service handling share links, hashed tokens, download counters, and recipient checks."""

    def create_share(self, sender_user_id: str, request: ShareCreateRequest) -> ShareCreateResponse:
        """Create restricted share record with high-entropy token and SHA-256 storage."""
        raise NotImplementedError("create_share will be implemented by Developer 3 in Phase 2.")

    def get_share_for_recipient(
        self, share_id: str, raw_token: str, recipient_user_id: str
    ) -> ShareDetailResponse:
        """Validate token hash, verify recipient authorization, check expiry and quota."""
        raise NotImplementedError("get_share_for_recipient will be implemented by Developer 3 in Phase 2.")

    def list_sent_shares(self, sender_user_id: str) -> List[ShareSummaryResponse]:
        """List shares originated by the caller."""
        raise NotImplementedError("list_sent_shares will be implemented by Developer 3 in Phase 2.")

    def list_received_shares(self, recipient_user_id: str) -> List[ShareSummaryResponse]:
        """List shares intended for the caller."""
        raise NotImplementedError("list_received_shares will be implemented by Developer 3 in Phase 2.")

    def revoke_share(self, share_id: str, sender_user_id: str) -> bool:
        """Mark share as revoked by sender."""
        raise NotImplementedError("revoke_share will be implemented by Developer 3 in Phase 2.")
