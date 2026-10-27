/**
 * Gupit Frontend TypeScript Type Definitions.
 * Strictly aligned with docs/API_CONTRACT.md and docs/CRYPTO_INTERFACE.md.
 */

export interface HealthStatus {
  status: 'ok' | 'degraded' | 'error';
  app: string;
  version: string;
  storage_backend: string;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export interface UserSummary {
  id: string;
  username: string;
  email: string;
  primary_identity_id?: string;
  created_at?: string;
}

export interface RecipientUser {
  id: string;
  username: string;
  email: string;
  has_identity: boolean;
}

export interface IdentitySummary {
  identity_id: string;
  user_id: string;
  encryption_key_fingerprint: string;
  signing_key_fingerprint: string;
  created_at: string;
  is_active: boolean;
}

export interface EncryptedPackageSummary {
  package_id: string;
  original_filename: string;
  file_size_bytes: number;
  ciphertext_size_bytes: number;
  recipient_user_id: string;
  sender_user_id: string;
  package_version: number;
  created_at: string;
}

export interface ShareSummary {
  share_id: string;
  package_id?: string;
  original_filename: string;
  recipient_username?: string;
  sender_username?: string;
  file_size_bytes?: number;
  created_at: string;
  expires_at: string;
  downloads_count?: number;
  downloads_remaining?: number;
  max_downloads?: number;
  is_revoked: boolean;
}

export interface ShareDetail {
  share_id: string;
  original_filename: string;
  sender_username: string;
  file_size_bytes: number;
  expires_at: string;
  downloads_remaining: number;
  package_version: number;
  sender_signing_fingerprint: string;
}
