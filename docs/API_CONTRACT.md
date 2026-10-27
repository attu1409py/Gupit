# Gupit API Contract Specification

**Version:** 0.1.0  
**Status:** Frozen Interface (Phase 1 Foundation)  
**Base URL:** `/api`  

This document defines the formal HTTP REST API contract for Gupit. All clients (React frontend, automated test suites, CLI tools) and backend handlers must adhere strictly to these schemas and conventions.

---

## 1. Global Conventions

### 1.1 Content Types & Encoding
- All JSON request and response payloads must use `Content-Type: application/json` with UTF-8 encoding.
- File upload operations use `multipart/form-data`.
- Binary download responses use `application/octet-stream` with a sanitized `Content-Disposition` header.

### 1.2 Session Authentication & Security Headers
- **Session Delivery:** Authenticated endpoints read an opaque, cryptographically random session token from the `gupit_session` HttpOnly cookie.
- **CSRF Defense:** State-changing endpoints (`POST`, `PUT`, `DELETE`, `PATCH`) must supply a CSRF token passed either via custom header (`X-CSRF-Token`) matching the `gupit_csrf` cookie value or validated through Double Submit / backend CSRF tokens.
- **Authorization Context:** The backend resolves the session token by computing its SHA-256 hash and looking up the active session in SQLite.

### 1.3 Standard Error Response Structure
All error responses return a standardized JSON envelope with appropriate HTTP status codes:

```json
{
  "error": {
    "code": "ERROR_CODE_STRING",
    "message": "Human-readable explanation.",
    "details": null
  }
}
```

#### Standard Error Codes:
| Error Code | HTTP Status | Description |
| :--- | :--- | :--- |
| `INVALID_CREDENTIALS` | 401 | Username/email or password incorrect. |
| `UNAUTHENTICATED` | 401 | Missing, invalid, or expired session cookie. |
| `FORBIDDEN` | 403 | Authenticated user is not permitted to access this resource. |
| `NOT_FOUND` | 404 | The requested entity or share was not found. |
| `SHARE_EXPIRED` | 410 | The share link has passed its expiration time. |
| `SHARE_REVOKED` | 410 | The share was revoked by the sender. |
| `DOWNLOAD_LIMIT_EXCEEDED` | 410 | The share has reached its maximum download quota. |
| `FILE_TOO_LARGE` | 413 | Uploaded file exceeds configured server size limits. |
| `MALFORMED_PACKAGE` | 422 | Encrypted package failed structure or metadata validation. |
| `SIGNATURE_VERIFICATION_FAILED`| 422 | RSA-PSS package signature did not match sender's public key. |
| `DECRYPTION_FAILED` | 422 | AES-GCM tag verification or RSA-OAEP unwrapping failed. |
| `VALIDATION_ERROR` | 422 | Request body failed Pydantic schema validation. |
| `INTERNAL_ERROR` | 500 | Unexpected internal server error. |

---

## 2. Endpoint Matrix & Access Requirements

| Method | Endpoint | Auth Required | CSRF Required | Recipient Check | Description |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **GET** | `/api/health` | No | No | No | Service health check. |
| **POST** | `/api/auth/register` | No | No | No | Register new user account. |
| **POST** | `/api/auth/login` | No | No | No | Authenticate user & set session cookie. |
| **POST** | `/api/auth/logout` | Yes | Yes | No | Invalidate session & clear cookie. |
| **GET** | `/api/auth/me` | Yes | No | No | Return authenticated user details. |
| **GET** | `/api/users/search` | Yes | No | No | Search registered recipients by username/email. |
| **GET** | `/api/identities` | Yes | No | No | List user's cryptographic identity keys. |
| **POST** | `/api/identities` | Yes | Yes | No | Create/publish new key pair for user. |
| **GET** | `/api/identities/{identity_id}/public-keys` | Yes | No | No | Fetch public keys & fingerprints for a user. |
| **POST** | `/api/files/encrypt` | Yes | Yes | No | Upload file, perform hybrid encryption, store package. |
| **GET** | `/api/shares/sent` | Yes | No | No | List shares initiated by the caller. |
| **GET** | `/api/shares/received` | Yes | No | Yes | List shares targeted to the caller. |
| **POST** | `/api/shares` | Yes | Yes | No | Create restricted access link for encrypted package. |
| **GET** | `/api/shares/{share_id}` | Yes | No | Yes | Inspect share metadata & check caller access. |
| **POST** | `/api/shares/{share_id}/download` | Yes | Yes | Yes | Verify caller, verify signature, decrypt, stream file. |
| **DELETE**| `/api/shares/{share_id}` | Yes | Yes | No | Revoke sharing link (sender only). |

---

## 3. Endpoint Specifications

### 3.1 System Endpoints

#### GET `/api/health`
Returns current operational status of API service.
- **Request:** None
- **Response `200 OK`:**
```json
{
  "status": "ok",
  "app": "Gupit",
  "version": "0.1.0",
  "storage_backend": "local"
}
```

---

### 3.2 Authentication Endpoints

#### POST `/api/auth/register`
Creates a new user profile and triggers initial cryptographic identity generation.
- **Request Body:**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "SecurePassword123!"
}
```
- **Response `201 Created`:**
```json
{
  "id": "usr_9f82d1",
  "username": "alice",
  "email": "alice@example.com",
  "created_at": "2026-10-27T14:30:00Z"
}
```
- **Errors:**
  - `400 / 422`: Username or email already registered, or password complexity unmet.

#### POST `/api/auth/login`
Validates credentials against Argon2 hash, issues high-entropy session token stored as hash in SQLite, sets `gupit_session` HttpOnly cookie.
- **Request Body:**
```json
{
  "username_or_email": "alice",
  "password": "SecurePassword123!"
}
```
- **Response `200 OK`:** (Sets `Set-Cookie: gupit_session=...; HttpOnly; SameSite=Lax; Path=/`)
```json
{
  "user": {
    "id": "usr_9f82d1",
    "username": "alice",
    "email": "alice@example.com"
  },
  "csrf_token": "random_csrf_token_string"
}
```
- **Errors:**
  - `401 Unauthorized`: Generic error message (`"Invalid username or password"`).

#### POST `/api/auth/logout`
Terminates current session in database and clears the cookie.
- **Headers:** `X-CSRF-Token: ...`
- **Response `200 OK`:**
```json
{
  "message": "Successfully logged out."
}
```

#### GET `/api/auth/me`
Retrieves currently authenticated user and active identity summary.
- **Response `200 OK`:**
```json
{
  "id": "usr_9f82d1",
  "username": "alice",
  "email": "alice@example.com",
  "primary_identity_id": "idt_4812a0",
  "created_at": "2026-10-27T14:30:00Z"
}
```

---

### 3.3 Users & Cryptographic Identity Endpoints

#### GET `/api/users/search?q={query}`
Finds other registered users to select as file recipients.
- **Query Parameters:** `q` (min 2 chars)
- **Response `200 OK`:**
```json
[
  {
    "id": "usr_73ba19",
    "username": "bob",
    "email": "bob@example.com",
    "has_identity": true
  }
]
```

#### GET `/api/identities`
Retrieves caller's cryptographic identities, public keys, and fingerprints.
- **Response `200 OK`:**
```json
[
  {
    "identity_id": "idt_4812a0",
    "user_id": "usr_9f82d1",
    "encryption_key_fingerprint": "a8f5c3...64hex",
    "signing_key_fingerprint": "1e92d7...64hex",
    "created_at": "2026-10-27T14:30:00Z",
    "is_active": true
  }
]
```

#### POST `/api/identities`
Generates a fresh dual RSA keypair (one for RSA-OAEP encryption key wrapping, one for RSA-PSS signing).
- **Request Body:** `{}` (optional label)
- **Response `201 Created`:**
```json
{
  "identity_id": "idt_4812a0",
  "user_id": "usr_9f82d1",
  "encryption_key_fingerprint": "a8f5c3...64hex",
  "signing_key_fingerprint": "1e92d7...64hex",
  "created_at": "2026-10-27T14:30:00Z"
}
```

#### GET `/api/identities/{identity_id}/public-keys`
Fetches PEM-encoded public keys and fingerprints for a recipient to prepare hybrid encryption.
- **Response `200 OK`:**
```json
{
  "identity_id": "idt_4812a0",
  "user_id": "usr_73ba19",
  "encryption_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "signing_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "encryption_key_fingerprint": "a8f5c3...64hex",
  "signing_key_fingerprint": "1e92d7...64hex"
}
```

---

### 3.4 File Encryption & Sharing Endpoints

#### POST `/api/files/encrypt`
Uploads plaintext file, executes server-side hybrid encryption targeted to recipient's RSA public key, signs with sender's RSA private key, and stores versioned encrypted package.
- **Content-Type:** `multipart/form-data`
- **Form Fields:**
  - `file`: Binary file upload
  - `recipient_user_id`: Target recipient identifier (e.g. `usr_73ba19`)
- **Response `201 Created`:**
```json
{
  "package_id": "pkg_881a702b",
  "original_filename": "Quarterly_Report.pdf",
  "file_size_bytes": 1048576,
  "ciphertext_size_bytes": 1050200,
  "recipient_user_id": "usr_73ba19",
  "sender_user_id": "usr_9f82d1",
  "package_version": 1,
  "created_at": "2026-10-27T15:00:00Z"
}
```

#### POST `/api/shares`
Generates a restricted share link referencing an encrypted package with high-entropy token, download limits, and expiration.
- **Request Body:**
```json
{
  "package_id": "pkg_881a702b",
  "recipient_user_id": "usr_73ba19",
  "expires_in_hours": 48,
  "max_downloads": 3
}
```
- **Response `201 Created`:**
```json
{
  "share_id": "shr_3398f1",
  "share_url": "/share/shr_3398f1?token=sec_984f18a2091cbf72...",
  "recipient_user_id": "usr_73ba19",
  "expires_at": "2026-10-29T15:00:00Z",
  "max_downloads": 3,
  "downloads_remaining": 3,
  "is_revoked": false
}
```
*(Note: `token` is presented only once in the response. Its SHA-256 hash is stored in SQLite).*

#### GET `/api/shares/sent`
Lists active and historical shares created by the caller.
- **Response `200 OK`:**
```json
[
  {
    "share_id": "shr_3398f1",
    "package_id": "pkg_881a702b",
    "original_filename": "Quarterly_Report.pdf",
    "recipient_username": "bob",
    "created_at": "2026-10-27T15:00:00Z",
    "expires_at": "2026-10-29T15:00:00Z",
    "downloads_count": 0,
    "max_downloads": 3,
    "is_revoked": false
  }
]
```

#### GET `/api/shares/received`
Lists files shared specifically with the authenticated caller.
- **Response `200 OK`:**
```json
[
  {
    "share_id": "shr_3398f1",
    "original_filename": "Quarterly_Report.pdf",
    "sender_username": "alice",
    "file_size_bytes": 1048576,
    "created_at": "2026-10-27T15:00:00Z",
    "expires_at": "2026-10-29T15:00:00Z",
    "downloads_remaining": 3,
    "is_revoked": false
  }
]
```

#### GET `/api/shares/{share_id}?token={token}`
Inspects share details.
- **Access Rule:** Requires authenticated session **AND** matching recipient identity (`session.user_id == share.recipient_user_id`). Validates token hash, expiry, and revocation.
- **Response `200 OK`:**
```json
{
  "share_id": "shr_3398f1",
  "original_filename": "Quarterly_Report.pdf",
  "sender_username": "alice",
  "file_size_bytes": 1048576,
  "expires_at": "2026-10-29T15:00:00Z",
  "downloads_remaining": 3,
  "package_version": 1,
  "sender_signing_fingerprint": "1e92d7...64hex"
}
```

#### POST `/api/shares/{share_id}/download`
Executes authenticated decryption and verification.
1. Authenticates recipient session.
2. Verifies `session.user_id == share.recipient_user_id`.
3. Verifies share token hash, expiry timestamp, revocation flag, and remaining download quota.
4. Verifies RSA-PSS digital signature over encrypted package header and ciphertext using sender's public key. If verification fails, halts immediately.
5. Unwraps AES-256 session key using recipient's RSA private key.
6. Decrypts file using AES-256-GCM and verifies 128-bit authentication tag.
7. Decrements remaining download quota.
8. Streams the decrypted bytes to client.
- **Request Body:**
```json
{
  "token": "sec_984f18a2091cbf72..."
}
```
- **Response `200 OK`:** Binary stream
  - `Content-Type: application/octet-stream`
  - `Content-Disposition: attachment; filename="Quarterly_Report.pdf"`
  - `Content-Length: 1048576`
- **Errors:**
  - `401 Unauthorized`: Not logged in.
  - `403 Forbidden`: Logged in user is not the intended recipient.
  - `410 Gone`: Expired, revoked, or download limit reached.
  - `422 Unprocessable Entity`: Signature or authenticated decryption failure.

#### DELETE `/api/shares/{share_id}`
Allows sender to immediately revoke an active share.
- **Response `200 OK`:**
```json
{
  "share_id": "shr_3398f1",
  "is_revoked": true,
  "revoked_at": "2026-10-27T16:00:00Z"
}
```
