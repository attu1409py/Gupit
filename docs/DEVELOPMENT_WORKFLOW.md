# Gupit Development Workflow & Contributor Guide

**Project:** Gupit (Secure File Sharing Using Hybrid Cryptography)  
**Team Structure:** 3 Developers  
**Methodology:** Spec-Driven Development, Feature Branching, AI-Assisted Implementation  

---

## 1. Ownership & Division of Responsibilities

To enable independent development without code collisions, each developer owns a distinct architectural slice:

### Developer 1: Cryptographic Engine & Security Lead
- **Domain:** Cryptographic engine, key management, package serialization, and crypto security tests.
- **Primary Paths:**
  - `backend/app/services/crypto_engine.py`
  - `backend/tests/test_crypto_*.py`
  - `docs/CRYPTO_INTERFACE.md`
  - `docs/SECURITY_DESIGN.md`
- **Key Deliverables:**
  - Keypair generation (RSA-OAEP & RSA-PSS).
  - AES-256-GCM authenticated encryption/decryption.
  - Envelope creation, digital signatures, and package wire format parsing.
  - Unit tests for tag tampering, corrupted signatures, and invalid versions.

### Developer 2: Frontend Engineering & UI/UX
- **Domain:** React 19 / Vite / TypeScript single-page application, CSS design system, and client API communication.
- **Primary Paths:**
  - `frontend/src/`
  - `frontend/package.json`
  - `frontend/tsconfig*.json`
- **Key Deliverables:**
  - Dashboard shell, authentication pages, identity view, file upload/encryption view, and recipient download view.
  - Typed API client communicating with `/api` endpoints following `docs/API_CONTRACT.md`.
  - Responsive, accessible CSS layout adhering to modern web guidelines.
  - Production build and TypeScript type-check verification (`npm run build`).

### Developer 3: Backend API, Persistence & Authorization
- **Domain:** FastAPI application routing, Argon2 authentication, session management, SQLite schema, and file storage.
- **Primary Paths:**
  - `backend/app/main.py`
  - `backend/app/api/`
  - `backend/app/models/`
  - `backend/app/schemas/`
  - `backend/app/services/auth_service.py`
  - `backend/app/services/identity_store.py`
  - `backend/app/services/file_storage.py`
  - `backend/app/services/share_service.py`
  - `backend/tests/test_api_*.py`
- **Key Deliverables:**
  - User registration, Argon2 password hashing, and HttpOnly session cookies.
  - Share link generation, token hashing (SHA-256), expiry enforcement, and recipient authorization check.
  - Storage abstraction (`BaseStorageService`) and local filesystem driver.
  - API integration tests using HTTPX.

---

## 2. Immutable Interface Contracts

> [!CAUTION]
> **No Unilateral Changes to Shared Interfaces!**  
> `docs/API_CONTRACT.md` and `docs/CRYPTO_INTERFACE.md` are frozen contracts.  
> If an implementation change is required:
> 1. Discuss with the other two developers.
> 2. Open an RFC or PR updating the markdown contract doc first.
> 3. Obtain 2 peer approvals before altering the code implementation.

---

## 3. Git Workflow & Branching Strategy

The repository follows a clean GitHub Flow branching model:

```
 main (Protected: passes CI, clean builds, no direct commits)
   │
   ├── feature/crypto-key-generation    (Developer 1)
   ├── feature/frontend-auth-pages      (Developer 2)
   └── feature/backend-session-auth     (Developer 3)
```

### 3.1 Branch Naming Conventions
- `feature/<developer>-<short-description>` (e.g. `feature/d1-rsa-pss-signing`, `feature/d2-file-upload-ui`, `feature/d3-share-routes`)
- `fix/<short-description>` (e.g. `fix/csrf-header-validation`)
- `docs/<short-description>` (e.g. `docs/update-threat-model`)

### 3.2 Commit Message Convention (Conventional Commits)
Format: `<type>(<scope>): <subject>`

**Examples:**
- `feat(crypto): implement RSA-OAEP key wrapping in crypto_engine`
- `feat(api): add recipient authorization guard on /api/shares/{share_id}`
- `feat(ui): implement upload dropzone and recipient selector`
- `test(crypto): add test case for altered ciphertext tag mismatch`
- `docs(spec): clarify package binary framing in CRYPTO_INTERFACE`

---

## 4. Pull Request & Review Checklist

Before any PR is merged into `main`, the reviewer and author must verify:

- [ ] **Interface Adherence:** Does the PR conform strictly to `API_CONTRACT.md` and `CRYPTO_INTERFACE.md`?
- [ ] **No Hardcoded Secrets:** Are there any passwords, private keys, or actual tokens in the code or tests?
- [ ] **Tests Pass:**
  - Backend: `pytest` runs cleanly without failures.
  - Frontend: `npm run build` and `npx tsc --noEmit` pass with zero type errors.
- [ ] **Error Handling:** Does it raise domain-specific exceptions rather than returning silent defaults or crashing?
- [ ] **Documentation:** Are new functions documented with clear docstrings and parameter types?
