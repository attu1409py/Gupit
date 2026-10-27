# Gupit: Secure File Sharing Using Hybrid Cryptography

[![Phase](https://img.shields.io/badge/Phase-1%20Foundation%20Setup-blue.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7%2B%20Strict-blue.svg)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT%20Educational-green.svg)](#)

**Gupit** (spelled G-U-P-I-T) is an educational web application prototype demonstrating secure file transmission between authenticated users using **hybrid cryptography**.

---

> [!WARNING]
> ### Educational Prototype Notice & Server-Side Trust Model
> Gupit is an educational college mini-project prototype. The current version uses **server-side cryptographic processing** with keys protected at rest by a server-side master key (`SERVER_MASTER_KEY`).
> 
> **This application is NOT end-to-end encrypted (E2EE)** and must NOT be deployed to production or used to handle sensitive real-world files. See [docs/SECURITY_DESIGN.md](file:///./docs/SECURITY_DESIGN.md) for the complete security architecture and threat model.

---

## 1. Cryptographic Architecture

Gupit combines symmetric and asymmetric cryptography into an authenticated envelope:

```
[ Plaintext File ]
        |
        v
  [ AES-256-GCM ] <--- Fresh 256-bit Key & 96-bit Nonce
        |
        +---> [ Ciphertext + 128-bit Tag ]
        |
        v
  [ RSA-OAEP Wrap ] <--- Recipient's RSA Public Encryption Key (SHA-256 + MGF1)
        |
        v
  [ RSA-PSS Sign ]  <--- Sender's RSA Private Signing Key (SHA-256)
        |
        v
  [ Versioned Encrypted Package (.pkg) ]
```

1. **AES-256-GCM:** High-throughput symmetric authenticated encryption for file data with unique 12-byte nonces and 128-bit authentication tags.
2. **RSA-OAEP:** Optimal Asymmetric Encryption Padding with SHA-256 protects the 256-bit AES session key targeted to the recipient.
3. **RSA-PSS:** Probabilistic Signature Scheme provides non-repudiation and cryptographic authenticity proof.
4. **Separation of Duties:** Separate RSA keypairs are enforced for encryption wrapping vs. digital signatures.
5. **Authenticated Decryption Guarantee:** No plaintext file is ever delivered if signature verification or authentication tag validation fails.

---

## 2. Repository Layout

```
Gupit/
├── README.md                           # Main documentation & local setup instructions
├── PROJECT_SPEC.md                     # Architectural requirements & project boundaries
├── CONTRIBUTING.md                     # Contributor workflow and review rules
├── .env.example                        # Template environment variables (no secrets)
├── .gitignore                          # Ignores venv, node_modules, keys, packages, DBs
├── docs/
│   ├── API_CONTRACT.md                 # Frozen REST API contract & schemas
│   ├── CRYPTO_INTERFACE.md             # Frozen cryptographic signatures & error types
│   ├── SECURITY_DESIGN.md              # Threat model, CIA+A triad, and trust boundaries
│   └── DEVELOPMENT_WORKFLOW.md         # 3-person team ownership & Git flow
├── backend/
│   ├── requirements.txt                # FastAPI, cryptography, argon2-cffi, pytest, httpx
│   ├── app/
│   │   ├── main.py                     # FastAPI application entrypoint
│   │   ├── api/                        # Health and route stubs
│   │   ├── models/                     # SQLite entity models
│   │   ├── schemas/                    # Pydantic validation schemas
│   │   ├── services/                   # Storage, auth, share, and crypto interfaces
│   │   └── core/                       # App settings and security constants
│   └── tests/                          # Pytest suite & crypto stub tests
└── frontend/
    ├── package.json                    # React 19, TypeScript, Vite, Lucide React
    ├── tsconfig.json                   # Strict TypeScript compiler configuration
    ├── vite.config.ts                  # Vite config with API reverse proxy
    └── src/
        ├── components/                 # Header, Footer, StatusCard
        ├── pages/                      # DashboardShell with 10-step stepper
        ├── services/                   # Typed API client
        ├── styles/                     # Theme tokens and design system
        └── types/                      # TypeScript schemas from API contract
```

---

## 3. Team Ownership Model

To ensure independent development without code collisions:

| Role | Domain & Responsibilities | Key Files |
| :--- | :--- | :--- |
| **Developer 1** | Cryptographic engine, package serialization, RSA/AES tests, security design | `backend/app/services/crypto_engine.py`<br>`backend/tests/test_crypto_*.py` |
| **Developer 2** | React 19, TypeScript, CSS, UI components, dashboard shell, API client | `frontend/src/`<br>`frontend/package.json` |
| **Developer 3** | FastAPI routes, Argon2 auth, SQLite models, file storage, HTTPX tests | `backend/app/api/`<br>`backend/app/services/`<br>`backend/tests/test_api_*.py` |

---

## 4. Local Setup & Execution Guide

### Prerequisites
- **Python 3.11 or later** (`python --version`)
- **Node.js v18 or later** (`node --version`) and **npm** (`npm --version`)

---

### Step 1: Environment Configuration
Copy the template configuration file:

```bash
# Windows (PowerShell)
Copy-Item .env.example .env

# macOS / Linux
cp .env.example .env
```

---

### Step 2: Backend Setup & Execution

1. Create and activate a Python virtual environment:

```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

2. Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

3. Run the automated test suite:

```bash
pytest backend/tests -v
```

4. Start the FastAPI development server:

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify that the health check responds at:  
👉 `http://127.0.0.1:8000/api/health`  
Interactive Swagger docs are available at:  
👉 `http://127.0.0.1:8000/docs`

---

### Step 3: Frontend Setup & Execution

1. Navigate to the frontend directory:

```bash
cd frontend
```

2. Install dependencies:

```bash
npm install
```

3. Run TypeScript type checking and production build check:

```bash
npm run typecheck
npm run build
```

4. Start the Vite development server:

```bash
npm run dev
```

Open the application in your browser at:  
👉 `http://localhost:5173`

---

## 5. Security & Secret Handling Ground Rules

1. **No Real Secrets in Git:** Never commit `.env`, private keys (`*.pem`, `*.key`), or SQLite files (`*.db`).
2. **Password Protection:** Always hash user passwords with Argon2 before storage. Never store plaintext credentials.
3. **Session Delivery:** Use HttpOnly, SameSite cookies with CSRF validation. Never store auth tokens in browser `localStorage`.
4. **Recipient Authorization:** A valid sharing token alone does NOT grant access. The backend strictly verifies `authenticated_user.id == share.recipient_user_id`.
5. **No Cryptographic Shortcuts:** All cryptographic primitives must use standard implementations from the Python `cryptography` library. Custom implementations are forbidden.

---

## 6. Specification Documents

- [Project Specification](file:///./PROJECT_SPEC.md)
- [API Contract Specification](file:///./docs/API_CONTRACT.md)
- [Cryptographic Interface Specification](file:///./docs/CRYPTO_INTERFACE.md)
- [Security Architecture & Threat Model](file:///./docs/SECURITY_DESIGN.md)
- [Development Workflow & Ownership](file:///./docs/DEVELOPMENT_WORKFLOW.md)
- [Contributor Guide](file:///./CONTRIBUTING.md)
