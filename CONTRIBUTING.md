# Contributing to Gupit

Thank you for contributing to Gupit! This repository is configured for a collaborative three-person team.

---

## 1. Getting Started

1. Clone the repository.
2. Review the core specifications before writing code:
   - [Project Specification](file:///./PROJECT_SPEC.md)
   - [API Contract](file:///./docs/API_CONTRACT.md)
   - [Cryptographic Interface](file:///./docs/CRYPTO_INTERFACE.md)
   - [Security Design](file:///./docs/SECURITY_DESIGN.md)
   - [Development Workflow](file:///./docs/DEVELOPMENT_WORKFLOW.md)
3. Set up your local environment:
   - Backend: Create a Python virtual environment and run `pip install -r backend/requirements.txt`.
   - Frontend: In `frontend/`, run `npm install`.
   - Copy `.env.example` to `.env` in the project root.

---

## 2. Interface Changes & Code Reviews

- **Interface Stability:** Do not modify schemas in `docs/API_CONTRACT.md` or signatures in `docs/CRYPTO_INTERFACE.md` unilaterally. Any change requires team consensus.
- **Pull Requests:** Open small, focused PRs from dedicated feature branches (e.g. `feature/d1-key-generation`).
- **Review Criteria:**
  - Strict type checking must pass (`npx tsc --noEmit` and Pydantic validation).
  - Tests must pass (`pytest backend/tests`).
  - No secret values, private keys, or credentials committed.

---

## 3. Security Ground Rules

1. Never commit `.env` or any file containing real keys or secrets.
2. Never store passwords in plaintext (use Argon2).
3. Never bypass recipient authorization checks on share access.
4. Always verify RSA-PSS signatures before accepting packages for decryption.
5. All cryptographic primitives must use standard algorithms from the Python `cryptography` library. Never write custom crypto implementations.
