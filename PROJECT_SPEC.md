# Gupit Project Specification

**Title:** Gupit: Secure File Sharing Using Hybrid Cryptography  
**Project Classification:** Three-Person College Mini Project (Educational Prototype)  
**Status:** Phase 1 Foundation & Architecture Setup  

---

## 1. Executive Summary

**Gupit** is a web-based secure file sharing platform engineered to demonstrate the practical application of hybrid cryptography. It combines high-throughput symmetric authenticated encryption (AES-256-GCM) with asymmetric public-key cryptography (RSA-OAEP for key encapsulation and RSA-PSS for digital signatures).

The platform allows authenticated users to encrypt and transmit files targeted to specific registered recipients. Recipients can access files via high-entropy restricted links, subject to cryptographic signature verification, authenticated decryption, and strict user authorization checks.

---

## 2. Intended User Journey & Workflow

1. **Identity Setup:** Sender and recipient register user accounts. Each user possesses a cryptographic identity with distinct RSA keypairs for encryption wrapping and digital signatures.
2. **File Encapsulation & Signing:**
   - Sender chooses a file and selects a recipient.
   - Backend generates an ephemeral 256-bit AES key and 12-byte nonce.
   - Bulk file is encrypted with AES-256-GCM.
   - Ephemeral AES key is wrapped with the recipient's RSA public key using RSA-OAEP.
   - Package header and ciphertext digest are signed with the sender's RSA private key using RSA-PSS.
   - Encrypted package (`.pkg`) is saved to storage.
3. **Restricted Sharing:**
   - Sender generates a restricted sharing link with an expiration date and download quota.
   - Backend stores a SHA-256 hash of the random sharing token in SQLite.
4. **Authorized Retrieval & Decryption:**
   - Recipient logs in and opens the share link.
   - Backend verifies that:
     1. The caller is authenticated.
     2. `authenticated_caller.id == share.recipient_user_id`.
     3. Share link is unexpired, unrevoked, and has remaining download quota.
   - Backend verifies the sender's RSA-PSS digital signature over the package.
   - Backend unwraps the AES session key using recipient's RSA private key.
   - Backend executes authenticated decryption (verifying the 128-bit AES-GCM tag).
   - Only upon complete verification of both signature and authentication tag is the decrypted file streamed to the recipient.

---

## 3. Technology Stack

- **Frontend:** React 19, TypeScript (strict), Vite, Vanilla CSS design system, Lucide React icons.
- **Backend:** Python 3.11+, FastAPI, Uvicorn, Pydantic v2, Python `cryptography` library.
- **Security & Storage:** Argon2 password hashing (`argon2-cffi`), SQLite database, filesystem package storage behind an abstract storage interface.
- **Testing:** Pytest, HTTPX, TypeScript type checking, Vite build validation.

---

## 4. Educational Prototype Trust Boundary & Non-Goals

### Server-Side Trust Model:
- In this educational prototype, cryptographic processing is performed server-side.
- Private keys at rest are protected by a server master key (`SERVER_MASTER_KEY`).
- **This design is NOT end-to-end encrypted (E2EE).** The backend server is fully trusted with access to plaintext files during upload/download and access to user keys.

### Explicit Non-Goals for Phase 1:
- Not intended for production deployment or handling confidential real-world data.
- Client-side WebCrypto in-browser encryption is deferred to future project revisions.
- External cloud HSM / KMS integration is deferred.
