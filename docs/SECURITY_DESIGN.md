# Gupit Security Architecture & Threat Model

**Educational Prototype:** Secure File Sharing Using Hybrid Cryptography  
**Version:** 0.1.0 (Phase 1 Architecture Foundation)  
**Security Classification:** Server-Assisted Hybrid Cryptography (Not End-to-End Encrypted)  

---

## 1. System Architecture Overview

Gupit is designed to facilitate secure, authenticated, and access-controlled file sharing between registered users. It pairs asymmetric public-key cryptography (RSA) with symmetric authenticated file encryption (AES-GCM).

```
+-----------------------------------------------------------------------------------------+
|                                    GUPIT SYSTEM ARCHITECTURE                             |
+-----------------------------------------------------------------------------------------+

 [ Sender Client (React) ]                               [ Recipient Client (React) ]
         |                                                           |
         | 1. Upload File & Choose Recipient                         | 7. Access Share URL
         v                                                           v
+-----------------------------------------------------------------------------------------+
|                                Gupit Backend (FastAPI)                                  |
|                                                                                         |
|  [ Authentication & Sessions ]  [ CSRF Guard ]  [ Authorization & Share Verification ]  |
|                                                                                         |
|  [ Cryptographic Engine ]                                                               |
|    - AES-256-GCM symmetric file encryption / authenticated decryption                  |
|    - RSA-OAEP envelope unwrapping (using recipient encryption key)                      |
|    - RSA-PSS signature verification (using sender signing key)                          |
|                                                                                         |
|  [ Server-Side Key Management ]                                                         |
|    - Master Key (SERVER_MASTER_KEY from environment) wraps private keys at rest         |
+-----------------------------------------------------------------------------------------+
       |                                           |                                |
       v                                           v                                v
 [ SQLite Database ]                     [ Package Storage ]               [ Session Store ]
  - User credentials (Argon2)             - Encrypted Packages (.pkg)       - Hashed session
  - Identity public keys & fingerprints   - Tag, Nonce, Envelope            - Expiry & Revocation
  - Share metadata & token hashes         - Stored in local filesystem
```

---

## 2. Core Security Objectives: The CIA+A Triad

Gupit guarantees the following security properties:

1. **Confidentiality:** Only the intended recipient whose RSA public key wrapped the session key (and the trusted server assisting decryption) can recover the plaintext file content.
2. **Integrity:** The encrypted ciphertext cannot be modified or truncated in transit or storage without detection, guaranteed by the 128-bit AES-GCM authentication tag.
3. **Authenticity:** The recipient receives mathematical proof via an RSA-PSS digital signature that the package originated from the claimed sender and has not been altered since signing.
4. **Non-repudiation / Identity Binding:** Public key fingerprints bind sender and recipient cryptographic identities to user accounts.

---

## 3. Cryptographic Design Rationales

### 3.1 Why Combine AES and RSA (Hybrid Cryptography)?
- **Asymmetric Cryptography (RSA)** provides identity-based key exchange and public-key signatures without requiring a pre-shared secret between users. However, RSA is computationally intensive and mathematically restricted to encrypting payloads smaller than its modulus size (e.g., ~380 bytes for 3072-bit RSA).
- **Symmetric Cryptography (AES-GCM)** is hardware-accelerated, highly efficient, and capable of encrypting large multi-megabyte/gigabyte files rapidly.
- **The Hybrid Pattern:** Gupit generates a fresh, ephemeral 256-bit AES key for each file, encrypts the file bulk with AES-256-GCM, and then encrypts only the 32-byte AES key with the recipient's RSA public key using RSA-OAEP.

### 3.2 AES-GCM Nonces and Authentication Tags
- **Galois/Counter Mode (GCM)** is an Authenticated Encryption with Associated Data (AEAD) algorithm.
- **Nonce (Number used ONCE):** AES-GCM requires a unique 96-bit (12-byte) initialization vector for every encryption operation. Reusing a nonce with the same key catastrophically leaks the XOR of the plaintexts and destroys the authentication authenticity key. Gupit enforces fresh random nonces per package and throws away the ephemeral AES key after encryption.
- **Authentication Tag (128 bits):** A GHASH-computed polynomial authenticator. If even a single bit of the ciphertext or header metadata is modified, tag verification fails and decryption aborts completely.

### 3.3 RSA-OAEP and RSA-PSS
- **RSA-OAEP (Optimal Asymmetric Encryption Padding):** Traditional PKCS#1 v1.5 padding is vulnerable to chosen-ciphertext padding oracle attacks (Bleichenbacher attack). OAEP introduces randomized asymmetric Feistel masking with SHA-256 and MGF1, achieving IND-CCA2 security.
- **RSA-PSS (Probabilistic Signature Scheme):** Provides provable security based on the RSA problem, eliminating the deterministic signature risks present in legacy PKCS#1 v1.5 signature formats.
- **Separate Key Pairs:** Gupit mandates separate RSA key pairs for encryption wrapping vs. signing. Reusing a single RSA key for both encryption and signing violates cryptographic separation of duties and can expose systems to cross-protocol chosen-ciphertext attacks.

---

## 4. Authentication, Authorization, and Identity Model

### 4.1 Authentication vs. Authorization
- **Authentication ("Who are you?"):** Verifies user identity via Argon2id password hashing and validates active session cookies.
- **Authorization ("Are you allowed to access this?"):** Verifies that the authenticated caller has the legal right to access a specific share. 

> [!IMPORTANT]
> **Possession of a sharing URL or token is NOT sufficient.**  
> The backend checks both:
> 1. Does the request provide a valid, unexpired, unrevoked share token?
> 2. Does `authenticated_user.id == share.recipient_user_id`?
> If a different authenticated user opens the link, the request is denied with `403 Forbidden`.

### 4.2 User Accounts vs. Cryptographic Identities
- **User Accounts (`usr_...`):** Represent credentials, email, and human identity in SQLite.
- **Cryptographic Identities (`idt_...`):** Represent public/private key material. A user may cycle or revoke identities over time. Public keys are cataloged with SHA-256 fingerprints to guard against identity confusion.

### 4.3 Restricted Sharing Links
- Share URLs contain high-entropy random tokens (192+ bits of entropy).
- **Hashed Token Storage:** The raw token is displayed to the sender once. SQLite stores only `SHA-256(token)`. If the database is compromised, an attacker cannot extract usable sharing tokens from disk.
- **Expirations & Quotas:** Every share has an enforced expiration timestamp and a remaining download counter.

---

## 5. Web Application Security & Hardening

### 5.1 Session Protection
- Server-side sessions using opaque cryptographically random tokens (`secrets.token_urlsafe(32)`).
- Session tokens are stored in SQLite only as SHA-256 hashes.
- Cookies configured with:
  - `HttpOnly`: Prevents client-side script access (mitigating XSS session theft).
  - `SameSite=Lax` (or `Strict`): Prevents CSRF on normal navigation.
  - `Secure`: Required in production to enforce HTTPS transmission.

### 5.2 Cross-Site Request Forgery (CSRF) Defense
- All state-changing endpoints (`POST`, `PUT`, `DELETE`) require a CSRF token passed via custom request headers.

### 5.3 File Size and Package Validation
- File upload sizes are limited at the web server and application layers (default 50MB) to mitigate denial-of-service (DoS) memory exhaustion.
- Path traversal sanitization: Original filenames are sanitized before being placed into download headers.

---

## 6. Server-Side Key Management & Trust Model

### 6.1 Prototype Architecture (Server-Side Key Storage)
In this local-development educational prototype:
- RSA private keys are stored on the server.
- To prevent plaintext storage on disk, private keys are encrypted at rest using AES-256-GCM with a server master key (`SERVER_MASTER_KEY`).
- The server master key is supplied via environment variable and must never be committed to Git.

### 6.2 Why This Prototype is NOT End-to-End Encrypted (E2EE)
In true End-to-End Encryption (E2EE):
- Key generation, encryption, and decryption happen strictly on the client device (e.g. inside browser Web Crypto API).
- Private keys never leave the user's client device.
- The server is "zero-knowledge" and merely acts as a dumb relay for ciphertext.

In this Gupit Prototype:
- The server performs cryptographic operations on behalf of the user.
- The server has temporary access to the unencrypted file during upload/download processing and has access to private keys when decrypted with the master key.
- **Trust Assumption:** The backend is trusted.

### 6.3 Consequences of Server-Side Key Management
- If the backend host is compromised, an attacker with root access or memory extraction tools can obtain the master key and decrypt stored user private keys and files.
- If the `SERVER_MASTER_KEY` environment variable is exposed, all at-rest private keys can be decrypted.

---

## 7. Known Limitations & Future Roadmap

| Limitation | Impact in Prototype | Future Production Enhancement |
| :--- | :--- | :--- |
| **Server-side decryption** | Server sees plaintext and keys | Migrate to client-side Web Crypto API (genuine E2EE). |
| **Local SQLite & Filesystem** | Single server, scale limits | Migrate storage abstraction to S3/Cloud Storage & PostgreSQL. |
| **Master Key in Env Var** | Host-level exposure risk | Integrate with Hardware Security Modules (HSM) or Cloud KMS. |
| **Public Key Trust** | Trust-on-first-use (TOFU) | Certificate Authority (CA) or Web of Trust / key transparency log. |
| **Streaming Large Files** | Files buffered in memory/temp | Chunked streaming encryption via AES-GCM chunks. |
