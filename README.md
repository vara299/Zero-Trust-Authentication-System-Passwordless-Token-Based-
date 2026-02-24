## Zero-Trust Authentication System (Passwordless + Token-Based)

**Level**: Advanced / Pre-Industry  
**Domain**: Cybersecurity + Backend Systems  
**Tech**: Python, Flask, JWT, bcrypt

This project demonstrates a **zero-trust, passwordless-style authentication flow**:

- **No stored passwords** in the auth service
- **Short‑lived, signed JWT access tokens**
- **Server-side hashing** of tokens (no raw token stored)
- **Strict JWT claims** (issuer, audience, expiry, jti, subject)
- **Every request is re‑verified**
- **Basic replay attack protection** using the `jti` claim
- **CSRF‑safe pattern** using `Authorization: Bearer <token>` header (no cookies)

It is intentionally small enough to read end-to-end, but models patterns used in modern systems at companies like Google, Microsoft, and banks.

---

### 1. Install & Run

#### 1.1. Create a virtual environment (recommended)

```bash
cd "Zero-Trust Authentication System (Passwordless + Token-Based)"
python -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate
```

#### 1.2. Install dependencies

```bash
pip install -r requirements.txt
```

#### 1.3. Configure environment (optional but recommended)

Create a `.env` file next to `auth_server.py`:

```bash
cat > .env << 'EOF'
JWT_SECRET_KEY=change-me-in-production
JWT_ISSUER=zero-trust-auth-server
JWT_AUDIENCE=zero-trust-clients
ACCESS_TOKEN_TTL_MINUTES=2
EOF
```

If you skip this, a **dev-only fallback secret** is used.

#### 1.4. Start the auth server

```bash
python auth_server.py
```

The server listens on `http://127.0.0.1:5000`.

#### 1.5. Run the demo client

In another terminal (with the same virtualenv activated):

```bash
python client.py
```

You will see:

- A token issue call to `/request-token`
- A successful call to `/secure-data`
- A **second call with the same token** rejected as a replay

---

### 2. Files Overview

- `requirements.txt` – Python dependencies.
- `token_utils.py` – **Core security logic**:
  - Loads `JWT_SECRET_KEY`, issuer, audience, TTL from environment.
  - Generates JWTs with `sub`, `jti`, `iss`, `aud`, `iat`, `nbf`, `exp`.
  - Verifies JWT signature + claims on every request.
  - Hashes tokens with bcrypt and verifies them without storing the raw token.
- `auth_server.py` – **Zero‑trust API server**:
  - `/health` – Simple healthcheck.
  - `/request-token` – Issues a short‑lived JWT after a simulated passwordless login.
  - `/secure-data` – Protected resource; checks JWT, hash, and replay.
- `client.py` – **Simulated client**:
  - Requests a token for `user123`.
  - Calls the protected endpoint with `Authorization: Bearer <token>`.
  - Replays the same token to demonstrate replay detection.

---

### 3. Zero‑Trust Properties Implemented

- **No session trust**:
  - The server does **not** keep a trusted session.
  - Every call to `/secure-data` must present a valid, signed, unexpired JWT.

- **Short‑lived tokens**:
  - Lifetime is controlled via `ACCESS_TOKEN_TTL_MINUTES` (default: 2 minutes).
  - Token expiry is enforced by `exp`, checked on every request.

- **Strict JWT claims**:
  - `iss` (issuer) and `aud` (audience) are validated.
  - `sub` (subject) identifies the user.
  - `jti` (JWT ID) is a unique identifier used for replay detection.
  - `nbf` and `iat` ensure tokens are not accepted before they are valid.

- **Server‑side token hashing**:
  - The raw token is returned to the client but **never stored** on the server.
  - Only a bcrypt hash is kept in `active_token_hashes`.
  - On each request, the presented token is bcrypt‑verified against the stored hash.

- **Basic replay protection (one‑time tokens)**:
  - Each token embeds a unique `jti`.
  - On successful use, the `jti` is added to `used_jtis`.
  - Any subsequent request with the same `jti` is rejected as a replay.
  - If a new token is issued for the same user, older tokens with different `jti` are treated as **stale**.

- **CSRF‑safe usage pattern**:
  - Tokens are only accepted in the `Authorization: Bearer <token>` header.
  - The server **rejects** tokens sent in other formats, making it easier to avoid cookie‑based CSRF vectors.

---

### 4. How This Differs from “Normal” Auth Demos

Typical tutorials:

- Store passwords or password hashes.
- Log the user in once, then **implicitly trust** a long‑lived session cookie.
- Rarely enforce issuer/audience/nbf/jti claims, or hashed token storage.

This project:

- Does **not** store user passwords at all (assumes some external passwordless verification step).
- Issues **short‑lived**, strongly signed tokens with strict claims.
- **Verifies every request** independently (signature, claims, hash).
- Implements **basic replay detection** with `jti` and an in‑memory store.

---

### 5. Ideas for Next-Level Extensions

If you want to push this closer to an industry‑grade system, consider:

- **Real passwordless factors**:
  - Integrate WebAuthn / FIDO2 for device‑bound credentials.
  - Email‑based magic links or TOTP‑based second factors.
- **Stronger replay protection**:
  - Move `used_jtis` into Redis with TTL.
  - Store per‑user device IDs and rotate tokens on suspicious behavior.
- **Token types**:
  - Add refresh tokens with longer lifetimes and stronger binding rules.
  - Separate access vs. management scopes in the JWT claims.
- **Network‑level zero‑trust**:
  - mTLS between services.
  - IP reputation / risk scoring / anomaly detection.
- **Auditing**:
  - Log authentication events, token issuance, and replay attempts centrally.

This repo gives you a compact, readable base that already demonstrates **zero‑trust, passwordless‑style, token‑based authentication with replay protection** that you can walk through in an interview or presentation.

# Zero-Trust-Authentication-System-Passwordless-Token-Based-
