# TrustVault

> **Enterprise Confidential Document Management Platform**  
> *Engineered around server-side zero-trust authorization, AES-256-GCM envelope encryption, native PostgreSQL 16 Row-Level Security, tamper-evident cryptographic auditing, and human-in-the-loop AI assistance.*

🌐 **Live Application**: [https://trustvault-ui.onrender.com](https://trustvault-ui.onrender.com/)  
📚 **API Documentation**: [https://trustvault-api-s6ba.onrender.com/docs](https://trustvault-api-s6ba.onrender.com/docs)  
🩺 **Health Endpoint**: [https://trustvault-api-s6ba.onrender.com/api/v1/health](https://trustvault-api-s6ba.onrender.com/api/v1/health)

---

[![Live Demo](https://img.shields.io/badge/Live%20Demo-trustvault--ui.onrender.com-brightgreen?style=flat-square&logo=render)](https://trustvault-ui.onrender.com/)
[![CI Pipeline](https://github.com/Narendra-1715/Trust_Vault/actions/workflows/ci.yml/badge.svg)](https://github.com/Narendra-1715/Trust_Vault/actions)
[![Security Invariants](https://img.shields.io/badge/Security%20Invariants-6%2F6%20Enforced-blue?style=flat-square)](THREATS.md)
[![Test Suite](https://img.shields.io/badge/Tests-165%20Passed%20(Hypothesis%20%2B%20PostgreSQL%2016)-success?style=flat-square)](#7-automated-security-test-suite--pentest-validation)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM%20Envelope-blueviolet?style=flat-square)](#2-key-architectural-features)
[![PostgreSQL 16](https://img.shields.io/badge/Database-PostgreSQL%2016%20RLS-336791?style=flat-square&logo=postgresql)](https://www.postgresql.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/Frontend-React%2019%20%2B%20TypeScript-61DAFB?style=flat-square&logo=react)](https://react.dev/)

---

## Table of Contents

1. [Non-Negotiable Security Invariants](#1-non-negotiable-security-invariants)
2. [Key Architectural Features](#2-key-architectural-features)
3. [System Architecture Diagram](#3-system-architecture-diagram)
4. [Centralized Authorization & Access Matrix](#4-centralized-authorization--access-matrix)
5. [Tamper-Evident Cryptographic Audit Ledger](#5-tamper-evident-cryptographic-audit-ledger)
6. [Human-in-the-Loop AI Boundary (Invariant I6)](#6-human-in-the-loop-ai-boundary-invariant-i6)
7. [Automated Security Test Suite & Pentest Validation](#7-automated-security-test-suite--pentest-validation)
8. [API Endpoint Directory](#8-api-endpoint-directory)
9. [Demonstration Personas & Evaluation Walkthrough](#9-demonstration-personas--evaluation-walkthrough)
10. [Local Quickstart & Execution](#10-local-quickstart--execution)
11. [Production Deployment & Environment Variables](#11-production-deployment--environment-variables)
12. [Security Architecture & Threat Model](#12-security-architecture--threat-model)

---

## 1. Non-Negotiable Security Invariants

TrustVault is constructed upon six inviolable architectural invariants:

| Invariant | Name | Architectural Enforcement |
| :---: | :--- | :--- |
| **I1** | **Server-Side Sole Authority** | Access decisions are executed exclusively by the backend centralized `AuthorizationService`. Client tokens, UI states, and claims are completely untrusted. |
| **I2** | **Immediate Revocation** | Downloads are dynamically authorized and streamed within the active transaction. Permissions are re-checked upon every request; revocation is instant on the subsequent byte stream. |
| **I3** | **Zero Information Leaks** | Access attempts to unowned or unpermitted documents return a uniform `404 Not Found` (never `403`), backed by timing-equalized dummy queries to prevent resource enumeration. |
| **I4** | **Tamper-Evident Ledger** | Every state-altering action appends an immutable audit event linked via deterministic canonical JSON serialization and SHA-256 cryptographic hash chaining from a fixed genesis block. |
| **I5** | **Private File Boundary** | Files are stored outside the web root under randomized UUID keys with extension allowlists, 25MB stream limits, and magic-byte header validation. |
| **I6** | **AI Zero-Write Boundary** | Advisory LLMs interact exclusively with sanitized metadata via `ai_document_metadata_view` with **zero database write permissions**; all permissions require explicit human owner approval. |

---

## 2. Key Architectural Features

### Cryptographic Envelope Encryption (AES-256-GCM)
- **Per-Document Keys:** Every uploaded document is encrypted with an isolated 256-bit AES-GCM Data Encryption Key (DEK).
- **Master Key Derivation:** Master key is derived using HKDF-SHA256 with cryptographically random salt and context parameters.
- **Key Rotation & Multi-Version Support:** Key metadata is managed in a dedicated `DocumentKey` schema, supporting on-demand key re-encryption without re-encrypting the underlying storage binary.

### Native PostgreSQL 16 Row-Level Security (RLS)
- **Database-Level Isolation:** Multi-tenant boundaries enforced directly by PostgreSQL RLS policies (`CREATE POLICY ON documents`).
- **Parameterized Session Scoping:** Session boundaries are established per request using PostgreSQL's native `SELECT set_config('app.current_user_id', :uid, true)` and `SELECT set_config('app.current_org_id', :org, true)`.
- **Role Separation:** Distinct database roles provisioned for specific operational domains: `app_rw`, `migrator`, `audit_writer`, `ai_readonly`, and `backup_ro`.

### Enterprise Governance & Access Lifecycles
- **Time-Bound Permissions:** Access grants support mandatory `expires_at` timestamps with automatic server-side pruning.
- **Self-Service Access Requests:** Viewers can request access with business justifications; owners review, grant, or deny through dual-custody controls.
- **Compliance Access Reviews:** Periodic recertification workflows allow owners and security compliance officers to audit active permissions.
- **Audited Break-Glass Access:** Emergency administrative access protocol requiring documented justification, generating high-priority security audit events.

### Multi-Backend Storage Engine
- **Cloud & Local Storage:** Pluggable storage architecture supporting AWS S3, Supabase Storage (S3-compatible via `boto3`), and isolated local disk volumes.
- **Fail-Safe Integrity:** Pre-stream SHA-256 checksum verification ensures corrupted files fail safely without leaking partial buffers.
- **Magic-Byte Signature Inspection:** Validates binary headers against format signatures (PDF, DOCX, XLSX, PNG, JPEG) to reject spoofed extensions.

### Perimeter Defense & Threat Prevention
- **Sliding-Window Rate Limiting:** In-memory and Redis-ready rate limiters for IP addresses, authentication attempts, downloads, and AI suggestions.
- **Argon2id Password Hashing:** RFC 9106 memory-hard password hashing with per-user salts.
- **Session Revocation & Tracking:** User sessions tracked with unique IDs; instant single-session or all-session invalidation on logout or password reset.
- **Anomaly Detection:** Real-time security alerts for brute-force bursts, abnormal downloading patterns, and privilege escalation attempts.

---

## 3. System Architecture Diagram

```mermaid
flowchart TD
    subgraph ClientLayer["Client Tier (Untrusted)"]
        Browser["React 19 + TypeScript SPA<br/>(Modern Enterprise Security Dashboard)"]
    end

    subgraph Perimeter["Perimeter & Edge Tier"]
        Proxy["Reverse Proxy / Cloudflare<br/>(TLS 1.3, Strict CSP, HSTS, CORS)"]
        Limiter["Sliding-Window Rate Limiter<br/>(Auth, Download, & AI Limits)"]
    end

    subgraph Backend["Trusted Backend Tier (FastAPI)"]
        Authn["Argon2id Auth & Session Manager<br/>(JWT JTI Revocation, Anti-Enumeration)"]
        Authz["Centralized Authorization Engine<br/>(ABAC + Org Isolation + Break-Glass)"]
        CryptoEngine["Envelope Encryption Engine<br/>(AES-256-GCM + HKDF Master Key)"]
        StorageAdapter["Private Storage Manager<br/>(Magic-Byte Check + Stream Capping)"]
        AuditChainer["Tamper-Evident Audit Chainer<br/>(SHA-256 Chain + Genesis Block)"]
        AIBoundary["AI Advisory Boundary (I6)<br/>(AIReadOnlySession + Sanitized View)"]
    end

    subgraph DataTier["Data Persistence Tier"]
        Postgres[("PostgreSQL 16 Database<br/>(Row-Level Security + Roles)")]
        VaultStorage[("Private Storage (S3 / Local)<br/>(UUID Blobs, Encrypted at Rest)")]
    end

    Browser -->|HTTPS + Bearer JWT| Proxy
    Proxy --> Limiter
    Limiter --> Authn
    Authn --> Authz
    Authz --> CryptoEngine
    CryptoEngine --> StorageAdapter
    StorageAdapter --> VaultStorage
    Authz -->|Parameterized Session RLS| Postgres
    Authz -->|Append-Only Chained Events| AuditChainer
    AuditChainer --> Postgres
    Authz -.->|Read-Only Sanitized Metadata| AIBoundary
    AIBoundary -.->|Zero DB Writes| Postgres
```

---

## 4. Centralized Authorization & Access Matrix

All authorization decisions pass through [`AuthorizationService`](backend/app/services/authorization.py). Global roles (`admin`, `owner`, `viewer`) govern platform administration, while **document-level permissions dictate confidential content access**:

| Operation | Document Owner | Active `EDIT` Grant | Active `READ` Grant | Authenticated Outsider | Global Admin |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Upload Document** | Authorized | Authorized | Authorized | Authorized | Authorized |
| **List Documents** | Own records | Permitted records | Permitted records | Isolated (0 leak) | Inventory audit |
| **View Metadata** | Authorized | Authorized | Authorized | **404 Not Found** | Explicit audit |
| **Stream Download** | Authorized | Authorized | Authorized | **404 Not Found** | **Denied** (requires grant) |
| **Edit Metadata / Replace** | Authorized | Authorized | **403 Forbidden** | **404 Not Found** | **Denied** (requires grant) |
| **Delete Document** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | Admin soft-delete |
| **Grant / Revoke Access** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | **Denied** (owner only) |
| **Manage Access Requests** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | **Denied** (owner only) |
| **Request AI Suggestions** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | **Denied** (owner only) |
| **Approve AI Suggestions** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | **Denied** (owner only) |
| **Execute Break-Glass** | Denied | Denied | Denied | Denied | **Audited Dual-Control** |
| **Verify Audit Ledger** | Authorized | Authorized | Authorized | Authorized | Authorized |

---

## 5. Tamper-Evident Cryptographic Audit Ledger

Every security-sensitive event produces an immutable cryptographic digest linked to its chronological predecessor:

```mermaid
flowchart LR
    Genesis["Genesis Block<br/>previous_hash = 0^64"] --> Event1["Event 1 (Upload)<br/>SHA256(CanonicalPayload_1)"]
    Event1 --> Event2["Event 2 (Grant)<br/>SHA256(CanonicalPayload_2)"]
    Event2 --> Event3["Event 3 (Download)<br/>SHA256(CanonicalPayload_3)"]
    Event3 --> EventN["Event N (Revoke)<br/>SHA256(CanonicalPayload_N)"]
```

### Mathematical Chain Formulation

Every event $i$ generates a SHA-256 digest $H_i$ computed from deterministic canonical JSON:

$$H_i = \mathrm{SHA256}\Big(\mathrm{CanonicalJSON}(e_i)\Big)$$

where payload $e_i$ contains normalized fields:

$$e_i = \Big( \text{id},\; \text{timestamp}_{\text{UTC}},\; \text{actor},\; \text{action},\; \text{resource},\; \text{outcome},\; \text{metadata},\; H_{i-1} \Big)$$

For the genesis record ($i = 0$): $H_0 = 0^{64}$.

- **Tamper Detection:** Modifying any historical row, deleting an event, or altering sequence timestamps breaks the chain and flags the exact corrupted record index via `GET /api/v1/audit/verify`.

---

## 6. Human-in-the-Loop AI Boundary (Invariant I6)

TrustVault integrates advisory AI assistance (Google Gemini 2.5 Flash / deterministic offline fallback) while preventing autonomous privilege escalation:

```mermaid
sequenceDiagram
    autonumber
    actor Owner as Document Owner
    participant API as FastAPI Backend
    participant AI as Gemini 2.5 Flash / Mock Adapter
    participant DB as PostgreSQL 16 Database

    Owner->>API: POST /documents/{id}/ai-recommendations
    Note over API: Verifies Owner Authority & Queries Sanitized View
    API->>AI: Generate candidate access grants from metadata
    AI-->>API: Structured SuggestedGrant JSON Schema
    API->>DB: Store in ai_access_suggestions (Status: PENDING)
    API-->>Owner: Display suggestions with confidence & rationale
    Note over Owner: Human Owner Reviews & Selects Grants
    Owner->>API: POST /documents/{id}/ai-recommendations/approve
    Note over API: Re-validates Ownership & Applies Grants in Transaction
    API->>DB: Insert DocumentPermission records
    API->>DB: Append AUDIT event (ai.recommendation.approved)
    API-->>Owner: Applied permissions confirmed
```

- **Zero Database Write Access:** Enforced via `AIReadOnlySession` and PostgreSQL `ai_readonly` role.
- **Sanitized Metadata Isolation:** The AI engine accesses exclusively `ai_document_metadata_view`; document binaries and raw contents are never transmitted.
- **No Autonomous Grants:** Recommendations remain strictly inert until an authenticated owner approves them.

---

## 7. Automated Security Test Suite & Pentest Validation

The platform includes **165 automated security, integration, property-based, and pentest simulation tests** running against PostgreSQL 16:

```bash
cd backend
pytest -v --tb=short
```

### Test Suite Architecture (37 Test Modules)

| Security Category | Test Files | Target Invariant & Coverage |
| :--- | :--- | :--- |
| **Authentication & Sessions** | `test_auth.py`, `test_session_management.py` | Argon2id verification, JWT JTI revocation, sliding-window rate limiters, anti-enumeration |
| **Authorization & Isolation** | `test_authorization.py`, `test_authorization_matrix.py`, `test_admin_control.py` | Invariants I1 & I3: Complete ABAC matrix, lateral tenant isolation, cross-user denial |
| **PostgreSQL 16 RLS & Roles** | `test_no_direct_permission_checks.py`, Alembic migrations | DB-level row security, `set_config` transaction parameters, role privileges |
| **Envelope Encryption** | `test_encryption_envelope.py`, `test_document_versions.py` | AES-256-GCM per-document encryption, HKDF key derivation, multi-version document keys |
| **Revocation & Streaming** | `test_revocation.py`, `test_revocation_and_streaming.py` | Invariant I2: Immediate transactional download revocation, chunked authorized streaming |
| **Storage & File Security** | `test_s3_storage.py`, `test_storage_uploads.py`, `test_storage_fail_safe.py` | Invariant I5: Magic-byte inspection, path traversal sanitization, fail-safe no split-brain |
| **Cryptographic Audit Ledger** | `test_audit_integrity.py`, `test_audit_ledger_phase5.py`, `test_audit_export.py` | Invariant I4: SHA-256 hash chaining, genesis block verification, tampering & deletion detection |
| **AI Boundary & Invariant I6** | `test_ai_boundary_phase6.py`, `test_ai_recommendations.py` | Invariant I6: Zero-write DB boundary (`AIReadOnlySession`), owner approval lifecycle |
| **Governance & Access Lifecycles**| `test_access_expiry.py`, `test_access_requests.py`, `test_access_reviews.py` | Time-bound permission expiry, dual-custody access requests, compliance access reviews |
| **Emergency Break-Glass** | `test_break_glass_phase7.py` | Audited emergency access, dual-custody justification requirement |
| **Anomaly Detection & Alerts** | `test_suspicious_activity.py`, `test_security_alerts.py` | Brute-force burst detection, suspicious download anomaly alerts |
| **Property-Based Testing** | `test_authorization_hypothesis.py`, `test_property_based.py` | Hypothesis fuzzing with 100+ random permission and role permutations |
| **Pentest & Adversarial Sims** | `test_pentest_simulation_phase12.py`, `test_external_posture_phase9.py` | Active penetration test simulations, CSP/HSTS headers, supply chain vulnerability audit |

---

## 8. API Endpoint Directory

All endpoints are versioned under `/api/v1` and fully documented in Swagger UI (`/docs`):

### Authentication & Sessions
- `POST /api/v1/auth/login` — Authenticate credentials with Argon2id, rate-limited by IP and user.
- `POST /api/v1/auth/register` — Register new user account with role validation.
- `GET /api/v1/auth/me` — Retrieve active user session profile.
- `POST /api/v1/auth/logout` — Invalidate current session token (JTI blacklist).
- `POST /api/v1/auth/logout-all` — Revoke all active sessions for the authenticated user.

### Confidential Documents & Storage
- `POST /api/v1/documents/upload` — Upload and envelope-encrypt document (AES-256-GCM + magic bytes).
- `GET /api/v1/documents` — List authorized documents (filtered by owner and explicit grants).
- `GET /api/v1/documents/{id}` — Retrieve document metadata (uniform 404 on unpermitted).
- `GET /api/v1/documents/{id}/download` — Stream decrypted document bytes (authorized transactionally).
- `PATCH /api/v1/documents/{id}` — Update document classification metadata.
- `DELETE /api/v1/documents/{id}` — Delete document binary and purge encryption keys (owner only).

### Access Control & Governance
- `GET /api/v1/documents/{id}/permissions` — List active permission grants for a document.
- `POST /api/v1/documents/{id}/permissions` — Grant or update user permissions with optional expiry.
- `DELETE /api/v1/documents/{id}/permissions/{user_id}` — Revoke permissions immediately.
- `POST /api/v1/access-requests` — Submit self-service access request with business justification.
- `GET /api/v1/access-requests` — View pending access requests for owned documents.
- `POST /api/v1/access-requests/{id}/approve` — Approve access request (dual-custody).
- `POST /api/v1/access-requests/{id}/deny` — Deny access request with reason.
- `POST /api/v1/admin/break-glass` — Execute emergency audited break-glass access (admins only).

### AI Advisory Recommendations (Invariant I6)
- `POST /api/v1/documents/{id}/ai-recommendations` — Generate pending access recommendations (zero DB writes).
- `POST /api/v1/documents/{id}/ai-recommendations/approve` — Explicitly apply selected recommendations.
- `POST /api/v1/documents/{id}/ai-recommendations/reject` — Dismiss pending recommendations.

### Audit Ledger & Health
- `GET /api/v1/audit/events` — Retrieve tamper-evident audit trail (paginated, scoped).
- `GET /api/v1/audit/verify` — Verify cryptographic SHA-256 hash chain from genesis block.
- `GET /api/v1/audit/export` — Export cryptographically verifiable audit ledger in CSV/JSON format.
- `GET /api/v1/health` — Public health probe reporting storage backend and database connectivity.

---

## 9. Demonstration Personas & Evaluation Walkthrough

The platform includes pre-seeded demo accounts with distinct personas (`backend/seed.py`):

| Persona | Email | Password | Role & Authorization Scope |
| :--- | :--- | :--- | :--- |
| **Alice** | `owner_a@trustvault.com` | `OwnerAPass123!` | **Document Owner A** (Uploads, grants/revokes access, approves AI) |
| **Bob** | `owner_b@trustvault.com` | `OwnerBPass123!` | **Document Owner B** (Completely isolated tenant; zero cross-access) |
| **Carol** | `viewer_a@trustvault.com` | `ViewerAPass123!` | **Restricted Viewer** (Read-only access strictly when explicitly granted) |
| **Admin** | `admin@trustvault.com` | `AdminPass123!` | **Security Administrator** (Audit ledger verification, emergency break-glass) |

### 5-Minute Evaluation Walkthrough

1. **Sign In as Owner (Alice):** Navigate to [https://trustvault-ui.onrender.com/login](https://trustvault-ui.onrender.com/login), click the quick-login persona **Alice**, and sign in.
2. **Upload & Envelope Encryption:** Click **Upload Document**, attach a sample PDF or TXT file, set classification to `Confidential`, and upload. Notice the automatic SHA-256 checksum and envelope encryption key creation.
3. **Grant Explicit Access:** Open the document, go to **Sharing & Permissions**, grant `Read Only` access to **Carol Viewer (`viewer_a@trustvault.com`)**.
4. **Verify Access as Viewer (Carol):** Switch to Carol using persona login. Carol can see and download the document.
5. **Immediate Revocation:** Switch back to Alice and revoke Carol's access. Switch to Carol and refresh; the document instantly disappears from the UI, and direct API access to `/download` returns `404 Not Found`.
6. **AI Advisory Recommendation:** As Alice, open a document and click **Request AI Recommendations**. Verify suggestions are presented with confidence scores and remain inert until Alice explicitly clicks **Approve**.
7. **Verify Cryptographic Ledger:** Navigate to **Audit Trail** and click **Verify Ledger Integrity**. The backend recalculates the full SHA-256 hash chain from genesis ($0^{64}$) and confirms zero tampering.

---

## 10. Local Quickstart & Execution

### Prerequisites
- Python 3.12+
- Node.js 20+ and npm

### 1. Backend Setup
```bash
cd backend
python -m pip install -r requirements.txt
python -m alembic upgrade head
python seed.py
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base: `http://127.0.0.1:8000`
- Interactive Docs: `http://127.0.0.1:8000/docs`
- Health Probe: `http://127.0.0.1:8000/api/v1/health`

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
- Web Application: `http://localhost:5173`

---

## 11. Production Deployment & Environment Variables

### Production Architecture on Render.com
- **Frontend SPA:** Static site deployment on Render with client-side routing rewrites (`/* -> /index.html`).
- **Backend API:** Python web service running FastAPI under Uvicorn with Gunicorn process management.
- **Database:** Managed PostgreSQL 16 with Row-Level Security enabled.
- **Storage:** S3-compatible object storage (Supabase Storage / AWS S3) with encrypted bucket policies.

### Environment Variable Reference

| Variable | Description | Production Example |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL 16 connection string | `postgresql+psycopg://user:pass@host:5432/dbname` |
| `SECRET_KEY` | JWT signing secret key | 64-character cryptographically random hex string |
| `STORAGE_BACKEND` | Storage adapter backend | `s3` (or `local` for disk volume) |
| `S3_ENDPOINT_URL` | S3 API endpoint URL | `https://<project-ref>.supabase.co/storage/v1/s3` |
| `S3_BUCKET_NAME` | Private S3 bucket name | `trustvault-storage` |
| `S3_ACCESS_KEY_ID` | S3 access key ID | Configured via secrets manager |
| `S3_SECRET_ACCESS_KEY`| S3 secret access key | Configured via secrets manager |
| `S3_REGION_NAME` | S3 bucket region | `us-east-1` |
| `AI_PROVIDER` | AI provider adapter | `gemini` (live Google GenAI) or `mock` (offline) |
| `GEMINI_API_KEY` | Google Gemini API Key | Stored in secrets manager |
| `AI_MODEL` | Gemini LLM model identifier | `gemini-2.5-flash` |
| `ENVIRONMENT` | Operational environment | `production` |
| `DEBUG` | FastAPI debug mode | `false` |

---

## 12. Security Architecture & Threat Model

For comprehensive security analysis, threat modeling, and audit documentation, refer to:
- [**Threat Model & Invariant Analysis (THREATS.md)**](THREATS.md)
- [**Requirements Traceability Matrix (REQUIREMENTS_TRACEABILITY.md)**](REQUIREMENTS_TRACEABILITY.md)
- [**Security Audit & Remediation Log (SECURITY_REMEDIATION.md)**](SECURITY_REMEDIATION.md)
- [**Incident Response & Runbooks (docs/RUNBOOKS.md)**](docs/RUNBOOKS.md)

---

*TrustVault &copy; 2026. Confidential Document Management Platform.*
