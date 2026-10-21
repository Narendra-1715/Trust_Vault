# TrustVault

> **Enterprise Confidential Document Management Platform**  
> *Engineered around server-side zero-trust authorization, transactional access revocation, tamper-evident cryptographic auditing, and human-in-the-loop AI assistance.*

---

[![CI Pipeline](https://github.com/Narendra-1715/Trust_Vault/actions/workflows/ci.yml/badge.svg)](https://github.com/Narendra-1715/Trust_Vault/actions)
[![Security Architecture](https://img.shields.io/badge/Security-Zero--Trust%20Server--Side-blue?style=flat-square)](THREATS.md)
[![Audit Ledger](https://img.shields.io/badge/Audit-SHA--256%20Hash%20Chained-emerald?style=flat-square)](#4-tamper-evident-cryptographic-audit-ledger)
[![Authorization Matrix](https://img.shields.io/badge/AuthZ-Row--Level%20Enforced-navy?style=flat-square)](#3-centralized-authorization-matrix)
[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.14-blue?style=flat-square&logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2019%20%2B%20TypeScript-61DAFB?style=flat-square&logo=react)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2016-336791?style=flat-square&logo=postgresql)](https://www.postgresql.org/)

---

## Table of Contents

1. [Executive Overview & Non-Negotiable Invariants](#1-executive-overview--non-negotiable-invariants)
2. [System Architecture](#2-system-architecture)
3. [Centralized Authorization Matrix](#3-centralized-authorization-matrix)
4. [Tamper-Evident Cryptographic Audit Ledger](#4-tamper-evident-cryptographic-audit-ledger)
5. [Private Storage & File Security Model](#5-private-storage--file-security-model)
6. [Human-in-the-Loop AI Architecture](#6-human-in-the-loop-ai-architecture)
7. [API Endpoint Directory](#7-api-endpoint-directory)
8. [Automated Security Test Suite](#8-automated-security-test-suite)
9. [Local Quickstart & Execution](#9-local-quickstart--execution)
10. [Docker Compose & Production Deployment](#10-docker-compose--production-deployment)
11. [Development Fixtures & Demonstration Script](#11-development-fixtures--demonstration-script)
12. [Threat Model & Accepted Limitations](#12-threat-model--accepted-limitations)
13. [Engineering Transparency & Prompts Log](#13-engineering-transparency--prompts-log)

---

## 1. Executive Overview & Non-Negotiable Invariants

TrustVault is a confidential document repository designed to protect high-value business assets (financial reports, executive roadmaps, contracts, and IP) from both external threat actors and unauthorized authenticated insiders.

### Core Architectural Invariants

- **Server-Side Sole Authority:** Access decisions are made exclusively on the backend. Client-supplied roles, cached tokens, and hidden UI controls are untrusted.
- **Immediate Permission Revocation:** Download URLs are short-lived and non-static. Downloads are streamed directly through authenticated endpoints that re-query the database within the active transaction; revocation is instantaneous on the subsequent request.
- **Information-Leak Prevention:** Requests for inaccessible documents return a uniform `404 Not Found` (never `403 Forbidden`), preventing attackers from enumerating private document existence.
- **Isolated Private Storage:** Document binaries are stored outside the public web root under randomized UUID keys with enforced extension allowlists, size limits, and magic-byte signature validation.
- **Tamper-Evident Audit Ledger:** Every state-altering action appends an immutable audit event linked via canonical JSON serialization and SHA-256 hash chaining.
- **Advisory AI Boundaries:** External LLMs operate exclusively on document metadata. AI models possess **zero database write permissions**; permission grants require explicit human owner approval.

---

## 2. System Architecture

```mermaid
flowchart TD
    subgraph ClientLayer["Untrusted Client Tier"]
        Browser["React 19 + TypeScript SPA<br/>(Restrained Enterprise UI)"]
    end

    subgraph Perimeter["Edge & Reverse Proxy Tier"]
        Proxy["Nginx / Reverse Proxy<br/>(Security Headers, TLS, Host Checks)"]
        Limiter["Sliding-Window IP Rate Limiter<br/>(Brute-Force & Abuse Mitigation)"]
    end

    subgraph CoreBackend["Trusted Backend Tier (FastAPI)"]
        Authn["Argon2id Auth Engine<br/>(RFC 9106, Memory-Hard Hashes)"]
        PolicyEngine["Centralized Policy Engine<br/>(AuthorizationPolicy)"]
        StorageEngine["Private Storage Manager<br/>(Magic-Byte & Stream Protection)"]
        AuditEngine["Audit Hash Chainer<br/>(Canonical JSON + SHA-256)"]
        AIService["AI Advisory Service<br/>(Gemini 3.8 Flash / Deterministic Mock)"]
    end

    subgraph Persistence["Persistent Storage Tier"]
        Postgres[(PostgreSQL 16 Database<br/>Alembic Migrations)]
        PrivateStorage[("Private Filesystem Storage<br/>(Outside Web Root, UUID Keys)")]
    end

    Browser -->|HTTPS + Bearer JWT| Proxy
    Proxy --> Limiter
    Limiter --> Authn
    Authn --> PolicyEngine
    PolicyEngine -->|Strict Row-Level Check| Postgres
    PolicyEngine -->|Streaming Authorized IO| StorageEngine
    StorageEngine --> PrivateStorage
    PolicyEngine -->|Append-Only Chained Events| AuditEngine
    AuditEngine --> Postgres
    PolicyEngine -.->|Sanitized Metadata Only| AIService
```

---

## 3. Centralized Authorization Matrix

Global roles (`admin`, `owner`, `viewer`) govern administrative scopes, but **document-level permissions dictate document confidentiality**. An administrator role does not grant implicit content access unless an explicit permission has been granted.

| Operation | Document Owner | Active `EDIT` Grant | Active `READ` Grant | Authenticated Outsider | Global Admin |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Upload Document** | Authorized | Authorized | Authorized | Authorized | Authorized |
| **List Documents** | Own records | Permitted records | Permitted records | Isolated (0 leak) | Full inventory (audited) |
| **View Metadata** | Authorized | Authorized | Authorized | **404 Not Found** | Explicit inventory audit |
| **Stream Download** | Authorized | Authorized | Authorized | **404 Not Found** | **Denied** (requires grant) |
| **Edit Metadata** | Authorized | Authorized | **403 Forbidden** | **404 Not Found** | **Denied** (requires grant) |
| **Delete Document** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | Soft/Hard policy |
| **Grant Access** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | **Denied** (owner only) |
| **Revoke Access** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | **Denied** (owner only) |
| **Request AI Suggestions** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | **Denied** (owner only) |
| **Approve AI Suggestions** | Authorized | **403 Forbidden** | **403 Forbidden** | **404 Not Found** | **Denied** (owner only) |
| **View Document Audit** | Authorized | Authorized | Authorized | **404 Not Found** | Authorized (audited) |
| **Verify Audit Ledger** | Denied | Denied | Denied | Denied | Authorized |
| **Manage User Roles** | Denied | Denied | Denied | Denied | Authorized |

---

## 4. Tamper-Evident Cryptographic Audit Ledger

Every security-sensitive event is linked to its chronological predecessor using a deterministic SHA-256 hash chain:

```mermaid
flowchart LR
    Genesis["Genesis State<br/>previous_hash = 0^64"] --> Event1["Event 1 (Upload)<br/>SHA256(CanonicalPayload_1)"]
    Event1 --> Event2["Event 2 (Grant)<br/>SHA256(CanonicalPayload_2)"]
    Event2 --> Event3["Event 3 (Download)<br/>SHA256(CanonicalPayload_3)"]
    Event3 --> EventN["Event N (Revoke)<br/>SHA256(CanonicalPayload_N)"]
```

### Mathematical Formulation

$$\text{CanonicalPayload}_i = \text{CanonicalJSON}\Big(\text{id}, \text{timestamp}_{\text{UTC}}, \text{actor\_id}, \text{action}, \text{resource\_type}, \text{resource\_id}, \text{outcome}, \text{metadata}, \text{previous\_event\_hash}\Big)$$

$$\text{event\_hash}_i = \text{SHA-256}\Big(\text{CanonicalPayload}_i\Big)$$

- **Deterministic Normalization:** Timestamps are normalized to strict ISO-8601 UTC strings (`%Y-%m-%dT%H:%M:%S.%fZ`), preventing serialization divergence across database engines.
- **Verification Engine:** Executed via `GET /api/v1/audit/verify`. Recalculates the hash chain from genesis ($0^{64}$) forward. Any altered payload, deleted row, or reordered sequence causes an immediate hash mismatch and identifies the exact tampered record.

---

## 5. Private Storage & File Security Model

1. **Path-Traversal Protection:** Original filenames are stripped of relative traversal tokens (`../`, `..\`), slashes, and null bytes (`\0`). Files are written to `/data/vault_storage/{uuid4}.bin`.
2. **Magic-Byte Signature Inspection:** File headers are validated against signature allowlists prior to processing:
   - PDF: `%PDF`
   - Microsoft Office (DOCX/XLSX/PPTX): `PK\x03\x04`
   - PNG: `\x89PNG\r\n\x1a\n`
   - JPEG: `\xff\xd8\xff`
3. **Capacity Boundaries:** Streams are capped at 25MB (`MAX_FILE_SIZE_BYTES`); violations trigger automatic buffer cleanup and storage removal.
4. **Authorized Streaming:** Content is transferred using chunked `StreamingResponse` with:
   - `Content-Disposition: attachment; filename="..."`
   - `X-Content-Type-Options: nosniff`
   - Authenticated permission evaluation preceding byte dispatch.

---

## 6. Human-in-the-Loop AI Architecture

TrustVault incorporates an advisory AI integration designed to assist document owners in setting minimum-necessary access permissions while preventing autonomous privilege escalation.

```mermaid
sequenceDiagram
    autonumber
    actor Owner as Document Owner
    participant API as FastAPI Backend
    participant AI as Gemini 3.8 Flash / Mock Adapter
    participant DB as PostgreSQL Database

    Owner->>API: POST /documents/{id}/ai-recommendations
    Note over API: Verifies Owner Authority & Sanitizes Metadata
    API->>AI: Generate recommendations (Title, Category, Candidate Roles)
    AI-->>API: Validated JSON Response (SuggestedGrant Schema)
    API->>DB: Persist suggestion as PENDING (Zero grants created)
    API-->>Owner: Display suggestions with confidence & rationale
    Owner->>API: POST /documents/{id}/ai-recommendations/approve (Explicit selection)
    Note over API: Re-verifies Owner Authority & Validates Grants
    API->>DB: Insert DocumentPermission records in active transaction
    API->>DB: Append AUDIT event (ai.recommendation.approved)
    API-->>Owner: Applied permissions confirmed
```

- **Prompt Injection Defense:** Model inputs are restricted to structured metadata; raw document binaries are never sent to external model providers.
- **Fail-Safe Operation:** If the Gemini API experiences upstream throttling (e.g. 503) or is unconfigured, the system automatically uses the deterministic [`MockAIProvider`](file:///c:/Users/chint/OneDrive/Desktop/Trust_val/backend/app/ai/mock_provider.py) while explicitly labeling `is_mock: true`.

---

## 7. API Endpoint Directory

All endpoints are versioned under `/api/v1` and document security schemas in OpenAPI (`/docs`).

| Method | Endpoint | Authentication | Required Authorization | Audit Event Logged |
| :--- | :--- | :---: | :---: | :--- |
| `POST` | `/api/v1/auth/login` | Anonymous | Rate Limited | `auth.login.success` / `auth.login.failed` |
| `POST` | `/api/v1/auth/register` | Anonymous | Open / Configured | `auth.register` |
| `GET` | `/api/v1/auth/me` | Bearer Token | Active User | None |
| `GET` | `/api/v1/users` | Bearer Token | Active User | None |
| `PATCH` | `/api/v1/users/{id}` | Bearer Token | **Admin Role** | `admin.user.update` |
| `POST` | `/api/v1/documents/upload` | Bearer Token | Active User | `document.upload` |
| `GET` | `/api/v1/documents` | Bearer Token | Row-Level Filter | None |
| `GET` | `/api/v1/documents/{id}` | Bearer Token | Document Owner / Reader | None (Consistent 404 on unauth) |
| `GET` | `/api/v1/documents/{id}/download` | Bearer Token | Document Owner / Reader | `document.download` (or `.denied`) |
| `PATCH` | `/api/v1/documents/{id}` | Bearer Token | Document Owner / Editor | `document.update` |
| `DELETE` | `/api/v1/documents/{id}` | Bearer Token | **Document Owner Only** | `document.delete` |
| `GET` | `/api/v1/documents/{id}/permissions` | Bearer Token | Document Owner / Reader | None |
| `POST` | `/api/v1/documents/{id}/permissions` | Bearer Token | **Document Owner Only** | `permission.grant` / `permission.update` |
| `DELETE` | `/api/v1/documents/{id}/permissions/{u_id}` | Bearer Token | **Document Owner Only** | `permission.revoke` |
| `POST` | `/api/v1/documents/{id}/ai-recommendations` | Bearer Token | **Document Owner Only** | `ai.recommendation.generated` |
| `POST` | `/api/v1/documents/{id}/ai-recommendations/approve` | Bearer Token | **Document Owner Only** | `ai.recommendation.approved` |
| `POST` | `/api/v1/documents/{id}/ai-recommendations/reject` | Bearer Token | **Document Owner Only** | `ai.recommendation.rejected` |
| `GET` | `/api/v1/audit/events` | Bearer Token | Admin or Document Owner | None |
| `GET` | `/api/v1/audit/verify` | Bearer Token | Active User / Admin | `audit.verify` |
| `GET` | `/api/v1/health` | Anonymous | Public Health Probe | None |

---

## 8. Automated Security Test Suite

The platform includes 23 integration and security test cases executed against isolated test databases and private storage instances.

```bash
cd backend
python -m pytest -v
```

### Verified Test Results

| Security Category | Test Identifier | Assertion & Invariant Verified | Result |
| :--- | :--- | :--- | :---: |
| **Authentication** | `test_unauthenticated_request_rejected` | Protected endpoints return 401 without bearer token | `PASSED` |
| | `test_valid_login_success` | Argon2id verification succeeds; issues valid JWT | `PASSED` |
| | `test_invalid_password_rejected_with_generic_message` | Rejection details prevent username enumeration | `PASSED` |
| | `test_disabled_user_login_prevented` | Inactive accounts receive 403 Forbidden | `PASSED` |
| | `test_tampered_bearer_token_rejected` | Modified JWT signatures return 401 | `PASSED` |
| **Authorization** | `test_cross_user_read_isolation_returns_404` | Owner A cannot read Owner B's document (returns 404) | `PASSED` |
| | `test_cross_user_download_isolation_returns_404` | Owner A cannot download Owner B's file (returns 404) | `PASSED` |
| | `test_cross_user_edit_denied` | Metadata edit attempts on unowned documents return 404 | `PASSED` |
| | `test_cross_user_delete_denied` | Delete attempts on unowned documents return 404 | `PASSED` |
| | `test_viewer_with_read_access_cannot_edit` | Viewers with `read` permission cannot edit (returns 403) | `PASSED` |
| | `test_viewer_cannot_grant_permissions` | Viewers cannot grant permissions to third parties (403) | `PASSED` |
| | `test_search_never_reveals_unauthorized_documents` | Search queries exclude inaccessible documents | `PASSED` |
| **Revocation** | `test_immediate_permission_revocation_lifecycle` | Revocation immediately denies the next request (404) | `PASSED` |
| **Storage Security** | `test_executable_upload_rejected` | Executable file extensions are rejected (400) | `PASSED` |
| | `test_mime_magic_byte_spoofing_rejected` | Spoofed extensions without magic bytes are rejected (400) | `PASSED` |
| | `test_filename_sanitization_strips_path_traversal` | Relative directory paths and null bytes are sanitized | `PASSED` |
| | `test_document_deletion_removes_private_file` | Deleting document removes binary from private storage | `PASSED` |
| **Audit Integrity** | `test_audit_event_generation_and_valid_hash_chain` | Chained SHA-256 events pass full verification | `PASSED` |
| | `test_tampering_event_payload_detected` | Payload alteration causes hash mismatch detection | `PASSED` |
| | `test_tampering_event_deletion_detected` | Deleting a record triggers a chain-break detection | `PASSED` |
| **AI Boundaries** | `test_ai_mock_recommendation_and_explicit_approval_workflow` | AI suggestions create zero grants until owner approves | `PASSED` |
| | `test_ai_recommendation_rejection_leaves_no_grants` | Rejecting AI recommendations creates zero grants | `PASSED` |

```text
======================= 23 passed in 13.66s =======================
```

---

## 9. Local Quickstart & Execution

### Prerequisites

- Python 3.12+ (or Conda / virtual environment)
- Node.js 20+ and npm

### 1. Backend Setup & Seeding

```powershell
cd backend
python -m pip install -r requirements.txt
python -m alembic upgrade head
python seed.py
```

### 2. Start Backend Server

```powershell
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- API Base: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`
- Health Probe: `http://127.0.0.1:8000/api/v1/health`

### 3. Start Frontend Client

```powershell
cd frontend
npm install
npm run dev
```

- Web Client: `http://localhost:5173`

---

## 10. Docker Compose & Production Deployment

For complete containerized execution (PostgreSQL 16, FastAPI backend, and Nginx reverse proxy):

```bash
docker-compose up --build -d
```

### Production Environment Variables

| Variable | Description | Recommended Production Setting |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+psycopg://user:pass@host:5432/dbname` |
| `SECRET_KEY` | JWT signing secret | 64-character cryptographically random string |
| `STORAGE_DIR` | Private storage path | Dedicated persistent volume outside web root |
| `AI_PROVIDER` | Active AI provider adapter | `gemini` (or `mock` for air-gapped environments) |
| `AI_MODEL` | Google GenAI model | `gemini-3.8-flash` |
| `GEMINI_API_KEY` | Google Gemini API key | Stored in backend secrets manager |
| `ENVIRONMENT` | Operational environment | `production` |
| `DEBUG` | FastAPI debugging flag | `false` |

---

## 11. Development Fixtures & Demonstration Script

### Demo Accounts

The database seeder (`backend/seed.py`) configures distinct identities for testing:

| User | Email | Password | Role & Scope |
| :--- | :--- | :--- | :--- |
| **Alice** | `owner_a@trustvault.com` | `OwnerAPass123!` | Document Owner (Uploads, grants/revokes access, requests AI) |
| **Bob** | `owner_b@trustvault.com` | `OwnerBPass123!` | Document Owner (Isolated tenant for cross-user tests) |
| **Carol** | `viewer_a@trustvault.com` | `ViewerAPass123!` | Restricted Viewer (Read-only access when granted) |
| **Admin** | `admin@trustvault.com` | `AdminPass123!` | Security Administrator (Ledger verification, role management) |

### 5-Minute Evaluation Walkthrough

1. **Sign In as Owner A:** Navigate to `http://localhost:5173/login`, click **Alice (Document Owner A)**, and sign in.
2. **Upload Confidential Document:** Click **Upload Document**, attach a sample PDF/TXT file, label it `Q4 Strategic Planning`, category `Executive`, and submit. Note the calculated SHA-256 checksum.
3. **Grant Explicit Access:** Open the document, navigate to **Sharing & Permissions**, select **Carol Viewer (`viewer_a@trustvault.com`)**, assign `Read Only`, and submit.
4. **Verify Access as Viewer:** Sign out, log in as **Carol**, verify the document appears in the repository, and click **Download** to stream the file. Notice edit and delete operations are restricted.
5. **Immediate Revocation:** Sign back in as **Alice**, click **Revoke Access** on Carol's permission. Log back in as **Carol**; the document is immediately removed from the repository, and direct requests to `/download` return `404 Not Found`.
6. **AI Advisory Recommendation:** Sign in as **Alice**, open a document, go to **AI Access Recommendations**, and click **Request AI Recommendations**. Verify that suggestions remain pending with **zero permissions granted** until Alice explicitly clicks **Approve & Grant Access**.
7. **Verify Cryptographic Ledger:** Navigate to **Audit Trail** and click **Verify Ledger Integrity**. The system recalculates all SHA-256 hash chains and confirms integrity.

---

## 12. Threat Model & Accepted Limitations

For the complete threat analysis, see [`THREATS.md`](THREATS.md).

### Known Architectural Limitations & Accepted Risks

1. **Database-Only Hash Chain:** The cryptographic hash chain detects unauthorized deletion or tampering of audit records by application users and compromised accounts. However, a database superuser with root write access could theoretically rewrite the table and recompute hashes. In high-assurance production environments, periodic signed checkpoints must be pushed to an external, write-once audit destination (e.g., AWS S3 Object Lock or an append-only transparency log).
2. **Antivirus Scanning:** Magic-byte inspection and extension allowlists are enforced; however, binary malware scanning (e.g. ClamAV) must be incorporated into the upload pipeline prior to public production deployment.
3. **Legal Review:** The Privacy Policy ([`/privacy`](file:///c:/Users/chint/OneDrive/Desktop/Trust_val/frontend/src/routes/PrivacyPage.tsx)) and Terms and Conditions ([`/terms`](file:///c:/Users/chint/OneDrive/Desktop/Trust_val/frontend/src/routes/TermsPage.tsx)) are functional architectural drafts reflecting actual platform mechanics and require legal counsel sign-off before commercial release.

---

## 13. Engineering Transparency & Prompts Log

For a chronological record of architectural design sessions, security decisions, bug investigations, and human corrections, refer to [`PROMPTS.md`](PROMPTS.md).

---

*TrustVault &copy; 2026. Confidential Document Management Platform.*
