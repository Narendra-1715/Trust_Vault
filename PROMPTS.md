# TrustVault Development & Security Decisions Log (PROMPTS.md)

This document provides a genuine, chronological record of engineering sessions, security design evaluations, architectural decisions, and human corrections throughout the implementation of TrustVault.

---

### Session 1: Architecture Invariants & PostgreSQL Database Modeling
- **Date:** 2026-10-21
- **Task / Objective:** Design normalized PostgreSQL schema and configure Alembic migrations for users, documents, permissions, audit events, and AI recommendations.
- **Architectural Decision:** Modeled `document_permissions` with explicit `revoked_at` timestamp rather than physical row deletion, providing historical lineage while allowing an unambiguous index filter (`WHERE revoked_at IS NULL`) for instantaneous permission checks.
- **Human Review & Changes:**
  - Added dual-dialect engine support in `session.py` so the system defaults to PostgreSQL for production/docker containers while permitting clean SQLite execution for local standalone test isolation.
  - Enabled SQLite foreign key enforcement listener (`PRAGMA foreign_keys=ON;`).
- **Tests & Verification:**
  - Ran `alembic revision --autogenerate` producing migration `bd7569ef1c23`.
  - Ran `alembic upgrade head` successfully against a clean database.

---

### Session 2: Centralized Authorization & Information-Leak Prevention
- **Date:** 2026-10-21
- **Task / Objective:** Implement server-side authorization policy service (`app/policies/authorization.py`) preventing IDOR/BOLA and eliminating timing/enumeration leaks.
- **Architectural Decision:** Implemented uniform `404 Not Found` responses when unauthorized users request a document ID they do not own or lack permission to read. A `403 Forbidden` error on document existence queries leaks information by confirming to an attacker that an inaccessible private document ID exists.
- **Human Review & Changes:**
  - Refactored `can_read_document` and `can_edit_document` to query the live database transaction on every request.
  - Denied administrators implicit document reading capabilities: admins can inspect metadata in designated inventory audits, but cannot read or download confidential document bodies without an explicit document permission.
- **Tests & Verification:**
  - Verified with `test_cross_user_read_isolation_returns_404` and `test_cross_user_download_isolation_returns_404`.

---

### Session 3: Cryptographic Audit Hash Chain & Timestamp Normalization Fix
- **Date:** 2026-10-21
- **Task / Objective:** Build append-only audit log with SHA-256 hash chaining and automated verification.
- **Critical Discovery & Bug Fix:**
  - During the first execution of `verify_audit_integrity`, the recomputed SHA-256 hash failed on row 0.
  - **Root Cause:** When `datetime.now(timezone.utc)` was inserted into the database, SQLite reloaded it as a naive datetime string (`2026-10-21T18:07:53.804589`), stripping the `+00:00` timezone offset. This slight string discrepancy altered the canonical JSON hash output.
  - **Correction:** Implemented `format_canonical_timestamp(ts)` in `hash_chain.py` to normalize naive and timezone-aware datetimes into a strict canonical UTC format (`%Y-%m-%dT%H:%M:%S.%fZ`).
- **Tests & Verification:**
  - Re-ran seeder: `Audit integrity verified: is_valid=True, total_events=8`.
  - Automated tests `test_tampering_event_payload_detected` and `test_tampering_event_deletion_detected` passed with 100% accuracy.

---

### Session 4: File Security, Magic Bytes & Path-Traversal Prevention
- **Date:** 2026-10-21
- **Task / Objective:** Implement secure file storage outside the web root with extension allowlists, magic-byte inspection, and streaming downloads.
- **Architectural Decision:**
  - Client-provided filenames are never used for filesystem operations. Uploaded files are written to `/data/vault_storage/{uuid4}.bin`.
  - Downloads are never served as static URLs; every byte stream is authenticated via `StreamingResponse` with `X-Content-Type-Options: nosniff`.
- **Human Review & Changes:**
  - Added signature verification for PDF (`%PDF`), PNG (`\x89PNG`), JPEG (`\xff\xd8\xff`), and OpenXML (`PK\x03\x04`).
  - Added strict realpath directory boundary enforcement in `_resolve_safe_path`.
- **Tests & Verification:**
  - Tested disguised files with `test_mime_magic_byte_spoofing_rejected` and `test_filename_sanitization_strips_path_traversal`.

---

### Session 5: AI Advisory Architecture & Human-in-the-Loop Isolation
- **Date:** 2026-10-21
- **Task / Objective:** Integrate Google Gemini LLM provider adapter and deterministic mock provider with strict security boundaries.
- **Architectural Decision:**
  - The AI provider is isolated behind a backend service (`app/ai/`). Provider credentials never reach the browser.
  - Initial access recommendations operate **strictly on metadata** (title, category, candidate roles). Raw document contents are not sent to third-party model providers.
  - AI responses are validated against Pydantic schema `SuggestedGrant`.
  - Proposals remain in `pending` status until the human document owner explicitly submits `POST /ai-recommendations/approve`.
- **Human Review & Changes:**
  - Built graceful fallback: if the Gemini API experiences upstream 503 load or is unreachable, the system automatically falls back to the deterministic mock engine while transparently tagging `is_mock: true` and detailing the upstream error.
- **Tests & Verification:**
  - Verified with `test_ai_mock_recommendation_and_explicit_approval_workflow` and `test_ai_recommendation_rejection_leaves_no_grants`.

---

### Session 6: Rate Limiting & Test Fixture Resolution
- **Date:** 2026-10-21
- **Task / Objective:** Enforce IP rate limiting on login and upload endpoints while maintaining test suite speed and reliability.
- **Issue Encountered:**
  - In initial pytest runs, tests started failing with `429 Too Many Requests` because the test runner executed more than 10 logins within a single second.
  - Additionally, `email-validator` rejected `.local` TLDs (e.g. `owner_a@test.local`) as reserved names.
- **Correction:**
  - Updated demonstration and test domain to `@trustvault.com` and `@test.com`.
  - Added an autouse pytest fixture `reset_rate_limiters` in `conftest.py` to reset in-memory sliding window counters between test iterations.
- **Tests & Verification:**
  - All 23 security tests in pytest passed with zero failures in 12.30s.

---

### Session 7: Cloud Deployment on Render & PostgreSQL Protocol Normalization
- **Date:** 2026-10-22
- **Task / Objective:** Deploy production infrastructure on Render using declarative `render.yaml` Blueprint (Managed PostgreSQL, FastAPI Web Service, Static Site).
- **Critical Discovery & Where AI Was Wrong:**
  - The AI initially assumed passing Render's `property: connectionString` into `DATABASE_URL` would connect directly with SQLAlchemy 2.0. However, Render PostgreSQL URLs start with `postgres://`, which raises `sqlalchemy.exc.NoSuchModuleError: Can't load plugin: sqlalchemy.dialects:postgres`.
  - Furthermore, Render passed `BACKEND_CORS_ORIGINS: "*"`. Because Pydantic's `BaseSettings` typed this field as `List[str]`, Pydantic called `json.loads('*')` on startup, crashing with a fatal `JSONDecodeError`.
- **Engineering Correction:**
  - Added `@field_validator("DATABASE_URL", mode="before")` across `Settings`, `session.py`, and `alembic/env.py` to automatically normalize `postgres://` or `postgresql://` into `postgresql+psycopg://`.
  - Added `psycopg2-binary>=2.9.9` alongside `psycopg[binary]==3.3.6` for total dialect coverage.
  - Retyped `BACKEND_CORS_ORIGINS` to `Union[str, List[str]]` with a safe parsing property supporting comma-separated strings, wildcard `*`, or JSON arrays.
- **Tests & Verification:**
  - Render Blueprint provisioned PostgreSQL `trustvault-postgres` and deployed backend web service `trustvault-api` successfully.

---

### Session 8: Internal Container Hostname vs. Public Browser Resolution
- **Date:** 2026-10-22
- **Task / Objective:** Connect the browser frontend static site to the deployed cloud backend API.
- **Critical Discovery & Where AI Was Wrong:**
  - In `render.yaml`, referencing `fromService: type: web, name: trustvault-api, property: host` provided Render's **internal private virtual network hostname** (e.g. `trustvault-api-s6ba`).
  - Because static React sites run in the client's public browser (not inside Render's internal network), the browser attempted `POST https://trustvault-api-s6ba/api/v1/auth/login` and failed with `net::ERR_NAME_NOT_RESOLVED`.
- **Engineering Correction:**
  - Updated `frontend/src/lib/api.ts` with a resilient URL resolver that detects cloud-internal hostnames without a domain dot and automatically appends `.onrender.com`, resolving cleanly to `https://trustvault-api-s6ba.onrender.com`.
- **Tests & Verification:**
  - Verified live login in browser across all roles with instant Argon2id token issuance.

---

### Session 9: Cross-Platform Path Sanitization & Toast UX Overhaul
- **Date:** 2026-10-22
- **Task / Objective:** Ensure automated test suite passes on both Windows and Linux CI runners, and eliminate jarring browser alert modals.
- **Critical Discovery & Where AI Was Wrong:**
  - `test_filename_sanitization_strips_path_traversal` passed locally on Windows, but failed on Ubuntu Linux runner in GitHub Actions:
    `assert '..' not in '....windowssystem32calc.exe'`
  - **Root Cause:** `os.path.basename("..\\..\\windows\\system32\\calc.exe")` treats backslashes as path separators on Windows, but as literal filename characters on Linux!
- **Engineering Correction:**
  - Updated `sanitize_filename` in `app/storage/local.py` to normalize backslashes to forward slashes (`filename.replace('\\', '/')`) before calling `os.path.basename`, and explicitly stripped repeated dots (`re.sub(r'\.{2,}', '', clean)`).
  - Replaced browser `alert()` popups across the entire frontend with an Antigravity-style floating bottom-right Toast Notification system with green checkmark animations and auto-dismissal.
- **Tests & Verification:**
  - GitHub Actions CI (Run #39674499447) passed 100% green on both `Backend Migrations & Security Tests` and `Frontend Typecheck & Build`.

---

### Session 10: Self-Service User Registration & Lifecycle Expansion
- **Date:** 2026-10-23
- **Task / Objective:** Implement complete self-service account registration on the login page while preserving one-click evaluator demo roles.
- **Architectural Decision:**
  - Added a clean segmented tab toggle (`[ Sign In ]` / `[ Create Account ]`) on the login screen.
  - Wired the existing Argon2id-encrypted `/api/v1/auth/register` endpoint to the frontend.
  - Automatically signs in newly registered users with an immediate session token and directs them to their private workspace, displaying a toast notification.
- **Tests & Verification:**
  - Tested registration with custom credentials; confirmed user created with Argon2id hash and audit event `auth.register` recorded in the cryptographic ledger.
