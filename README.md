# TrustVault: Confidential Document Management Platform

TrustVault is a security-first confidential document repository designed around zero-trust server-side authorization, immutable cryptographic auditing, private file storage, and human-in-the-loop AI assistance.

---

## 1. Core Security Invariants

1. **Server-Side Authorization Authority:** The backend is the sole authority for every read, write, download, delete, and permission decision. Client-side role claims and hidden buttons are completely untrusted.
2. **Information-Leak Prevention:** Unauthorized document requests yield a uniform `404 Not Found` (never `403`), ensuring attackers cannot determine whether private documents exist.
3. **Immediate Permission Revocation:** No long-lived or pre-signed download URLs exist. Every download is streamed through the authenticated API (`/api/v1/documents/{id}/download`), which re-evaluates database permissions on every call.
4. **Isolated Private Storage:** File binaries are stored outside the public web root using randomized UUID keys. Extension allowlists, size limits, and magic-byte signatures are enforced prior to storage.
5. **Tamper-Evident Audit Ledger:** Audit records are linked sequentially through canonical JSON and SHA-256 cryptographic hash chains ($\text{event\_hash} = \text{SHA256}(\text{CanonicalPayload})$).
6. **Advisory AI Boundaries:** AI models analyze metadata only. AI cannot execute database writes or grant access autonomously; explicit human owner approval is required for every permission grant.

---

## 2. Technology Stack

- **Backend:** Python 3.12+ / 3.14, FastAPI, SQLAlchemy 2.x, Alembic, PostgreSQL / SQLite, Argon2id (`argon2-cffi`), Google GenAI SDK (`gemini-3.8-flash`), Pytest, HTTPX.
- **Frontend:** React 19, TypeScript (strict mode), Vite, React Router 7, TanStack Query, Lucide Icons, Pure CSS Design System.
- **Infrastructure:** Docker, Docker Compose, Nginx, GitHub Actions CI.

---

## 3. Seed Accounts & Credentials (Development Only)

TrustVault provides an automated database seeder (`backend/seed.py`) with pre-configured demonstration accounts:

| Role | Email | Password | Intended Test Usage |
| :--- | :--- | :--- | :--- |
| **Security Admin** | `admin@trustvault.com` | `AdminPass123!` | Audit ledger verification, global user role management |
| **Document Owner A** | `owner_a@trustvault.com` | `OwnerAPass123!` | Uploading documents, sharing, revoking, requesting AI |
| **Document Owner B** | `owner_b@trustvault.com` | `OwnerBPass123!` | Proving cross-tenant isolation against Owner A |
| **Restricted Viewer A**| `viewer_a@trustvault.com` | `ViewerAPass123!` | Verifying read-only access and immediate revocation |

> [!WARNING]
> These credentials are strictly for development, evaluation, and automated testing. Change all passwords and secrets prior to public deployment.

---

## 4. Quickstart: Local Startup

### Prerequisites
- Python 3.12+ (or Conda/virtualenv)
- Node.js 20+ & npm

### Step 1: Initialize Database & Seed Demo Data
```bash
cd backend
pip install -r requirements.txt
alembic upgrade head
python seed.py
```

### Step 2: Start Backend API Server
```bash
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive OpenAPI Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- API Health Check: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

### Step 3: Start Frontend Client
```bash
cd frontend
npm install
npm run dev
```
- Workspace Web App: [http://localhost:5173](http://localhost:5173)

---

## 5. Docker Compose Deployment

To run the complete production stack (PostgreSQL 16, FastAPI Backend, and Nginx Frontend):

```bash
docker-compose up --build -d
```
Access the application at `http://localhost`.

---

## 6. Reproducible 5-Minute Demonstration Script

Follow this step-by-step verification script to inspect all core platform capabilities:

1. **Sign in as Document Owner:**
   - Navigate to `http://localhost:5173/login`.
   - Click the **Alice (Document Owner A)** quick-select button (`owner_a@trustvault.com`) and click **Sign in**.
2. **Upload a Confidential Document:**
   - In the Documents workspace, click **Upload Document**.
   - Select a sample PDF or TXT file, enter a title (e.g., `Q4 Compensation Planning`), choose `Financial`, and click **Upload Document**.
   - Note the SHA-256 checksum and randomized internal key assigned in private storage.
3. **Grant Explicit Access:**
   - Click **View** on the uploaded document.
   - Under the **Sharing & Permissions** tab, select **Carol Viewer (`viewer_a@trustvault.com`)**, choose `Read Only`, and click **Grant Access**.
4. **Verify Access as Viewer:**
   - Click **Sign out** in the top navigation.
   - Click **Carol (Restricted Viewer)** quick-select button and sign in.
   - Notice the document appears in Carol's repository with `Read Access`.
   - Click **Download**; the file streams successfully through the authenticated API.
   - Attempt to edit metadata or delete the document: notice the controls are disabled and any direct API modification attempt returns `403 Forbidden`.
5. **Immediate Access Revocation:**
   - Sign back in as **Alice (`owner_a@trustvault.com`)** and open the document.
   - In the Permissions table, click **Revoke Access** next to Carol.
   - Sign back in as **Carol (`viewer_a@trustvault.com`)**.
   - Carol's repository immediately shows `No authorized documents found`.
   - Any attempt to access `/documents/{id}` or `/documents/{id}/download` immediately returns `404 Not Found`.
6. **Request & Review AI Access Recommendations:**
   - Sign in as **Alice** and open a document.
   - Switch to the **AI Access Recommendations** tab and click **Request AI Recommendations**.
   - Inspect the structured suggestions generated by Google Gemini (`gemini-3.8-flash` or the deterministic mock engine).
   - Verify the security notice: suggestions remain in `pending` state with **zero access granted** until the owner clicks **Approve & Grant Access**.
7. **Verify Cryptographic Audit Trail:**
   - Navigate to **Audit Trail** in the top navigation.
   - Inspect the chronological records of the logins, upload, permission grant, download, and revocation.
   - Click **Verify Ledger Integrity**; the system recalculates all SHA-256 hash links and confirms that the chain is intact.
8. **Run Automated Security Test Suite:**
   - In terminal, execute: `cd backend && pytest -v`
   - Observe all 23 security tests pass, proving cross-user isolation, IDOR prevention, revocation immediacy, and tampering detection.

---

## 7. Automated Test Suite Results

Run backend automated tests:
```bash
cd backend
python -m pytest -v
```

### Verified Test Cases (23 Passed, 0 Failed):
- `test_unauthenticated_request_rejected`: Unauthenticated API requests are denied (401).
- `test_valid_login_success`: Valid login issues JWT token and role profile.
- `test_invalid_password_rejected_with_generic_message`: Generic rejection message prevents enumeration.
- `test_disabled_user_login_prevented`: Inactive accounts cannot authenticate (403).
- `test_tampered_bearer_token_rejected`: Tampered tokens are rejected (401).
- `test_cross_user_read_isolation_returns_404`: Owner A cannot read Owner B's document (404).
- `test_cross_user_download_isolation_returns_404`: Owner A cannot download Owner B's file (404).
- `test_cross_user_edit_denied`: Cross-user metadata edits are rejected.
- `test_cross_user_delete_denied`: Cross-user deletions are rejected.
- `test_viewer_with_read_access_cannot_edit`: Viewers cannot edit documents (403).
- `test_viewer_cannot_grant_permissions`: Viewers cannot grant permissions to other users (403).
- `test_search_never_reveals_unauthorized_documents`: Search results filter by authorization.
- `test_immediate_permission_revocation_lifecycle`: Revocation blocks subsequent requests immediately.
- `test_executable_upload_rejected`: Executable binaries are rejected.
- `test_mime_magic_byte_spoofing_rejected`: Spoofed extensions without magic bytes are rejected.
- `test_filename_sanitization_strips_path_traversal`: Path traversal symbols are sanitized.
- `test_document_deletion_removes_private_file`: Deleting document removes file from private storage.
- `test_audit_event_generation_and_valid_hash_chain`: Chained audit ledger verifies successfully.
- `test_tampering_event_payload_detected`: Altering an event's payload is detected by verification.
- `test_tampering_event_deletion_detected`: Deleting an audit event breaks the chain and is detected.
- `test_ai_mock_recommendation_and_explicit_approval_workflow`: AI suggestions require explicit owner approval to create grants.
- `test_ai_recommendation_rejection_leaves_no_grants`: Rejected AI suggestions create zero grants.

---

## 8. Limitations & Accepted Risks

1. **Database-Only Hash Chain:** The cryptographic hash chain detects unauthorized modification or deletion of prior audit events. However, a database superuser with root access could theoretically recompute the chain from a point of tampering forward. In high-assurance production environments, periodic cryptographic checkpoints should be anchored to an external, write-once audit destination (e.g. AWS S3 Object Lock or a transparency log).
2. **Malware Scanning:** File signature validation and extension allowlists are enforced; however, binary malware scanning (e.g. ClamAV) is not included out-of-the-box and should be placed in the upload pipeline before general enterprise deployment.
3. **Legal Review:** The Privacy Policy and Terms and Conditions are technical product drafts matching the system architecture and require formal counsel review prior to commercial launch.
