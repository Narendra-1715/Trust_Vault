# TRUSTVAULT VERIFIED AUTHORIZATION MATRIX & DIRECTORY SHARING POLICY

**Audit Date:** October 23, 2026  
**Verification Method:** Empirical execution via `backend/scripts/audit_verifier_suite.py` and live production probing on `https://trustvault-api-s6ba.onrender.com` (Commit: `03c5150`).

---

## 1. Architectural Scope & Persona Definitions

TrustVault is engineered as a **single-organization confidential document repository** with zero-trust document isolation. Users belong to the same organizational domain (e.g. `@trustvault.com`).

- **Anonymous:** Unauthenticated external client (no credentials).
- **Viewer A (No Grant):** Authenticated viewer with zero grants on Document A (`viewer_a@trustvault.com`).
- **Viewer A (Granted):** Authenticated viewer with active `read` permission on Document A (`viewer_a@trustvault.com`).
- **Owner B (Peer Colleague / Unrelated Owner):** Authenticated document owner in the same company (`owner_b@trustvault.com`). Does not own Document A.
- **Owner A (Creator & Owner):** Authenticated owner and creator of Document A (`owner_a@trustvault.com`).
- **Admin:** Authenticated platform security administrator (`admin@trustvault.com`).

---

## 2. Master Endpoint Authorization Matrix

The table below reflects **empirically validated responses** captured from local test suites and live production probes:

| Endpoint & HTTP Method | Anonymous | Viewer A (No Grant) | Viewer A (Granted) | Owner B (Peer Colleague) | Owner A (Creator) | Administrator (Zero-Trust) | Enforcement Invariant | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **POST `/auth/register`** | 201 (owner/viewer) | 201 | 201 | 201 | 201 | **422/403 (admin)** | Admin self-registration blocked. | **VERIFIED LIVE** |
| **POST `/auth/login`** | 200 | 200 | 200 | 200 | 200 | 200 | Argon2id verification + IP sliding-window rate limit. | **VERIFIED LIVE** |
| **GET `/auth/me`** | 401 | 200 | 200 | 200 | 200 | 200 | Active user check + JWT validation. | **VERIFIED LIVE** |
| **POST `/documents/upload`** | 401 | 403 | 403 | 201 | 201 | 201 | Restricted to `owner` and `admin` roles. | **VERIFIED LIVE** |
| **GET `/documents`** | 401 | 200 (empty) | 200 (doc A) | 200 (doc B) | 200 (doc A) | 200 (owned/inv) | Scoped query. Admin can view metadata inventory via `admin_inventory=true`. | **VERIFIED LIVE** |
| **GET `/documents/{id}`** | 401 | 404 | 200 | **404** | 200 | **404** | 404 masks document existence from peer owners and admins. | **VERIFIED LIVE** |
| **GET `/documents/{id}/download`** | 401 | 404 | 200 | **404** | 200 | **404** | Live DB check on `revoked_at IS NULL` + SHA-256 pre-stream checksum check. | **VERIFIED LIVE** |
| **PATCH `/documents/{id}`** | 401 | 404 | 403 | 404 | 200 | 404 | Requires document ownership or explicit edit grant. | **VERIFIED LIVE** |
| **DELETE `/documents/{id}`** | 401 | 404 | 403 | 404 | 204 | 404 | Restricted exclusively to document creator. | **VERIFIED LIVE** |
| **GET `/documents/{id}/permissions`** | 401 | 404 | 200 | 404 | 200 | 404 | Permitted viewers can inspect active grants; unpermitted receive 404. | **VERIFIED LIVE** |
| **POST `/documents/{id}/permissions`**| 401 | 404 | 403 | 404 | 201 | 404 | Only document creator can grant access. | **VERIFIED LIVE** |
| **DELETE `/documents/{id}/permissions/{u}`**| 401 | 404 | 403 | 404 | 204 | 404 | Synchronously writes `revoked_at`. Subsequent calls return 404. | **VERIFIED LIVE** |
| **POST `/documents/{id}/ai-recommendations`**| 401 | 404 | 403 | 404 | 200 | 404 | AI suggestion generation restricted to document owner. | **VERIFIED LIVE** |
| **POST `/ai-recommendations/{id}/approve`**| 401 | 404 | 403 | 404 | 200 | 404 | Human-in-the-loop grant execution by owner. | **VERIFIED LIVE** |
| **POST `/ai-recommendations/{id}/reject`**| 401 | 404 | 403 | 404 | 200 | 404 | Rejection leaves zero database grants. | **VERIFIED LIVE** |
| **GET `/audit/events`** | 401 | 200 (self) | 200 (self) | 200 (self+owned) | 200 (self+owned) | 200 (org-wide) | Scoped audit visibility. Owners see download denials on owned documents. | **VERIFIED LIVE** |
| **GET `/audit/verify`** | 401 | 403 | 403 | 200 | 200 | 200 | Canonical JSON SHA-256 hash chain verification. | **VERIFIED LIVE** |
| **GET `/users`** | 401 | **403** | **403** | **200 (minimal)** | **200 (minimal)** | **200 (minimal)** | Internal directory for sharing. Viewers forbidden. Non-admins receive minimal fields. | **VERIFIED LIVE** |
| **GET `/users/all`** | 401 | 403 | 403 | 403 | 403 | 200 | Admin-only account management directory. | **VERIFIED LIVE** |
| **PATCH `/users/{id}`** | 401 | 403 | 403 | 403 | 403 | 200 | Admin-only account activation / role modification. | **VERIFIED LIVE** |
| **GET `/health`** | 200 | 200 | 200 | 200 | 200 | 200 | Public health telemetry + `commit_sha`. | **VERIFIED LIVE** |

---

## 3. Directory Sharing Policy & Peer Owner Isolation Clarification

### 3.1 Single-Organization Scope
TrustVault implements a **single-organization enterprise workspace**:
- All users belong to the same corporate instance.
- **Why Owner B can call `GET /api/v1/users`:** Because Owner B (like Owner A) is a document owner who needs to discover coworkers to share documents with.
- **Data Minimization:** `GET /api/v1/users` returns only `UserDirectoryItem` (`id`, `email`, `display_name`, `role`). Internal account metadata (`created_at`, `updated_at`, `is_active`) is completely omitted.
- **Viewer Restriction:** Ordinary Viewers cannot grant permissions and have no legitimate need to enumerate corporate employees. Viewers attempting `GET /api/v1/users` receive `HTTP 403 Forbidden`.

### 3.2 Peer Document Isolation
Even though Owner A and Owner B can discover each other's names in the employee directory:
1. **Document Metadata Isolation:** Owner B calling `GET /api/v1/documents/{doc_a_id}` receives `HTTP 404 Not Found`.
2. **Document Download Isolation:** Owner B calling `GET /api/v1/documents/{doc_a_id}/download` receives `HTTP 404 Not Found`.
3. **Search Isolation:** Owner B searching for keywords contained in Owner A's unshared documents receives `0` results.
4. **Enforcement:** Verified in regression test `test_peer_owner_isolation_in_same_organization` and on the live production API.