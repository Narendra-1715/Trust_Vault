# TRUSTVAULT VERIFIED ADVERSARIAL AUTHORIZATION MATRIX

**Audit Date:** October 23, 2026  
**Verification Method:** Empirical execution via `backend/scripts/audit_verifier_suite.py`  
**Execution Environment:** Local live test client with SQLite/PostgreSQL transactional engine.

---

## 1. Persona Definitions

- **Anonymous:** Unauthenticated client (no `Authorization` header).
- **Viewer A (No Grant):** Authenticated viewer with zero grants on Document A (`viewer_a@trustvault.com`).
- **Viewer A (Granted):** Authenticated viewer with active `read` permission on Document A (`viewer_a@trustvault.com`).
- **Owner B:** Authenticated document owner of Document B; competitor/unauthorized party relative to Document A (`owner_b@trustvault.com`).
- **Owner A:** Authenticated owner and creator of Document A (`owner_a@trustvault.com`).
- **Admin:** Authenticated platform security administrator (`admin@trustvault.com`).

---

## 2. Empirical Endpoint Authorization Matrix

The table below reflects the **actual observed HTTP response codes** captured directly from live test execution against Document A (owned by Owner A):

| Endpoint & HTTP Method | Anonymous | Viewer A (No Grant) | Viewer A (Granted) | Owner B (Cross-Tenant) | Owner A (Creator) | Admin (Zero-Trust) | Security Enforcement Mechanism | Empirical Test Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **GET `/documents/{id}`** | 401 | 404 | 200 | 404 | 200 | **404** | `AuthorizationPolicy.require_read` masks existence from non-permitted users and admins. | **VERIFIED** |
| **GET `/documents/{id}/download`**| 401 | 404 | 200 | 404 | 200 | **404** | Live DB query on `revoked_at IS NULL`. Zero admin content bypass. Logs `download.denied` on 404. | **VERIFIED** |
| **PATCH `/documents/{id}`** | 401 | 404 | 403 | 404 | 200 | **404** | Requires edit permission. Viewers receive 403; unpermitted users and admins receive 404. | **VERIFIED** |
| **DELETE `/documents/{id}`** | 401 | 404 | 403 | 404 | 204 | **404** | `AuthorizationPolicy.require_owner` strictly limits deletion to document creator. | **VERIFIED** |
| **GET `/documents/{id}/permissions`**| 401 | 404 | 200 | 404 | 200 | **404** | Requires read authorization. Permitted viewers can inspect active grants; unpermitted receive 404. | **VERIFIED** |
| **POST `/documents/{id}/permissions`**| 401 | 404 | 403 | 404 | 201 | **404** | Only the document owner can grant permissions. Viewers receive 403; admins receive 404. | **VERIFIED** |
| **DELETE `/documents/{id}/permissions/{uid}`**| 401 | 404 | 403 | 404 | 204 | **404** | Immediate revocation. Only document owner can revoke. Sets `revoked_at` timestamp. | **VERIFIED** |
| **POST `/documents/{id}/ai-recommendations`**| 401 | 404 | 403 | 404 | 200 | **404** | AI recommendation generation restricted to document owner. | **VERIFIED** |
| **GET `/documents`** | 401 | 200 (Empty) | 200 (Doc A) | 200 (Doc B) | 200 (Doc A) | 200 (Owned/Inv) | Scoped SQL query. Admin can inspect inventory via `admin_inventory=true` (metadata only). | **VERIFIED** |
| **POST `/documents/upload`** | 401 | 403 | 403 | 201 | 201 | 201 | Restricted to `admin` and `owner` roles. Viewers rejected with 403. | **VERIFIED** |
| **GET `/audit/events`** | 401 | 200 (Actor) | 200 (Actor) | 200 (Owned+Act) | 200 (Owned+Act) | 200 (Org-wide) | Scoped audit visibility. Document owners see denials on owned files. | **VERIFIED** |
| **GET `/audit/verify`** | 401 | 403 | 403 | 200 | 200 | 200 | SHA-256 canonical hash chain verification. Viewers rejected with 403. | **VERIFIED** |
| **PATCH `/users/{uid}/status`** | 401 | 403 | 403 | 403 | 403 | 200 | Global administrative account lock/unlock. Restricted strictly to admin. | **VERIFIED** |
| **GET `/health`** | 200 | 200 | 200 | 200 | 200 | 200 | Public service health check. Reports status and version. | **VERIFIED** |

---

## 3. Key Authorization Findings & Corrections

### 3.1 Correction to Prior Test Matrix (Admin Zero-Trust Enforcement)
- **Prior Report Assumption:** The previous report assumed standard RBAC where `Admin` has root read and download access to all documents (marked as `200 Allowed`).
- **Empirical Reality:** In the actual source code (`backend/app/policies/authorization.py`), TrustVault enforces **Zero-Trust Document Isolation**:
  ```python
  # backend/app/policies/authorization.py:30-31
  # Admins do not automatically have content access unless explicitly granted.
  ```
  When Admin attempts `GET /documents/{id}/download` for a document owned by Owner A, the server returns `HTTP 404 Not Found`. Admin does NOT possess content download privileges unless granted by Owner A.

### 3.2 404 Masking vs 403 Disclosure
- Cross-tenant users (Owner B) and unpermitted viewers (Viewer A) receive `404 Not Found` across all document operations.
- Permitted viewers attempting write operations (PATCH, POST permissions, DELETE) receive `403 Forbidden` because their read grant allows them to know the document exists, but their role lacks edit/management authority.

### 3.3 Synchronous Revocation Evidence
- **Before Revocation:** Viewer A issued `GET /documents/{id}/download` $\rightarrow$ `200 OK` (binary stream delivered).
- **Owner Invokes Revocation:** `DELETE /documents/{id}/permissions/{viewer_a_id}` $\rightarrow$ `204 No Content`.
- **Immediate Next Download Call:** Viewer A issued `GET /documents/{id}/download` $\rightarrow$ `404 Not Found` (instant rejection).
- **Audit Logging:** An audit event `document.download.denied` was synchronously committed to the audit ledger.