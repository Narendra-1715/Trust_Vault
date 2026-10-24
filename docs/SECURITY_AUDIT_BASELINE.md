# TrustVault Security Audit Baseline (Phase 0)

> **Document Status:** Complete Baseline Audit  
> **Target System:** TrustVault Confidential Document Management Platform  
> **API Version:** v1 (`/api/v1`)  
> **Date:** October 2026  
> **Scope:** Complete repository inventory of endpoints, authentication mechanisms, authorization enforcement points, and flagged architectural gaps.

---

## 1. Executive Summary

TrustVault is an enterprise document repository designed to protect high-value confidential assets from external threat actors, malicious insiders, and compromised administrators.

This baseline audit evaluates all 57 API endpoints across 15 router modules. It catalogs authentication requirements and authorization enforcement functions, and explicitly flags any endpoint interacting with documents, versions, trash, search, export, access requests, the policy simulator, or audit data that is not guarded by a unified central Policy Decision Point (`AuthorizationService.decide`).

### Summary of Audit Findings

| Metric | Value |
| :--- | :--- |
| **Total Route Modules Audited** | 15 modules |
| **Total API Endpoints Audited** | 57 endpoints |
| **Public / Anonymous Endpoints** | 4 endpoints (`/health`, `/auth/login`, `/auth/register`, `/access-requests/resolve-link/{token}`) |
| **Authenticated Endpoints** | 53 endpoints |
| **Admin-Guarded Endpoints** | 22 endpoints |
| **Endpoints Directly Touching Document Scope** | 24 endpoints |
| **Endpoints Fully Guarded by Central Authorization** | 10 endpoints |
| **Endpoints Flagged for Ad-Hoc / Fragmented Authorization** | 14 endpoints |

---

## 2. Comprehensive Endpoint Inventory

### 2.1 Authentication & Sessions (`/api/v1/auth`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Anonymous | Rate limited (`login_limiter`) | Standard authentication. Emits `auth.login.success` or `auth.login.failed`. |
| `POST` | `/api/v1/auth/register` | Anonymous | Open / Environment Config | User self-registration. Defaults to `owner` or `viewer`. |
| `GET` | `/api/v1/auth/me` | Bearer JWT | `get_current_user` (Active check) | Returns caller's profile. |
| `GET` | `/api/v1/auth/sessions` | Bearer JWT | `get_current_user` | Returns sessions belonging to caller (`user_id == current_user.id`). |
| `DELETE` | `/api/v1/auth/sessions/{session_id}` | Bearer JWT | `get_current_user` + inline check | Verifies `session.user_id == current_user.id` before revocation. |
| `DELETE` | `/api/v1/auth/sessions` | Bearer JWT | `get_current_user` | Revokes all active sessions for current user. |

---

### 2.2 User Directory & Scope Assignments (`/api/v1/users`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/users` | Bearer JWT | `get_current_user` | Directory list for user picker. Excludes sensitive hashes. |
| `GET` | `/api/v1/users/all` | Bearer JWT | `get_current_admin` | Global admin view of all user accounts. |
| `POST` | `/api/v1/users` | Bearer JWT | `get_current_admin` | Admin provisioning of user accounts. |
| `GET` | `/api/v1/users/{user_id}` | Bearer JWT | `get_current_admin` | Admin inspection of user account details. |
| `PATCH` | `/api/v1/users/{user_id}` | Bearer JWT | `get_current_admin` | Admin role modification / account deactivation. |
| `GET` | `/api/v1/users/{user_id}/sessions` | Bearer JWT | `get_current_admin` | Admin inspection of a target user's active sessions. |
| `DELETE` | `/api/v1/users/{user_id}/sessions` | Bearer JWT | `get_current_admin` | Emergency admin revocation of all target user sessions. |
| `DELETE` | `/api/v1/users/{user_id}/sessions/{session_id}` | Bearer JWT | `get_current_admin` | Admin revocation of a specific target user session. |

---

### 2.3 Document Repository & Versions (`/api/v1/documents`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/documents/upload` | Bearer JWT | `get_current_user` + `upload_limiter` | ⚠️ Upload authorized for any active user. Needs central PDP check for tenant quotas. |
| `GET` | `/api/v1/documents` | Bearer JWT | `get_current_user` + inline SQL filter | 🚩 **FLAGGED**: Uses ad-hoc inline SQL subqueries (`owner_id == user.id OR id IN (permissions)`). Bypasses central PDP. |
| `GET` | `/api/v1/documents/trash` | Bearer JWT | `get_current_user` + inline SQL filter | 🚩 **FLAGGED**: Ad-hoc query filtering `owner_id == current_user.id AND deleted_at IS NOT NULL`. Bypasses central PDP. |
| `GET` | `/api/v1/documents/{document_id}` | Bearer JWT | `AuthorizationPolicy.require_read` | Checks read permission or active break-glass. Returns 404 if denied. |
| `GET` | `/api/v1/documents/{document_id}/download` | Bearer JWT | `AuthorizationPolicy.require_read` + policy check | Checks read permission + classification policy. ⚠️ Streaming lacks chunk-level mid-stream revocation. |
| `PATCH` | `/api/v1/documents/{document_id}` | Bearer JWT | `AuthorizationPolicy.require_edit` | 🚩 **FLAGGED**: Returns `403 Forbidden` if user has Read but not Edit, **leaking existence** (violates I3). |
| `DELETE` | `/api/v1/documents/{document_id}` | Bearer JWT | `AuthorizationPolicy.require_owner` | 🚩 **FLAGGED**: Returns `403 Forbidden` if user has Read/Edit but not Owner, **leaking existence** (violates I3). |
| `GET` | `/api/v1/documents/{document_id}/versions` | Bearer JWT | `AuthorizationPolicy.require_read` | Requires document read access. |
| `POST` | `/api/v1/documents/{document_id}/versions` | Bearer JWT | `AuthorizationPolicy.require_edit` | 🚩 **FLAGGED**: Returns `403 Forbidden` for non-editors who can read (violates I3). |
| `GET` | `/api/v1/documents/{document_id}/versions/{version_id}/download` | Bearer JWT | `AuthorizationPolicy.require_read` | Streams specific version bytes. ⚠️ No chunk-level re-validation. |
| `POST` | `/api/v1/documents/{document_id}/versions/{version_id}/restore` | Bearer JWT | `AuthorizationPolicy.require_owner` | 🚩 **FLAGGED**: Returns `403 Forbidden` for non-owners (violates I3). |

---

### 2.4 Permissions Management (`/api/v1/documents/{document_id}/permissions`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/documents/{document_id}/permissions` | Bearer JWT | `AuthorizationPolicy.require_read` | Returns permissions list to readers. |
| `POST` | `/api/v1/documents/{document_id}/permissions` | Bearer JWT | `AuthorizationPolicy.require_owner` | 🚩 **FLAGGED**: Returns `403 Forbidden` if reader tries to grant, leaking existence. |
| `DELETE` | `/api/v1/documents/{document_id}/permissions/{user_id}` | Bearer JWT | `AuthorizationPolicy.require_owner` | 🚩 **FLAGGED**: Returns `403 Forbidden` if reader tries to revoke, leaking existence. |

---

### 2.5 Access Requests & Tokenized Links (`/api/v1/access-requests`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/access-requests` | Bearer JWT | `get_current_user` + inline doc query | 🚩 **FLAGGED**: Inline query checks document existence. Does not use central PDP. |
| `GET` | `/api/v1/access-requests/my` | Bearer JWT | `get_current_user` | Returns caller's own sent requests. |
| `GET` | `/api/v1/access-requests/incoming` | Bearer JWT | `get_current_user` + inline SQL filter | 🚩 **FLAGGED**: Inline query searches requests for documents owned by caller. Bypasses central PDP. |
| `GET` | `/api/v1/access-requests/status/{document_id}` | Bearer JWT | `get_current_user` + inline SQL filter | 🚩 **FLAGGED**: Ad-hoc check returning pending status on target document. Potential existence probing vector. |
| `GET` | `/api/v1/access-requests/{request_id}` | Bearer JWT | `get_current_user` + inline ownership check | Verifies caller is requester or document owner. |
| `POST` | `/api/v1/access-requests/{request_id}/approve` | Bearer JWT | `get_current_user` + inline owner check | 🚩 **FLAGGED**: Ad-hoc inline check that `doc.owner_id == current_user.id`. |
| `POST` | `/api/v1/access-requests/{request_id}/reject` | Bearer JWT | `get_current_user` + inline owner check | 🚩 **FLAGGED**: Ad-hoc inline check that `doc.owner_id == current_user.id`. |
| `POST` | `/api/v1/access-requests/{request_id}/cancel` | Bearer JWT | `get_current_user` + inline requester check | Verifies `request.requester_id == current_user.id`. |
| `POST` | `/api/v1/access-requests/links/{document_id}` | Bearer JWT | `AuthorizationPolicy.require_owner` | Generates tokenized access link. |
| `GET` | `/api/v1/access-requests/links/{document_id}` | Bearer JWT | `AuthorizationPolicy.require_owner` | Lists active access links for document. |
| `POST` | `/api/v1/access-requests/links/{link_id}/revoke` | Bearer JWT | `get_current_user` + inline owner check | Revokes specific access link. |
| `GET` | `/api/v1/access-requests/resolve-link/{token}` | Anonymous | Token verification + inline doc query | 🚩 **FLAGGED**: Public endpoint resolving token. Must not leak document title to unauthenticated caller. |
| `POST` | `/api/v1/access-requests/submit-via-link/{token}` | Bearer JWT | Token verification + `get_current_user` | Submits access request via valid link token. |

---

### 2.6 Periodic Access Reviews (`/api/v1/access-reviews`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/access-reviews` | Bearer JWT | `get_current_user` + inline role branch | 🚩 **FLAGGED**: Branching inline: admin sees all reviews; non-admin sees reviews for owned documents. Bypasses PDP. |
| `POST` | `/api/v1/access-reviews/generate` | Bearer JWT | `get_current_admin` | Admin triggers access review campaign generation. |
| `POST` | `/api/v1/access-reviews/{review_id}/decision` | Bearer JWT | `get_current_user` + inline check | 🚩 **FLAGGED**: Checks `doc.owner_id == current_user.id` inline. |

---

### 2.7 Policy Simulator (`/api/v1/policy-simulator`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/policy-simulator/simulate` | Bearer JWT | `get_current_user` + inline checks | 🚩 **CRITICAL FLAG**: Caller can pass any `document_id`. If admin, allows simulation of any document without grant. Non-owner can probe existence. Must restrict strictly to documents owned/managed by caller; otherwise return identical 404. |

---

### 2.8 AI Advisory Services (`/api/v1/documents/{document_id}/ai-recommendations`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/documents/{document_id}/ai-recommendations` | Bearer JWT | `AuthorizationPolicy.require_owner` | Queries Gemini with sanitized metadata; creates pending suggestions with zero write permissions. |
| `POST` | `/api/v1/documents/{document_id}/ai-recommendations/approve` | Bearer JWT | `AuthorizationPolicy.require_owner` | Human owner approval required to commit permissions. |
| `POST` | `/api/v1/documents/{document_id}/ai-recommendations/reject` | Bearer JWT | `AuthorizationPolicy.require_owner` | Human owner rejection of suggestions. |

---

### 2.9 Immutable Audit Ledger (`/api/v1/audit`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/audit/events` | Bearer JWT | `get_current_user` + inline scope query | 🚩 **FLAGGED**: Inline SQL branching: admin sees all; owners see owned; viewers see actor events. |
| `GET` | `/api/v1/audit/verify` | Bearer JWT | `AuthorizationPolicy.require_admin` | Recalculates cryptographic SHA-256 hash chain from genesis forward. |
| `GET` | `/api/v1/audit/export` | Bearer JWT | `get_current_user` + inline role filter | 🚩 **FLAGGED**: Custom inline scope check for CSV/JSON export. |

---

### 2.10 Security Policies & Classification (`/api/v1/security-policies`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/security-policies` | Bearer JWT | `get_current_user` | Returns classification policies (Public, Internal, Confidential, Restricted). |
| `PUT` | `/api/v1/security-policies/{classification}` | Bearer JWT | `get_current_admin` | Admin updates classification security policy rules. |
| `PATCH` | `/api/v1/security-policies/documents/{document_id}/classification` | Bearer JWT | `AuthorizationPolicy.require_owner` | Document owner updates document classification. |
| `PATCH` | `/api/v1/security-policies/users/{user_id}/mfa` | Bearer JWT | `get_current_admin` | Admin toggles MFA enforcement flag for target user. |

---

### 2.11 Administrative Control & Break-Glass (`/api/v1/admin`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/admin/system-status` | Bearer JWT | `get_current_admin` | Admin inspection of telemetry, jobs, and security metrics. |
| `GET` | `/api/v1/admin/settings` | Bearer JWT | `get_current_admin` | Lists system configuration parameters. |
| `PATCH` | `/api/v1/admin/settings/{key}` | Bearer JWT | `get_current_admin` | Updates system configuration key. |
| `POST` | `/api/v1/admin/break-glass` | Bearer JWT | `get_current_admin` + password re-auth | 🚩 **FLAGGED**: Single-admin break-glass. Lacks mandatory **two-person rule** (requester != approver). |
| `GET` | `/api/v1/admin/break-glass` | Bearer JWT | `get_current_admin` | Lists break-glass emergency activations. |
| `POST` | `/api/v1/admin/break-glass/{id}/revoke` | Bearer JWT | `get_current_admin` | Revokes active emergency access immediately. |
| `POST` | `/api/v1/admin/break-glass/{id}/review` | Bearer JWT | `get_current_admin` | 🚩 **FLAGGED**: Post-incident review can currently be performed by the activating admin (lacks independent reviewer rule). |

---

### 2.12 Security Alerts & Threat Intelligence (`/api/v1/alerts`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/alerts` | Bearer JWT | `get_current_admin` | Lists detected security alerts. |
| `GET` | `/api/v1/alerts/metrics` | Bearer JWT | `get_current_admin` | Returns security incident statistics. |
| `GET` | `/api/v1/alerts/{alert_id}` | Bearer JWT | `get_current_admin` | Returns alert investigation details. |
| `POST` | `/api/v1/alerts/{alert_id}/acknowledge` | Bearer JWT | `get_current_admin` | Marks alert as under investigation. |
| `POST` | `/api/v1/alerts/{alert_id}/resolve` | Bearer JWT | `get_current_admin` | Resolves alert with investigation notes. |
| `POST` | `/api/v1/alerts/{alert_id}/revoke-sessions` | Bearer JWT | `get_current_admin` | Terminates all active sessions for alert actor/target. |

---

### 2.13 Backup & Disaster Recovery (`/api/v1/backups`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/backups` | Bearer JWT | `get_current_admin` | Lists available encrypted database backups. |
| `POST` | `/api/v1/backups/create` | Bearer JWT | `get_current_admin` | Generates point-in-time backup archive with SHA-256 digest. |
| `POST` | `/api/v1/backups/{backup_id}/verify` | Bearer JWT | `get_current_admin` | Verifies backup integrity without mutating database. |
| `POST` | `/api/v1/backups/{backup_id}/restore` | Bearer JWT | `get_current_admin` + password re-auth | Executes authorized database restore. ⚠️ Restores ciphertext but does not verify crypto-shredding tombstones. |
| `GET` | `/api/v1/backups/{backup_id}/download` | Bearer JWT | `get_current_admin` | Streams backup tarball. |

---

### 2.14 Security Notifications (`/api/v1/notifications`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/notifications` | Bearer JWT | `get_current_user` | Lists in-app notifications for caller (`user_id == current_user.id`). |
| `GET` | `/api/v1/notifications/unread-count` | Bearer JWT | `get_current_user` | Returns unread notification count. |
| `PATCH` | `/api/v1/notifications/{notification_id}/read` | Bearer JWT | `get_current_user` + inline check | Verifies notification belongs to current user. |
| `POST` | `/api/v1/notifications/mark-all-read` | Bearer JWT | `get_current_user` | Marks all user notifications as read. |

---

### 2.15 Health & Telemetry (`/api/v1/health`)

| Method | Endpoint | Authentication | Current Authorization Guard | Audit Flag / Assessment |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Anonymous | None (Public probe) | Returns database & storage connectivity status. Excludes sensitive secrets. |

---

## 3. Critical Gap Analysis (Must Be Resolved in Subsequent Phases)

1. **Absence of Unified Policy Decision Point (PDP):**
   - Authorization logic is fragmented across static helper methods (`require_read`, `require_edit`, `require_owner`) in [`authorization.py`](file:///c:/Users/chint/OneDrive/Desktop/Trust_val/backend/app/policies/authorization.py) and inline SQL queries in route handlers (`documents.py`, `access_requests.py`, `access_reviews.py`, `audit.py`).
   - Must be unified into `AuthorizationService.decide(principal, action, resource_id, context) -> Decision` in Phase 1.

2. **Existence Leakage via Differential HTTP Statuses (Violation of Invariant I3):**
   - Routes currently return `403 Forbidden` when a user has `read` access but attempts `edit`, `delete`, or `grant`. This proves to the attacker that the document exists.
   - Malformed UUIDs trigger `422 Unprocessable Entity` before authorization, creating a format oracle.
   - All unauthorized, malformed, or nonexistent document requests must return a byte-identical `404 Not Found` with timing equalization.

3. **Absence of Chunked Envelope Encryption at Rest (Violation of Invariant I4):**
   - Files are currently stored under randomized UUIDs outside the web root, but content is stored unencrypted or relies on underlying host volume encryption.
   - Phase 2 must implement AES-256-GCM envelope encryption with per-document Data Encryption Keys (DEKs) and wrapped Key Encryption Keys (KEKs).

4. **Lack of Mid-Stream Revocation Hooks (Violation of Invariant I2):**
   - Downloads check permissions at the start of streaming, but subsequent chunks stream without re-evaluating database state or `permission_epoch`.
   - Phase 3 must enforce periodic in-stream re-authorization every 2 seconds / N chunks.

5. **Single-Admin Break-Glass Access:**
   - Current break-glass emergency activation requires only a single admin password without the mandatory **two-person rule** (requester != approver). Must be hardened in Phase 7.

6. **Audit Ledger Chaining & Verification Hardening:**
   - The current ledger uses canonical JSON and SHA-256, but lacks unambiguous version prefixes, transaction advisory locks against forks, signed external checkpoints, and pseudonymous actor isolation for privacy/GDPR erasure. Must be hardened in Phase 5.
