# TrustVault: 5-Minute Hackathon Demonstration Script

This document provides a repeatable, 5-minute demonstration of TrustVault for judges and reviewers. It covers the browser UI walkthrough and provides an automated CLI alternative.

---

## Demonstration Overview

| Step | Action | Persona | Expected Outcome | Key Security Invariant |
|---|---|---|---|---|
| **0** | Health & Storage Probe | Anonymous | `HTTP 200 OK`, `storage_backend: "s3"` | Safe telemetry, no secrets disclosed |
| **1** | Owner Login | Alice Owner (`owner_a`) | Authenticates into dashboard | Argon2id + short-lived JWT |
| **2** | Document Upload | Alice Owner (`owner_a`) | Uploads confidential PDF | File saved with opaque UUID; SHA-256 computed |
| **3** | Unauthorized Attempt | Carol Viewer (`viewer_a`) | Attempts direct download | **`404 Not Found`** (masked existence) |
| **4** | Grant Permission | Alice Owner (`owner_a`) | Grants Carol "Read Access" | Owner sole authority; live DB grant |
| **5** | Authorized Download | Carol Viewer (`viewer_a`) | Streams & views document | Exact SHA-256 match before streaming |
| **6** | Permission Revocation | Alice Owner (`owner_a`) | Revokes Carol's access | Synchronous `revoked_at` timestamp |
| **7** | Post-Revocation Attempt | Carol Viewer (`viewer_a`) | Attempts refresh / download | **`404 Not Found`** (instant cutoff) |
| **8** | Audit Trail Inspection | Alice Owner / Admin | Views Document Activity Log | Append-only ledger shows upload, download, denial |
| **9** | Hash Chain Verification | Alice Owner / Admin | Calls `/api/v1/audit/verify` | Cryptographic SHA-256 chain: `is_valid: true` |
| **10**| Architecture & Limits | Presenter | Explains boundaries | Transparent security disclosures |

---

## 5-Minute Presentation Walkthrough (UI)

### Minute 1: The Problem & Architecture (30 Seconds)
> *"Welcome to TrustVault. In enterprise document sharing, administrators typically have unchecked access to executive files, revocation takes hours to propagate across caches, and missing files are often concealed. TrustVault is built on Zero-Trust Architecture: admins cannot read files without explicit grants, revocation is instantaneous, and audit logs are cryptographically chained."*

### Minute 2: Document Ingestion & Zero-Trust Isolation (60 Seconds)
1. Open [https://trustvault-ui.onrender.com](https://trustvault-ui.onrender.com) in Browser Tab 1.
2. Sign in as **Alice Owner**:
   * Email: `owner_a@trustvault.com`
   * Password: `OwnerAPass123!`
3. Click **+ Upload Document** and upload a sample PDF (e.g. `Hackathon_Confidential_Patent.pdf`).
4. Point out:
   * File is assigned an **opaque UUID storage key** in private storage.
   * Server computes and stores a **SHA-256 cryptographic digest**.

### Minute 3: Information Leak Prevention (60 Seconds)
1. Open an Incognito window (Browser Tab 2) and sign in as **Carol Viewer**:
   * Email: `viewer_a@trustvault.com`
   * Password: `ViewerAPass123!`
2. Notice: Alice's new document does **not** appear in Carol's document list.
3. If Carol attempts to access the direct URL (`/documents/<id>`):
   * **Result:** **`404 Not Found`** (never `403 Forbidden`).
   * **Why:** Masking existence prevents malicious insiders from probing whether confidential M&A or patent files exist.

### Minute 4: Instant Revocation & Cryptographic Parity (60 Seconds)
1. Switch back to **Tab 1 (Alice Owner)**:
   * Open the document $\rightarrow$ click **Sharing & Permissions**.
   * Select `viewer_a@trustvault.com`, choose **Read Access**, and click **Grant Access**.
2. Switch to **Tab 2 (Carol Viewer)**:
   * Refresh the page. The document is now available.
   * Click **Secure Preview**: notice the dynamic forensic watermark showing Carol's identity.
   * Click **Download File**: file streams and verifies checksum matches.
3. Switch back to **Tab 1 (Alice Owner)**:
   * Click **Revoke** next to Carol's name.
4. Switch immediately to **Tab 2 (Carol Viewer)**:
   * Click **Download File** again.
   * **Result:** The download is instantly blocked with **`404 Not Found`**.
   * **Why:** No cached tokens or pre-signed URLs; every single download verifies live database state within the transaction.

### Minute 5: Cryptographic Audit Ledger & Boundaries (60 Seconds)
1. In Tab 1, switch to the **Document Activity Log** tab:
   * Point out the exact audit sequence: `document.upload` $\rightarrow$ `document.download` $\rightarrow$ `permission.revoke` $\rightarrow$ `document.download.denied`.
2. Navigate to **Audit Trail** $\rightarrow$ click **Verify Ledger Integrity**:
   * Shows `is_valid: true` across all cryptographically linked SHA-256 events.
3. Conclude with **Honest Technical Boundaries**:
   * *In-Flight Bytes:* Network packets already transferred over TCP cannot be un-sent; revocation guarantees instant refusal for all subsequent requests.
   * *DBA Boundary:* A database root administrator could theoretically alter rows and recompute the hash chain; in production, external WORM checkpoints (e.g. S3 Object Lock) are recommended.

---

## 1-Command Automated Hackathon CLI Demonstration

If presenting without a browser or for automated verification, run:

```bash
# Against Live Production Cloud API:
python backend/scripts/demo_hackathon.py --live

# Against Local Staging:
python backend/scripts/demo_hackathon.py
```

### Observed Output:
```text
===========================================================================
[TRUSTVAULT] 5-MINUTE HACKATHON REPEATABLE DEMONSTRATION
Target Service: https://trustvault-api-s6ba.onrender.com/api/v1
===========================================================================
[Step 0/10] Telemetry Check: Active Backend & Service Health... PASSED
[Step 1/10] Authenticating as Document Owner (Alice Owner)... PASSED
[Step 2/10] Owner Uploads Confidential Sample Document... PASSED
[Step 3/10] Attempting Access as Ungranted Viewer (Carol Viewer)... BLOCKED (404 Not Found)
[Step 4/10] Owner Grants Viewer Read Access... PASSED (201 Created)
[Step 5/10] Authorized Viewer Downloads Document & Verifies Integrity... PASSED (Exact SHA-256)
[Step 6/10] Owner Revokes Viewer Permission... PASSED (204 No Content)
[Step 7/10] Viewer Attempts Download Immediately After Revocation... BLOCKED (404 Not Found)
[Step 8/10] Inspecting Immutable Audit Trail for this Asset... PASSED
[Step 9/10] Cryptographic Hash Chain Ledger Verification... PASSED (is_valid=True)
[Step 10/10] Storage Architecture & Real-World Boundaries Explained... PASSED
===========================================================================
[SUCCESS] ALL 10 HACKATHON DEMONSTRATION STEPS PASSED 100%!
===========================================================================
```

---

## Demo Account Reference

| Persona | Email | Password | Role / Purpose |
|---|---|---|---|
| **Alice Owner** | `owner_a@trustvault.com` | `OwnerAPass123!` | Document creator, grants & revokes access |
| **Carol Viewer** | `viewer_a@trustvault.com` | `ViewerAPass123!` | Read-only consumer, demonstrates instant denial |
| **Bob Owner** | `owner_b@trustvault.com` | `OwnerBPass123!` | Peer owner, demonstrates lateral isolation |
| **Security Admin**| `admin@trustvault.com` | `AdminPass123!` | Platform administrator (zero-trust content isolated) |
