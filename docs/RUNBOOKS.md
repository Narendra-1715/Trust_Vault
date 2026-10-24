# TrustVault Incident Response Runbooks

This document provides actionable, step-by-step Standard Operating Procedures (SOPs) for responding to high-severity security incidents in TrustVault.

---

## Runbook 1: Document Owner Account Compromised

### Trigger:
- Anomalous login from high-risk ASN/country.
- Burst of suspicious permissions granted to unverified accounts.
- Automated alert: `USER_COMPROMISE_ISOLATION` or `burst_permission_changes`.

### Severity:
- **CRITICAL**

### Immediate Containment Steps (under 2 minutes):
1. **Execute Account Isolation**:
   Run the isolation CLI command immediately:
   ```bash
   python -m trustvault.incident isolate-user <USER_UUID> --reason "Suspicious account takeover detected"
   ```
   *Alternative via Admin API:*
   ```bash
   POST /api/v1/admin/users/<USER_UUID>/isolate
   ```
2. **Automated Impact of Isolation**:
   - `is_active` set to `False`.
   - `session_version` incremented (invalidating all active JWTs).
   - All active `UserSession` records terminated (`revoked_at = now()`).
   - All owned documents frozen (`is_frozen = True`, `permission_epoch` incremented).
   - All outgoing permissions granted by the user revoked.
3. **Verify Document Freezing**:
   Confirm that all documents owned by the user return `404 Not Found` (Invariant I3) to all users and grantees.
4. **Emergency Document Access (if business-critical)**:
   Access to frozen documents is restricted to approved emergency break-glass with multi-party sign-off.
5. **Recovery & Re-enablement**:
   - Perform out-of-band identity verification with the user.
   - Force password reset with Argon2id and reissue MFA credentials.
   - Transfer critical documents to a designated successor if account remains untrusted.

---

## Runbook 2: Administrator Credential Leaked

### Trigger:
- Admin credentials discovered in public logs, git repository, or leaked dump.
- Unrecognized admin login alert or unauthorized break-glass attempt.

### Severity:
- **CRITICAL**

### Immediate Containment Steps:
1. **Revoke Active Admin Sessions**:
   ```sql
   UPDATE user_sessions SET revoked_at = NOW() WHERE user_id = '<ADMIN_UUID>' AND revoked_at IS NULL;
   UPDATE users SET session_version = session_version + 1, is_active = FALSE WHERE id = '<ADMIN_UUID>';
   ```
2. **Terminate All Active Break-Glass Grants**:
   Inspect active emergency grants and revoke immediately:
   ```bash
   # Walk all active emergency accesses and revoke
   POST /api/v1/admin/break-glass/<ID>/revoke
   ```
3. **Rotate Platform Admin Secrets**:
   - Rotate `SECRET_KEY`, `ADMIN_PASSWORD_HASH`, and JWT signing keys in deployment environment.
   - Force platform deployment rollback or reboot.
4. **Audit Review**:
   Examine audit ledger for any administrative operations performed during the compromise window:
   ```bash
   python -m trustvault.audit verify
   ```

---

## Runbook 3: KMS Key-Encryption Key (KEK) Emergency Rotation

### Trigger:
- KMS key policy exposure, AWS/GCP root credential exposure, or periodic cryptographic compliance requirement.

### Severity:
- **HIGH**

### Execution Steps (Zero-Downtime Envelope Re-wrapping):
1. **Provision New KMS Key / Local KEK**:
   Generate or provision the new key version in KMS / Cloud HSM and record the new Key ID (`new-kek-v2`).
2. **Execute KEK Rotation**:
   Run the zero-downtime re-wrap command:
   ```bash
   # CLI rewrap command
   python -m trustvault.kms rotate-kek --new-key-id "new-kek-v2"
   ```
   *Alternative via Admin Endpoint:*
   ```bash
   POST /api/v1/admin/kms/rotate-kek
   {
       "new_kek_id": "new-kek-v2"
   }
   ```
3. **Validation**:
   - Verify that all Data Encryption Keys (DEKs) in `document_keys` are re-wrapped with the new KEK version.
   - Download a sample document through `ContentService.stream` to verify seamless decryption roundtrip.
   - Verify zero modification of ciphertext chunks on disk or S3.
4. **Retire Old KEK**:
   Disable (do not immediately destroy) the old KEK in KMS until all backup verification jobs complete.

---

## Runbook 4: Audit Chain Break or Tampering Detected

### Trigger:
- Automated CLI verification alerts: `[FAIL] Cryptographic audit chain verification failed!`.
- Integrity verification API returns `is_valid: false`.

### Severity:
- **CRITICAL**

### Investigation Steps:
1. **Identify Tampered Event**:
   Run the CLI verifier to pinpoint the sequence number and event ID:
   ```bash
   python -m trustvault.audit verify
   ```
2. **Assess Tampering Vector**:
   - **Sequence Gap**: Indicates record deletion by an attacker with database access.
   - **Previous Hash Mismatch**: Indicates an event in the chain was altered or an out-of-order event was inserted.
   - **HMAC Signature Mismatch**: Indicates bit modification of event fields (timestamp, actor, action).
   - **Checkpoint Deviation**: Sequence number or hash diverged from the external signed daily checkpoint anchor.
3. **Isolate Database Access**:
   - Immediately revoke direct PostgreSQL write roles (`app_rw`, `migrator`).
   - Investigate database query logs and connection pool traces for superuser bypass.
4. **Restore Ledger from Verified Backup**:
   - Compare database state with the most recent signed checkpoint in the write-once store (`data/audit_checkpoints`).
   - Restore audit events from verified encrypted snapshot and verify chain continuity:
     ```bash
     python -m trustvault.audit verify --checkpoints-dir /path/to/checkpoints
     ```

---

## Runbook 5: Suspected Data Exfiltration in Progress

### Trigger:
- Burst of document downloads from a single session.
- AI egress filter alert: `AI_EGRESS_LEAK_BLOCKED`.
- Anomalous break-glass access from foreign IP/ASN.

### Severity:
- **CRITICAL**

### Immediate Containment Steps:
1. **Sever In-Flight Download Streams**:
   Trigger platform-wide permission epoch increments or isolate the suspect user:
   ```bash
   python -m trustvault.incident isolate-user <ACTOR_UUID>
   ```
2. **Block Offending IP / Network at Cloudflare Edge**:
   - Deploy immediate Cloudflare WAF block rule for the offending ASN/IP range.
   - Force session termination by clearing session tokens in Cloudflare Cache Rules.
3. **Inspect Active Break-Glass Emergency Grants**:
   Revoke any active break-glass sessions:
   ```bash
   POST /api/v1/admin/break-glass/<ID>/revoke
   ```
4. **Inspect AI Outbound Egress Filter**:
   Confirm whether outbound data leakage was intercepted and blocked by `AIEgressFilter`.
5. **Perform Forensic Scope Analysis**:
   Query all successful `document.download` events within the past 24 hours:
   ```bash
   python -m trustvault.audit verify
   ```
