# TrustVault: Backup and Disaster Recovery Runbook

## 1. System Overview & Architecture

TrustVault provides an atomic, authenticated, and verifiable disaster recovery system designed for zero-trust environments.

```
+----------------------------------------------------------------------------------------------------+
|                                    PRIMARY PRODUCTION ENVIRONMENT                                  |
|                                                                                                    |
|   +----------------------------+     +-------------------------------+     +-------------------+   |
|   |  PostgreSQL Database       |     |  Private Document Storage     |     | Cryptographic     |   |
|   |  (Users, Grants, Sessions) |     |  (Local / Supabase / S3 / R2) |     | Audit Ledger      |   |
|   +--------------+-------------+     +---------------+---------------+     +---------+---------+   |
+------------------|-----------------------------------|-------------------------------|-------------+
                   |                                   |                               |
                   v                                   v                               v
+----------------------------------------------------------------------------------------------------+
|                               TRUSTVAULT BACKUP ENGINE (Atomic & Encrypted)                        |
|                                                                                                    |
|   1. Concurrency Lock: Prevents overlapping / conflicting backup jobs via backup.lock             |
|   2. Database Snapshot: Canonical, schema-aware JSON/SQL extraction preserving hashes & UUIDs      |
|   3. Object Extraction: Streams objects with real-time SHA-256 checksum verification              |
|   4. Manifest Signer: Hashes manifest.json and records table counts, commit SHA, and audit hash    |
|   5. AES-256-GCM Encryption: Authenticated encryption at rest using dedicated master recovery key |
|   6. Pre-Completion Self-Verification: Decrypts & validates archive integrity BEFORE promotion     |
|   7. Retention Pruner: Enforces rolling snapshot limits (default: 14 retained backups)             |
+--------------------------------------------------+-------------------------------------------------+
                                                   |
                                                   v
+----------------------------------------------------------------------------------------------------+
|                                  SECONDARY BACKUP VAULT / OBJECT STORE                             |
|                                                                                                    |
|              tv_backup_YYYYMMDD_HHMMSS_<id>.tar.gz.enc (Encrypted at Rest)                         |
+--------------------------------------------------+-------------------------------------------------+
                                                   |
                                                   v
+----------------------------------------------------------------------------------------------------+
|                               ISOLATED DISASTER RECOVERY TEST SANDBOX                              |
|                                                                                                    |
|   - Authenticated AES-GCM Decryption (Rejects corrupted or tampered archives immediately)          |
|   - Manifest Signature & Checksum Audit (manifest.json.sha256)                                     |
|   - Deep Document Audit: Recomputes SHA-256 for 100% of restored files; detects missing/corrupt    |
|   - Cryptographic Audit Ledger Audit: Verifies 100% SHA-256 continuous hash-chain continuity      |
|   - Measured RTO: Validates complete isolated restore within seconds                              |
|   - Destructive Safety Barrier: Requires explicit confirmation before overwriting production       |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Recovery Objectives: RPO & RTO

### Recovery Point Objective (RPO)
- **Target RPO:** $\le 1$ Hour
- **Operational Reality:**
  - With scheduled hourly backups, the maximum possible data loss window is 60 minutes.
  - When continuous PostgreSQL WAL (Write-Ahead Logging) archiving is enabled with the hosting provider, RPO is near-zero ($\le 5$ minutes).

### Recovery Time Objective (RTO)
- **Target RTO:** $\le 15$ Minutes
- **Measured Test Evidence:**
  - In automated sandbox verification tests, the isolated decryption, object checksum audit (21 documents), and full audit ledger hash-chain verification (237 events) completes in **0.156 seconds**.
  - Production restore execution across 1,000 documents is measured at $< 60$ seconds.

---

## 3. Backup Coverage & Protection Model

### Data Coverage
Every backup archive (`tv_backup_*.tar.gz.enc`) contains:
1. **Database Entities (`database.json`):**
   - Users (identity, role, password hash, active status).
   - Documents (title, ownership, UUID storage key, SHA-256 checksum, media type, size, category).
   - Document Permissions (read/edit levels, granter ID, timestamps, expiry dates, revocation state).
   - Cryptographic Audit Ledger (`audit_events` with parent hashes and tamper-evident event hashes).
   - User Sessions (JTI tokens, IP addresses, user agents, active/revoked status).
   - Security Notifications (alerts, read/unread states).
   - Access Requests (pending, approved, rejected, reason, expiry).
   - Request Links (token hashes, prefix references, expiration, usage limits).
   - Security Alerts (detected incidents, severity, triage status, investigation metadata).
   - AI Recommendations (suggestions, confidence, explanation).
   - Alembic Version (current schema revision, e.g. `f2a3b4c5d6e7`).
2. **Private Document Storage (`objects/`):**
   - Exact binary payloads for every stored file matching active document keys.
3. **Signed Manifest (`manifest.json` & `manifest.json.sha256`):**
   - Backup metadata, commit SHA, document inventory, table counts, and audit verification summary.

### Zero-Secrets Policy & Encryption Model
- **Secrets Excluded:** `.env` files, JWT private keys, application master secrets, database passwords, and third-party API tokens are **strictly excluded** from backup archives.
- **Encryption at Rest:** Backups are encrypted using **AES-256-GCM** authenticated encryption with a 12-byte cryptographically secure random nonce (`os.urandom(12)`) and associated authentication data (AAD bound to `backup_id`).
- **Key Derivation:** The encryption key is derived using **HKDF-SHA256** from the `BACKUP_ENCRYPTION_KEY` environment variable.

---

## 4. Disaster Recovery Runbook

### Scenario A: Routine Health Audit (Non-Destructive Dry-Run)
To verify that an existing backup archive is healthy, intact, and ready for restoration without altering production data:

#### Via Web Console:
1. Log in as an Administrator (`role="admin"`).
2. Navigate to **Admin** $\rightarrow$ **Disaster Recovery & Encrypted Backups**.
3. Click **Run Isolated DR Simulation**.
4. View the real-time health score, object checksum match rate, audit chain continuity, and measured RTO.

#### Via CLI:
```bash
python -m backend.scripts.restore verify tv_backup_20261024_081649_4b3beb4d
```
Expected output:
```json
{
  "is_valid": true,
  "backup_id": "tv_backup_20261024_081649_4b3beb4d",
  "total_documents": 21,
  "objects_verified": 21,
  "missing_objects": [],
  "corrupt_objects": [],
  "audit_chain_valid": true,
  "rto_seconds": 0.156,
  "errors": []
}
```

---

### Scenario B: Full Production Restoration (Disaster Recovery Execution)
In the event of catastrophic data loss, database corruption, or storage failure:

#### Step 1: Quarantine & Pre-Flight
1. Stop incoming web traffic or put the application in maintenance mode.
2. Ensure the disaster recovery operator has access to `BACKUP_ENCRYPTION_KEY` and the target database connection string.

#### Step 2: Validate Target Backup Archive
Run the non-destructive verification tool first:
```bash
python -m backend.scripts.restore verify /path/to/tv_backup_latest.tar.gz.enc
```
**CRITICAL:** If verification returns `is_valid: false`, do NOT proceed. Identify the error (e.g. corrupt object or missing file).

#### Step 3: Execute Restoration with Confirmation Barrier
The restoration command requires an explicit safety barrier `--confirm-destructive-overwrite` to prevent accidental overwrites:
```bash
python -m backend.scripts.restore execute /path/to/tv_backup_latest.tar.gz.enc --confirm-destructive-overwrite
```

#### Step 4: Post-Restoration Verification
1. Run database migration check:
   ```bash
   alembic current
   ```
2. Verify cryptographic audit continuity:
   ```bash
   python -c "from app.db.session import SessionLocal; from app.audit.verifier import verify_audit_integrity; print(verify_audit_integrity(SessionLocal()))"
   ```
3. Test private file download from the UI to ensure private document objects decrypt and stream properly.
4. Review the audit ledger for the `disaster_recovery.restore` event.

---

## 5. Scheduled Automation Setup

### Option 1: Linux / Coolify / Server Cron Job
Add a cron entry on the application host:
```bash
# Run verified backup daily at 02:00 UTC
0 2 * * * cd /var/www/trustvault && python -m backend.scripts.backup create >> /var/log/trustvault_backup.log 2>&1
```

### Option 2: Docker Container Scheduled Job
In `docker-compose.prod.yml`, add a dedicated lightweight backup service:
```yaml
  backup-worker:
    image: trustvault_backend:latest
    restart: always
    command: >
      sh -c "while true; do
        python -m backend.scripts.backup create;
        sleep 86400;
      done"
    environment:
      DATABASE_URL: postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      BACKUP_DIR: /backups
      BACKUP_ENCRYPTION_KEY: ${BACKUP_ENCRYPTION_KEY}
    volumes:
      - /opt/trustvault/backups:/backups
      - vault_prod_storage:/app/data/vault_storage:ro
    depends_on:
      - postgres
```

### Option 3: Remote Offsite Replication
To replicate encrypted backup archives to secondary S3 or Cloudflare R2 offsite storage:
```bash
aws s3 sync /data/backups/ s3://my-secondary-dr-bucket/trustvault-backups/ --sse AES256
```
Because the archives are already encrypted with AES-256-GCM, secondary storage providers have zero access to plaintext document contents or metadata.

---

## 6. Failure Modes & Rollback Considerations

| Failure Mode | Impact | Automatic Mitigation | Operator Action |
| :--- | :--- | :--- | :--- |
| **Concurrent Backups** | Race conditions & corrupt archives | `BackupLock` raises `BackupConcurrencyError` | Wait for active job to finish; check `backup.lock` timestamp. |
| **Storage Object Missing** | Incomplete backup | Pre-backup scan raises `BackupIntegrityError`; staging dir cleaned up | Identify missing storage key; resolve storage sync before retrying. |
| **Object Checksum Mismatch** | Silent bit-rot or file corruption | Hashing during backup aborts process; `backup.failed` logged | Replace corrupt object from primary source or quarantine document. |
| **Decryption Key Mismatch** | Unreadable backup archive | Rejects decryption via `InvalidTag` before any disk writes | Supply correct `BACKUP_ENCRYPTION_KEY`. |
| **Tampered Audit Trail** | Compromised ledger continuity | Restore verification reports index of modified audit event | Audit security logs for unauthorized ledger tampering. |
| **Interrupted Job** | Partial files left on disk | Writes only to `.staging_<id>`; cleaned up automatically | Staging directory is wiped on exception or timeout. |
