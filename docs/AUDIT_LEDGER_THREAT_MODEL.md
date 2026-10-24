# Threat Model: Tamper-Evident Audit Ledger (Invariant I5)

## 1. Overview & Architectural Goals
TrustVault enforces **Invariant I5**: every security-relevant event across the entire system lifecycle is written to an immutable, append-only, chained cryptographic audit ledger.

The audit system guarantees:
1. **Append-Only Immutability**: Historical records cannot be altered, inserted out-of-order, or deleted without immediate detection.
2. **Cryptographic Chaining with Dedicated Key**: Each record incorporates a strict sequence number and the previous record's hash, signed using `HMAC-SHA256` under an isolated `AUDIT_HMAC_KEY` distinct from data encryption keys.
3. **External Write-Once Anchoring**: Periodic signed checkpoints anchor the latest sequence number and record hash into external write-once storage (e.g., AWS S3 Object Lock in Compliance Mode, CloudTrail, or GCP Log Sink).
4. **Zero-Knowledge Privacy**: Client IP addresses are pseudonymized using a daily-rotated HMAC secret (`AUDIT_IP_SALT_SECRET`) and truncated to prevent PII exposure.

---

## 2. Attacker Capabilities & Threat Boundary Analysis

This threat model specifically evaluates the resistance of the audit ledger against an adversary with privileged access, up to and including a compromised PostgreSQL superuser (`postgres` role) or hostile database administrator.

```
       +-------------------------------------------------------------+
       |                  Adversary: DB Superuser                    |
       |  Full direct SQL write/delete access to PostgreSQL tables    |
       +-------------------------------------------------------------+
                                     |
                                     v
       +-------------------------------------------------------------+
       |                  TrustVault Audit Ledger                    |
       |  - Monotonic sequence_number: 1, 2, 3, ...                   |
       |  - prev_hash chaining: Hash(N) binds Hash(N-1)              |
       |  - HMAC-SHA256 signature with external KMS key              |
       +-------------------------------------------------------------+
                                     |
                                     v
       +-------------------------------------------------------------+
       |              External Signed Checkpoints (WORM)             |
       |  - S3 Object Lock / WORM Log Sink (Write Once, Read Many)   |
       |  - Signed with external audit HMAC secret                   |
       +-------------------------------------------------------------+
```

---

## 3. What an Attacker CAN and CANNOT Do

### What an Attacker CANNOT Do

1. **CANNOT Modify Historical Events Without Detection**:
   - Every audit record hash is calculated as:
     $$\text{record\_hash}_i = \text{HMAC}_{K_{\text{audit}}}\left(\text{SHA-256}\left(\text{prev\_hash}_{i-1} \parallel \text{seq}_i \parallel \text{timestamp} \parallel \text{actor\_id} \parallel \text{action} \parallel \text{metadata}\right)\right)$$
   - If an attacker modifies even a single byte (such as changing an `outcome="denied"` to `outcome="success"`, or altering a timestamp), the recomputed hash diverges.
   - Because the attacker does not possess the `AUDIT_HMAC_KEY` (which resides in KMS/HSM or isolated secret storage outside the database), they cannot re-sign the tampered record.

2. **CANNOT Splice, Delete, or Reorder Intermediate Records**:
   - Each record enforces strict monotonic sequence numbering ($\text{seq}_i = \text{seq}_{i-1} + 1$).
   - Deleting any intermediate record creates an immediate sequence gap ($\text{seq}_{i+1} - \text{seq}_{i-1} > 1$).
   - Reordering records breaks both the sequence order and the cryptographic chain ($\text{prev\_hash}_i \neq \text{record\_hash}_{i-1}$).

3. **CANNOT Forge Historical Records Between Published Checkpoints**:
   - Daily signed checkpoints anchor the latest sequence number, record hash, and record count to external WORM storage.
   - Even if a database superuser attempts to replace an entire historical segment, the external checkpoint contains an authentic cryptographic commitment to the true state of the ledger at that timestamp.
   - Any historical discrepancy between the database and the signed checkpoint is flagged immediately by the verification CLI (`python -m trustvault.audit verify`).

4. **CANNOT Corrupt Active Logs as Standard Application User**:
   - The PostgreSQL role `audit_writer` is granted `INSERT` permissions only.
   - `UPDATE`, `DELETE`, and `TRUNCATE` privileges are explicitly revoked at the database role level (`REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM audit_writer`).

---

### What an Attacker CAN Do (Residual Risks & Physical Limits)

1. **Tail Truncation (Denial of Unanchored Tail)**:
   - A compromised database superuser with raw disk or `DROP TABLE` access can delete records that were committed *after* the most recent external checkpoint anchor.
   - *Mitigation*: The CLI and monitoring daemon detect tail truncation on the very next verification cycle because the expected sequence from the last checkpoint does not advance or is truncated. Furthermore, checkpointing frequency can be configured down to hourly intervals.

2. **Denial of Service (Dropping the Table)**:
   - A superuser can issue `DROP TABLE audit_events;`.
   - *Mitigation*: The application fails closed when the audit ledger cannot be written. Historical records prior to the drop remain preserved and verifiable in external replica streams and signed checkpoints.

3. **Total KMS Key Compromise**:
   - If an attacker compromises both the database superuser AND the external KMS key (`AUDIT_HMAC_KEY`), they can recompute HMACs for a forged chain.
   - *Mitigation*: The audit key is managed in a separate KMS / HSM policy with audit logging enabled. IAM permissions forbid application admin roles from exporting or decrypting the audit HMAC key.

---

## 4. Verification CLI Reference

The audit ledger is continuously verifiable using the offline and online verification CLI:

```bash
# Verify entire audit ledger and external checkpoints
python -m trustvault.audit verify

# Verify specific time window
python -m trustvault.audit verify --from 2026-10-01T00:00:00Z --to 2026-10-24T23:59:59Z

# Generate a signed checkpoint anchor
python -m trustvault.audit checkpoint --output-dir ./data/audit_checkpoints
```

**Verification Invariants Checked**:
1. Genesis hash conformity ($\text{prev\_hash}_1 = 0^{64}$).
2. Monotonic sequence continuity ($\forall i > 1: \text{seq}_i = \text{seq}_{i-1} + 1$).
3. Chain link integrity ($\forall i > 1: \text{prev\_hash}_i = \text{record\_hash}_{i-1}$).
4. HMAC-SHA256 signature validity on every individual event.
5. All external signed checkpoint anchors point to matching database records.
