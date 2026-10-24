# TrustVault Security Incident Response Runbooks (Phase 11)

This document establishes the enterprise Incident Response (IR) protocols, severity definitions, containment procedures, automated tooling, and escalation matrices for TrustVault.

---

## 1. Severity Classification and Response SLAs

| Severity | Definition & Trigger Examples | Initial Triage SLA | Containment SLA | Post-Mortem SLA |
| :--- | :--- | :--- | :--- | :--- |
| **SEV-1 (Critical)** | Active envelope key compromise, cryptographic audit ledger tampering / hash break, unauthenticated data exfiltration, ransomware attack, rogue admin takeover. | **< 15 minutes** | **< 1 hour** | 48 hours |
| **SEV-2 (High)** | Targeted brute-force account compromise, unauthorized cross-owner probe burst, abnormal break-glass activation, rate limit bypass attempts. | **< 30 minutes** | **< 4 hours** | 5 business days |
| **SEV-3 (Medium)** | Repeated permission denials from legitimate user, rapid session generation anomalies, single-route 429 threshold triggers. | **< 2 hours** | **< 24 hours** | Standard sprint review |
| **SEV-4 (Low)** | Isolated credential typos, sporadic 404 reference probes, informational webhook delivery delays. | **< 24 hours** | Next release cycle | N/A |

---

## 2. Standard Operating Procedures (SOPs)

### Playbook 1: Compromised Credentials & Account Takeover (SEV-1 / SEV-2)

#### 1. Identification & Triage
- **Trigger**: `brute_force_login`, `rapid_session_creation`, or external threat intelligence alert.
- Identify the compromised `actor_id` or `target_user_id` from the active alert:
  ```bash
  curl -X GET "https://vault.internal/api/v1/alerts?event_type=brute_force_login" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
  ```

#### 2. Immediate Containment
- **Instant Session Termination (Invariant I2)**: Execute the automated revocation endpoint:
  ```bash
  curl -X POST "https://vault.internal/api/v1/alerts/{alert_id}/revoke-sessions" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
  ```
  *Result*: Instantly revokes all active JWT tokens and `UserSession` records in database.

#### 3. Eradication & Remediation
- Deactivate or reset user credentials:
  ```bash
  # Invalidate user account temporarily if external breach suspected
  curl -X PATCH "https://vault.internal/api/v1/users/{user_id}" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"is_active": false}'
  ```
- Force credential change and rotate any linked API tokens.

#### 4. Post-Incident Investigation
- Extract forensic audit trail to inspect every resource accessed during the window:
  ```bash
  curl -X GET "https://vault.internal/api/v1/audit/export?format=ecs" \
    -H "Authorization: Bearer $ADMIN_TOKEN" > incident_forensics.ecs.ndjson
  ```

---

### Playbook 2: Envelope Encryption Key Compromise & Key Rotation (SEV-1)

#### 1. Immediate Containment
- Determine scope: Was the Master Key (KEK) or an individual Document Encryption Key (DEK) exposed?
- If Master Key was compromised, provision a new 256-bit AES Master Key immediately in KMS / Secret Manager.

#### 2. DEK Re-Encryption Pipeline
- TrustVault employs envelope encryption (AES-256-GCM). When the Master Key is rotated:
  1. Each document's encrypted DEK is decrypted using the old Master Key.
  2. The plaintext DEK is immediately re-encrypted with the new Master Key.
  3. The ciphertext file on disk or S3 remains unchanged, ensuring zero re-encryption downtime for large files.
- Run the administrative key rotation procedure:
  ```bash
  python -m app.cli.rotate_keys --old-key "$OLD_MASTER_KEY" --new-key "$NEW_MASTER_KEY"
  ```

#### 3. Verification & Cleanup
- Verify all document records have updated `kek_version`.
- Securely burn and zero-out the compromised key from memory and environment variables.

---

### Playbook 3: Audit Ledger Hash Chain Severance / Tampering (SEV-1)

#### 1. Identification
- **Trigger**: System emits alert `audit_ledger_tampered` or verifier reports `is_valid: False`.
- Run the standalone verification suite:
  ```bash
  python scripts/audit_verifier_suite.py
  ```
- Inspect `tampered_event_id`, `sequence_number`, and `error_reason`.

#### 2. Containment
- Place database in READ-ONLY mode to preserve forensic state:
  ```sql
  ALTER DATABASE trustvault SET READ ONLY;
  ```
- Export forensic database snapshot and server transaction logs (WAL).

#### 3. Reconciliation with Periodic Checkpoints
- TrustVault continuously signs periodic Merkle/hash checkpoints.
- Compare the corrupted sequence against the latest verified checkpoint:
  ```bash
  curl -X GET "https://vault.internal/api/v1/audit/checkpoints" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
  ```
- Pinpoint the exact point of bit modification, deleted row gap, or re-ordering.
- Restore from the nearest uncorrupted checkpoint and re-apply valid WAL records.

---

### Playbook 4: Malicious Administrator / Insider Threat (SEV-1)

#### 1. Triage & Privacy Invariant Verification
- TrustVault architecture guarantees **Invariant I1 (Admin Blindness)**:
  - Administrators cannot view document titles, document categories, or file plaintext.
  - Access is strictly limited to user accounts, audit oversight, and system metadata.
- Verify whether the rogue admin attempted unauthorized file downloads or privilege escalation:
  ```bash
  curl -X GET "https://vault.internal/api/v1/audit/events?action=document.read" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
  ```
  *Note: All unauthorized admin attempts return uniform 404 (Invariant I3).*

#### 2. Containment
- Terminate the rogue administrator's sessions immediately.
- Strip administrative role in database:
  ```sql
  UPDATE users SET role = 'viewer', is_active = false WHERE id = '<rogue_admin_id>';
  ```
- Rotate all database and infrastructure service credentials.

---

### Playbook 5: Emergency Break-Glass Post-Incident Audit (SEV-2)

#### 1. Post-Activation Review
- When emergency break-glass is activated, the system generates high-visibility audit records and alert triggers.
- Once the incident is resolved:
  1. Revoke emergency role elevation immediately.
  2. Audit all actions performed during the elevated window:
     ```bash
     curl -X GET "https://vault.internal/api/v1/audit/events?action=break_glass" \
       -H "Authorization: Bearer $ADMIN_TOKEN"
     ```
  3. Archive the incident ticket number and justification notes alongside the immutable audit ledger.

---

## 3. Outbound Security Webhook Integration

TrustVault supports automated webhook dispatch for SIEM and SOAR platforms (Splunk, Elastic, Datadog, PagerDuty):

### 3.1 Webhook Headers
```http
POST /security-webhook HTTP/1.1
Host: siem.enterprise.corp
Content-Type: application/json
User-Agent: TrustVault-Security-Webhook/1.0
X-TrustVault-Delivery: 8fa734b0-a65c-44d3-82ef-4d3752e259b1
X-TrustVault-Event: brute_force_login
X-TrustVault-Timestamp: 1730000000
X-TrustVault-Signature: sha256=a1b2c3d4e5f6...
```

### 3.2 Signature Verification (Python Example)
```python
import hmac, hashlib

def verify_trustvault_webhook(payload_bytes: bytes, secret: str, timestamp_hdr: str, sig_hdr: str) -> bool:
    expected_sign_data = timestamp_hdr.encode('utf-8') + b"." + payload_bytes
    expected_sig = hmac.new(secret.encode('utf-8'), expected_sign_data, hashlib.sha256).hexdigest()
    provided_sig = sig_hdr.replace("sha256=", "").strip()
    return hmac.compare_digest(expected_sig, provided_sig)
```

---

## 4. Incident Escalation Contacts & Notification Matrix

| Role | Responsibility | Contact Channel |
| :--- | :--- | :--- |
| **Incident Commander** | Overall response leadership, status updates | `security-ic@trustvault.internal` |
| **Security Engineering** | Threat triage, containment, forensic analysis | `sec-eng@trustvault.internal` |
| **Infrastructure Lead** | Key rotation, node isolation, database snapshots | `infra-oncall@trustvault.internal` |
| **Legal & Compliance** | Regulatory disclosures (GDPR / HIPAA / SOX) | `legal-privacy@trustvault.internal` |
| **Executive Escalation** | Customer advisories and press releases | `ciso@trustvault.internal` |
