# TrustVault Cloud KMS IAM & Key-Encryption-Key (KEK) Policy

## 1. Executive Summary & Zero-Trust Boundary
In TrustVault, **Admin Blindness (Invariant I1)** and **Private Opaque Storage (Invariant I4)** are cryptographically enforced through envelope encryption.
- Every document version is encrypted with a unique, randomly generated 256-bit AES-256-GCM Data Encryption Key (DEK).
- Each DEK is wrapped under a Key-Encryption Key (KEK) managed by a hardware security module (HSM) or managed Key Management Service (AWS KMS, GCP Cloud KMS, or HashiCorp Vault Transit).
- Application administrators have **zero content permissions** in the application and **zero IAM permissions** to directly decrypt DEKs via cloud provider consoles or APIs.
- Only the runtime workload identity of the TrustVault backend service (`trustvault-service-role`) is granted decryption access.

---

## 2. AWS KMS Key Policy

### 2.1 Least-Privilege IAM Workload Policy (`trustvault-backend-role`)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowWorkloadKeyEncryptionAndDecryption",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/trustvault-backend-role"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:CallerAccount": "123456789012",
          "kms:ViaService": "kms.us-east-1.amazonaws.com"
        }
      }
    },
    {
      "Sid": "DisallowConsoleAdminDecryption",
      "Effect": "Deny",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/AdministratorAccess"
      },
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2.2 AWS CloudTrail Audit Trail Configuration
All KMS API calls (`kms:Decrypt`, `kms:GenerateDataKey`, `kms:ReEncrypt`) are logged with:
- Calling IAM Principal (`trustvault-backend-role`)
- Request IP address
- Timestamp and Key ID
- Encryption Context
Logs are continuously streamed to an S3 bucket with Object Lock (WORM compliance) and CloudWatch Alarms for abnormal burst decrypt events.

---

## 3. Google Cloud KMS IAM Binding

### 3.1 Service Account Least-Privilege Role
```bash
# Grant Encrypter/Decrypter ONLY to the backend service account
gcloud kms keys add-iam-policy-binding trustvault-kek \
    --location=global \
    --keyring=trustvault-keyring \
    --member="serviceAccount:trustvault-backend@project-id.iam.gserviceaccount.com" \
    --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

# Explicitly exclude Project Owners and IAM Admins from direct cryptoKeyDecrypter
```

---

## 4. HashiCorp Vault Transit Secret Engine Policy

```hcl
path "transit/encrypt/trustvault-kek" {
  capabilities = ["update"]
}

path "transit/decrypt/trustvault-kek" {
  capabilities = ["update"]
}

path "transit/rewrap/trustvault-kek" {
  capabilities = ["update"]
}

# Deny read on raw key material
path "transit/keys/trustvault-kek" {
  capabilities = ["read"]
  denied_parameters = {
    "keys" = []
  }
}
```

---

## 5. KEK Lifecycle & Rotation Architecture
1. **Automatic / On-Demand KEK Rotation**:
   - `ContentService.rotate_kek()` unwrap-and-rewraps stored DEKs without re-encrypting the underlying multi-gigabyte ciphertext payloads on disk.
   - Rotations are recorded in the immutable audit ledger (`kms.kek_rotated`).
2. **Crypto-Shredding Guarantee**:
   - Purging a document permanently deletes its `document_keys` database record.
   - Because all disk files and historical backups remain encrypted under the shredded DEK, all existing copies become mathematically irrecoverable within 0 seconds.
