import os
import json
import uuid
import hmac
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent
from app.audit.hash_chain import format_canonical_timestamp, canonical_json
from app.core.config import settings

class CheckpointVerificationError(Exception):
    pass

def compute_checkpoint_signature(checkpoint_dict: Dict[str, Any], audit_key: Optional[str] = None) -> str:
    key = audit_key or getattr(settings, "AUDIT_HMAC_KEY", "default_audit_hmac_secret_key")
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    canonical_bytes = canonical_json(checkpoint_dict).encode("utf-8")
    digest = hashlib.sha256(canonical_bytes).digest()
    return hmac.new(key_bytes, digest, hashlib.sha256).hexdigest()

def create_signed_checkpoint(
    db: Session,
    output_dir: Optional[str] = None,
    audit_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Phase 5 / Invariant I5:
    Generates a daily cryptographically signed anchor / checkpoint over the audit ledger.
    Published to external append-only storage (e.g. S3 Object Lock, CloudTrail, or local WORM directory).
    Guarantees that database superusers cannot truncate the tail without immediate detection.
    """
    last_event = db.query(AuditEvent).order_by(
        AuditEvent.sequence_number.desc(),
        AuditEvent.timestamp.desc(),
        AuditEvent.id.desc()
    ).first()

    total_records = db.query(AuditEvent).count()

    checkpoint_data = {
        "checkpoint_id": str(uuid.uuid4()),
        "timestamp_utc": format_canonical_timestamp(datetime.now(timezone.utc)),
        "sequence_number": last_event.sequence_number if last_event else 0,
        "latest_event_id": last_event.id if last_event else None,
        "latest_record_hash": last_event.event_hash if last_event else "0" * 64,
        "total_records": total_records,
        "key_id": "audit-hmac-v1"
    }

    # Compute HMAC-SHA256 signature
    signature = compute_checkpoint_signature(checkpoint_data, audit_key=audit_key)
    signed_checkpoint = {
        **checkpoint_data,
        "signature": signature
    }

    # Save to write-once storage directory
    target_dir = output_dir or getattr(settings, "AUDIT_CHECKPOINT_DIR", "./data/audit_checkpoints")
    os.makedirs(target_dir, exist_ok=True)

    date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"checkpoint_{date_str}_seq{checkpoint_data['sequence_number']}.json"
    filepath = os.path.join(target_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(signed_checkpoint, f, indent=2)

    signed_checkpoint["filepath"] = filepath
    return signed_checkpoint

def verify_checkpoint(
    checkpoint: Dict[str, Any],
    db: Session,
    audit_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verifies a signed checkpoint against the database state:
    1. Re-verifies HMAC-SHA256 signature with audit_key
    2. Verifies that the anchored latest_event_id exists in DB
    3. Verifies that sequence number and event_hash match the anchor exactly
    """
    if "signature" not in checkpoint:
        return {"is_valid": False, "error_reason": "Checkpoint missing HMAC signature"}

    signature = checkpoint["signature"]
    unsigned_payload = {k: v for k, v in checkpoint.items() if k not in ["signature", "filepath"]}

    expected_signature = compute_checkpoint_signature(unsigned_payload, audit_key=audit_key)
    if not hmac.compare_digest(signature, expected_signature):
        return {
            "is_valid": False,
            "error_reason": f"Invalid checkpoint signature on checkpoint {checkpoint.get('checkpoint_id')}"
        }

    # If checkpoint anchored 0 records, verify DB is empty
    if checkpoint.get("sequence_number") == 0:
        count = db.query(AuditEvent).count()
        if count != 0:
            return {"is_valid": False, "error_reason": "Checkpoint claims 0 records, but database contains records"}
        return {"is_valid": True, "checkpoint_id": checkpoint.get("checkpoint_id")}

    anchored_id = checkpoint.get("latest_event_id")
    event = db.query(AuditEvent).filter(AuditEvent.id == anchored_id).first()
    if not event:
        return {
            "is_valid": False,
            "error_reason": (
                f"Anchored event {anchored_id} from checkpoint {checkpoint.get('checkpoint_id')} "
                f"is missing from database (suspected tail truncation or rollback attack)"
            )
        }

    if event.sequence_number != checkpoint.get("sequence_number"):
        return {
            "is_valid": False,
            "error_reason": (
                f"Anchored sequence mismatch for event {anchored_id}: "
                f"checkpoint claims {checkpoint.get('sequence_number')}, database has {event.sequence_number}"
            )
        }

    if event.event_hash != checkpoint.get("latest_record_hash"):
        return {
            "is_valid": False,
            "error_reason": (
                f"Anchored record hash mismatch for event {anchored_id}: "
                f"checkpoint claims {checkpoint.get('latest_record_hash')}, database has {event.event_hash}"
            )
        }

    return {"is_valid": True, "checkpoint_id": checkpoint.get("checkpoint_id")}

def verify_checkpoint_files(
    db: Session,
    checkpoint_dir: Optional[str] = None,
    audit_key: Optional[str] = None
) -> Dict[str, Any]:
    """Verifies all checkpoints located in the checkpoint directory."""
    target_dir = checkpoint_dir or getattr(settings, "AUDIT_CHECKPOINT_DIR", "./data/audit_checkpoints")
    if not os.path.exists(target_dir):
        return {"is_valid": True, "checkpoints_verified": 0}

    files = [f for f in os.listdir(target_dir) if f.endswith(".json")]
    if not files:
        return {"is_valid": True, "checkpoints_verified": 0}

    for fname in sorted(files):
        fpath = os.path.join(target_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                cp_data = json.load(f)
            v_res = verify_checkpoint(cp_data, db=db, audit_key=audit_key)
            if not v_res["is_valid"]:
                return {
                    "is_valid": False,
                    "filename": fname,
                    "error_reason": v_res["error_reason"]
                }
        except Exception as e:
            return {
                "is_valid": False,
                "filename": fname,
                "error_reason": f"Failed reading checkpoint {fname}: {str(e)}"
            }

    return {"is_valid": True, "checkpoints_verified": len(files)}
