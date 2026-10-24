import json
import hashlib
import hmac
from typing import Any, Dict, Optional, Union
from datetime import datetime, timezone
from app.core.config import settings

GENESIS_PREVIOUS_HASH = "0" * 64

def format_canonical_timestamp(ts: Union[datetime, str]) -> str:
    """
    Normalizes any datetime into canonical UTC ISO-8601 string representation.
    Guarantees deterministic serialization regardless of dialect or reloading.
    """
    if isinstance(ts, str):
        return ts
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    utc_dt = ts.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

def canonical_json(data: Dict[str, Any]) -> str:
    """
    Serializes a dictionary into canonical JSON with deterministic key ordering,
    compact separators, and standardized UTC ISO-8601 timestamps.
    """
    def serialize_obj(obj):
        if isinstance(obj, datetime):
            return format_canonical_timestamp(obj)
        return str(obj)

    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        default=serialize_obj,
        ensure_ascii=True
    )

def compute_ip_hash(ip: Optional[str], salt: Optional[str] = None) -> Optional[str]:
    """
    Generates a privacy-preserving truncated HMAC of client IP using a rotated secret salt.
    Prevents raw IP storage in compliance with data privacy mandates.
    """
    if not ip or ip in ["unknown", "testclient"]:
        return None
    secret = salt or getattr(settings, "AUDIT_IP_SALT_SECRET", "default_audit_ip_salt")
    return hmac.new(secret.encode("utf-8"), ip.strip().encode("utf-8"), hashlib.sha256).hexdigest()[:32]

def compute_user_agent_hash(user_agent: Optional[str]) -> Optional[str]:
    """Computes a deterministic hash of user agent header."""
    if not user_agent or user_agent == "testclient":
        return None
    return hashlib.sha256(user_agent.strip().encode("utf-8")).hexdigest()[:32]

def build_canonical_payload(
    event_id: str,
    timestamp: Union[datetime, str],
    actor_id: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    outcome: str,
    request_id: Optional[str],
    structured_metadata: Dict[str, Any],
    previous_event_hash: str,
    sequence_number: Optional[int] = None,
    org_id: Optional[str] = None,
    ip_hash: Optional[str] = None,
    user_agent_hash: Optional[str] = None
) -> str:
    """Builds the canonical JSON string for an audit record."""
    payload: Dict[str, Any] = {
        "id": str(event_id),
        "timestamp": format_canonical_timestamp(timestamp),
        "actor_id": str(actor_id) if actor_id else "anonymous",
        "action": str(action),
        "resource_type": str(resource_type),
        "resource_id": str(resource_id) if resource_id else None,
        "outcome": str(outcome),
        "request_id": str(request_id) if request_id else None,
        "structured_metadata": structured_metadata,
        "previous_event_hash": str(previous_event_hash)
    }
    if sequence_number is not None:
        payload["sequence_number"] = int(sequence_number)
    if org_id is not None:
        payload["org_id"] = str(org_id)
    if ip_hash is not None:
        payload["ip_hash"] = str(ip_hash)
    if user_agent_hash is not None:
        payload["user_agent_hash"] = str(user_agent_hash)

    return canonical_json(payload)

def compute_event_hash(
    event_id: str,
    timestamp: Union[datetime, str],
    actor_id: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    outcome: str,
    request_id: Optional[str],
    structured_metadata: Dict[str, Any],
    previous_event_hash: str,
    sequence_number: Optional[int] = None,
    org_id: Optional[str] = None,
    ip_hash: Optional[str] = None,
    user_agent_hash: Optional[str] = None,
    audit_key: Optional[str] = None
) -> str:
    """
    Phase 5 / Invariant I5:
    Computes record_hash = HMAC(key=audit_key, SHA-256(prev_hash || fields...))
    The audit key is distinct from data encryption keys.
    """
    canonical_payload = build_canonical_payload(
        event_id=event_id,
        timestamp=timestamp,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=request_id,
        structured_metadata=structured_metadata,
        previous_event_hash=previous_event_hash,
        sequence_number=sequence_number,
        org_id=org_id,
        ip_hash=ip_hash,
        user_agent_hash=user_agent_hash
    )

    key = audit_key or getattr(settings, "AUDIT_HMAC_KEY", "default_audit_hmac_secret_key")
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key

    # SHA-256 digest of canonical record
    payload_sha256 = hashlib.sha256(canonical_payload.encode("utf-8")).digest()

    # HMAC-SHA256 signature
    return hmac.new(key_bytes, payload_sha256, hashlib.sha256).hexdigest()

def compute_raw_sha256(canonical_payload: str) -> str:
    """Legacy plain SHA-256 calculation for backward compatibility."""
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
