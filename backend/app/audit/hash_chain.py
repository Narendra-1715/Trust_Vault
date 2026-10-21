import json
import hashlib
from typing import Any, Dict, Optional, Union
from datetime import datetime, timezone

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
    previous_event_hash: str
) -> str:
    """
    Computes a deterministic SHA-256 hash over the canonical representation of an audit event.
    """
    canonical_payload = canonical_json({
        "id": str(event_id),
        "timestamp": format_canonical_timestamp(timestamp),
        "actor_id": str(actor_id) if actor_id else None,
        "action": str(action),
        "resource_type": str(resource_type),
        "resource_id": str(resource_id) if resource_id else None,
        "outcome": str(outcome),
        "request_id": str(request_id) if request_id else None,
        "structured_metadata": structured_metadata,
        "previous_event_hash": str(previous_event_hash)
    })
    
    return hashlib.sha256(canonical_payload.encode('utf-8')).hexdigest()
