import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from app.models.audit import AuditEvent
from app.audit.hash_chain import compute_event_hash, GENESIS_PREVIOUS_HASH

def log_audit_event(
    db: Session,
    action: str,
    resource_type: str,
    outcome: str,
    resource_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    request_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> AuditEvent:
    """
    Appends a new cryptographically chained audit event.
    Safe: Sanitizes metadata to prevent logging sensitive credentials.
    """
    safe_metadata = dict(metadata or {})
    # Strip any potential sensitive credentials
    for sensitive_key in ["password", "token", "secret", "authorization", "api_key"]:
        if sensitive_key in safe_metadata:
            safe_metadata[sensitive_key] = "[REDACTED]"

    # Retrieve last event to establish cryptographic chaining
    last_event = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc()).first()
    previous_hash = last_event.event_hash if last_event else GENESIS_PREVIOUS_HASH

    event_id = str(uuid.uuid4())
    event_timestamp = datetime.now(timezone.utc)

    # Compute hash chain
    event_hash = compute_event_hash(
        event_id=event_id,
        timestamp=event_timestamp,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=request_id,
        structured_metadata=safe_metadata,
        previous_event_hash=previous_hash
    )

    audit_entry = AuditEvent(
        id=event_id,
        timestamp=event_timestamp,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=request_id,
        structured_metadata=safe_metadata,
        previous_event_hash=previous_hash,
        event_hash=event_hash
    )

    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry
