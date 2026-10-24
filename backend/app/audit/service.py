import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from app.models.audit import AuditEvent
from app.audit.hash_chain import (
    compute_event_hash,
    compute_ip_hash,
    compute_user_agent_hash,
    GENESIS_PREVIOUS_HASH
)

def log_audit_event(
    db: Session,
    action: str,
    resource_type: str,
    outcome: str,
    resource_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    org_id: Optional[str] = None,
    request_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> AuditEvent:
    """
    Appends a new cryptographically chained, tamper-evident audit event (Invariant I5).
    Features:
    - Immutable sequence numbering.
    - Privacy-preserving IP pseudonymization via truncated HMAC salt.
    - SHA-256 user-agent fingerprinting.
    - HMAC-SHA256 signature chained to previous record hash with dedicated audit key.
    - Sensitive metadata credential redaction.
    """
    safe_metadata = dict(metadata or {})
    # Strip any potential sensitive credentials
    for sensitive_key in ["password", "token", "secret", "authorization", "api_key", "bearer"]:
        if sensitive_key in safe_metadata:
            safe_metadata[sensitive_key] = "[REDACTED]"

    # Retrieve last event to establish cryptographic chaining and monotonic sequence
    last_event = db.query(AuditEvent).order_by(
        AuditEvent.sequence_number.desc(),
        AuditEvent.timestamp.desc(),
        AuditEvent.id.desc()
    ).first()

    previous_hash = last_event.event_hash if last_event else GENESIS_PREVIOUS_HASH
    sequence_number = (last_event.sequence_number + 1) if (last_event and last_event.sequence_number is not None) else 1
    effective_org_id = org_id or "default-org"

    event_id = str(uuid.uuid4())
    event_timestamp = datetime.now(timezone.utc)

    # Compute privacy-preserving hashes
    ip_hash_val = compute_ip_hash(client_ip)
    ua_hash_val = compute_user_agent_hash(user_agent)

    # Compute HMAC hash chain
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
        previous_event_hash=previous_hash,
        sequence_number=sequence_number,
        org_id=effective_org_id,
        ip_hash=ip_hash_val,
        user_agent_hash=ua_hash_val
    )

    audit_entry = AuditEvent(
        id=event_id,
        sequence_number=sequence_number,
        org_id=effective_org_id,
        timestamp=event_timestamp,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=request_id,
        ip_hash=ip_hash_val,
        user_agent_hash=ua_hash_val,
        structured_metadata=safe_metadata,
        previous_event_hash=previous_hash,
        event_hash=event_hash
    )

    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry
