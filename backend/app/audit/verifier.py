from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.audit import AuditEvent
from app.audit.hash_chain import compute_event_hash, GENESIS_PREVIOUS_HASH

def verify_audit_integrity(db: Session) -> Dict[str, Any]:
    """
    Scans the entire audit log in chronological order and verifies:
    1. The genesis event points to GENESIS_PREVIOUS_HASH
    2. Each subsequent event's previous_event_hash matches the previous event's event_hash
    3. The recomputed SHA-256 hash matches the stored event_hash
    Detects row modification, deletion, insertion, or reordering.
    """
    events = db.query(AuditEvent).order_by(AuditEvent.timestamp.asc(), AuditEvent.id.asc()).all()
    
    total_events = len(events)
    if total_events == 0:
        return {
            "is_valid": True,
            "total_events": 0,
            "tampered_event_id": None,
            "error_reason": None,
            "verified_at_event_id": None
        }

    expected_previous_hash = GENESIS_PREVIOUS_HASH

    for idx, event in enumerate(events):
        # 1. Verify previous hash chaining
        if event.previous_event_hash != expected_previous_hash:
            return {
                "is_valid": False,
                "total_events": total_events,
                "tampered_event_id": event.id,
                "event_index": idx,
                "error_reason": (
                    f"Chain break at event {event.id}: previous_event_hash mismatch. "
                    f"Expected {expected_previous_hash}, found {event.previous_event_hash}"
                ),
                "verified_at_event_id": events[idx - 1].id if idx > 0 else None
            }

        # 2. Recompute hash for data integrity
        recomputed_hash = compute_event_hash(
            event_id=event.id,
            timestamp=event.timestamp,
            actor_id=event.actor_id,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            outcome=event.outcome,
            request_id=event.request_id,
            structured_metadata=event.structured_metadata or {},
            previous_event_hash=event.previous_event_hash
        )

        if recomputed_hash != event.event_hash:
            return {
                "is_valid": False,
                "total_events": total_events,
                "tampered_event_id": event.id,
                "event_index": idx,
                "error_reason": (
                    f"Tampered content at event {event.id}: event_hash mismatch. "
                    f"Computed {recomputed_hash}, stored {event.event_hash}"
                ),
                "verified_at_event_id": events[idx - 1].id if idx > 0 else None
            }

        expected_previous_hash = event.event_hash

    return {
        "is_valid": True,
        "total_events": total_events,
        "tampered_event_id": None,
        "error_reason": None,
        "verified_at_event_id": events[-1].id if events else None
    }
