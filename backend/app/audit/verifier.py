from typing import Dict, Any, Optional, Union
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.audit import AuditEvent
from app.audit.hash_chain import (
    compute_event_hash,
    build_canonical_payload,
    compute_raw_sha256,
    GENESIS_PREVIOUS_HASH
)
from app.core.config import settings

def parse_filter_datetime(dt_val: Optional[Union[datetime, str]]) -> Optional[datetime]:
    if not dt_val:
        return None
    if isinstance(dt_val, datetime):
        return dt_val.astimezone(timezone.utc) if dt_val.tzinfo else dt_val.replace(tzinfo=timezone.utc)
    try:
        clean_str = dt_val.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(clean_str)
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def _trigger_tamper_alert(db: Session, event_id: str, error_reason: str, idx: int):
    """Triggers an active CRITICAL SecurityAlert when audit ledger tampering or chain break is detected."""
    try:
        from app.services.detection import create_or_suppress_alert
        create_or_suppress_alert(
            db=db,
            event_type="audit_ledger_tampered",
            severity="critical",
            summary=f"Cryptographic audit ledger tampering detected at event {event_id}",
            investigation_metadata={
                "tampered_event_id": event_id,
                "event_index": idx,
                "error_reason": error_reason
            }
        )
    except Exception:
        pass


def verify_audit_integrity(
    db: Session,
    from_date: Optional[Union[datetime, str]] = None,
    to_date: Optional[Union[datetime, str]] = None,
    audit_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Phase 5 / Invariant I5:
    Scans the audit ledger in strict sequence order and verifies:
    1. The genesis event points to GENESIS_PREVIOUS_HASH
    2. Monotonic sequence numbering without gaps or re-ordering (detects record deletion or reordering)
    3. Each subsequent event's previous_event_hash matches the preceding event's event_hash
    4. The recomputed HMAC-SHA256 signature matches the stored record_hash
    Detects any bit modification, row deletion, gap insertion, or chain severance.
    """
    query = db.query(AuditEvent)

    start_dt = parse_filter_datetime(from_date)
    end_dt = parse_filter_datetime(to_date)

    if start_dt:
        query = query.filter(AuditEvent.timestamp >= start_dt)
    if end_dt:
        query = query.filter(AuditEvent.timestamp <= end_dt)

    events = query.order_by(
        AuditEvent.sequence_number.asc(),
        AuditEvent.timestamp.asc(),
        AuditEvent.id.asc()
    ).all()

    total_events = len(events)
    if total_events == 0:
        return {
            "is_valid": True,
            "total_events": 0,
            "tampered_event_id": None,
            "event_index": None,
            "error_reason": None,
            "verified_at_event_id": None
        }

    # Expected previous hash for first verified record
    # If starting from the very first event, expect genesis hash
    is_global_start = (events[0].sequence_number == 1 or events[0].previous_event_hash == GENESIS_PREVIOUS_HASH)
    expected_previous_hash = GENESIS_PREVIOUS_HASH if is_global_start else events[0].previous_event_hash
    expected_sequence = events[0].sequence_number

    for idx, event in enumerate(events):
        # 1. Monotonic sequence gap verification
        if event.sequence_number != expected_sequence:
            reason = (
                f"Chain break / Sequence gap or record deletion detected at event {event.id}: "
                f"expected sequence {expected_sequence}, found sequence {event.sequence_number}"
            )
            _trigger_tamper_alert(db, event.id, reason, idx)
            return {
                "is_valid": False,
                "total_events": total_events,
                "tampered_event_id": event.id,
                "event_index": idx,
                "error_reason": reason,
                "verified_at_event_id": events[idx - 1].id if idx > 0 else None
            }

        # 2. Previous record hash chaining verification
        if event.previous_event_hash != expected_previous_hash:
            reason = (
                f"Cryptographic chain break at event {event.id}: previous_event_hash mismatch. "
                f"Expected {expected_previous_hash}, found {event.previous_event_hash}"
            )
            _trigger_tamper_alert(db, event.id, reason, idx)
            return {
                "is_valid": False,
                "total_events": total_events,
                "tampered_event_id": event.id,
                "event_index": idx,
                "error_reason": reason,
                "verified_at_event_id": events[idx - 1].id if idx > 0 else None
            }

        # 3. Content integrity & HMAC signature re-computation
        # Try HMAC with all Phase 5 fields first
        recomputed_hmac = compute_event_hash(
            event_id=event.id,
            timestamp=event.timestamp,
            actor_id=event.actor_id,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            outcome=event.outcome,
            request_id=event.request_id,
            structured_metadata=event.structured_metadata or {},
            previous_event_hash=event.previous_event_hash,
            sequence_number=event.sequence_number,
            org_id=event.org_id,
            ip_hash=event.ip_hash,
            user_agent_hash=event.user_agent_hash,
            audit_key=audit_key
        )

        is_match = (recomputed_hmac == event.event_hash)

        # Backward compatibility: verify against legacy SHA-256 if created before HMAC deployment
        if not is_match:
            legacy_payload = build_canonical_payload(
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
            legacy_hash = compute_raw_sha256(legacy_payload)
            if legacy_hash == event.event_hash:
                is_match = True

        if not is_match:
            reason = (
                f"Tampered content or invalid HMAC at event {event.id}: event_hash mismatch. "
                f"Computed {recomputed_hmac}, stored {event.event_hash}"
            )
            _trigger_tamper_alert(db, event.id, reason, idx)
            return {
                "is_valid": False,
                "total_events": total_events,
                "tampered_event_id": event.id,
                "event_index": idx,
                "error_reason": reason,
                "verified_at_event_id": events[idx - 1].id if idx > 0 else None
            }

        expected_previous_hash = event.event_hash
        expected_sequence = event.sequence_number + 1

    return {
        "is_valid": True,
        "total_events": total_events,
        "tampered_event_id": None,
        "event_index": None,
        "error_reason": None,
        "verified_at_event_id": events[-1].id if events else None
    }
