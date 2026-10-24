import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.security_alert import SecurityAlert
from app.models.audit import AuditEvent
from app.models.notification import SecurityNotification
from app.models.user import User
from app.audit.service import log_audit_event

logger = logging.getLogger(__name__)

class DetectionConfig:
    FAILED_LOGIN_THRESHOLD: int = 5
    FAILED_LOGIN_WINDOW_MINUTES: int = 15

    REPEATED_DENIALS_THRESHOLD: int = 3
    REPEATED_DENIALS_WINDOW_MINUTES: int = 15

    INVALID_REFERENCE_THRESHOLD: int = 3
    INVALID_REFERENCE_WINDOW_MINUTES: int = 15

    BURST_PERMISSIONS_THRESHOLD: int = 5
    BURST_PERMISSIONS_WINDOW_MINUTES: int = 10

    RAPID_SESSIONS_THRESHOLD: int = 4
    RAPID_SESSIONS_WINDOW_MINUTES: int = 10

    CROSS_OWNER_PROBE_THRESHOLD: int = 3
    CROSS_OWNER_PROBE_WINDOW_MINUTES: int = 15

    ALERT_SUPPRESSION_WINDOW_MINUTES: int = 15

def sanitize_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitizes metadata to ensure credentials or contents are never logged."""
    safe = dict(meta or {})
    for secret_key in ["password", "token", "raw_token", "secret", "authorization", "api_key", "content", "file_data"]:
        if secret_key in safe:
            safe[secret_key] = "[REDACTED]"
    return safe

def create_or_suppress_alert(
    db: Session,
    event_type: str,
    severity: str,
    summary: str,
    investigation_metadata: Dict[str, Any],
    actor_id: Optional[str] = None,
    target_user_id: Optional[str] = None,
    target_document_id: Optional[str] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None
) -> SecurityAlert:
    """
    Creates a new security alert with duplicate suppression.
    If an open or investigating alert already exists for the same subject within the cooldown window,
    updates its count and metadata rather than generating duplicate alert floods.
    """
    now = datetime.now(timezone.utc)
    cooldown_cutoff = now - timedelta(minutes=DetectionConfig.ALERT_SUPPRESSION_WINDOW_MINUTES)

    # Check for active alert to suppress duplicates
    query = db.query(SecurityAlert).filter(
        SecurityAlert.event_type == event_type,
        SecurityAlert.status.in_(["open", "investigating"]),
        SecurityAlert.timestamp >= cooldown_cutoff
    )

    if actor_id:
        query = query.filter(SecurityAlert.actor_id == actor_id)
    elif target_user_id:
        query = query.filter(SecurityAlert.target_user_id == target_user_id)

    existing_alert = query.order_by(SecurityAlert.timestamp.desc()).first()

    clean_meta = sanitize_metadata(investigation_metadata)

    if existing_alert:
        # Suppress duplicate alert flood; increment count
        existing_meta = dict(existing_alert.investigation_metadata or {})
        existing_meta["duplicate_occurrences"] = existing_meta.get("duplicate_occurrences", 1) + 1
        existing_meta["latest_occurrence"] = now.isoformat()
        existing_alert.investigation_metadata = existing_meta
        existing_alert.updated_at = now
        db.commit()
        db.refresh(existing_alert)
        return existing_alert

    # Create new first-class alert
    alert = SecurityAlert(
        id=str(uuid.uuid4()),
        event_type=event_type,
        severity=severity,
        status="open",
        timestamp=now,
        actor_id=actor_id,
        target_user_id=target_user_id,
        target_document_id=target_document_id,
        session_id=session_id,
        request_id=request_id,
        summary=summary,
        investigation_metadata=clean_meta,
        created_at=now,
        updated_at=now
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Dispatch safe notifications to active Administrators
    try:
        admins = db.query(User).filter(User.role == "admin", User.is_active == True).all()
        for admin in admins:
            notif = SecurityNotification(
                id=str(uuid.uuid4()),
                user_id=admin.id,
                title=f"Security Alert: {summary[:60]}",
                message=summary,
                severity=severity,
                event_type=f"alert.{event_type}",
                resource_id=alert.id,
                created_at=now,
                is_read=False
            )
            db.add(notif)

        # Also notify affected user if target account is compromised
        if target_user_id and target_user_id != actor_id:
            user_notif = SecurityNotification(
                id=str(uuid.uuid4()),
                user_id=target_user_id,
                title="Account Security Notice",
                message=summary,
                severity=severity,
                event_type=f"alert.{event_type}",
                resource_id=alert.id,
                created_at=now,
                is_read=False
            )
            db.add(user_notif)

        db.commit()
    except Exception as e:
        logger.error(f"Failed to dispatch alert notifications: {e}")
        db.rollback()

    # Log audit event for alert creation (anti-recursion: success outcome)
    try:
        log_audit_event(
            db=db,
            action="alert.created",
            resource_type="security_alert",
            outcome="success",
            resource_id=alert.id,
            actor_id=actor_id,
            request_id=request_id,
            metadata={
                "event_type": event_type,
                "severity": severity,
                "summary": summary
            }
        )
    except Exception as e:
        logger.error(f"Failed to log audit event for alert creation: {e}")

    return alert

def detect_failed_logins(
    db: Session,
    email: str,
    ip_address: Optional[str] = None,
    request_id: Optional[str] = None
) -> Optional[SecurityAlert]:
    """
    Detection Rule 1: Repeated failed login attempts.
    Triggers when >= 5 failed attempts occur within 15 minutes.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=DetectionConfig.FAILED_LOGIN_WINDOW_MINUTES)

    # Check audit events for failed login actions matching target email
    failed_count = db.query(AuditEvent).filter(
        AuditEvent.action.in_(["auth.login.failed", "auth.failed_login"]),
        AuditEvent.timestamp >= window_start,
        AuditEvent.resource_id == email
    ).count()

    if failed_count >= DetectionConfig.FAILED_LOGIN_THRESHOLD:
        target_user = db.query(User).filter(User.email == email).first()
        target_user_id = target_user.id if target_user else None

        return create_or_suppress_alert(
            db=db,
            event_type="brute_force_login",
            severity="high",
            summary=f"{failed_count} repeated failed login attempts detected for account '{email}' within {DetectionConfig.FAILED_LOGIN_WINDOW_MINUTES} minutes.",
            investigation_metadata={
                "target_email": email,
                "ip_address": ip_address,
                "attempt_count": failed_count,
                "time_window_minutes": DetectionConfig.FAILED_LOGIN_WINDOW_MINUTES,
                "threshold": DetectionConfig.FAILED_LOGIN_THRESHOLD
            },
            target_user_id=target_user_id,
            request_id=request_id
        )
    return None

def detect_repeated_denials(
    db: Session,
    actor_id: str,
    document_id: Optional[str] = None,
    document_title: Optional[str] = None,
    request_id: Optional[str] = None
) -> Optional[SecurityAlert]:
    """
    Detection Rule 2: Repeated denied document-access attempts.
    Triggers when >= 3 denied access attempts occur within 15 minutes.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=DetectionConfig.REPEATED_DENIALS_WINDOW_MINUTES)

    denial_count = db.query(AuditEvent).filter(
        AuditEvent.actor_id == actor_id,
        AuditEvent.outcome == "denied",
        AuditEvent.timestamp >= window_start
    ).count()

    if denial_count >= DetectionConfig.REPEATED_DENIALS_THRESHOLD:
        doc_str = f" for '{document_title}'" if document_title else ""
        return create_or_suppress_alert(
            db=db,
            event_type="repeated_denials",
            severity="high",
            summary=f"{denial_count} unauthorized document access attempts{doc_str} recorded within {DetectionConfig.REPEATED_DENIALS_WINDOW_MINUTES} minutes.",
            investigation_metadata={
                "actor_id": actor_id,
                "document_id": document_id,
                "document_title": document_title,
                "denial_count": denial_count,
                "time_window_minutes": DetectionConfig.REPEATED_DENIALS_WINDOW_MINUTES,
                "threshold": DetectionConfig.REPEATED_DENIALS_THRESHOLD
            },
            actor_id=actor_id,
            target_document_id=document_id,
            request_id=request_id
        )
    return None

def detect_invalid_reference_probes(
    db: Session,
    actor_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    token_prefix: Optional[str] = None,
    request_id: Optional[str] = None
) -> Optional[SecurityAlert]:
    """
    Detection Rule 3: Repeated invalid, expired, or revoked access-reference attempts.
    Triggers when >= 3 probe attempts occur within 15 minutes.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=DetectionConfig.INVALID_REFERENCE_WINDOW_MINUTES)

    query = db.query(AuditEvent).filter(
        AuditEvent.action.in_(["request_link.resolve_failed", "request_link.submit_failed"]),
        AuditEvent.timestamp >= window_start
    )
    if actor_id:
        query = query.filter(AuditEvent.actor_id == actor_id)

    probe_count = query.count()

    if probe_count >= DetectionConfig.INVALID_REFERENCE_THRESHOLD:
        return create_or_suppress_alert(
            db=db,
            event_type="invalid_reference_probe",
            severity="medium",
            summary=f"{probe_count} attempts to access invalid, expired, or revoked document request links detected within {DetectionConfig.INVALID_REFERENCE_WINDOW_MINUTES} minutes.",
            investigation_metadata={
                "actor_id": actor_id,
                "ip_address": ip_address,
                "token_prefix": token_prefix,
                "probe_count": probe_count,
                "time_window_minutes": DetectionConfig.INVALID_REFERENCE_WINDOW_MINUTES,
                "threshold": DetectionConfig.INVALID_REFERENCE_THRESHOLD
            },
            actor_id=actor_id,
            request_id=request_id
        )
    return None

def detect_burst_permission_changes(
    db: Session,
    actor_id: str,
    document_id: Optional[str] = None,
    request_id: Optional[str] = None
) -> Optional[SecurityAlert]:
    """
    Detection Rule 4: Unusual bursts of permission changes.
    Triggers when >= 5 permission grants/revokes occur within 10 minutes.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=DetectionConfig.BURST_PERMISSIONS_WINDOW_MINUTES)

    burst_count = db.query(AuditEvent).filter(
        AuditEvent.actor_id == actor_id,
        AuditEvent.action.in_(["permission.grant", "permission.update", "permission.revoke", "permission.revoke_expired"]),
        AuditEvent.timestamp >= window_start
    ).count()

    if burst_count >= DetectionConfig.BURST_PERMISSIONS_THRESHOLD:
        return create_or_suppress_alert(
            db=db,
            event_type="burst_permission_changes",
            severity="medium",
            summary=f"Unusual burst of {burst_count} permission modifications performed by user within {DetectionConfig.BURST_PERMISSIONS_WINDOW_MINUTES} minutes.",
            investigation_metadata={
                "actor_id": actor_id,
                "document_id": document_id,
                "modification_count": burst_count,
                "time_window_minutes": DetectionConfig.BURST_PERMISSIONS_WINDOW_MINUTES,
                "threshold": DetectionConfig.BURST_PERMISSIONS_THRESHOLD
            },
            actor_id=actor_id,
            target_document_id=document_id,
            request_id=request_id
        )
    return None

def detect_rapid_sessions(
    db: Session,
    actor_id: str,
    ip_address: Optional[str] = None,
    request_id: Optional[str] = None
) -> Optional[SecurityAlert]:
    """
    Detection Rule 5: Rapid session creation / unexpected authentication anomalies.
    Triggers when >= 4 sessions are established within 10 minutes.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=DetectionConfig.RAPID_SESSIONS_WINDOW_MINUTES)

    session_count = db.query(AuditEvent).filter(
        AuditEvent.actor_id == actor_id,
        AuditEvent.action == "session.created",
        AuditEvent.timestamp >= window_start
    ).count()

    if session_count >= DetectionConfig.RAPID_SESSIONS_THRESHOLD:
        return create_or_suppress_alert(
            db=db,
            event_type="rapid_session_creation",
            severity="medium",
            summary=f"Rapid generation of {session_count} concurrent login sessions detected within {DetectionConfig.RAPID_SESSIONS_WINDOW_MINUTES} minutes.",
            investigation_metadata={
                "actor_id": actor_id,
                "ip_address": ip_address,
                "session_count": session_count,
                "time_window_minutes": DetectionConfig.RAPID_SESSIONS_WINDOW_MINUTES,
                "threshold": DetectionConfig.RAPID_SESSIONS_THRESHOLD
            },
            actor_id=actor_id,
            target_user_id=actor_id,
            request_id=request_id
        )
    return None

detect_rapid_session_creation = detect_rapid_sessions

def detect_cross_owner_probes(
    db: Session,
    actor_id: str,
    target_document_id: Optional[str] = None,
    request_id: Optional[str] = None
) -> Optional[SecurityAlert]:
    """
    Detection Rule 6: Repeated attempts to access or modify documents belonging to other owners.
    Triggers when >= 3 denied owner operations occur within 15 minutes.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=DetectionConfig.CROSS_OWNER_PROBE_WINDOW_MINUTES)

    cross_probes = db.query(AuditEvent).filter(
        AuditEvent.actor_id == actor_id,
        AuditEvent.outcome == "denied",
        AuditEvent.action.in_(["document.delete", "document.update", "request_link.create", "permission.grant", "document.read"]),
        AuditEvent.timestamp >= window_start
    ).count()

    if cross_probes >= DetectionConfig.CROSS_OWNER_PROBE_THRESHOLD:
        return create_or_suppress_alert(
            db=db,
            event_type="cross_owner_probe",
            severity="high",
            summary=f"{cross_probes} denied operations detected on documents owned by other users within {DetectionConfig.CROSS_OWNER_PROBE_WINDOW_MINUTES} minutes.",
            investigation_metadata={
                "actor_id": actor_id,
                "target_document_id": target_document_id,
                "probe_count": cross_probes,
                "time_window_minutes": DetectionConfig.CROSS_OWNER_PROBE_WINDOW_MINUTES,
                "threshold": DetectionConfig.CROSS_OWNER_PROBE_THRESHOLD
            },
            actor_id=actor_id,
            target_document_id=target_document_id,
            request_id=request_id
        )
    return None
