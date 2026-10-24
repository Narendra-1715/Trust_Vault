from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models.notification import SecurityNotification
from app.models.audit import AuditEvent
from app.services.detection import detect_repeated_denials
from app.services.websocket import manager

def create_security_notification(
    db: Session,
    user_id: str,
    title: str,
    message: str,
    severity: str = "info",
    event_type: str = "general",
    resource_id: Optional[str] = None
) -> SecurityNotification:
    """
    Creates and persists a user-specific security notification.
    """
    notif = SecurityNotification(
        user_id=user_id,
        title=title,
        message=message,
        severity=severity,
        event_type=event_type,
        resource_id=resource_id,
        created_at=datetime.now(timezone.utc),
        is_read=False
    )
    db.add(notif)
    db.commit()
    db.refresh(notif)

    # Real-time WebSocket dispatch to recipient
    try:
        manager.sync_send_to_user(str(user_id), {
            "type": "NOTIFICATION_RECEIVED",
            "data": {
                "id": str(notif.id),
                "title": notif.title,
                "message": notif.message,
                "severity": notif.severity,
                "event_type": notif.event_type,
                "resource_id": notif.resource_id,
                "created_at": notif.created_at.isoformat() if notif.created_at else None,
                "is_read": notif.is_read
            }
        })
    except Exception:
        pass

    return notif

def check_and_notify_repeated_denials(
    db: Session,
    user_id: Optional[str],
    resource_id: Optional[str] = None,
    resource_title: Optional[str] = None
) -> Optional[SecurityNotification]:
    """
    Monitors repeated access denial events. If >= 3 denials are recorded within
    a 15-minute sliding window for a user, triggers a high-severity security alert.
    """
    if not user_id:
        return None

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=15)

    recent_denials = db.query(AuditEvent).filter(
        AuditEvent.actor_id == user_id,
        AuditEvent.outcome == "denied",
        AuditEvent.timestamp >= window_start
    ).count()

    if recent_denials >= 3:
        # Check if an alert was already dispatched within this window to avoid spamming
        existing_alert = db.query(SecurityNotification).filter(
            SecurityNotification.user_id == user_id,
            SecurityNotification.event_type == "security.denial.threshold",
            SecurityNotification.created_at >= window_start
        ).first()

        if not existing_alert:
            target_str = f" for '{resource_title}'" if resource_title else ""
            alert = create_security_notification(
                db=db,
                user_id=user_id,
                title="Repeated Access Denial Detected",
                message=f"{recent_denials} unauthorized access attempts{target_str} were recorded from your account in the last 15 minutes.",
                severity="danger",
                event_type="security.denial.threshold",
                resource_id=resource_id
            )
            # Trigger central administrative SecurityAlert
            detect_repeated_denials(
                db=db,
                actor_id=user_id,
                document_id=resource_id,
                document_title=resource_title
            )
            return alert

    return None
