import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.session import get_db
from app.models.user import User
from app.models.security_alert import SecurityAlert
from app.models.session import UserSession
from app.models.notification import SecurityNotification
from app.schemas.security_alert import (
    SecurityAlertResponse,
    SecurityAlertListResponse,
    SecurityAlertMetricsResponse,
    SecurityAlertResolveRequest,
    SecurityAlertRevokeSessionsResponse
)
from app.api.deps import get_current_user, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.audit.service import log_audit_event

router = APIRouter()

def build_alert_response(alert: SecurityAlert) -> SecurityAlertResponse:
    actor_name = alert.actor.display_name if alert.actor else None
    actor_email = alert.actor.email if alert.actor else None
    target_user_email = alert.target_user.email if alert.target_user else None
    target_doc_title = alert.target_document.title if alert.target_document else None
    ack_name = alert.acknowledger.display_name if alert.acknowledger else None
    res_name = alert.resolver.display_name if alert.resolver else None

    return SecurityAlertResponse(
        id=alert.id,
        event_type=alert.event_type,
        severity=alert.severity,
        status=alert.status,
        timestamp=alert.timestamp,
        actor_id=alert.actor_id,
        actor_name=actor_name,
        actor_email=actor_email,
        target_user_id=alert.target_user_id,
        target_user_email=target_user_email,
        target_document_id=alert.target_document_id,
        target_document_title=target_doc_title,
        session_id=alert.session_id,
        request_id=alert.request_id,
        summary=alert.summary,
        investigation_metadata=alert.investigation_metadata or {},
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by=alert.acknowledged_by,
        acknowledged_by_name=ack_name,
        resolved_at=alert.resolved_at,
        resolved_by=alert.resolved_by,
        resolved_by_name=res_name,
        resolution_notes=alert.resolution_notes,
        created_at=alert.created_at,
        updated_at=alert.updated_at
    )

@router.get("", response_model=SecurityAlertListResponse)
def list_security_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    status: Optional[str] = Query(None, description="Filter by status (open, investigating, resolved)"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists security alerts with pagination and filtering. Accessible strictly to administrators.
    """
    AuthorizationPolicy.require_admin(current_user)

    query = db.query(SecurityAlert)

    if severity:
        query = query.filter(SecurityAlert.severity == severity.lower())
    if status:
        query = query.filter(SecurityAlert.status == status.lower())
    if event_type:
        query = query.filter(SecurityAlert.event_type == event_type)

    total = query.count()
    alerts = query.order_by(desc(SecurityAlert.timestamp)).offset(offset).limit(limit).all()

    return SecurityAlertListResponse(
        total=total,
        alerts=[build_alert_response(a) for a in alerts]
    )

@router.get("/metrics", response_model=SecurityAlertMetricsResponse)
def get_security_alert_metrics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns real-time operational counts of active security alerts.
    """
    AuthorizationPolicy.require_admin(current_user)

    total_alerts = db.query(SecurityAlert).count()
    open_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "open").count()
    critical_alerts = db.query(SecurityAlert).filter(
        SecurityAlert.severity.in_(["critical", "high"]),
        SecurityAlert.status.in_(["open", "investigating"])
    ).count()
    investigating_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "investigating").count()
    resolved_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "resolved").count()

    return SecurityAlertMetricsResponse(
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        investigating_alerts=investigating_alerts,
        resolved_alerts=resolved_alerts
    )

@router.get("/{alert_id}", response_model=SecurityAlertResponse)
def get_security_alert_details(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves full investigation details for a specific security alert.
    """
    AuthorizationPolicy.require_admin(current_user)

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found"
        )

    return build_alert_response(alert)

@router.post("/{alert_id}/acknowledge", response_model=SecurityAlertResponse)
def acknowledge_security_alert(
    alert_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request_id: Optional[str] = Depends(get_request_id)
):
    """
    Acknowledges an open alert, transitioning its status to 'investigating'.
    """
    AuthorizationPolicy.require_admin(current_user)

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found"
        )

    now_utc = datetime.now(timezone.utc)
    alert.status = "investigating"
    alert.acknowledged_at = now_utc
    alert.acknowledged_by = current_user.id
    alert.updated_at = now_utc

    db.commit()
    db.refresh(alert)

    # Log audit event
    log_audit_event(
        db=db,
        action="alert.acknowledged",
        resource_type="security_alert",
        resource_id=alert.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "previous_status": "open",
            "new_status": "investigating",
            "event_type": alert.event_type
        }
    )

    return build_alert_response(alert)

@router.post("/{alert_id}/resolve", response_model=SecurityAlertResponse)
def resolve_security_alert(
    alert_id: str,
    body: SecurityAlertResolveRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request_id: Optional[str] = Depends(get_request_id)
):
    """
    Resolves an alert with documented resolution notes.
    """
    AuthorizationPolicy.require_admin(current_user)

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found"
        )

    now_utc = datetime.now(timezone.utc)
    alert.status = "resolved"
    alert.resolved_at = now_utc
    alert.resolved_by = current_user.id
    alert.resolution_notes = body.resolution_notes.strip()
    alert.updated_at = now_utc

    db.commit()
    db.refresh(alert)

    # Log audit event
    log_audit_event(
        db=db,
        action="alert.resolved",
        resource_type="security_alert",
        resource_id=alert.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "resolution_notes": alert.resolution_notes,
            "event_type": alert.event_type
        }
    )

    return build_alert_response(alert)

@router.post("/{alert_id}/revoke-sessions", response_model=SecurityAlertRevokeSessionsResponse)
def revoke_suspicious_user_sessions(
    alert_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request_id: Optional[str] = Depends(get_request_id)
):
    """
    Response Action: Allows authorized administrators to immediately revoke all active sessions
    of a suspicious user associated with an alert, without suspending their account or deleting grants.
    """
    AuthorizationPolicy.require_admin(current_user)

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found"
        )

    target_user_id = alert.actor_id or alert.target_user_id
    if not target_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No user identity is bound to this security alert."
        )

    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user account not found."
        )

    now_utc = datetime.now(timezone.utc)
    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == target_user_id,
        UserSession.revoked_at.is_(None)
    ).all()

    revoked_count = len(active_sessions)
    for s in active_sessions:
        s.revoked_at = now_utc
        s.session_version = (s.session_version or 1) + 1

    target_user = db.query(User).filter(User.id == target_user_id).first()
    if target_user:
        target_user.session_version = (target_user.session_version or 1) + 1

    # Append resolution update to the alert
    existing_meta = dict(alert.investigation_metadata or {})
    existing_meta["admin_session_revocation"] = {
        "revoked_at": now_utc.isoformat(),
        "revoked_by": current_user.id,
        "sessions_revoked_count": revoked_count
    }
    alert.investigation_metadata = existing_meta
    alert.status = "investigating"
    alert.updated_at = now_utc

    # Dispatch notification to the target user
    user_notif = SecurityNotification(
        id=str(uuid.uuid4()),
        user_id=target_user_id,
        title="Active Sessions Terminated by Administrator",
        message="An administrator has terminated your active login sessions following a security review. Please log in again to verify your identity.",
        severity="warning",
        event_type="admin.session.revocation",
        resource_id=alert.id,
        created_at=now_utc,
        is_read=False
    )
    db.add(user_notif)

    db.commit()

    # Log audit event
    log_audit_event(
        db=db,
        action="admin.user_sessions.revoked",
        resource_type="user",
        resource_id=target_user_id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "alert_id": alert.id,
            "revoked_sessions_count": revoked_count,
            "target_user_email": target_user.email
        }
    )

    return SecurityAlertRevokeSessionsResponse(
        revoked_sessions_count=revoked_count,
        message=f"Successfully terminated {revoked_count} active device session(s) for user '{target_user.email}'."
    )
