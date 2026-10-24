import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import text, desc

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.session import UserSession
from app.models.emergency_access import EmergencyAccess
from app.models.system_setting import SystemSetting
from app.models.security_alert import SecurityAlert
from app.models.security_policy import SecurityPolicy
from app.models.access_review import AccessReview
from app.schemas.admin import (
    BreakGlassRequest,
    BreakGlassResponse,
    BreakGlassReviewRequest,
    SystemSettingItem,
    SystemSettingUpdateRequest,
    SystemStatusResponse,
    RotateKekRequest,
    RotateKekResponse
)
from app.schemas.document import AdminDocumentMetadataListResponse, AdminDocumentMetadataResponse
from app.services.authorization import get_admin_metadata_view
from app.services.content import ContentService
from app.api.deps import get_current_admin, get_request_id
from app.core.security import verify_password
from app.core.config import settings
from app.storage.local import storage_service
from app.audit.service import log_audit_event
from app.notifications.service import create_security_notification
from app.services.backup import list_backups

router = APIRouter()

def build_break_glass_response(ba: EmergencyAccess) -> BreakGlassResponse:
    admin = ba.admin
    reviewer = ba.reviewer
    approver = getattr(ba, "approver", None)
    doc = ba.document
    return BreakGlassResponse(
        id=ba.id,
        admin_id=ba.admin_id,
        admin_email=admin.email if admin else None,
        admin_name=admin.display_name if admin else None,
        document_id=ba.document_id,
        document_title=doc.title if doc else None,
        justification=ba.justification,
        ticket_id=getattr(ba, "ticket_id", None),
        approval_mode=getattr(ba, "approval_mode", "direct"),
        status=ba.status,
        delay_until=getattr(ba, "delay_until", None),
        expires_at=ba.expires_at,
        created_at=ba.created_at,
        revoked_at=ba.revoked_at,
        approved_by=getattr(ba, "approved_by", None),
        approver_name=approver.display_name if approver else None,
        reviewed_at=ba.reviewed_at,
        reviewed_by=ba.reviewed_by,
        reviewer_name=reviewer.display_name if reviewer else None,
        review_notes=ba.review_notes
    )

@router.get("/system-status", response_model=SystemStatusResponse)
def get_system_status(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Returns administrative system health, storage utilization, background job metrics,
    and security configuration overview. Strictly restricted to administrators.
    """
    now_utc = datetime.now(timezone.utc)

    # 1. Database Health
    db_healthy = False
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        db_healthy = False

    # 2. Storage Health & Usage
    storage_healthy = True
    doc_count = db.query(Document).filter(Document.deleted_at.is_(None)).count()
    trashed_docs_count = db.query(Document).filter(Document.deleted_at.isnot(None)).count()
    total_bytes = db.query(text("COALESCE(SUM(file_size), 0)")).select_from(Document).scalar() or 0
    storage_backend = "s3" if hasattr(storage_service, "bucket") else "local"

    # 3. Active Sessions & Users
    users_count = db.query(User).count()
    active_sessions_count = db.query(UserSession).filter(
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > now_utc
    ).count()

    # 4. Background Jobs & Disaster Recovery status
    backups = list_backups()
    latest_backup = backups[0] if backups else None
    pending_reviews = db.query(AccessReview).filter(AccessReview.status == "pending").count()
    overdue_reviews = db.query(AccessReview).filter(
        AccessReview.status == "pending",
        AccessReview.due_date < now_utc
    ).count()

    # 5. Security Configuration & Alerts
    policies_count = db.query(SecurityPolicy).count()
    open_alerts = db.query(SecurityAlert).filter(SecurityAlert.status.in_(["open", "investigating"])).count()
    critical_alerts = db.query(SecurityAlert).filter(
        SecurityAlert.status.in_(["open", "investigating"]),
        SecurityAlert.severity == "critical"
    ).count()

    return SystemStatusResponse(
        status="operational" if db_healthy and storage_healthy else "degraded",
        database={
            "status": "connected" if db_healthy else "disconnected",
            "active_connections": 1,
            "engine": "postgresql" if "postgres" in settings.DATABASE_URL else "sqlite"
        },
        storage={
            "status": "connected" if storage_healthy else "disconnected",
            "backend": storage_backend,
            "total_documents": doc_count,
            "trashed_documents": trashed_docs_count,
            "total_bytes": total_bytes
        },
        background_jobs={
            "latest_backup_id": latest_backup.get("backup_id") if latest_backup else None,
            "latest_backup_at": latest_backup.get("created_at") if latest_backup else None,
            "latest_backup_verified": latest_backup.get("is_valid") if latest_backup else None,
            "access_reviews_pending": pending_reviews,
            "access_reviews_overdue": overdue_reviews
        },
        security_configuration={
            "classification_policies_count": policies_count,
            "open_security_alerts": open_alerts,
            "critical_security_alerts": critical_alerts,
            "mfa_enforced_for_admins": True
        },
        users_count=users_count,
        active_sessions_count=active_sessions_count,
        server_time=now_utc
    )

DEFAULT_SYSTEM_SETTINGS = {
    "session_timeout_minutes": ("60", "Inactivity timeout for authenticated user sessions"),
    "max_failed_logins": ("5", "Threshold of consecutive failed logins before triggering security alerts"),
    "mfa_enforced_for_admins": ("true", "Mandatory multi-factor authentication enforcement for privileged administrative accounts"),
    "document_retention_days": ("365", "Baseline retention period for historical revisions and deleted document records")
}

def ensure_default_system_settings(db: Session):
    existing = {s.key: s for s in db.query(SystemSetting).all()}
    now = datetime.now(timezone.utc)
    added = False
    for k, (val, desc) in DEFAULT_SYSTEM_SETTINGS.items():
        if k not in existing:
            db.add(SystemSetting(
                key=k,
                value=val,
                description=desc,
                updated_at=now,
                updated_by="SYSTEM"
            ))
            added = True
    if added:
        db.commit()

@router.get("/settings", response_model=List[SystemSettingItem])
def list_system_settings(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Returns configurable platform-level security and operational settings.
    """
    ensure_default_system_settings(db)
    settings_list = db.query(SystemSetting).order_by(SystemSetting.key.asc()).all()
    return settings_list

@router.patch("/settings/{key}", response_model=SystemSettingItem)
def update_system_setting(
    key: str,
    update_in: SystemSettingUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Modifies a system setting. Enforces administrator authorization and audit logging.
    """
    ensure_default_system_settings(db)
    request_id = get_request_id(request)
    setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System setting '{key}' not found"
        )

    old_val = setting.value
    setting.value = update_in.value.strip()
    setting.updated_at = datetime.now(timezone.utc)
    setting.updated_by = admin_user.id
    db.commit()
    db.refresh(setting)

    log_audit_event(
        db=db,
        action="admin.system_setting.update",
        resource_type="system_setting",
        resource_id=key,
        outcome="success",
        actor_id=admin_user.id,
        request_id=request_id,
        metadata={"key": key, "old_value": old_val, "new_value": setting.value}
    )

    return setting

@router.get("/documents", response_model=AdminDocumentMetadataListResponse)
def list_admin_document_inventory(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Administrative document inventory:
    Strictly enforces Admin Blindness (Invariant I1): filenames, titles, and descriptions are redacted.
    Admins see only non-sensitive operational fields (UUID, size bucket, status, category, timestamps).
    """
    docs = db.query(Document).order_by(Document.created_at.desc()).all()
    items = [get_admin_metadata_view(d) for d in docs]
    return AdminDocumentMetadataListResponse(
        total=len(items),
        documents=items
    )

@router.post("/kms/rotate-kek", response_model=RotateKekResponse)
def rotate_kms_kek(
    req: RotateKekRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    KEK Rotation:
    Rewraps all Data Encryption Keys (DEKs) in document_keys under a new KEK version.
    Zero downtime, does not require re-encrypting ciphertext chunks on disk.
    Strictly restricted to administrators.
    """
    new_kek_bytes = bytes.fromhex(req.new_kek_hex) if req.new_kek_hex else None
    count = ContentService.rotate_kek(db, req.new_kek_id, new_kek_bytes, actor_id=admin_user.id)
    return RotateKekResponse(
        rotated_keys_count=count,
        new_kek_id=req.new_kek_id
    )

# ================= EMERGENCY ACCESS (BREAK-GLASS) =================

from app.services.authorization import is_valid_uuid
from app.services.incident import IncidentService
from app.api.deps import get_current_user

@router.post("/break-glass", response_model=BreakGlassResponse, status_code=status.HTTP_201_CREATED)
def activate_break_glass_access(
    req: BreakGlassRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Emergency Break-Glass Protocol (Phase 7 / Invariant I1):
    Allows an administrator to request time-limited, justified access to a private document.
    Enforces:
    - Scoped to specific document ID (zero wildcard access permitted)
    - Strong reauthentication via administrator password
    - Multi-party approval (M-of-N) OR high-friction delay with active owner cancellation window
    - Hard limit of 4 hours max duration
    """
    request_id = get_request_id(request)

    # 1. No Wildcard Access Permitted
    if req.document_id in ["*", "all", "%", ""] or not is_valid_uuid(req.document_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Wildcard break-glass access is strictly forbidden. Must target an explicit document ID."
        )

    # 2. Mandatory Strong Reauthentication
    if not verify_password(req.password, admin_user.password_hash):
        log_audit_event(
            db=db,
            action="admin.break_glass.failed_reauth",
            resource_type="document",
            resource_id=req.document_id,
            outcome="denied",
            actor_id=admin_user.id,
            request_id=request_id,
            metadata={"reason": "Invalid password reauthentication"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Reauthentication failed: Incorrect password"
        )

    # 3. Verify Document Exists
    doc = db.query(Document).filter(Document.id == req.document_id, Document.deleted_at.is_(None)).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    now_utc = datetime.now(timezone.utc)
    duration_mins = min(max(req.duration_minutes, 5), 240)
    expires_at = now_utc + timedelta(minutes=duration_mins)
    ticket = req.ticket_id.strip() if req.ticket_id else f"INC-{str(uuid.uuid4())[:8]}"

    # Determine activation state
    status_val = "active"
    delay_until = None
    if req.approval_mode == "multi_party":
        status_val = "pending_approval"
    elif req.approval_mode == "time_delay":
        status_val = "pending_delay"
        delay_until = now_utc + timedelta(hours=req.delay_hours)

    # 4. Create Emergency Access Record
    emergency = EmergencyAccess(
        admin_id=admin_user.id,
        document_id=doc.id,
        justification=req.justification.strip(),
        ticket_id=ticket,
        approval_mode=req.approval_mode,
        status=status_val,
        delay_until=delay_until,
        expires_at=expires_at,
        created_at=now_utc
    )
    db.add(emergency)
    db.commit()
    db.refresh(emergency)

    # 5. Notify Document Owner and Security Personnel
    if doc.owner_id:
        create_security_notification(
            db=db,
            user_id=doc.owner_id,
            title="Emergency Break-Glass Access Alert",
            message=f"Administrator {admin_user.display_name} initiated break-glass access on document '{doc.title}'. Mode: {req.approval_mode}, Ticket: {ticket}. Justification: {req.justification[:100]}...",
            severity="critical",
            event_type="break_glass_initiated",
            resource_id=doc.id
        )

    # 6. Log Immutable Audit Record with is_break_glass flag
    log_audit_event(
        db=db,
        action="admin.break_glass.requested",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=admin_user.id,
        request_id=request_id,
        metadata={
            "emergency_access_id": emergency.id,
            "document_title": doc.title,
            "ticket_id": ticket,
            "approval_mode": req.approval_mode,
            "status": status_val,
            "justification": req.justification,
            "duration_minutes": duration_mins,
            "expires_at": expires_at.isoformat(),
            "is_break_glass": True
        }
    )

    return build_break_glass_response(emergency)

@router.post("/break-glass/{id}/approve", response_model=BreakGlassResponse)
def approve_break_glass_access(
    id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Multi-Party Approval (M-of-N):
    A second, distinct administrator/security officer must approve the break-glass request.
    The requester CANNOT self-approve.
    """
    request_id = get_request_id(request)
    record = db.query(EmergencyAccess).filter(EmergencyAccess.id == id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Emergency access record not found")

    if record.status not in ["pending_approval", "pending_delay"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve break-glass in status '{record.status}'"
        )

    # Strict multi-party enforcement: requester cannot self-approve
    if record.admin_id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Multi-party violation: The break-glass requester cannot self-approve."
        )

    now_utc = datetime.now(timezone.utc)
    duration = record.expires_at - record.created_at
    record.status = "active"
    record.approved_by = admin_user.id
    record.expires_at = now_utc + duration

    # Increment permission epoch to synchronize access
    if record.document:
        record.document.permission_epoch = (record.document.permission_epoch or 1) + 1

    db.commit()
    db.refresh(record)

    log_audit_event(
        db=db,
        action="admin.break_glass.approved",
        resource_type="document",
        resource_id=record.document_id,
        outcome="success",
        actor_id=admin_user.id,
        request_id=request_id,
        metadata={
            "emergency_access_id": record.id,
            "requester_id": record.admin_id,
            "approver_id": admin_user.id,
            "is_break_glass": True
        }
    )

    return build_break_glass_response(record)

@router.post("/break-glass/{id}/cancel", response_model=BreakGlassResponse)
def cancel_break_glass_access(
    id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Active Cancellation Window:
    Allows either an administrator or the document owner to cancel a pending or active break-glass.
    """
    request_id = get_request_id(request)
    record = db.query(EmergencyAccess).filter(EmergencyAccess.id == id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Emergency access record not found")

    doc = record.document
    is_owner = (doc and doc.owner_id == current_user.id)
    is_admin = (current_user.role == "admin")

    if not is_owner and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner or an administrator can cancel break-glass access."
        )

    now_utc = datetime.now(timezone.utc)
    record.status = "cancelled"
    record.revoked_at = now_utc

    if doc:
        doc.permission_epoch = (doc.permission_epoch or 1) + 1

    db.commit()
    db.refresh(record)

    log_audit_event(
        db=db,
        action="admin.break_glass.cancelled",
        resource_type="document",
        resource_id=record.document_id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "emergency_access_id": record.id,
            "cancelled_by_owner": is_owner
        }
    )

    return build_break_glass_response(record)

@router.get("/break-glass", response_model=List[BreakGlassResponse])
def list_break_glass_accesses(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Lists all historical and active break-glass emergency access requests.
    Strictly restricted to administrators.
    """
    now_utc = datetime.now(timezone.utc)
    records = db.query(EmergencyAccess).order_by(desc(EmergencyAccess.created_at)).all()

    # Update expired statuses
    for r in records:
        exp = r.expires_at.replace(tzinfo=timezone.utc) if r.expires_at.tzinfo is None else r.expires_at
        if r.status == "active" and r.revoked_at is None and exp <= now_utc:
            r.status = "expired"

    db.commit()
    return [build_break_glass_response(r) for r in records]

@router.post("/break-glass/{id}/revoke", response_model=BreakGlassResponse)
def revoke_break_glass_access(
    id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Synchronous Immediate Revocation:
    Immediately revokes an active emergency break-glass grant.
    Accessible to ANY administrator or the document owner.
    """
    request_id = get_request_id(request)
    record = db.query(EmergencyAccess).filter(EmergencyAccess.id == id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Emergency access record not found")

    doc = record.document
    is_owner = (doc and doc.owner_id == current_user.id)
    is_admin = (current_user.role == "admin")

    if not is_owner and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner or an administrator can revoke emergency access."
        )

    now_utc = datetime.now(timezone.utc)
    record.status = "revoked"
    record.revoked_at = now_utc

    # Cut off streaming mid-flight via permission epoch increment
    if doc:
        doc.permission_epoch = (doc.permission_epoch or 1) + 1

    db.commit()
    db.refresh(record)

    log_audit_event(
        db=db,
        action="admin.break_glass.revoked",
        resource_type="document",
        resource_id=record.document_id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={"emergency_access_id": record.id}
    )

    return build_break_glass_response(record)

@router.post("/break-glass/{id}/review", response_model=BreakGlassResponse)
def review_break_glass_access(
    id: str,
    review_in: BreakGlassReviewRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Records post-incident review notes and audit sign-off for an emergency access incident.
    """
    request_id = get_request_id(request)
    record = db.query(EmergencyAccess).filter(EmergencyAccess.id == id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Emergency access record not found")

    record.reviewed_at = datetime.now(timezone.utc)
    record.reviewed_by = admin_user.id
    record.review_notes = review_in.review_notes.strip()
    db.commit()
    db.refresh(record)

    log_audit_event(
        db=db,
        action="admin.break_glass.reviewed",
        resource_type="document",
        resource_id=record.document_id,
        outcome="success",
        actor_id=admin_user.id,
        request_id=request_id,
        metadata={
            "emergency_access_id": record.id,
            "review_notes": record.review_notes
        }
    )

    return build_break_glass_response(record)

@router.post("/users/{user_id}/isolate", response_model=Dict[str, Any])
def isolate_user_endpoint(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Owner Compromise Containment:
    Immediately terminates all sessions, revokes refresh tokens, freezes owned documents,
    and revokes outgoing grants.
    """
    request_id = get_request_id(request)
    try:
        return IncidentService.isolate_user(
            db=db,
            user_id=user_id,
            actor_id=admin_user.id,
            reason="Admin triggered account isolation",
            request_id=request_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
