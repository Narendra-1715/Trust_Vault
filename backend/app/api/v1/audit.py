from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.audit import AuditEvent
from app.schemas.audit import AuditEventResponse, AuditListResponse, AuditVerificationResponse
from app.api.deps import get_current_user, get_current_admin, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.audit.verifier import verify_audit_integrity
from app.audit.service import log_audit_event

router = APIRouter()

def build_audit_response(event: AuditEvent) -> AuditEventResponse:
    return AuditEventResponse(
        id=event.id,
        timestamp=event.timestamp,
        actor_id=event.actor_id,
        actor_email=event.actor.email if event.actor else None,
        action=event.action,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        outcome=event.outcome,
        request_id=event.request_id,
        structured_metadata=event.structured_metadata or {},
        previous_event_hash=event.previous_event_hash,
        event_hash=event.event_hash
    )

@router.get("/events", response_model=AuditListResponse)
def list_audit_events(
    document_id: Optional[str] = Query(None, description="Filter by document ID"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    outcome: Optional[str] = Query(None, description="Filter by outcome (success, denied, failure)"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns immutable audit log events.
    Access Control:
    - Administrators can inspect all organizational audit events.
    - Document owners and authorized users can view audit events for documents they have read access to.
    """
    filters = []

    if document_id:
        doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
        AuthorizationPolicy.require_read(db, current_user, doc)
        filters.append(AuditEvent.resource_id == document_id)
    else:
        # Access scope:
        # - Administrators can inspect all organizational audit events.
        # - Document owners see events where they are the actor OR events on documents they own (e.g. download denials).
        # - Viewers see audit events where they are the actor.
        if current_user.role != "admin":
            owned_doc_ids = db.query(Document.id).filter(
                Document.owner_id == current_user.id,
                Document.deleted_at.is_(None)
            ).scalar_subquery()

            filters.append(
                or_(
                    AuditEvent.actor_id == current_user.id,
                    AuditEvent.resource_id.in_(owned_doc_ids)
                )
            )

    if action:
        filters.append(AuditEvent.action.ilike(f"%{action.strip()}%"))
    if outcome:
        filters.append(AuditEvent.outcome == outcome.strip())
    if resource_type:
        filters.append(AuditEvent.resource_type == resource_type.strip())

    total = db.query(AuditEvent).filter(*filters).count()
    events = (
        db.query(AuditEvent)
        .filter(*filters)
        .order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AuditListResponse(
        total=total,
        events=[build_audit_response(e) for e in events]
    )

@router.get("/verify", response_model=AuditVerificationResponse)
def verify_audit_log_integrity(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes cryptographic SHA-256 hash-chain verification over the full audit ledger.
    Verifies that no previous records have been deleted, inserted, modified, or reordered.
    """
    request_id = get_request_id(request)
    result = verify_audit_integrity(db)

    # Log that an integrity verification was performed
    log_audit_event(
        db=db,
        action="audit.verify",
        resource_type="audit_integrity",
        resource_id="ledger",
        outcome="success" if result["is_valid"] else "failure",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "is_valid": result["is_valid"],
            "total_events_checked": result["total_events"],
            "tampered_event_id": result.get("tampered_event_id")
        }
    )

    return AuditVerificationResponse(**result)
