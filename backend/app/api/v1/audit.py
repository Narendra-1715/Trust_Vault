import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional, List, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.audit import AuditEvent
from app.schemas.audit import AuditEventResponse, AuditListResponse, AuditVerificationResponse
from app.api.deps import get_current_user, get_current_admin, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.services.authorization import AuthorizationService, Action
from app.audit.verifier import verify_audit_integrity
from app.audit.service import log_audit_event

router = APIRouter()

def sanitize_csv_cell(value: Any) -> str:
    """
    Prevents CSV Formula Injection (DDE attacks).
    Prepends a single quote if the field begins with =, +, -, @, \\t, or \\r.
    """
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text

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
    date_from: Optional[datetime] = Query(None, description="Events on or after this timestamp"),
    date_to: Optional[datetime] = Query(None, description="Events on or before this timestamp"),
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
        # Enforce server-side authorization: unauthorized callers receive uniform 404
        if current_user.role != "admin":
            AuthorizationService.enforce(db, current_user, Action.VIEW_METADATA, document_id)
        filters.append(AuditEvent.resource_id == document_id)
    else:
        # Access scope:
        # - Administrators can inspect all organizational audit events.
        # - Document owners see events where they are the actor OR events on documents they own (including deleted documents).
        # - Viewers see audit events where they are the actor.
        if current_user.role != "admin":
            owned_doc_ids = db.query(Document.id).filter(
                Document.owner_id == current_user.id
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
    if date_from:
        filters.append(AuditEvent.timestamp >= date_from)
    if date_to:
        filters.append(AuditEvent.timestamp <= date_to)

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

@router.get("/export")
def export_audit_log(
    request: Request,
    export_format: str = Query("csv", alias="format", description="Export format: 'csv' or 'json'"),
    document_id: Optional[str] = Query(None, description="Filter by document ID"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    outcome: Optional[str] = Query(None, description="Filter by outcome"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    date_from: Optional[datetime] = Query(None, description="Events on or after this timestamp"),
    date_to: Optional[datetime] = Query(None, description="Events on or before this timestamp"),
    limit: int = Query(5000, ge=1, le=50000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Exports cryptographic audit logs in CSV or JSON format.
    Enforces strict role-based authorization:
    - Administrators can export full enterprise audit trails.
    - Document Owners can export audit trails for documents they own or actions they initiated.
    - Viewers can only export audit events where they are the authenticated actor.
    - Mitigates CSV Formula Injection (DDE) by sanitizing all cells.
    """
    filters = []

    if document_id:
        if current_user.role != "admin":
            AuthorizationService.enforce(db, current_user, Action.VIEW_METADATA, document_id)
        filters.append(AuditEvent.resource_id == document_id)
    else:
        if current_user.role != "admin":
            owned_doc_ids = db.query(Document.id).filter(
                Document.owner_id == current_user.id
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
    if date_from:
        filters.append(AuditEvent.timestamp >= date_from)
    if date_to:
        filters.append(AuditEvent.timestamp <= date_to)

    events = (
        db.query(AuditEvent)
        .filter(*filters)
        .order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc())
        .limit(limit)
        .all()
    )

    request_id = get_request_id(request)
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Record the export itself in the immutable audit ledger
    log_audit_event(
        db=db,
        action="audit.export",
        resource_type="audit_log",
        resource_id=document_id or "ledger",
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "format": export_format,
            "record_count": len(events),
            "filters": {
                "action": action,
                "outcome": outcome,
                "document_id": document_id
            }
        }
    )

    if export_format.lower() == "json":
        export_data = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "actor_id": e.actor_id,
                "actor_email": e.actor.email if e.actor else None,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "outcome": e.outcome,
                "request_id": e.request_id,
                "structured_metadata": e.structured_metadata or {},
                "previous_event_hash": e.previous_event_hash,
                "event_hash": e.event_hash,
            }
            for e in events
        ]
        json_bytes = json.dumps(export_data, indent=2).encode("utf-8")
        filename = f"trustvault_audit_{now_str}.json"
        return StreamingResponse(
            io.BytesIO(json_bytes),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    # Default CSV export with formula injection mitigation
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header
    writer.writerow([
        "Event ID",
        "Timestamp (UTC)",
        "Actor ID",
        "Actor Email",
        "Action",
        "Resource Type",
        "Resource ID",
        "Outcome",
        "Request ID",
        "Metadata",
        "Previous Event Hash",
        "Event Hash"
    ])

    for e in events:
        actor_email = e.actor.email if e.actor else ""
        meta_str = json.dumps(e.structured_metadata or {})
        writer.writerow([
            sanitize_csv_cell(e.id),
            sanitize_csv_cell(e.timestamp.isoformat() if e.timestamp else ""),
            sanitize_csv_cell(e.actor_id),
            sanitize_csv_cell(actor_email),
            sanitize_csv_cell(e.action),
            sanitize_csv_cell(e.resource_type),
            sanitize_csv_cell(e.resource_id),
            sanitize_csv_cell(e.outcome),
            sanitize_csv_cell(e.request_id),
            sanitize_csv_cell(meta_str),
            sanitize_csv_cell(e.previous_event_hash),
            sanitize_csv_cell(e.event_hash),
        ])

    csv_bytes = output.getvalue().encode("utf-8")
    filename = f"trustvault_audit_{now_str}.csv"
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
