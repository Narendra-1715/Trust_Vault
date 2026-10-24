import secrets
import hashlib
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.access_request import AccessRequest
from app.models.request_link import DocumentRequestLink
from app.schemas.access_request import (
    AccessRequestCreate,
    AccessRequestApprove,
    AccessRequestReject,
    AccessRequestResponse,
    AccessRequestStatusCheck
)
from app.schemas.request_link import (
    RequestLinkCreate,
    RequestLinkCreatedResponse,
    RequestLinkListItem,
    RequestLinkResolved,
    RequestLinkSubmit
)
from app.api.deps import get_current_user, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.audit.service import log_audit_event
from app.notifications.service import create_security_notification

router = APIRouter()

def build_request_link_list_item(link: DocumentRequestLink) -> RequestLinkListItem:
    now_utc = datetime.now(timezone.utc)
    is_revoked = link.revoked_at is not None
    is_expired = False
    if link.expires_at is not None:
        exp = link.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        is_expired = exp <= now_utc

    if is_revoked:
        link_status = "revoked"
    elif is_expired or (link.max_uses and link.use_count >= link.max_uses):
        link_status = "expired"
    else:
        link_status = "active"

    return RequestLinkListItem(
        id=link.id,
        document_id=link.document_id,
        token_prefix=link.token_prefix,
        name=link.name,
        expires_at=link.expires_at,
        revoked_at=link.revoked_at,
        created_at=link.created_at,
        use_count=link.use_count,
        max_uses=link.max_uses,
        status=link_status
    )

def build_access_request_response(req: AccessRequest) -> AccessRequestResponse:
    requester = req.requester
    owner = req.owner
    decider = req.decider
    doc = req.document

    return AccessRequestResponse(
        id=req.id,
        document_id=req.document_id,
        document_title=doc.title if doc and doc.deleted_at is None else "[Unavailable]",
        requester_id=req.requester_id,
        requester_email=requester.email if requester else None,
        requester_name=requester.display_name if requester else None,
        owner_id=req.owner_id,
        owner_email=owner.email if owner else None,
        owner_name=owner.display_name if owner else None,
        reason=req.reason,
        status=req.status,
        requested_permission=req.requested_permission,
        requested_expiry=req.requested_expiry,
        approved_permission=req.approved_permission,
        approved_expiry=req.approved_expiry,
        rejection_reason=req.rejection_reason,
        decided_by=req.decided_by,
        decided_by_name=decider.display_name if decider else None,
        decided_at=req.decided_at,
        cancelled_at=req.cancelled_at,
        created_at=req.created_at,
        updated_at=req.updated_at
    )

@router.post("", response_model=AccessRequestResponse, status_code=status.HTTP_201_CREATED)
def create_access_request(
    request_in: AccessRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Submits a new document access request.
    Enforces strict authorization:
    - User cannot request access to nonexistent or deleted documents (404, no metadata leakage).
    - Document owner cannot request access to their own document (400).
    - Users with existing active access cannot submit redundant requests (400).
    - Duplicate pending requests for the same user and document are rejected (409 Conflict).
    - Derives owner_id and requester_id server-side to prevent IDOR/tampering.
    """
    request_id = get_request_id(request)
    now_utc = datetime.now(timezone.utc)

    # Validate target document existence
    doc = db.query(Document).filter(
        Document.id == request_in.document_id,
        Document.deleted_at.is_(None)
    ).first()

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )

    # Document owner check
    if doc.owner_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Document owner already has full access"
        )

    # Check if user already has active access (read or edit)
    if AuthorizationPolicy.can_read_document(db, current_user, doc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You already have active access to this document"
        )

    # Check for existing pending request
    existing_pending = db.query(AccessRequest).filter(
        AccessRequest.document_id == doc.id,
        AccessRequest.requester_id == current_user.id,
        AccessRequest.status == "pending"
    ).first()

    if existing_pending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a pending access request for this document"
        )

    # Validate requested permission level
    perm_level = (request_in.requested_permission or "read").strip().lower()
    if perm_level not in ["read", "edit"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Requested permission must be 'read' or 'edit'"
        )

    # Validate requested expiry
    req_expiry = request_in.requested_expiry
    if req_expiry is not None:
        if req_expiry.tzinfo is None:
            req_expiry = req_expiry.replace(tzinfo=timezone.utc)
        if req_expiry <= now_utc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Requested expiration date must be in the future"
            )

    # Create access request with server-verified owner_id and requester_id
    new_request = AccessRequest(
        document_id=doc.id,
        requester_id=current_user.id,
        owner_id=doc.owner_id,
        reason=request_in.reason.strip(),
        status="pending",
        requested_permission=perm_level,
        requested_expiry=req_expiry,
        created_at=now_utc,
        updated_at=now_utc
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)

    # Audit log entry (safe metadata only: IDs and permission, zero confidential content)
    log_audit_event(
        db=db,
        action="access_request.create",
        resource_type="access_request",
        resource_id=new_request.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "document_id": doc.id,
            "requested_permission": perm_level,
            "has_expiry": bool(req_expiry)
        }
    )

    # Inform document owner via security notification
    create_security_notification(
        db=db,
        user_id=doc.owner_id,
        title="Access Request Received",
        message=f"{current_user.display_name} ({current_user.email}) requested {perm_level} access to '{doc.title}'.",
        severity="info",
        event_type="access_request.received",
        resource_id=new_request.id
    )

    return build_access_request_response(new_request)

@router.get("/my", response_model=List[AccessRequestResponse])
def get_my_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns all access requests submitted by the current user.
    """
    requests = db.query(AccessRequest).filter(
        AccessRequest.requester_id == current_user.id
    ).order_by(AccessRequest.created_at.desc()).all()

    return [build_access_request_response(r) for r in requests]

@router.get("/incoming", response_model=List[AccessRequestResponse])
def get_incoming_access_requests(
    status_filter: Optional[str] = Query(None, description="Filter by status (e.g. 'pending')"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns access requests for documents owned by the current user.
    Only the actual document owner can view incoming requests for their files.
    """
    query = db.query(AccessRequest).filter(
        AccessRequest.owner_id == current_user.id
    )

    if status_filter:
        query = query.filter(AccessRequest.status == status_filter.strip().lower())

    requests = query.order_by(AccessRequest.created_at.desc()).all()
    return [build_access_request_response(r) for r in requests]

@router.get("/status/{document_id}", response_model=AccessRequestStatusCheck)
def check_document_access_request_status(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Checks if current user has an active pending request on a document.
    Safe against metadata leakage: returns clean status without disclosing document details.
    """
    req = db.query(AccessRequest).filter(
        AccessRequest.document_id == document_id,
        AccessRequest.requester_id == current_user.id,
        AccessRequest.status == "pending"
    ).first()

    if not req:
        return AccessRequestStatusCheck(has_pending_request=False)

    return AccessRequestStatusCheck(
        has_pending_request=True,
        request_id=req.id,
        created_at=req.created_at,
        requested_permission=req.requested_permission,
        requested_expiry=req.requested_expiry
    )

@router.get("/{request_id}", response_model=AccessRequestResponse)
def get_access_request_details(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns access request details.
    Authorized only for the requester or the document owner.
    Prevents IDOR / unauthorized enumeration (returns 404 if unauthorized).
    """
    req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found"
        )

    # Authorization: requester or owner only
    if req.requester_id != current_user.id and req.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found"
        )

    return build_access_request_response(req)

@router.post("/{request_id}/approve", response_model=AccessRequestResponse)
def approve_access_request(
    request_id: str,
    approve_in: AccessRequestApprove,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Approves an access request and atomically creates/updates the document permission.
    Strictly enforced:
    - Only the actual document owner can approve (current_user.id == doc.owner_id).
    - Requester cannot approve their own request.
    - Non-owners cannot approve.
    - Cannot approve a request that is not in 'pending' status (prevents replay/conflict).
    - Failed grant creation will automatically roll back and never leave request marked approved.
    """
    http_req_id = get_request_id(request)
    now_utc = datetime.now(timezone.utc)

    # Row-level lock to prevent concurrent duplicate approvals
    access_req = db.query(AccessRequest).filter(
        AccessRequest.id == request_id
    ).with_for_update().first()

    if not access_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found"
        )

    # Security check: Requester cannot approve their own request
    if access_req.requester_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requesters cannot approve their own requests"
        )

    # Security check: Only the verified document owner can approve
    if access_req.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can approve access requests"
        )

    # Re-verify document existence and live ownership
    doc = db.query(Document).filter(
        Document.id == access_req.document_id,
        Document.deleted_at.is_(None)
    ).first()

    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Document ownership verification failed"
        )

    # Replay prevention
    if access_req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve request with status '{access_req.status}'"
        )

    # Validate permission level
    approved_perm = (approve_in.approved_permission or "read").strip().lower()
    if approved_perm not in ["read", "edit"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Approved permission must be 'read' or 'edit'"
        )

    # Validate approved expiry
    approved_exp = approve_in.approved_expiry
    if approved_exp is not None:
        if approved_exp.tzinfo is None:
            approved_exp = approved_exp.replace(tzinfo=timezone.utc)
        if approved_exp <= now_utc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expiration date must be in the future"
            )

    # Atomic grant creation using existing DocumentPermission system
    existing_perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id,
        DocumentPermission.user_id == access_req.requester_id,
        DocumentPermission.revoked_at.is_(None)
    ).first()

    if existing_perm:
        existing_perm.permission_level = approved_perm
        existing_perm.granted_by = current_user.id
        existing_perm.updated_at = now_utc
        existing_perm.expires_at = approved_exp
        perm_record = existing_perm
        perm_action = "permission.update"
    else:
        new_perm = DocumentPermission(
            document_id=doc.id,
            user_id=access_req.requester_id,
            permission_level=approved_perm,
            granted_by=current_user.id,
            granted_at=now_utc,
            updated_at=now_utc,
            expires_at=approved_exp
        )
        db.add(new_perm)
        perm_record = new_perm
        perm_action = "permission.grant"

    # Mark request as approved
    access_req.status = "approved"
    access_req.approved_permission = approved_perm
    access_req.approved_expiry = approved_exp
    access_req.decided_by = current_user.id
    access_req.decided_at = now_utc
    access_req.updated_at = now_utc

    # Commit grant and approval atomically
    db.commit()
    db.refresh(access_req)
    db.refresh(perm_record)

    # Record audit events for request approval and grant creation
    log_audit_event(
        db=db,
        action="access_request.approve",
        resource_type="access_request",
        resource_id=access_req.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=http_req_id,
        metadata={
            "document_id": doc.id,
            "requester_id": access_req.requester_id,
            "approved_permission": approved_perm,
            "expires_at": approved_exp.isoformat() if approved_exp else None
        }
    )

    log_audit_event(
        db=db,
        action=perm_action,
        resource_type="permission",
        resource_id=perm_record.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=http_req_id,
        metadata={
            "target_user_id": access_req.requester_id,
            "permission_level": approved_perm,
            "source": "access_request_approval",
            "access_request_id": access_req.id,
            "expires_at": approved_exp.isoformat() if approved_exp else None
        }
    )

    # Dispatch notification to requester
    create_security_notification(
        db=db,
        user_id=access_req.requester_id,
        title="Access Request Approved",
        message=f"Your request for '{doc.title}' was approved by {current_user.display_name}. You now have {approved_perm} access.",
        severity="info",
        event_type="access_request.approved",
        resource_id=doc.id
    )

    return build_access_request_response(access_req)

@router.post("/{request_id}/reject", response_model=AccessRequestResponse)
def reject_access_request(
    request_id: str,
    reject_in: AccessRequestReject,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Rejects an access request.
    Strictly enforced:
    - Only the actual document owner can reject.
    - Requesters cannot reject their own request.
    - Cannot reject a request that is not in 'pending' status.
    - No permission grant is created.
    """
    http_req_id = get_request_id(request)
    now_utc = datetime.now(timezone.utc)

    access_req = db.query(AccessRequest).filter(
        AccessRequest.id == request_id
    ).with_for_update().first()

    if not access_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found"
        )

    # Security check: Requester cannot reject their own request
    if access_req.requester_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requesters cannot reject their own requests"
        )

    # Security check: Only verified document owner can reject
    if access_req.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can reject access requests"
        )

    # Replay check
    if access_req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject request with status '{access_req.status}'"
        )

    rejection_msg = (reject_in.rejection_reason or "").strip() or None

    access_req.status = "rejected"
    access_req.rejection_reason = rejection_msg
    access_req.decided_by = current_user.id
    access_req.decided_at = now_utc
    access_req.updated_at = now_utc

    db.commit()
    db.refresh(access_req)

    # Audit log entry
    log_audit_event(
        db=db,
        action="access_request.reject",
        resource_type="access_request",
        resource_id=access_req.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=http_req_id,
        metadata={
            "document_id": access_req.document_id,
            "requester_id": access_req.requester_id,
            "has_rejection_reason": bool(rejection_msg)
        }
    )

    # Notify requester
    doc = access_req.document
    doc_title = doc.title if doc else "the requested document"
    reason_suffix = f" Reason: {rejection_msg}" if rejection_msg else ""

    create_security_notification(
        db=db,
        user_id=access_req.requester_id,
        title="Access Request Declined",
        message=f"Your access request for '{doc_title}' was declined by the owner.{reason_suffix}",
        severity="warning",
        event_type="access_request.rejected",
        resource_id=access_req.document_id
    )

    return build_access_request_response(access_req)

@router.post("/{request_id}/cancel", response_model=AccessRequestResponse)
def cancel_access_request(
    request_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cancels a pending access request.
    Strictly enforced:
    - Only the original requester can cancel their request.
    - Cannot cancel a request that is not in 'pending' status.
    """
    http_req_id = get_request_id(request)
    now_utc = datetime.now(timezone.utc)

    access_req = db.query(AccessRequest).filter(
        AccessRequest.id == request_id
    ).with_for_update().first()

    if not access_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found"
        )

    # Authorization: only requester can cancel
    if access_req.requester_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only cancel your own access requests"
        )

    # Replay check
    if access_req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel request with status '{access_req.status}'"
        )

    access_req.status = "cancelled"
    access_req.cancelled_at = now_utc
    access_req.updated_at = now_utc

    db.commit()
    db.refresh(access_req)

    # Audit log entry
    log_audit_event(
        db=db,
        action="access_request.cancel",
        resource_type="access_request",
        resource_id=access_req.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=http_req_id,
        metadata={
            "document_id": access_req.document_id
        }
    )

    return build_access_request_response(access_req)

# ================= SECURE REQUEST-ACCESS REFERENCE & LINK WORKFLOW =================

@router.post("/links/{document_id}", response_model=RequestLinkCreatedResponse, status_code=status.HTTP_201_CREATED)
def create_document_request_link(
    document_id: str,
    link_in: RequestLinkCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates an unpredictable, revocable request-access reference link for a specific document.
    Strictly enforced:
    - Only the verified document owner can create request links.
    - Raw token is never stored in plaintext (only SHA-256 hash is persisted).
    - Raw token is returned only once to the owner for distribution.
    - The link NEVER confers document content access.
    """
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.deleted_at.is_(None)
    ).first()
    AuthorizationPolicy.require_owner(db, current_user, doc)

    now_utc = datetime.now(timezone.utc)
    exp = link_in.expires_at
    if exp is not None:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now_utc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expiration date must be in the future"
            )

    # 256 bits of cryptographic entropy (unpredictable token)
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    token_prefix = raw_token[:8]

    new_link = DocumentRequestLink(
        document_id=doc.id,
        owner_id=doc.owner_id,
        created_by=current_user.id,
        token_hash=token_hash,
        token_prefix=token_prefix,
        name=link_in.name.strip() if link_in.name else None,
        expires_at=exp,
        max_uses=link_in.max_uses,
        created_at=now_utc
    )
    db.add(new_link)
    db.commit()
    db.refresh(new_link)

    # Cryptographic audit trail: logs prefix and link ID, NEVER the raw token
    log_audit_event(
        db=db,
        action="request_link.create",
        resource_type="request_link",
        resource_id=new_link.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=get_request_id(request),
        metadata={
            "document_id": doc.id,
            "token_prefix": token_prefix,
            "has_expiry": bool(exp),
            "max_uses": link_in.max_uses
        }
    )

    return RequestLinkCreatedResponse(
        id=new_link.id,
        document_id=doc.id,
        document_title=doc.title,
        token=raw_token,
        token_prefix=token_prefix,
        name=new_link.name,
        expires_at=new_link.expires_at,
        created_at=new_link.created_at,
        max_uses=new_link.max_uses,
        use_count=new_link.use_count
    )

@router.get("/links/{document_id}", response_model=List[RequestLinkListItem])
def list_document_request_links(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists all request-access links for a document.
    Only the document owner can inspect links.
    Never exposes raw tokens.
    """
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.deleted_at.is_(None)
    ).first()
    AuthorizationPolicy.require_owner(db, current_user, doc)

    links = db.query(DocumentRequestLink).filter(
        DocumentRequestLink.document_id == document_id
    ).order_by(DocumentRequestLink.created_at.desc()).all()

    return [build_request_link_list_item(l) for l in links]

@router.post("/links/{link_id}/revoke", status_code=status.HTTP_200_OK)
def revoke_document_request_link(
    link_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Revokes a request-access link immediately.
    Strictly enforced: Only the document owner can revoke the link.
    Subsequent resolution or submission attempts via this link will fail immediately (410 Gone).
    """
    link = db.query(DocumentRequestLink).filter(
        DocumentRequestLink.id == link_id
    ).first()

    if not link or link.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Request link not found"
        )

    if link.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request link is already revoked"
        )

    now_utc = datetime.now(timezone.utc)
    link.revoked_at = now_utc
    db.commit()

    log_audit_event(
        db=db,
        action="request_link.revoke",
        resource_type="request_link",
        resource_id=link.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=get_request_id(request),
        metadata={
            "document_id": link.document_id,
            "token_prefix": link.token_prefix
        }
    )

    return {"message": "Request link revoked successfully"}

@router.get("/resolve-link/{token}", response_model=RequestLinkResolved)
def resolve_request_link(
    token: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Resolves a request-access reference link for an authenticated user.
    Safe against data leakage:
    - Verifies token validity against stored SHA-256 hash.
    - Rejects invalid, revoked, or expired tokens.
    - Exposes strictly non-sensitive discovery metadata (title, category, owner name/email).
    - Never exposes document contents, storage paths, checksums, or file bytes.
    - Never grants access to the document.
    """
    token_clean = token.strip()
    token_hash = hashlib.sha256(token_clean.encode("utf-8")).hexdigest()

    link = db.query(DocumentRequestLink).filter(
        DocumentRequestLink.token_hash == token_hash
    ).first()

    if not link:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid or expired request access link"
        )

    if link.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This request link has been revoked by the document owner"
        )

    now_utc = datetime.now(timezone.utc)
    if link.expires_at is not None:
        exp = link.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now_utc:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="This request link has expired"
            )

    if link.max_uses is not None and link.use_count >= link.max_uses:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This request link has reached its maximum permitted uses"
        )

    doc = db.query(Document).filter(
        Document.id == link.document_id,
        Document.deleted_at.is_(None)
    ).first()

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target document is no longer available"
        )

    owner = doc.owner
    has_access = AuthorizationPolicy.can_read_document(db, current_user, doc)
    
    pending_req = db.query(AccessRequest).filter(
        AccessRequest.document_id == doc.id,
        AccessRequest.requester_id == current_user.id,
        AccessRequest.status == "pending"
    ).first()

    return RequestLinkResolved(
        token_prefix=link.token_prefix,
        document_title=doc.title,
        category=doc.category,
        owner_name=owner.display_name if owner else None,
        owner_email=owner.email if owner else "",
        link_name=link.name,
        expires_at=link.expires_at,
        has_active_access=has_access,
        has_pending_request=pending_req is not None,
        pending_request_id=pending_req.id if pending_req else None
    )

@router.post("/submit-via-link/{token}", response_model=AccessRequestResponse, status_code=status.HTTP_201_CREATED)
def submit_access_request_via_link(
    token: str,
    submit_in: RequestLinkSubmit,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Submits an access request using a validated request-access reference link.
    Strictly enforced:
    - Never trusts client-supplied document IDs or owner IDs; derives all bindings from the validated link and database state.
    - Requester must be authenticated.
    - Document owner cannot request access to their own document (400).
    - Users with existing active access cannot submit duplicate requests (400).
    - Prevents duplicate pending requests for the same user and document (409 Conflict).
    - Increments link usage counter atomically under row lock.
    - Dispatches security alert to document owner.
    - Does NOT grant document access. Access remains denied until owner approval.
    """
    token_clean = token.strip()
    token_hash = hashlib.sha256(token_clean.encode("utf-8")).hexdigest()
    http_req_id = get_request_id(request)
    now_utc = datetime.now(timezone.utc)

    # Row-level lock on the link record
    link = db.query(DocumentRequestLink).filter(
        DocumentRequestLink.token_hash == token_hash
    ).with_for_update().first()

    if not link:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid request access link"
        )

    if link.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This request link has been revoked"
        )

    if link.expires_at is not None:
        exp = link.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now_utc:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="This request link has expired"
            )

    if link.max_uses is not None and link.use_count >= link.max_uses:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This request link has reached its maximum permitted uses"
        )

    # Verify target document
    doc = db.query(Document).filter(
        Document.id == link.document_id,
        Document.deleted_at.is_(None)
    ).first()

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )

    # Server-side validation: owner cannot request own doc
    if doc.owner_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Document owner already has full access"
        )

    # Check if user already has active access
    if AuthorizationPolicy.can_read_document(db, current_user, doc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You already have active access to this document"
        )

    # Check for existing pending request
    existing_pending = db.query(AccessRequest).filter(
        AccessRequest.document_id == doc.id,
        AccessRequest.requester_id == current_user.id,
        AccessRequest.status == "pending"
    ).first()

    if existing_pending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a pending access request for this document"
        )

    # Validate requested permission level
    perm_level = (submit_in.requested_permission or "read").strip().lower()
    if perm_level not in ["read", "edit"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Requested permission must be 'read' or 'edit'"
        )

    # Validate requested expiry
    req_exp = submit_in.requested_expiry
    if req_exp is not None:
        if req_exp.tzinfo is None:
            req_exp = req_exp.replace(tzinfo=timezone.utc)
        if req_exp <= now_utc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Requested expiration date must be in the future"
            )

    # Create AccessRequest bound strictly to server data
    new_request = AccessRequest(
        document_id=doc.id,
        requester_id=current_user.id,
        owner_id=doc.owner_id,
        reason=submit_in.reason.strip(),
        status="pending",
        requested_permission=perm_level,
        requested_expiry=req_exp,
        created_at=now_utc,
        updated_at=now_utc
    )
    db.add(new_request)

    # Atomically increment link use count
    link.use_count += 1

    db.commit()
    db.refresh(new_request)

    # Audit log entry (safe metadata only, zero raw tokens)
    log_audit_event(
        db=db,
        action="access_request.create_via_link",
        resource_type="access_request",
        resource_id=new_request.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=http_req_id,
        metadata={
            "document_id": doc.id,
            "link_id": link.id,
            "token_prefix": link.token_prefix,
            "requested_permission": perm_level
        }
    )

    # Notify document owner
    create_security_notification(
        db=db,
        user_id=doc.owner_id,
        title="Access Request Received (via Link)",
        message=f"{current_user.display_name} ({current_user.email}) requested {perm_level} access to '{doc.title}' using a request link.",
        severity="info",
        event_type="access_request.received",
        resource_id=new_request.id
    )

    return build_access_request_response(new_request)

