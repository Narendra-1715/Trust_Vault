from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.schemas.permission import PermissionResponse, PermissionGrantRequest
from app.api.deps import get_current_user, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.services.authorization import AuthorizationService, Action
from app.audit.service import log_audit_event
from app.notifications.service import create_security_notification
from app.services.detection import detect_burst_permission_changes
from app.services.classification_policy import get_security_policy, evaluate_grant_proposal

router = APIRouter()

def build_permission_response(perm: DocumentPermission) -> PermissionResponse:
    user = perm.user
    granter = perm.granter
    
    now_utc = datetime.now(timezone.utc)
    is_revoked = perm.revoked_at is not None
    is_expired = False
    if perm.expires_at is not None:
        exp = perm.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        is_expired = exp <= now_utc

    if is_revoked:
        perm_status = "revoked"
    elif is_expired:
        perm_status = "expired"
    else:
        perm_status = "active"

    return PermissionResponse(
        id=perm.id,
        document_id=perm.document_id,
        user_id=perm.user_id,
        user_email=user.email if user else "",
        user_display_name=user.display_name if user else "",
        permission_level=perm.permission_level,
        min_version_number=perm.min_version_number,
        max_version_number=perm.max_version_number,
        granted_by=perm.granted_by,
        granted_by_email=granter.email if granter else None,
        granted_at=perm.granted_at,
        updated_at=perm.updated_at,
        revoked_at=perm.revoked_at,
        expires_at=perm.expires_at,
        is_expired=is_expired,
        status=perm_status
    )

@router.get("/documents/{document_id}/permissions", response_model=List[PermissionResponse])
def get_document_permissions(
    document_id: str,
    include_revoked: bool = Query(False, description="Include revoked permissions"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists sharing permissions for a document.
    Requires VIEW_METADATA authorization via central AuthorizationService.
    """
    doc = AuthorizationService.enforce(db, current_user, Action.VIEW_METADATA, document_id)

    query = db.query(DocumentPermission).filter(DocumentPermission.document_id == document_id)
    if not include_revoked:
        query = query.filter(DocumentPermission.revoked_at.is_(None))

    perms = query.order_by(DocumentPermission.granted_at.desc()).all()
    return [build_permission_response(p) for p in perms]

@router.post("/documents/{document_id}/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
def grant_document_permission(
    document_id: str,
    grant_in: PermissionGrantRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Grants or updates explicit document access.
    Strictly enforced: Only the document owner can grant permissions.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.MANAGE_GRANTS, document_id, request_id=request_id)

    # Locate target user by ID or email
    target_user = None
    if grant_in.user_id:
        target_user = db.query(User).filter(User.id == grant_in.user_id).first()
    elif grant_in.email:
        target_user = db.query(User).filter(User.email == grant_in.email.strip().lower()).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found"
        )

    if target_user.id == doc.owner_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Document owner already has full access"
        )

    # Validate expires_at
    expires_at_val = grant_in.expires_at
    now_utc = datetime.now(timezone.utc)
    if expires_at_val is not None:
        if expires_at_val.tzinfo is None:
            expires_at_val = expires_at_val.replace(tzinfo=timezone.utc)
        if expires_at_val <= now_utc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expiration date must be in the future"
            )

    # Enforce classification security policy
    policy = get_security_policy(db, doc.classification)
    eval_result = evaluate_grant_proposal(
        doc=doc,
        proposer=current_user,
        target_user=target_user,
        permission_level=grant_in.permission_level,
        expires_at=grant_in.expires_at,
        policy=policy,
    )
    if not eval_result["is_allowed"]:
        log_audit_event(
            db=db,
            action="permission.grant.policy_denied",
            resource_type="document",
            resource_id=doc.id,
            outcome="denied",
            actor_id=current_user.id,
            request_id=request_id,
            metadata={"reason": eval_result["summary"], "classification": doc.classification}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST if "duration" in eval_result["summary"].lower() or "expiration" in eval_result["summary"].lower() or "future" in eval_result["summary"].lower() else status.HTTP_403_FORBIDDEN,
            detail=eval_result["summary"]
        )

    # Check for existing active or previous permission
    existing_perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document_id,
        DocumentPermission.user_id == target_user.id,
        DocumentPermission.revoked_at.is_(None)
    ).first()

    if existing_perm:
        old_level = existing_perm.permission_level
        existing_perm.permission_level = grant_in.permission_level
        existing_perm.min_version_number = grant_in.min_version_number
        existing_perm.max_version_number = grant_in.max_version_number
        existing_perm.granted_by = current_user.id
        existing_perm.updated_at = now_utc
        existing_perm.expires_at = expires_at_val
        doc.permission_epoch = (doc.permission_epoch or 1) + 1
        db.commit()
        db.refresh(existing_perm)
        perm_record = existing_perm
        action_name = "permission.update"
        meta = {
            "target_user_email": target_user.email,
            "old_level": old_level,
            "new_level": grant_in.permission_level,
            "min_version_number": grant_in.min_version_number,
            "max_version_number": grant_in.max_version_number,
            "permission_epoch": doc.permission_epoch,
            "expires_at": expires_at_val.isoformat() if expires_at_val else None
        }
    else:
        new_perm = DocumentPermission(
            document_id=document_id,
            user_id=target_user.id,
            permission_level=grant_in.permission_level,
            min_version_number=grant_in.min_version_number,
            max_version_number=grant_in.max_version_number,
            granted_by=current_user.id,
            granted_at=now_utc,
            updated_at=now_utc,
            expires_at=expires_at_val
        )
        db.add(new_perm)
        doc.permission_epoch = (doc.permission_epoch or 1) + 1
        db.commit()
        db.refresh(new_perm)
        perm_record = new_perm
        action_name = "permission.grant"
        meta = {
            "target_user_email": target_user.email,
            "permission_level": grant_in.permission_level,
            "min_version_number": grant_in.min_version_number,
            "max_version_number": grant_in.max_version_number,
            "permission_epoch": doc.permission_epoch,
            "expires_at": expires_at_val.isoformat() if expires_at_val else None
        }

    log_audit_event(
        db=db,
        action=action_name,
        resource_type="permission",
        resource_id=perm_record.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata=meta
    )

    # Dispatch security alert to recipient
    create_security_notification(
        db=db,
        user_id=target_user.id,
        title="Document Access Granted",
        message=f"You have been granted {grant_in.permission_level} access to '{doc.title}' by {current_user.display_name}.",
        severity="info",
        event_type="document.permission.granted",
        resource_id=doc.id
    )

    detect_burst_permission_changes(
        db=db,
        actor_id=current_user.id,
        document_id=doc.id,
        request_id=request_id
    )

    return build_permission_response(perm_record)

@router.delete("/documents/{document_id}/permissions/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_document_permission(
    document_id: str,
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Revokes user access immediately.
    Strictly enforced: Only the document owner can revoke permissions.
    Subsequent read or download requests from the revoked user will fail immediately.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.MANAGE_GRANTS, document_id, request_id=request_id)

    perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document_id,
        DocumentPermission.user_id == user_id,
        DocumentPermission.revoked_at.is_(None)
    ).first()

    if not perm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active permission grant not found"
        )

    perm.revoked_at = datetime.now(timezone.utc)
    doc.permission_epoch = (doc.permission_epoch or 1) + 1
    db.commit()

    # Dispatch security alert to revoked user
    create_security_notification(
        db=db,
        user_id=user_id,
        title="Document Access Revoked",
        message=f"Your access to '{doc.title}' has been revoked by {current_user.display_name}.",
        severity="warning",
        event_type="document.permission.revoked",
        resource_id=doc.id
    )

    log_audit_event(
        db=db,
        action="permission.revoke",
        resource_type="permission",
        resource_id=perm.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "revoked_user_id": user_id,
            "document_id": document_id
        }
    )

    detect_burst_permission_changes(
        db=db,
        actor_id=current_user.id,
        document_id=doc.id,
        request_id=request_id
    )

    return None
