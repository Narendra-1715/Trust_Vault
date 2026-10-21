from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.schemas.permission import PermissionResponse, PermissionGrantRequest
from app.api.deps import get_current_user, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.audit.service import log_audit_event

router = APIRouter()

def build_permission_response(perm: DocumentPermission) -> PermissionResponse:
    user = perm.user
    granter = perm.granter
    return PermissionResponse(
        id=perm.id,
        document_id=perm.document_id,
        user_id=perm.user_id,
        user_email=user.email if user else "",
        user_display_name=user.display_name if user else "",
        permission_level=perm.permission_level,
        granted_by=perm.granted_by,
        granted_by_email=granter.email if granter else None,
        granted_at=perm.granted_at,
        updated_at=perm.updated_at,
        revoked_at=perm.revoked_at
    )

@router.get("/documents/{document_id}/permissions", response_model=List[PermissionResponse])
def get_document_permissions(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists active sharing permissions for a document.
    Requires read authorization.
    """
    doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
    AuthorizationPolicy.require_read(db, current_user, doc)

    perms = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document_id,
        DocumentPermission.revoked_at.is_(None)
    ).all()

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
    doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
    AuthorizationPolicy.require_owner(db, current_user, doc)

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

    # Check for existing active permission
    existing_perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document_id,
        DocumentPermission.user_id == target_user.id,
        DocumentPermission.revoked_at.is_(None)
    ).first()

    now_utc = datetime.now(timezone.utc)
    if existing_perm:
        old_level = existing_perm.permission_level
        existing_perm.permission_level = grant_in.permission_level
        existing_perm.granted_by = current_user.id
        existing_perm.updated_at = now_utc
        db.commit()
        db.refresh(existing_perm)
        perm_record = existing_perm
        action_name = "permission.update"
        meta = {
            "target_user_email": target_user.email,
            "old_level": old_level,
            "new_level": grant_in.permission_level
        }
    else:
        new_perm = DocumentPermission(
            document_id=document_id,
            user_id=target_user.id,
            permission_level=grant_in.permission_level,
            granted_by=current_user.id,
            granted_at=now_utc,
            updated_at=now_utc
        )
        db.add(new_perm)
        db.commit()
        db.refresh(new_perm)
        perm_record = new_perm
        action_name = "permission.grant"
        meta = {
            "target_user_email": target_user.email,
            "permission_level": grant_in.permission_level
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
    doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
    AuthorizationPolicy.require_owner(db, current_user, doc)

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
    db.commit()

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
    return None
