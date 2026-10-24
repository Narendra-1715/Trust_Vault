from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.security_policy import SecurityPolicy, VALID_CLASSIFICATIONS
from app.schemas.security_policy import SecurityPolicyResponse, SecurityPolicyUpdate, DocumentClassificationUpdate
from app.schemas.document import DocumentResponse
from app.api.deps import get_current_user, get_request_id
from app.audit.service import log_audit_event
from app.services.classification_policy import (
    get_security_policy,
    can_user_change_classification,
)

router = APIRouter()

@router.get("", response_model=List[SecurityPolicyResponse])
def list_security_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List configured security policies for all classification levels.
    """
    # Ensure all default classifications are seeded in DB
    for cl in VALID_CLASSIFICATIONS:
        get_security_policy(db, cl)

    policies = db.query(SecurityPolicy).all()
    return policies

@router.put("/{classification}", response_model=SecurityPolicyResponse)
def update_security_policy(
    classification: str,
    update_data: SecurityPolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update rules for a classification security policy.
    Restricted to system administrators.
    """
    request_id = get_request_id(request)
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can configure organization security policies."
        )

    policy = get_security_policy(db, classification)
    changes = {}

    if update_data.allow_download is not None:
        changes["allow_download"] = {"old": policy.allow_download, "new": update_data.allow_download}
        policy.allow_download = update_data.allow_download

    if update_data.allow_sharing is not None:
        changes["allow_sharing"] = {"old": policy.allow_sharing, "new": update_data.allow_sharing}
        policy.allow_sharing = update_data.allow_sharing

    if update_data.max_grant_duration_days is not None:
        changes["max_grant_duration_days"] = {"old": policy.max_grant_duration_days, "new": update_data.max_grant_duration_days}
        policy.max_grant_duration_days = update_data.max_grant_duration_days

    if update_data.require_mfa is not None:
        changes["require_mfa"] = {"old": policy.require_mfa, "new": update_data.require_mfa}
        policy.require_mfa = update_data.require_mfa

    if update_data.elevated_classification_change is not None:
        changes["elevated_classification_change"] = {"old": policy.elevated_classification_change, "new": update_data.elevated_classification_change}
        policy.elevated_classification_change = update_data.elevated_classification_change

    policy.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(policy)

    log_audit_event(
        db=db,
        action="security_policy.update",
        resource_type="security_policy",
        resource_id=policy.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={"classification": policy.classification, "changes": changes}
    )

    return policy

@router.patch("/documents/{document_id}/classification", response_model=DocumentResponse)
def update_document_classification(
    document_id: str,
    update_data: DocumentClassificationUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update document classification level:
    - Enforces authorization: only owner or administrator can modify classification.
    - Validates target classification against allowed levels.
    - Enforces elevated authorization rules if configured.
    - Records immutable audit trail.
    """
    request_id = get_request_id(request)
    doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    target_classification = update_data.classification.strip()
    if target_classification not in VALID_CLASSIFICATIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid classification '{target_classification}'. Allowed: {', '.join(VALID_CLASSIFICATIONS)}"
        )

    current_policy = get_security_policy(db, doc.classification)
    target_policy = get_security_policy(db, target_classification)

    allowed, reason = can_user_change_classification(doc, current_user, target_classification, current_policy, target_policy)
    if not allowed:
        log_audit_event(
            db=db,
            action="document.classification.denied",
            resource_type="document",
            resource_id=doc.id,
            outcome="denied",
            actor_id=current_user.id,
            request_id=request_id,
            metadata={"reason": reason, "target_classification": target_classification}
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)

    old_classification = doc.classification
    doc.classification = target_classification
    doc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(doc)

    log_audit_event(
        db=db,
        action="document.classification.update",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "old_classification": old_classification,
            "new_classification": target_classification,
            "reason": update_data.reason
        }
    )

    from app.api.v1.documents import build_document_response
    return build_document_response(doc, current_user, db)

@router.patch("/users/{user_id}/mfa")
def toggle_user_mfa(
    user_id: str,
    enabled: bool,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Enable or disable MFA for a user (self or administrator).
    """
    if current_user.id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify MFA for other users.")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.mfa_enabled = enabled
    db.commit()
    db.refresh(target)
    return {"user_id": target.id, "mfa_enabled": target.mfa_enabled}
