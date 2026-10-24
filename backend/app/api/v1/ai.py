import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.ai_suggestion import AIAccessSuggestion
from app.schemas.ai import (
    AIRecommendationResult,
    AIApprovalRequest,
    AIRejectionRequest,
    SuggestedGrant
)
from app.schemas.permission import PermissionResponse
from app.api.deps import get_current_user, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.services.authorization import AuthorizationService, Action
from app.ai.service import ai_service
from app.core.rate_limit import ai_limiter, check_rate_limit
from app.audit.service import log_audit_event
from app.api.v1.permissions import build_permission_response

router = APIRouter()

@router.post("/documents/{document_id}/ai-recommendations", response_model=Dict[str, Any])
def request_ai_recommendations(
    document_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates human-advisory permission recommendations.
    Strictly enforced:
    - Only the document owner can request recommendations
    - AI output is stored as a pending suggestion and CANNOT create permissions without explicit owner approval
    """
    request_id = get_request_id(request)
    check_rate_limit(request, ai_limiter, key_prefix="ai")

    doc = AuthorizationService.enforce(db, current_user, Action.MANAGE_GRANTS, document_id, request_id=request_id)

    # Fetch candidate organization users
    candidate_users_db = db.query(User).filter(
        User.is_active == True,
        User.id != current_user.id
    ).all()

    candidates = [
        {"id": u.id, "email": u.email, "display_name": u.display_name, "role": u.role}
        for u in candidate_users_db
    ]

    # Generate structured recommendation with egress leak filter inspection
    from app.ai.egress_filter import AIEgressLeakDetectedException

    try:
        result: AIRecommendationResult = ai_service.get_recommendations(
            document_id=doc.id,
            document_title=doc.title,
            document_description=doc.description or "",
            category=doc.category,
            candidate_users=candidates,
            owner_email=current_user.email,
            db=db,
            actor_id=current_user.id,
            request_id=request_id
        )
    except AIEgressLeakDetectedException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AI Egress Security Violation: Outbound data transmission blocked ({str(e)})"
        )

    # Persist suggestion strictly in pending state (advisory only)
    suggestion_id = str(uuid.uuid4())
    primary_action = (
        result.suggested_actions[0].value
        if result.suggested_actions
        else "RECOMMEND_READ_GRANT"
    )

    ai_record = AIAccessSuggestion(
        id=suggestion_id,
        document_id=doc.id,
        requester_id=current_user.id,
        suggested_grants=[s.model_dump() for s in result.suggestions],
        explanation=result.explanation,
        provider_model=result.provider_model,
        action_type=primary_action,
        status="pending",
        created_at=datetime.now(timezone.utc)
    )
    db.add(ai_record)
    db.commit()

    log_audit_event(
        db=db,
        action="ai.recommendation.generated",
        resource_type="ai_recommendation",
        resource_id=suggestion_id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "document_id": doc.id,
            "provider_model": result.provider_model,
            "is_mock": result.is_mock,
            "suggested_actions": [a.value for a in result.suggested_actions],
            "suggestion_count": len(result.suggestions)
        }
    )

    return {
        "suggestion_id": suggestion_id,
        "recommendations": result.model_dump()
    }

@router.post("/documents/{document_id}/ai-recommendations/approve", response_model=List[PermissionResponse])
def approve_ai_recommendations(
    document_id: str,
    approval_in: AIApprovalRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Explicit owner review and approval of AI-generated suggestions.
    Only the document owner's deliberate approval creates active permission records.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.MANAGE_GRANTS, document_id, request_id=request_id)

    suggestion = db.query(AIAccessSuggestion).filter(
        AIAccessSuggestion.id == approval_in.suggestion_id,
        AIAccessSuggestion.document_id == document_id
    ).first()

    if not suggestion:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI suggestion not found")

    if suggestion.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Suggestion has already been resolved ({suggestion.status})"
        )

    now_utc = datetime.now(timezone.utc)
    applied_permissions: List[DocumentPermission] = []

    for item in approval_in.approved_grants:
        target_user = db.query(User).filter(User.id == item.user_id, User.is_active == True).first()
        if not target_user or target_user.id == doc.owner_id:
            continue

        existing_perm = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == target_user.id,
            DocumentPermission.revoked_at.is_(None)
        ).first()

        if existing_perm:
            existing_perm.permission_level = item.permission_level
            existing_perm.granted_by = current_user.id
            existing_perm.updated_at = now_utc
            applied_permissions.append(existing_perm)
        else:
            new_perm = DocumentPermission(
                document_id=document_id,
                user_id=target_user.id,
                permission_level=item.permission_level,
                granted_by=current_user.id,
                granted_at=now_utc,
                updated_at=now_utc
            )
            db.add(new_perm)
            applied_permissions.append(new_perm)

    # Mark suggestion as resolved
    is_modified = len(approval_in.approved_grants) != len(suggestion.suggested_grants)
    suggestion.status = "modified" if is_modified else "approved"
    suggestion.decision = "approved_with_modifications" if is_modified else "approved"
    suggestion.reviewed_at = now_utc
    suggestion.reviewed_by = current_user.id

    doc.permission_epoch = (doc.permission_epoch or 1) + 1
    db.commit()
    for p in applied_permissions:
        db.refresh(p)

    log_audit_event(
        db=db,
        action="ai.recommendation.approved",
        resource_type="ai_recommendation",
        resource_id=suggestion.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "document_id": document_id,
            "status": suggestion.status,
            "grants_created_or_updated": len(applied_permissions),
            "notes": approval_in.decision_notes
        }
    )

    return [build_permission_response(p) for p in applied_permissions]

@router.post("/documents/{document_id}/ai-recommendations/reject", status_code=status.HTTP_200_OK)
def reject_ai_recommendations(
    document_id: str,
    rejection_in: AIRejectionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Explicit owner rejection of AI recommendations.
    Ensures zero permission changes occur.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.MANAGE_GRANTS, document_id, request_id=request_id)

    suggestion = db.query(AIAccessSuggestion).filter(
        AIAccessSuggestion.id == rejection_in.suggestion_id,
        AIAccessSuggestion.document_id == document_id
    ).first()

    if not suggestion:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI suggestion not found")

    if suggestion.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Suggestion has already been resolved ({suggestion.status})"
        )

    suggestion.status = "rejected"
    suggestion.decision = "rejected"
    suggestion.reviewed_at = datetime.now(timezone.utc)
    suggestion.reviewed_by = current_user.id

    doc.permission_epoch = (doc.permission_epoch or 1) + 1
    db.commit()

    log_audit_event(
        db=db,
        action="ai.recommendation.rejected",
        resource_type="ai_recommendation",
        resource_id=suggestion.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "document_id": document_id,
            "reason": rejection_in.rejection_reason
        }
    )

    return {"status": "rejected", "suggestion_id": suggestion.id}
