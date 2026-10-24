from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.access_review import AccessReview
from app.schemas.access_review import (
    AccessReviewResponse,
    AccessReviewListResponse,
    AccessReviewDecisionRequest
)
from app.api.deps import get_current_user, get_request_id
from app.services.access_review import (
    build_access_review_response,
    generate_pending_access_reviews,
    process_access_review_decision
)

router = APIRouter()

@router.get("", response_model=AccessReviewListResponse)
def list_access_reviews(
    status_filter: Optional[str] = Query(None, description="Filter by status: pending, retained, revoked"),
    document_id: Optional[str] = Query(None, description="Filter by document ID"),
    all_org: bool = Query(False, description="Admin organizational view"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List access reviews requiring decision or historical review records.
    - Owners see reviews for their own documents.
    - Administrators can inspect all reviews.
    """
    query = db.query(AccessReview)

    if all_org and current_user.role == "admin":
        pass
    else:
        query = query.filter(AccessReview.reviewer_id == current_user.id)

    if document_id:
        query = query.filter(AccessReview.document_id == document_id)

    if status_filter and status_filter.strip():
        query = query.filter(AccessReview.status == status_filter.strip().lower())

    reviews = query.order_by(AccessReview.due_date.asc(), AccessReview.created_at.desc()).all()

    now_utc = datetime.now(timezone.utc)
    review_responses = [build_access_review_response(r) for r in reviews]

    pending_count = sum(1 for r in review_responses if r.status == "pending")
    overdue_count = sum(1 for r in review_responses if r.is_overdue)

    return AccessReviewListResponse(
        total=len(review_responses),
        pending_count=pending_count,
        overdue_count=overdue_count,
        reviews=review_responses
    )

@router.post("/generate")
def trigger_access_reviews(
    force_all_active: bool = Query(False, description="Generate reviews for all active grants immediately"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers periodic access review generation for active grants.
    Idempotent job execution.
    """
    count = generate_pending_access_reviews(db, force_all_active=force_all_active)
    return {"message": "Access reviews generated successfully", "created_count": count}

@router.post("/{review_id}/decision", response_model=AccessReviewResponse)
def submit_access_review_decision(
    review_id: str,
    decision_in: AccessReviewDecisionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Record an owner's decision to retain or revoke an access grant.
    - Only document owners or administrators can review.
    - Revoking immediately applies server-side permission revocation.
    """
    request_id = get_request_id(request)
    review = process_access_review_decision(
        db=db,
        review_id=review_id,
        reviewer=current_user,
        decision=decision_in.decision,
        decision_notes=decision_in.decision_notes,
        request_id=request_id
    )
    return build_access_review_response(review)
