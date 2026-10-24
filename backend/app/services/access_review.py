import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from fastapi import HTTPException, status

from app.models.access_review import AccessReview
from app.models.permission import DocumentPermission
from app.models.document import Document
from app.models.user import User
from app.schemas.access_review import AccessReviewResponse
from app.audit.service import log_audit_event
from app.notifications.service import create_security_notification

logger = logging.getLogger(__name__)

DEFAULT_REVIEW_INTERVAL_DAYS = 30
DEFAULT_DUE_WINDOW_DAYS = 7

def build_access_review_response(review: AccessReview) -> AccessReviewResponse:
    doc = review.document
    perm = review.permission
    grantee = perm.user if perm else None
    reviewer = review.reviewer

    now_utc = datetime.now(timezone.utc)
    due_utc = review.due_date if review.due_date.tzinfo else review.due_date.replace(tzinfo=timezone.utc)
    is_overdue = review.status == "pending" and due_utc < now_utc

    return AccessReviewResponse(
        id=review.id,
        document_id=review.document_id,
        document_title=doc.title if doc else "Unknown Document",
        permission_id=review.permission_id,
        grantee_id=perm.user_id if perm else "",
        grantee_email=grantee.email if grantee else "",
        grantee_name=grantee.display_name if grantee else "",
        permission_level=perm.permission_level if perm else "read",
        grant_created_at=perm.granted_at if perm else review.created_at,
        grant_expires_at=perm.expires_at if perm else None,
        reviewer_id=review.reviewer_id,
        reviewer_email=reviewer.email if reviewer else None,
        status=review.status,
        due_date=review.due_date,
        is_overdue=is_overdue,
        decision=review.decision,
        decided_at=review.decided_at,
        decision_notes=review.decision_notes,
        next_review_due=review.next_review_due,
        created_at=review.created_at
    )

def generate_pending_access_reviews(
    db: Session,
    interval_days: int = DEFAULT_REVIEW_INTERVAL_DAYS,
    force_all_active: bool = False
) -> int:
    """
    Identifies eligible active grants due for review and generates review records.
    - Idempotent and safe to retry without creating duplicates.
    - Excludes revoked and expired permissions.
    - Notifies the document owner via notifications service.
    - Notification failures never corrupt grant or review creation.
    """
    now_utc = datetime.now(timezone.utc)

    # 1. Query candidate active permissions
    active_perms = (
        db.query(DocumentPermission)
        .join(Document, Document.id == DocumentPermission.document_id)
        .filter(
            Document.deleted_at.is_(None),
            DocumentPermission.revoked_at.is_(None),
            or_(
                DocumentPermission.expires_at.is_(None),
                DocumentPermission.expires_at > now_utc
            )
        )
        .all()
    )

    created_count = 0
    cutoff_date = now_utc - timedelta(days=interval_days)

    for perm in active_perms:
        doc = perm.document
        if not doc:
            continue

        # Check if a pending review already exists for this permission (prevents duplicate review floods)
        existing_pending = (
            db.query(AccessReview)
            .filter(
                AccessReview.permission_id == perm.id,
                AccessReview.status == "pending"
            )
            .first()
        )
        if existing_pending:
            continue

        # Check latest completed review for this permission
        latest_completed = (
            db.query(AccessReview)
            .filter(
                AccessReview.permission_id == perm.id,
                AccessReview.status.in_(["retained", "revoked"])
            )
            .order_by(AccessReview.decided_at.desc())
            .first()
        )

        should_create = False
        if force_all_active:
            should_create = True
        elif latest_completed:
            decided_time = latest_completed.decided_at
            if decided_time:
                decided_utc = decided_time if decided_time.tzinfo else decided_time.replace(tzinfo=timezone.utc)
                if decided_utc <= cutoff_date:
                    should_create = True
        else:
            # First review: check grant date
            grant_time = perm.granted_at
            grant_utc = grant_time if grant_time.tzinfo else grant_time.replace(tzinfo=timezone.utc)
            if grant_utc <= cutoff_date:
                should_create = True

        if should_create:
            new_review = AccessReview(
                id=str(uuid.uuid4()),
                document_id=doc.id,
                permission_id=perm.id,
                reviewer_id=doc.owner_id,
                status="pending",
                due_date=now_utc + timedelta(days=DEFAULT_DUE_WINDOW_DAYS),
                created_at=now_utc
            )
            db.add(new_review)
            created_count += 1

            # Dispatch notification to document owner
            try:
                grantee_label = perm.user.email if perm.user else "User"
                create_security_notification(
                    db=db,
                    user_id=doc.owner_id,
                    title="Periodic Access Review Due",
                    message=f"Access grant for '{grantee_label}' on document '{doc.title}' is due for periodic access review.",
                    severity="medium",
                    event_type="access_review.due",
                    resource_id=doc.id
                )
                new_review.reminder_sent_at = now_utc
            except Exception as e:
                # Reminder delivery failure must never corrupt review or grant state
                logger.warning(f"Failed to deliver access review notification: {e}")

    db.commit()
    return created_count

def process_access_review_decision(
    db: Session,
    review_id: str,
    reviewer: User,
    decision: str,
    decision_notes: Optional[str] = None,
    request_id: Optional[str] = None
) -> AccessReview:
    """
    Records owner's decision to retain or revoke an access grant:
    - Validates reviewer identity (owner of document or system admin).
    - Prevents concurrent conflicting decisions on non-pending reviews.
    - 'retain': confirms continued access, does NOT expand permissions or extend expiry.
    - 'revoke': invokes immediate grant revocation on the permission.
    - Records immutable audit trail.
    """
    review = db.query(AccessReview).filter(AccessReview.id == review_id).first()
    if not review:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access review record not found.")

    if review.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"This review has already been decided as '{review.status}' on {review.decided_at}."
        )

    doc = review.document
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Associated document not found.")

    # Authorization rule: only document owner or admin can review
    is_owner = doc.owner_id == reviewer.id
    is_admin = reviewer.role == "admin"
    if not (is_owner or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to review access grants for this document."
        )

    perm = review.permission
    if not perm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Associated permission grant not found.")

    now_utc = datetime.now(timezone.utc)
    decision_clean = decision.strip().lower()

    if decision_clean == "retain":
        review.status = "retained"
        review.decision = "retain"
        review.decided_at = now_utc
        review.decision_notes = decision_notes.strip() if decision_notes else None
        review.next_review_due = now_utc + timedelta(days=DEFAULT_REVIEW_INTERVAL_DAYS)

        log_audit_event(
            db=db,
            action="access_review.retain",
            resource_type="document",
            resource_id=doc.id,
            outcome="success",
            actor_id=reviewer.id,
            request_id=request_id,
            metadata={
                "review_id": review.id,
                "grantee_id": perm.user_id,
                "permission_level": perm.permission_level,
                "decision_notes": decision_notes,
                "next_review_due": review.next_review_due.isoformat()
            }
        )

    elif decision_clean == "revoke":
        review.status = "revoked"
        review.decision = "revoke"
        review.decided_at = now_utc
        review.decision_notes = decision_notes.strip() if decision_notes else None

        # Revoke the permission grant immediately
        perm.revoked_at = now_utc

        log_audit_event(
            db=db,
            action="access_review.revoke",
            resource_type="document",
            resource_id=doc.id,
            outcome="success",
            actor_id=reviewer.id,
            request_id=request_id,
            metadata={
                "review_id": review.id,
                "grantee_id": perm.user_id,
                "permission_level": perm.permission_level,
                "decision_notes": decision_notes
            }
        )
        log_audit_event(
            db=db,
            action="permission.revoke",
            resource_type="document",
            resource_id=doc.id,
            outcome="success",
            actor_id=reviewer.id,
            request_id=request_id,
            metadata={
                "target_user_id": perm.user_id,
                "permission_level": perm.permission_level,
                "source": "access_review"
            }
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision '{decision}'. Must be 'retain' or 'revoke'."
        )

    db.commit()
    db.refresh(review)
    return review
