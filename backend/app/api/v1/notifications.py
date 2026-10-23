from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.user import User
from app.models.notification import SecurityNotification
from app.schemas.notification import (
    NotificationResponse, 
    UnreadCountResponse, 
    MarkAllReadResponse
)
from app.api.deps import get_current_user

router = APIRouter()

@router.get("", response_model=List[NotificationResponse])
def list_notifications(
    unread_only: bool = Query(False, description="Filter for unread notifications only"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns security activity alerts and permission notifications for the authenticated user.
    """
    query = db.query(SecurityNotification).filter(
        SecurityNotification.user_id == current_user.id
    )

    if unread_only:
        query = query.filter(SecurityNotification.is_read.is_(False))

    notifications = query.order_by(SecurityNotification.created_at.desc()).offset(offset).limit(limit).all()
    return notifications

@router.get("/unread-count", response_model=UnreadCountResponse)
def get_unread_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns the count of unread notifications for notification badges.
    """
    count = db.query(SecurityNotification).filter(
        SecurityNotification.user_id == current_user.id,
        SecurityNotification.is_read.is_(False)
    ).count()

    return UnreadCountResponse(unread_count=count)

@router.patch("/{notification_id}/read", response_model=NotificationResponse)
def mark_notification_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Marks a specific security notification as read.
    """
    notif = db.query(SecurityNotification).filter(
        SecurityNotification.id == notification_id,
        SecurityNotification.user_id == current_user.id
    ).first()

    if not notif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found"
        )

    if not notif.is_read:
        notif.is_read = True
        notif.read_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(notif)

    return notif

@router.post("/mark-all-read", response_model=MarkAllReadResponse)
def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Marks all unread notifications for the current user as read in bulk.
    """
    now = datetime.now(timezone.utc)
    unread_notifs = db.query(SecurityNotification).filter(
        SecurityNotification.user_id == current_user.id,
        SecurityNotification.is_read.is_(False)
    ).all()

    marked_count = len(unread_notifs)
    for n in unread_notifs:
        n.is_read = True
        n.read_at = now

    db.commit()

    return MarkAllReadResponse(
        message=f"Marked {marked_count} notification(s) as read.",
        marked_count=marked_count
    )
