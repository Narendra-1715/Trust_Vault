from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import UserResponse, UserUpdate, UserDirectoryItem
from app.api.deps import get_current_user, get_current_admin, get_request_id
from app.audit.service import log_audit_event

router = APIRouter()

@router.get("", response_model=List[UserDirectoryItem])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns minimal directory listing (id, email, display_name, role) for authorized sharing workflows.
    Restricted to document owners and administrators. Ordinary viewers cannot enumerate the organization directory.
    """
    if current_user.role == "viewer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Viewers are not authorized to enumerate organization members."
        )
    users = db.query(User).filter(User.is_active == True).order_by(User.display_name.asc()).all()
    return users

@router.get("/all", response_model=List[UserResponse])
def list_all_users_admin(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """Admin-only endpoint to list all users, including deactivated accounts."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    return users

@router.patch("/{user_id}", response_model=UserResponse)
def update_user_role_status(
    user_id: str,
    update_data: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Admin-only endpoint to modify user role or activation status.
    """
    request_id = get_request_id(request)
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    changes = {}
    if update_data.display_name is not None:
        target_user.display_name = update_data.display_name.strip()
        changes["display_name"] = target_user.display_name
    if update_data.role is not None:
        changes["old_role"] = target_user.role
        target_user.role = update_data.role
        changes["new_role"] = target_user.role
    if update_data.is_active is not None:
        changes["old_active"] = target_user.is_active
        target_user.is_active = update_data.is_active
        changes["new_active"] = target_user.is_active

    db.commit()
    db.refresh(target_user)

    log_audit_event(
        db=db,
        action="admin.user.update",
        resource_type="user",
        resource_id=target_user.id,
        outcome="success",
        actor_id=admin_user.id,
        request_id=request_id,
        metadata={"changes": changes, "target_user_email": target_user.email}
    )

    return target_user
