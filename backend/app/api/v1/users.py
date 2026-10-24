from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.session import get_db
from app.models.user import User
from app.models.session import UserSession
from app.schemas.user import UserResponse, UserUpdate, UserDirectoryItem
from app.schemas.admin import AdminUserCreateRequest, AdminUserDetailResponse
from app.schemas.session import SessionResponse
from app.api.deps import get_current_user, get_current_admin, get_request_id
from app.audit.service import log_audit_event
from app.core.security import hash_password

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

@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user_admin(
    user_in: AdminUserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Admin-only endpoint to provision new user accounts with specific roles.
    """
    request_id = get_request_id(request)
    normalized_email = user_in.email.strip().lower()

    existing = db.query(User).filter(User.email == normalized_email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )

    new_user = User(
        email=normalized_email,
        password_hash=hash_password(user_in.password),
        display_name=user_in.display_name.strip(),
        role=user_in.role,
        is_active=user_in.is_active,
        mfa_enabled=user_in.mfa_enabled
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db=db,
        action="admin.user.create",
        resource_type="user",
        resource_id=new_user.id,
        outcome="success",
        actor_id=admin_user.id,
        request_id=request_id,
        metadata={"email": normalized_email, "role": new_user.role, "is_active": new_user.is_active}
    )

    return new_user

@router.get("/{user_id}", response_model=AdminUserDetailResponse)
def get_user_detail_admin(
    user_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Admin-only endpoint to inspect detailed account status and security-related user metadata.
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    now_utc = datetime.now(timezone.utc)
    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == target_user.id,
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > now_utc
    ).all()

    latest_session = db.query(UserSession).filter(
        UserSession.user_id == target_user.id
    ).order_by(desc(UserSession.last_active_at)).first()

    return AdminUserDetailResponse(
        id=target_user.id,
        email=target_user.email,
        display_name=target_user.display_name,
        role=target_user.role,
        is_active=target_user.is_active,
        mfa_enabled=getattr(target_user, "mfa_enabled", False),
        created_at=target_user.created_at,
        updated_at=target_user.updated_at,
        active_sessions_count=len(active_sessions),
        last_active_at=latest_session.last_active_at if latest_session else None
    )

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
    Protected against removing or demoting the last usable administrative account.
    """
    request_id = get_request_id(request)
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # SAFEGUARD: Do not allow an administrator to accidentally remove the last usable administrative account.
    is_demoting_admin = update_data.role is not None and update_data.role != "admin"
    is_disabling_admin = update_data.is_active is False
    if target_user.role == "admin" and target_user.is_active:
        if is_demoting_admin or is_disabling_admin:
            active_admin_count = db.query(User).filter(User.role == "admin", User.is_active == True).count()
            if active_admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot disable or demote the last usable administrative account."
                )

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

# ================= USER SESSION MANAGEMENT (ADMIN) =================

@router.get("/{user_id}/sessions", response_model=List[SessionResponse])
def list_user_sessions_admin(
    user_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Admin-only endpoint to inspect active and recent login sessions for any user.
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    sessions = db.query(UserSession).filter(
        UserSession.user_id == target_user.id
    ).order_by(desc(UserSession.last_active_at)).all()

    now_utc = datetime.now(timezone.utc)
    results = []
    for s in sessions:
        exp = s.expires_at.replace(tzinfo=timezone.utc) if s.expires_at.tzinfo is None else s.expires_at
        is_active = (s.revoked_at is None) and (exp > now_utc)
        results.append(
            SessionResponse(
                id=s.id,
                user_id=s.user_id,
                ip_address=s.ip_address,
                user_agent=s.user_agent,
                device_info=s.device_info,
                created_at=s.created_at,
                last_active_at=s.last_active_at,
                expires_at=s.expires_at,
                is_current=False,
                is_active=is_active
            )
        )
    return results

@router.delete("/{user_id}/sessions", status_code=status.HTTP_200_OK)
def revoke_all_user_sessions_admin(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Admin-only endpoint to revoke all active sessions for a user.
    """
    request_id = get_request_id(request)
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    now_utc = datetime.now(timezone.utc)
    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == target_user.id,
        UserSession.revoked_at.is_(None)
    ).all()

    revoked_count = len(active_sessions)
    for s in active_sessions:
        s.revoked_at = now_utc
        s.session_version = (s.session_version or 1) + 1
    target_user.session_version = (target_user.session_version or 1) + 1
    db.commit()

    log_audit_event(
        db=db,
        action="admin.sessions.revoke_all",
        resource_type="user",
        resource_id=target_user.id,
        outcome="success",
        actor_id=admin_user.id,
        request_id=request_id,
        metadata={"target_user_email": target_user.email, "revoked_sessions_count": revoked_count}
    )

    return {"message": f"Successfully revoked {revoked_count} active sessions for {target_user.email}", "revoked_count": revoked_count}

@router.delete("/{user_id}/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_single_user_session_admin(
    user_id: str,
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_current_admin)
):
    """
    Admin-only endpoint to revoke a specific active user session.
    """
    request_id = get_request_id(request)
    session = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == user_id
    ).first()

    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    if session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        session.session_version = (session.session_version or 1) + 1
        db.commit()

        log_audit_event(
            db=db,
            action="admin.session.revoke",
            resource_type="session",
            resource_id=session.id,
            outcome="success",
            actor_id=admin_user.id,
            request_id=request_id,
            metadata={"target_user_id": user_id}
        )
