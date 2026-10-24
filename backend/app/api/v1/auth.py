import uuid
from datetime import datetime, timedelta, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.config import settings
from app.core.security import verify_password, hash_password, create_access_token
from app.core.rate_limit import login_limiter, check_rate_limit
from app.core.user_agent import parse_device_info
from app.models.user import User
from app.models.session import UserSession
from app.schemas.user import UserCreate, UserResponse, LoginRequest, TokenResponse
from app.schemas.session import SessionResponse, RevokeAllResponse
from app.api.deps import get_current_user, get_request_id
from app.audit.service import log_audit_event
from app.notifications.service import create_security_notification
from app.services.detection import detect_failed_logins, detect_rapid_sessions

router = APIRouter()

@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    credentials: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticates user with Argon2id and issues short-lived JWT token.
    Rate limited against brute-force attacks.
    """
    request_id = get_request_id(request)
    check_rate_limit(request, login_limiter, key_prefix="login")

    # Determine client IP and User Agent early for security detection
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    user_agent = request.headers.get("user-agent", "Unknown")
    device_info = parse_device_info(user_agent)

    # Normalize email to lowercase
    normalized_email = credentials.email.strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()

    if not user or not verify_password(credentials.password, user.password_hash):
        log_audit_event(
            db=db,
            action="auth.login.failed",
            resource_type="auth",
            resource_id=normalized_email,
            outcome="denied",
            actor_id=user.id if user else None,
            request_id=request_id,
            metadata={"email": normalized_email, "ip_address": client_ip, "reason": "Invalid credentials"}
        )
        # Check brute force threshold
        detect_failed_logins(db=db, email=normalized_email, ip_address=client_ip, request_id=request_id)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        log_audit_event(
            db=db,
            action="auth.login.disabled",
            resource_type="auth",
            resource_id=normalized_email,
            outcome="denied",
            actor_id=user.id,
            request_id=request_id,
            metadata={"email": normalized_email, "reason": "Account disabled"}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled. Contact system administrator."
        )

    # Generate unique session identifier JTI
    jti = str(uuid.uuid4())
    session_ver = getattr(user, "session_version", 1) or 1
    access_token = create_access_token(
        subject=user.id,
        role=user.role,
        jti=jti,
        session_version=session_ver
    )

    # Determine client IP and User Agent
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    user_agent = request.headers.get("user-agent", "Unknown")
    device_info = parse_device_info(user_agent)
    now_utc = datetime.now(timezone.utc)
    session_expire = now_utc + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Persist active session
    new_session = UserSession(
        user_id=user.id,
        session_token_jti=jti,
        session_version=session_ver,
        ip_address=client_ip,
        user_agent=user_agent[:500],
        device_info=device_info,
        created_at=now_utc,
        last_active_at=now_utc,
        expires_at=session_expire,
        revoked_at=None
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    log_audit_event(
        db=db,
        action="session.created",
        resource_type="session",
        resource_id=new_session.id,
        outcome="success",
        actor_id=user.id,
        request_id=request_id,
        metadata={"ip_address": client_ip, "device_info": device_info, "role": user.role}
    )

    log_audit_event(
        db=db,
        action="auth.login.success",
        resource_type="auth",
        resource_id=user.id,
        outcome="success",
        actor_id=user.id,
        request_id=request_id,
        metadata={"role": user.role, "session_id": new_session.id}
    )

    create_security_notification(
        db=db,
        user_id=user.id,
        title="New Login Session",
        message=f"New session established on {device_info} from IP {client_ip}.",
        severity="info",
        event_type="session.created",
        resource_id=new_session.id
    )

    detect_rapid_sessions(db=db, actor_id=user.id, ip_address=client_ip, request_id=request_id)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role
    )

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    request: Request,
    user_in: UserCreate,
    db: Session = Depends(get_db)
):
    """
    Registers a new user account.
    """
    request_id = get_request_id(request)
    normalized_email = user_in.email.strip().lower()

    existing = db.query(User).filter(User.email == normalized_email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )

    if user_in.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-registration as administrator is not permitted. Administrative accounts must be provisioned."
        )

    new_user = User(
        email=normalized_email,
        password_hash=hash_password(user_in.password),
        display_name=user_in.display_name.strip(),
        role=user_in.role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db=db,
        action="auth.register",
        resource_type="user",
        resource_id=new_user.id,
        outcome="success",
        actor_id=new_user.id,
        request_id=request_id,
        metadata={"email": normalized_email, "role": new_user.role}
    )

    return new_user

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Returns profile of currently authenticated user."""
    return current_user

@router.get("/sessions", response_model=List[SessionResponse])
def list_user_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists all active and recent login sessions for the currently authenticated user.
    """
    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id
    ).order_by(UserSession.last_active_at.desc()).all()

    current_session = getattr(request.state, "current_session", None)
    current_session_id = current_session.id if current_session else None
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
                is_current=(s.id == current_session_id),
                is_active=is_active
            )
        )
    return results

@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_single_session(
    session_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revokes a specific session belonging to the currently authenticated user.
    Subsequent requests using this session token are immediately rejected.
    """
    session = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == current_user.id
    ).first()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

    if session.revoked_at is None:
        now_utc = datetime.now(timezone.utc)
        session.revoked_at = now_utc
        session.session_version = (session.session_version or 1) + 1
        db.commit()

        request_id = get_request_id(request)
        current_session = getattr(request.state, "current_session", None)
        is_current = current_session and (current_session.id == session.id)

        log_audit_event(
            db=db,
            action="session.revoked",
            resource_type="session",
            resource_id=session.id,
            outcome="success",
            actor_id=current_user.id,
            request_id=request_id,
            metadata={
                "ip_address": session.ip_address,
                "device_info": session.device_info,
                "is_current_session": bool(is_current)
            }
        )

        create_security_notification(
            db=db,
            user_id=current_user.id,
            title="Session Revoked",
            message=f"Login session on {session.device_info or 'device'} was terminated.",
            severity="warning",
            event_type="session.revoked",
            resource_id=session.id
        )

    return None

@router.delete("/sessions", response_model=RevokeAllResponse)
def revoke_other_sessions(
    request: Request,
    exclude_current: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revokes all active sessions for the user, with option to preserve the current session.
    """
    current_session = getattr(request.state, "current_session", None)
    current_session_id = current_session.id if current_session else None

    query = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None)
    )

    if exclude_current and current_session_id:
        query = query.filter(UserSession.id != current_session_id)

    sessions_to_revoke = query.all()
    now_utc = datetime.now(timezone.utc)
    revoked_count = len(sessions_to_revoke)

    for s in sessions_to_revoke:
        s.revoked_at = now_utc
        s.session_version = (s.session_version or 1) + 1

    if not exclude_current:
        current_user.session_version = (current_user.session_version or 1) + 1

    db.commit()

    request_id = get_request_id(request)
    log_audit_event(
        db=db,
        action="session.revoked_all",
        resource_type="session",
        resource_id=current_user.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "revoked_count": revoked_count,
            "excluded_current": bool(exclude_current and current_session_id)
        }
    )

    if revoked_count > 0:
        create_security_notification(
            db=db,
            user_id=current_user.id,
            title="Remote Sessions Revoked",
            message=f"Terminated {revoked_count} active remote login session(s).",
            severity="warning",
            event_type="session.revoked_all"
        )

    return RevokeAllResponse(
        message=f"Successfully revoked {revoked_count} active session(s).",
        revoked_count=revoked_count
    )
