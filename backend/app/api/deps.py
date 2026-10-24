import uuid
from typing import Generator, Optional
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.security import decode_access_token
from app.models.user import User
from app.models.session import UserSession

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

def get_request_id(request: Request) -> str:
    """Extracts or generates unique request correlation ID."""
    req_id = request.headers.get("X-Request-ID")
    if not req_id:
        req_id = str(uuid.uuid4())
    return req_id

def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Validates bearer token and returns current active authenticated user.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not token:
        # Check Authorization header manually as fallback
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            
    if not token:
        raise credentials_exception

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    user_id: str = payload.get("sub")
    if user_id is None:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account"
        )

    # Session validation for tokens with JTI
    jti = payload.get("jti")
    current_session = None
    if jti:
        session = db.query(UserSession).filter(UserSession.session_token_jti == jti).first()
        if not session or session.revoked_at is not None:
            raise credentials_exception

        now_utc = datetime.now(timezone.utc)
        exp = session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at
        if exp < now_utc:
            raise credentials_exception

        current_session = session
        # Touch last_active_at periodically
        last_active = session.last_active_at.replace(tzinfo=timezone.utc) if session.last_active_at.tzinfo is None else session.last_active_at
        if (now_utc - last_active).total_seconds() > 60:
            session.last_active_at = now_utc
            try:
                db.commit()
            except Exception:
                db.rollback()

    request.state.current_session = current_session
    request.state.current_user = user

    # Set PostgreSQL RLS transaction context
    if db.bind and db.bind.dialect.name == "postgresql":
        try:
            from sqlalchemy import text
            db.execute(text("SET LOCAL app.current_user_id = :uid"), {"uid": str(user.id)})
            db.execute(text("SET LOCAL app.current_org_id = :org"), {"org": str(getattr(user, "org_id", "default-org"))})
        except Exception:
            pass

    return user

def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Enforces administrator role requirement.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required"
        )
    return current_user
