from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.security import verify_password, hash_password, create_access_token
from app.core.rate_limit import login_limiter, check_rate_limit
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, LoginRequest, TokenResponse
from app.api.deps import get_current_user, get_request_id
from app.audit.service import log_audit_event

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
            metadata={"email": normalized_email, "reason": "Invalid credentials"}
        )
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

    access_token = create_access_token(subject=user.id, role=user.role)

    log_audit_event(
        db=db,
        action="auth.login.success",
        resource_type="auth",
        resource_id=user.id,
        outcome="success",
        actor_id=user.id,
        request_id=request_id,
        metadata={"role": user.role}
    )

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
