from datetime import datetime, timedelta, timezone
from typing import Any, Union, Optional
import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from app.core.config import settings

# Initialize Argon2id password hasher with secure parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    type=Type.ID
)

def hash_password(password: str) -> str:
    """Hashes a password using Argon2id."""
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against an Argon2id hash."""
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

def create_access_token(
    subject: Union[str, Any],
    role: str,
    expires_delta: Optional[timedelta] = None,
    jti: Optional[str] = None,
    session_version: Optional[int] = None
) -> str:
    """Generates a signed JWT access token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "sub": str(subject),
        "role": role,
        "iat": now,
        "exp": expire,
    }
    if jti:
        to_encode["jti"] = str(jti)
    if session_version is not None:
        to_encode["session_version"] = int(session_version)
        
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    """Decodes and validates a JWT access token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except (jwt.PyJWTError, Exception):
        return None
