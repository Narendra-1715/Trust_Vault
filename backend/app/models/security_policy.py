import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, Integer, DateTime
from app.db.session import Base

VALID_CLASSIFICATIONS = ["Internal", "Confidential", "Highly Restricted"]

DEFAULT_POLICIES = {
    "Internal": {
        "allow_download": True,
        "allow_sharing": True,
        "max_grant_duration_days": None,
        "require_mfa": False,
        "elevated_classification_change": False,
    },
    "Confidential": {
        "allow_download": True,
        "allow_sharing": True,
        "max_grant_duration_days": 90,
        "require_mfa": False,
        "elevated_classification_change": False,
    },
    "Highly Restricted": {
        "allow_download": False,
        "allow_sharing": True,
        "max_grant_duration_days": 7,
        "require_mfa": True,
        "elevated_classification_change": True,
    },
}

class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    classification = Column(String(50), nullable=False, unique=True, index=True)
    allow_download = Column(Boolean, nullable=False, default=True)
    allow_sharing = Column(Boolean, nullable=False, default=True)
    max_grant_duration_days = Column(Integer, nullable=True)
    require_mfa = Column(Boolean, nullable=False, default=False)
    elevated_classification_change = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
