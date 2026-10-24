import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.db.session import Base

class EmergencyAccess(Base):
    """
    Break-Glass Emergency Access Model.
    Records justified, time-limited, reauthenticated emergency access
    granted to an administrator for a private document.
    """
    __tablename__ = "emergency_accesses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    justification = Column(Text, nullable=False)
    status = Column(String(20), default="active", nullable=False)  # active, expired, revoked
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    reviewed_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    review_notes = Column(Text, nullable=True)

    # Relationships
    admin = relationship("User", foreign_keys=[admin_id])
    reviewer = relationship("User", foreign_keys=[reviewed_by])
    document = relationship("Document")

    @property
    def is_currently_active(self) -> bool:
        now_utc = datetime.now(timezone.utc)
        exp = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return self.status == "active" and self.revoked_at is None and exp > now_utc
