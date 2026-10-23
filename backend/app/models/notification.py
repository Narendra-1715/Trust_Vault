import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Index, Text
from sqlalchemy.orm import relationship
from app.db.session import Base

class SecurityNotification(Base):
    __tablename__ = "security_notifications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), default="info", nullable=False)  # info, warning, danger, critical
    event_type = Column(String(100), nullable=False, index=True)
    resource_id = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    read_at = Column(DateTime, nullable=True, index=True)
    is_read = Column(Boolean, default=False, nullable=False, index=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])

    __table_args__ = (
        Index("ix_user_notif_unread", "user_id", "is_read", "created_at"),
    )
