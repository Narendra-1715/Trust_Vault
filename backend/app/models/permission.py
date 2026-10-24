import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Index, UniqueConstraint, Integer
from sqlalchemy.orm import relationship
from app.db.session import Base

class DocumentPermission(Base):
    __tablename__ = "document_permissions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    permission_level = Column(String(20), nullable=False)  # "read" or "edit"
    min_version_number = Column(Integer, nullable=True)
    max_version_number = Column(Integer, nullable=True)
    granted_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    granted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    revoked_at = Column(DateTime, nullable=True, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)

    # Relationships
    document = relationship("Document", back_populates="permissions")
    user = relationship("User", foreign_keys=[user_id], back_populates="permissions_received")
    granter = relationship("User", foreign_keys=[granted_by], back_populates="permissions_granted")

    __table_args__ = (
        Index("ix_doc_user_revoked", "document_id", "user_id", "revoked_at"),
        Index("ix_doc_user_revoked_expires", "document_id", "user_id", "revoked_at", "expires_at"),
    )
