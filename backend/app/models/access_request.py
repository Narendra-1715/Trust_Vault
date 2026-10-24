import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Index, Text, text
from sqlalchemy.orm import relationship
from app.db.session import Base

class AccessRequest(Base):
    __tablename__ = "access_requests"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    requester_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    reason = Column(String(1000), nullable=False)
    status = Column(String(20), default="pending", nullable=False, index=True)  # pending, approved, rejected, cancelled, expired
    requested_permission = Column(String(20), default="read", nullable=False)  # read, edit
    requested_expiry = Column(DateTime, nullable=True)

    approved_permission = Column(String(20), nullable=True)  # read, edit
    approved_expiry = Column(DateTime, nullable=True)
    rejection_reason = Column(String(500), nullable=True)

    decided_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    document = relationship("Document", foreign_keys=[document_id])
    requester = relationship("User", foreign_keys=[requester_id])
    owner = relationship("User", foreign_keys=[owner_id])
    decider = relationship("User", foreign_keys=[decided_by])

    __table_args__ = (
        Index("ix_access_request_doc_requester", "document_id", "requester_id", "status"),
        Index("ix_access_request_owner_status", "owner_id", "status"),
        Index("ix_access_request_requester_created", "requester_id", "created_at"),
    )
