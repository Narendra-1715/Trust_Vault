import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.db.session import Base

class AccessReview(Base):
    __tablename__ = "access_reviews"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    permission_id = Column(String(36), ForeignKey("document_permissions.id", ondelete="CASCADE"), nullable=False, index=True)
    reviewer_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="pending", index=True)  # "pending", "retained", "revoked"
    due_date = Column(DateTime, nullable=False, index=True)
    decision = Column(String(20), nullable=True)  # "retain", "revoke"
    decided_at = Column(DateTime, nullable=True)
    decision_notes = Column(Text, nullable=True)
    next_review_due = Column(DateTime, nullable=True)
    reminder_sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    document = relationship("Document")
    permission = relationship("DocumentPermission")
    reviewer = relationship("User", foreign_keys=[reviewer_id])

    __table_args__ = (
        Index("ix_access_reviews_reviewer_status", "reviewer_id", "status"),
        Index("ix_access_reviews_perm_status", "permission_id", "status"),
    )
