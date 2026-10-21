import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Index, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base

class AIAccessSuggestion(Base):
    __tablename__ = "ai_access_suggestions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    requester_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    suggested_grants = Column(JSON, nullable=False)  # List of {user_id, email, permission_level, confidence}
    explanation = Column(Text, nullable=False)
    provider_model = Column(String(100), nullable=False)
    status = Column(String(30), default="pending", nullable=False, index=True) # pending, approved, rejected, modified
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    reviewed_at = Column(DateTime, nullable=True)
    reviewed_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decision = Column(String(50), nullable=True)

    # Relationships
    document = relationship("Document", back_populates="ai_suggestions")
    requester = relationship("User", foreign_keys=[requester_id])
    reviewer = relationship("User", foreign_keys=[reviewed_by])
