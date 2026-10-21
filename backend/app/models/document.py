import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, BigInteger, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.db.session import Base

class Document(Base):
    __tablename__ = "documents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    original_filename = Column(String(255), nullable=False)
    internal_storage_key = Column(String(255), nullable=False, unique=True)
    detected_media_type = Column(String(100), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    checksum = Column(String(64), nullable=False)  # SHA-256
    category = Column(String(50), nullable=False, default="General", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    deleted_at = Column(DateTime, nullable=True, index=True)

    # Relationships
    owner = relationship("User", back_populates="owned_documents", foreign_keys=[owner_id])
    permissions = relationship("DocumentPermission", back_populates="document", cascade="all, delete-orphan")
    ai_suggestions = relationship("AIAccessSuggestion", back_populates="document", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_documents_owner_deleted", "owner_id", "deleted_at"),
        Index("ix_documents_category_deleted", "category", "deleted_at"),
    )
