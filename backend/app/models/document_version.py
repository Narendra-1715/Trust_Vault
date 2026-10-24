import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, BigInteger, Integer, DateTime, ForeignKey, Index, Boolean
from sqlalchemy.orm import relationship
from app.db.session import Base

class DocumentVersion(Base):
    __tablename__ = "document_versions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    storage_key = Column(String(255), nullable=False, unique=True)
    original_filename = Column(String(255), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    checksum = Column(String(64), nullable=False)  # SHA-256
    detected_media_type = Column(String(100), nullable=False)
    change_summary = Column(Text, nullable=True)
    uploaded_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    is_current = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    document = relationship("Document", back_populates="versions")
    uploader = relationship("User", foreign_keys=[uploaded_by])

    __table_args__ = (
        Index("ix_doc_versions_doc_ver", "document_id", "version_number", unique=True),
        Index("ix_doc_versions_doc_current", "document_id", "is_current"),
    )
