import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, LargeBinary, Integer, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.db.session import Base

class DocumentKey(Base):
    __tablename__ = "document_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    version_id = Column(String(36), ForeignKey("document_versions.id", ondelete="CASCADE"), nullable=True, index=True)
    wrapped_dek = Column(LargeBinary, nullable=False)
    kek_id = Column(String(100), nullable=False, index=True)
    algorithm = Column(String(50), default="AES-256-GCM", nullable=False)
    chunk_size = Column(Integer, default=65536, nullable=False)  # 64 KiB
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    rotated_at = Column(DateTime, nullable=True)

    # Relationships
    document = relationship("Document", foreign_keys=[document_id])
    version = relationship("DocumentVersion", foreign_keys=[version_id])
