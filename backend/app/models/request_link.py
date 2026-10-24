import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Index, Integer
from sqlalchemy.orm import relationship
from app.db.session import Base

class DocumentRequestLink(Base):
    __tablename__ = "document_request_links"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    token_prefix = Column(String(10), nullable=False)
    name = Column(String(100), nullable=True)

    expires_at = Column(DateTime, nullable=True, index=True)
    revoked_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    use_count = Column(Integer, default=0, nullable=False)
    max_uses = Column(Integer, nullable=True)

    # Relationships
    document = relationship("Document", foreign_keys=[document_id])
    owner = relationship("User", foreign_keys=[owner_id])
    creator = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        Index("ix_request_link_doc_status", "document_id", "revoked_at", "expires_at"),
        Index("ix_request_link_owner_created", "owner_id", "created_at"),
    )
