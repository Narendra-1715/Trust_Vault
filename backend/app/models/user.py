import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.db.session import Base

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    display_name = Column(String(100), nullable=False)
    role = Column(String(30), nullable=False, default="owner")  # admin, owner, viewer
    is_active = Column(Boolean, default=True, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    owned_documents = relationship("Document", back_populates="owner", cascade="all, delete-orphan", foreign_keys="Document.owner_id")
    permissions_received = relationship("DocumentPermission", back_populates="user", foreign_keys="DocumentPermission.user_id")
    permissions_granted = relationship("DocumentPermission", back_populates="granter", foreign_keys="DocumentPermission.granted_by")
    audit_events = relationship("AuditEvent", back_populates="actor")
