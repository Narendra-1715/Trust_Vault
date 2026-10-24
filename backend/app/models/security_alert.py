import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Index, Text, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(50), nullable=False, index=True)  # brute_force_login, repeated_denials, invalid_reference_probe, burst_permission_changes, rapid_session_creation, cross_owner_probe
    severity = Column(String(20), default="medium", nullable=False, index=True)  # low, medium, high, critical
    status = Column(String(20), default="open", nullable=False, index=True)  # open, investigating, resolved
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    actor_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    target_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    target_document_id = Column(String(36), ForeignKey("documents.id", ondelete="SET NULL"), nullable=True, index=True)
    session_id = Column(String(64), nullable=True)
    request_id = Column(String(64), nullable=True)

    summary = Column(String(500), nullable=False)
    investigation_metadata = Column(JSON, nullable=False, default=dict)

    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    actor = relationship("User", foreign_keys=[actor_id])
    target_user = relationship("User", foreign_keys=[target_user_id])
    target_document = relationship("Document", foreign_keys=[target_document_id])
    acknowledger = relationship("User", foreign_keys=[acknowledged_by])
    resolver = relationship("User", foreign_keys=[resolved_by])

    __table_args__ = (
        Index("ix_alert_status_severity", "status", "severity", "timestamp"),
        Index("ix_alert_event_timestamp", "event_type", "timestamp"),
        Index("ix_alert_actor_status", "actor_id", "status"),
    )
