from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime
from app.db.session import Base

class SystemSetting(Base):
    """
    Configurable system-level security and operational settings.
    """
    __tablename__ = "system_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    updated_by = Column(String(36), nullable=True)
