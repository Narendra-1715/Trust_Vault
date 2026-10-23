from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    title: str
    message: str
    severity: str
    event_type: str
    resource_id: Optional[str] = None
    created_at: datetime
    read_at: Optional[datetime] = None
    is_read: bool

class UnreadCountResponse(BaseModel):
    unread_count: int

class MarkAllReadResponse(BaseModel):
    message: str
    marked_count: int
