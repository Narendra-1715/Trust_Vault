from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_info: Optional[str] = None
    created_at: datetime
    last_active_at: datetime
    expires_at: datetime
    is_current: bool = False
    is_active: bool = True

class RevokeAllResponse(BaseModel):
    message: str
    revoked_count: int
