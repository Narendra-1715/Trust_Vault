from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, ConfigDict

class PermissionGrantRequest(BaseModel):
    user_id: Optional[str] = None
    email: Optional[EmailStr] = None
    permission_level: str = Field(..., pattern="^(read|edit)$")

class PermissionRevokeRequest(BaseModel):
    user_id: str

class PermissionResponse(BaseModel):
    id: str
    document_id: str
    user_id: str
    user_email: str
    user_display_name: str
    permission_level: str
    granted_by: Optional[str]
    granted_by_email: Optional[str] = None
    granted_at: datetime
    updated_at: datetime
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
