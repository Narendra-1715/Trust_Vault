from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict

class RequestLinkCreate(BaseModel):
    name: Optional[str] = Field(None, max_length=100, description="Optional label for the link")
    expires_at: Optional[datetime] = Field(None, description="Expiration date for the link")
    max_uses: Optional[int] = Field(None, ge=1, le=1000, description="Optional maximum number of requests allowed")

class RequestLinkCreatedResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    document_id: str
    document_title: str
    token: str
    token_prefix: str
    name: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime
    max_uses: Optional[int] = None
    use_count: int = 0

class RequestLinkListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    document_id: str
    token_prefix: str
    name: Optional[str] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    created_at: datetime
    use_count: int
    max_uses: Optional[int] = None
    status: str  # active, revoked, expired

class RequestLinkResolved(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    token_prefix: str
    document_title: str
    category: str
    owner_name: Optional[str] = None
    owner_email: str
    link_name: Optional[str] = None
    expires_at: Optional[datetime] = None
    has_active_access: bool
    has_pending_request: bool
    pending_request_id: Optional[str] = None

class RequestLinkSubmit(BaseModel):
    reason: str = Field(..., min_length=5, max_length=1000, description="Business justification for requesting access")
    requested_permission: str = Field("read", description="Requested access level: 'read' or 'edit'")
    requested_expiry: Optional[datetime] = Field(None, description="Requested access expiration timestamp")
