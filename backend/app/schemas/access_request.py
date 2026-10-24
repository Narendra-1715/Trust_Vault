from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict

class AccessRequestCreate(BaseModel):
    document_id: str = Field(..., description="Target document ID")
    reason: str = Field(..., min_length=5, max_length=1000, description="Business justification for requesting access")
    requested_permission: str = Field("read", description="Requested access level: 'read' or 'edit'")
    requested_expiry: Optional[datetime] = Field(None, description="Requested access expiration timestamp")

class AccessRequestApprove(BaseModel):
    approved_permission: str = Field("read", description="Owner-approved access level: 'read' or 'edit'")
    approved_expiry: Optional[datetime] = Field(None, description="Owner-approved access expiration timestamp")

class AccessRequestReject(BaseModel):
    rejection_reason: Optional[str] = Field(None, max_length=500, description="Optional explanation for rejecting request")

class AccessRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    document_id: str
    document_title: Optional[str] = None
    requester_id: str
    requester_email: Optional[str] = None
    requester_name: Optional[str] = None
    owner_id: str
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    reason: str
    status: str  # pending, approved, rejected, cancelled, expired
    requested_permission: str
    requested_expiry: Optional[datetime] = None
    approved_permission: Optional[str] = None
    approved_expiry: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    decided_by: Optional[str] = None
    decided_by_name: Optional[str] = None
    decided_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

class AccessRequestStatusCheck(BaseModel):
    has_pending_request: bool
    request_id: Optional[str] = None
    created_at: Optional[datetime] = None
    requested_permission: Optional[str] = None
    requested_expiry: Optional[datetime] = None
