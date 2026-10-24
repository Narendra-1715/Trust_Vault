from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict

class SecurityAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: str
    severity: str
    status: str
    timestamp: datetime
    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    actor_email: Optional[str] = None
    target_user_id: Optional[str] = None
    target_user_email: Optional[str] = None
    target_document_id: Optional[str] = None
    target_document_title: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    summary: str
    investigation_metadata: Dict[str, Any] = Field(default_factory=dict)
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    acknowledged_by_name: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_by_name: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class SecurityAlertListResponse(BaseModel):
    total: int
    alerts: List[SecurityAlertResponse]

class SecurityAlertMetricsResponse(BaseModel):
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    investigating_alerts: int
    resolved_alerts: int

class SecurityAlertResolveRequest(BaseModel):
    resolution_notes: str = Field(..., min_length=3, max_length=1000)

class SecurityAlertRevokeSessionsResponse(BaseModel):
    revoked_sessions_count: int
    message: str
