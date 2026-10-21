from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict, field_serializer

class AuditEventResponse(BaseModel):
    id: str
    timestamp: datetime
    actor_id: Optional[str] = None
    actor_email: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    outcome: str
    request_id: Optional[str] = None
    structured_metadata: Dict[str, Any]
    previous_event_hash: str
    event_hash: str

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime, _info):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    model_config = ConfigDict(from_attributes=True)

class AuditListResponse(BaseModel):
    total: int
    events: List[AuditEventResponse]

class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_events: int
    tampered_event_id: Optional[str] = None
    event_index: Optional[int] = None
    error_reason: Optional[str] = None
    verified_at_event_id: Optional[str] = None
