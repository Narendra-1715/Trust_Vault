from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

class SecurityPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    classification: str
    allow_download: bool
    allow_sharing: bool
    max_grant_duration_days: Optional[int] = None
    require_mfa: bool
    elevated_classification_change: bool
    created_at: datetime
    updated_at: datetime

class SecurityPolicyUpdate(BaseModel):
    allow_download: Optional[bool] = None
    allow_sharing: Optional[bool] = None
    max_grant_duration_days: Optional[int] = Field(None, ge=1, le=3650)
    require_mfa: Optional[bool] = None
    elevated_classification_change: Optional[bool] = None

class DocumentClassificationUpdate(BaseModel):
    classification: str = Field(..., min_length=1, max_length=50)
    reason: Optional[str] = Field(None, max_length=500)
