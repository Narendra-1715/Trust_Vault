from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, EmailStr, ConfigDict

class BreakGlassRequest(BaseModel):
    document_id: str = Field(..., description="ID of private document requiring emergency access")
    justification: str = Field(..., min_length=15, description="Clear business or security emergency reason")
    duration_minutes: int = Field(default=30, ge=5, le=120, description="Access duration in minutes (max 120)")
    password: str = Field(..., min_length=1, description="Admin password for mandatory reauthentication")

class BreakGlassReviewRequest(BaseModel):
    review_notes: str = Field(..., min_length=5, description="Post-incident review observations")

class BreakGlassResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    admin_id: str
    admin_email: Optional[str] = None
    admin_name: Optional[str] = None
    document_id: str
    document_title: Optional[str] = None
    justification: str
    status: str
    expires_at: datetime
    created_at: datetime
    revoked_at: Optional[datetime] = None
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    reviewer_name: Optional[str] = None
    review_notes: Optional[str] = None

class SystemSettingItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    value: str
    description: Optional[str] = None
    updated_at: datetime
    updated_by: Optional[str] = None

class SystemSettingUpdateRequest(BaseModel):
    value: str = Field(..., min_length=1)

class SystemStatusResponse(BaseModel):
    status: str
    database: Dict[str, Any]
    storage: Dict[str, Any]
    background_jobs: Dict[str, Any]
    security_configuration: Dict[str, Any]
    users_count: int
    active_sessions_count: int
    server_time: datetime

class AdminUserCreateRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    display_name: str = Field(..., min_length=2)
    role: Literal["admin", "owner", "viewer"] = "viewer"
    is_active: bool = True
    mfa_enabled: bool = False

class AdminUserDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    display_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime
    active_sessions_count: int
    last_active_at: Optional[datetime] = None

class BackupRestoreRequest(BaseModel):
    confirmation: str = Field(..., description="Must be exactly 'RESTORE_DATABASE'")
    password: str = Field(..., min_length=1, description="Admin password for reauthentication")

class BackupRestoreResponse(BaseModel):
    success: bool
    backup_id: str
    restored_files_count: int
    table_counts: Dict[str, int]
    message: str
