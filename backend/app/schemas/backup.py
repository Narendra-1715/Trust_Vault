from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict

class BackupItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    backup_id: str
    filename: str
    size_bytes: int
    created_at: str
    alembic_version: Optional[str] = None
    total_documents: int = 0
    total_object_bytes: int = 0
    table_counts: Dict[str, int] = Field(default_factory=dict)
    is_encrypted: bool = True
    verified: bool = True

class BackupListResponse(BaseModel):
    total: int
    backups: List[BackupItemResponse]

class BackupCreateResponse(BaseModel):
    backup_id: str
    filename: str
    size_bytes: int
    created_at: str
    alembic_version: Optional[str] = None
    total_documents: int
    total_object_bytes: int
    table_counts: Dict[str, int]
    audit_chain_valid: bool
    verified: bool
    message: str

class RestoreVerificationReportResponse(BaseModel):
    is_valid: bool
    backup_id: str
    created_at: Optional[str] = None
    alembic_version: Optional[str] = None
    app_version: Optional[str] = None
    total_documents: int = 0
    objects_verified: int = 0
    missing_objects: List[str] = Field(default_factory=list)
    corrupt_objects: List[Dict[str, Any]] = Field(default_factory=list)
    orphan_objects: List[str] = Field(default_factory=list)
    database_records_verified: Dict[str, int] = Field(default_factory=dict)
    audit_chain_valid: bool = False
    audit_total_events: int = 0
    rto_seconds: float = 0.0
    errors: List[str] = Field(default_factory=list)
