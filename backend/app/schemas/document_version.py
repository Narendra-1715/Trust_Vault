from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict

class DocumentVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    document_id: str
    version_number: int
    original_filename: str
    file_size: int
    checksum: str
    detected_media_type: str
    change_summary: Optional[str] = None
    uploaded_by: Optional[str] = None
    uploader_name: Optional[str] = None
    uploader_email: Optional[str] = None
    is_current: bool
    created_at: datetime

class DocumentVersionListResponse(BaseModel):
    total: int
    versions: List[DocumentVersionResponse]
