from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class DocumentBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    category: str = Field(default="General", max_length=50)

class DocumentCreate(DocumentBase):
    pass

class DocumentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    category: Optional[str] = Field(None, max_length=50)

class DocumentResponse(DocumentBase):
    id: str
    owner_id: str
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    original_filename: str
    detected_media_type: str
    file_size: int
    checksum: str
    created_at: datetime
    updated_at: datetime
    effective_permission: str  # "owner", "edit", "read", "none"

    model_config = ConfigDict(from_attributes=True)

class DocumentListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    documents: List[DocumentResponse]
