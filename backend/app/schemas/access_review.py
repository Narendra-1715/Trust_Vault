from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, ConfigDict

class AccessReviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    document_id: str
    document_title: str
    permission_id: str
    grantee_id: str
    grantee_email: str
    grantee_name: str
    permission_level: str
    grant_created_at: datetime
    grant_expires_at: Optional[datetime] = None
    reviewer_id: str
    reviewer_email: Optional[str] = None
    status: str  # "pending", "retained", "revoked"
    due_date: datetime
    is_overdue: bool
    decision: Optional[str] = None
    decided_at: Optional[datetime] = None
    decision_notes: Optional[str] = None
    next_review_due: Optional[datetime] = None
    created_at: datetime

class AccessReviewDecisionRequest(BaseModel):
    decision: Literal["retain", "revoke"]
    decision_notes: Optional[str] = Field(None, max_length=1000)

class AccessReviewListResponse(BaseModel):
    total: int
    pending_count: int
    overdue_count: int
    reviews: List[AccessReviewResponse]
