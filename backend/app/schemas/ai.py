from typing import List, Optional
from pydantic import BaseModel, Field

class SuggestedGrant(BaseModel):
    user_id: str
    email: str
    display_name: str
    permission_level: str = Field(..., pattern="^(read|edit)$")
    confidence: float = Field(..., ge=0.0, le=1.0)
    rationale: str

class AIRecommendationResult(BaseModel):
    document_id: str
    document_title: str
    category: str
    provider_model: str
    is_mock: bool
    explanation: str
    suggestions: List[SuggestedGrant]

class AIApprovalItem(BaseModel):
    user_id: str
    permission_level: str = Field(..., pattern="^(read|edit)$")

class AIApprovalRequest(BaseModel):
    suggestion_id: str
    approved_grants: List[AIApprovalItem]
    decision_notes: Optional[str] = None

class AIRejectionRequest(BaseModel):
    suggestion_id: str
    rejection_reason: Optional[str] = None
