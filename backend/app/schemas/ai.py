from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class AIActionType(str, Enum):
    """
    Strictly constrained action enum for Phase 6 / Invariant I6.
    The AI cannot execute or suggest arbitrary system actions.
    """
    RECOMMEND_READ_GRANT = "RECOMMEND_READ_GRANT"
    FLAG_UNUSED_GRANT = "FLAG_UNUSED_GRANT"
    SUGGEST_RETENTION_LABEL = "SUGGEST_RETENTION_LABEL"

class SuggestedGrant(BaseModel):
    user_id: str
    email: str
    display_name: str
    permission_level: str = Field(..., pattern="^(read|edit)$")
    action: AIActionType = Field(default=AIActionType.RECOMMEND_READ_GRANT)
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
    suggested_actions: List[AIActionType] = Field(default_factory=lambda: [AIActionType.RECOMMEND_READ_GRANT])

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
