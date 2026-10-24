from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, ConfigDict

class RuleEvaluationResult(BaseModel):
    name: str
    rule: str
    passed: bool
    details: str

class PolicySimulationRequest(BaseModel):
    document_id: str
    recipient_email: Optional[str] = None
    recipient_user_id: Optional[str] = None
    permission_level: str = Field(default="read", pattern="^(read|edit)$")
    proposed_expiry: Optional[datetime] = None

class PolicySimulationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: Literal["allowed", "denied", "additional_requirements_needed"]
    is_allowed: bool
    summary: str
    document_id: str
    document_title: str
    classification: str
    proposed_permission: str
    recipient_email: Optional[str] = None
    current_permission_level: Optional[str] = None
    evaluated_rules: List[RuleEvaluationResult]
    failures: List[str]
    remediation: Optional[str] = None
    simulated_at: datetime
