from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.policies.authorization import AuthorizationPolicy
from app.services.authorization import AuthorizationService, Action
from app.schemas.policy_simulator import PolicySimulationRequest, PolicySimulationResponse, RuleEvaluationResult
from app.api.deps import get_current_user, get_request_id
from app.audit.service import log_audit_event
from app.services.classification_policy import (
    get_security_policy,
    evaluate_grant_proposal
)

router = APIRouter()

@router.post("/simulate", response_model=PolicySimulationResponse)
def simulate_policy_grant(
    sim_in: PolicySimulationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Access Policy Simulator:
    - Purely read-only advisory evaluation.
    - Never creates grants, mutates classifications, or revokes access.
    - Derives ownership, active grants, classification, and effective policies server-side.
    - Enforces that caller must hold read authorization for the referenced document.
    - Uses identical central policy evaluation logic as actual grant creation.
    """
    request_id = get_request_id(request)

    # 1. Fetch document and enforce grant-management authorization via AuthorizationService
    # Restricts simulation strictly to documents the caller owns or manages (Invariant I3 uniform 404)
    doc = AuthorizationService.enforce(db, current_user, Action.MANAGE_GRANTS, sim_in.document_id, request_id=request_id)

    # 2. Resolve target recipient
    target_user = None
    if sim_in.recipient_user_id:
        target_user = db.query(User).filter(User.id == sim_in.recipient_user_id).first()
    elif sim_in.recipient_email:
        target_user = db.query(User).filter(User.email == sim_in.recipient_email.strip().lower()).first()

    # 3. Check current grant on document for recipient if known
    current_perm_level = None
    if target_user:
        active_perm = AuthorizationPolicy.get_active_permission(db, doc.id, target_user.id)
        if active_perm:
            current_perm_level = active_perm.permission_level

    # 4. Fetch active classification policy
    policy = get_security_policy(db, doc.classification)

    # 5. Evaluate using the central shared policy engine
    eval_result = evaluate_grant_proposal(
        doc=doc,
        proposer=current_user,
        target_user=target_user,
        permission_level=sim_in.permission_level,
        expires_at=sim_in.proposed_expiry,
        policy=policy
    )

    # 6. Map status label
    is_allowed = eval_result["is_allowed"]
    failures = eval_result["failures"]

    if is_allowed:
        final_status = "allowed"
        summary = "Proposed grant is fully allowed by current security policies."
    else:
        # Check if failure is an additional requirement (e.g. MFA enrollment or missing expiration date)
        has_reqs_needed = any("mfa" in f.lower() or "missing" in f.lower() or "expiration" in f.lower() for f in failures)
        if has_reqs_needed and ("proposer lacks" not in failures[0].lower() and "disabled" not in failures[0].lower()):
            final_status = "additional_requirements_needed"
            summary = f"Additional requirements needed: {failures[0]}"
        else:
            final_status = "denied"
            summary = f"Denied by security policy: {failures[0]}"

    # Optional: Log clearly labeled simulation audit event
    log_audit_event(
        db=db,
        action="policy_simulator.evaluate",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "simulation_result": final_status,
            "proposed_permission": sim_in.permission_level,
            "target_recipient": target_user.email if target_user else sim_in.recipient_email,
            "classification": doc.classification
        }
    )

    evaluated_rules = [
        RuleEvaluationResult(
            name=r["name"],
            rule=r["rule"],
            passed=r["passed"],
            details=r["details"]
        )
        for r in eval_result["evaluated_rules"]
    ]

    return PolicySimulationResponse(
        status=final_status,
        is_allowed=is_allowed,
        summary=summary,
        document_id=doc.id,
        document_title=doc.title,
        classification=doc.classification,
        proposed_permission=sim_in.permission_level,
        recipient_email=target_user.email if target_user else sim_in.recipient_email,
        current_permission_level=current_perm_level,
        evaluated_rules=evaluated_rules,
        failures=failures,
        remediation=eval_result["remediation"],
        simulated_at=datetime.now(timezone.utc)
    )
