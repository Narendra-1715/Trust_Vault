import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session

from app.models.security_policy import SecurityPolicy, DEFAULT_POLICIES, VALID_CLASSIFICATIONS
from app.models.document import Document
from app.models.user import User

def get_security_policy(db: Session, classification: str) -> SecurityPolicy:
    """
    Retrieves the security policy for a classification level.
    If not yet in DB, dynamically falls back to defaults and creates the record.
    """
    cleaned = classification.strip() if classification else "Internal"
    if cleaned not in VALID_CLASSIFICATIONS:
        cleaned = "Internal"

    policy = db.query(SecurityPolicy).filter(SecurityPolicy.classification == cleaned).first()
    if not policy:
        default_config = DEFAULT_POLICIES.get(cleaned, DEFAULT_POLICIES["Internal"])
        policy = SecurityPolicy(
            id=str(uuid.uuid4()),
            classification=cleaned,
            allow_download=default_config["allow_download"],
            allow_sharing=default_config["allow_sharing"],
            max_grant_duration_days=default_config["max_grant_duration_days"],
            require_mfa=default_config["require_mfa"],
            elevated_classification_change=default_config["elevated_classification_change"]
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy

def evaluate_grant_proposal(
    doc: Document,
    proposer: User,
    target_user: Optional[User],
    permission_level: str,
    expires_at: Optional[datetime],
    policy: SecurityPolicy,
) -> Dict[str, Any]:
    """
    Central, shared evaluation logic used by BOTH grant creation endpoints
    and the read-only Access Policy Simulator.
    Ensures identical, consistent decisions with zero discrepancy.
    """
    now = datetime.now(timezone.utc)
    checks: List[Dict[str, Any]] = []
    failures: List[str] = []
    remediation_steps: List[str] = []

    # 1. Proposer Authorization Check
    is_owner = doc.owner_id == proposer.id
    is_admin = proposer.role == "admin"
    if not (is_owner or is_admin):
        checks.append({
            "name": "proposer_authorization",
            "rule": "Only document owner or authorized administrator can grant access.",
            "passed": False,
            "details": "Caller does not hold owner or admin privileges for this document."
        })
        failures.append("Proposer lacks ownership or administrator authorization.")
        remediation_steps.append("Request the document owner or an administrator to grant access.")
    else:
        checks.append({
            "name": "proposer_authorization",
            "rule": "Only document owner or authorized administrator can grant access.",
            "passed": True,
            "details": f"Caller authorized as {proposer.role if is_admin else 'owner'}."
        })

    # 2. Policy Sharing Rule Check
    if not policy.allow_sharing:
        checks.append({
            "name": "sharing_allowed_by_policy",
            "rule": f"Sharing is permitted by classification security policy ({doc.classification}).",
            "passed": False,
            "details": f"Document classification '{doc.classification}' strictly prohibits sharing."
        })
        failures.append(f"Sharing is disabled for {doc.classification} documents.")
        remediation_steps.append(f"Document classification '{doc.classification}' must be updated by an authorized user before sharing can be granted.")
    else:
        checks.append({
            "name": "sharing_allowed_by_policy",
            "rule": f"Sharing is permitted by classification security policy ({doc.classification}).",
            "passed": True,
            "details": f"Sharing is permitted under {doc.classification} policy."
        })

    # 3. Grant Expiry & Maximum Duration Check
    max_days = policy.max_grant_duration_days
    if max_days is not None:
        if not expires_at:
            checks.append({
                "name": "grant_duration_limit",
                "rule": f"Grant must have an expiration date not exceeding {max_days} days for {doc.classification}.",
                "passed": False,
                "details": f"No expiration specified. {doc.classification} documents require an explicit expiry within {max_days} days."
            })
            failures.append(f"Missing expiration date. Maximum allowable duration is {max_days} days.")
            remediation_steps.append(f"Specify an expiration timestamp within {max_days} days.")
        else:
            # Ensure expires_at is timezone-aware UTC for comparison
            exp_utc = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
            if exp_utc <= now:
                checks.append({
                    "name": "grant_duration_limit",
                    "rule": "Expiration date must be in the future.",
                    "passed": False,
                    "details": "Specified expiration timestamp is in the past."
                })
                failures.append("Expiration timestamp cannot be in the past.")
                remediation_steps.append("Choose a future expiration date.")
            else:
                max_future_date = now + timedelta(days=max_days, minutes=5)
                if exp_utc > max_future_date:
                    delta_days = (exp_utc - now).total_seconds() / 86400.0
                    checks.append({
                        "name": "grant_duration_limit",
                        "rule": f"Maximum grant duration for {doc.classification} is {max_days} days.",
                        "passed": False,
                        "details": f"Requested duration is {delta_days:.1f} days, exceeding the policy limit of {max_days} days."
                    })
                    failures.append(f"Requested duration ({delta_days:.1f} days) exceeds maximum limit of {max_days} days.")
                    remediation_steps.append(f"Reduce expiration period to {max_days} days or fewer.")
                else:
                    checks.append({
                        "name": "grant_duration_limit",
                        "rule": f"Maximum grant duration for {doc.classification} is {max_days} days.",
                        "passed": True,
                        "details": f"Expiration satisfies policy duration constraint (<= {max_days} days)."
                    })
    else:
        checks.append({
            "name": "grant_duration_limit",
            "rule": "Duration constraint",
            "passed": True,
            "details": f"No maximum duration limit configured for {doc.classification}."
        })

    # 4. MFA Compliance Check for Target Recipient
    if policy.require_mfa:
        if target_user and not target_user.mfa_enabled:
            checks.append({
                "name": "recipient_mfa_compliance",
                "rule": f"Multi-factor authentication (MFA) is required to access {doc.classification} documents.",
                "passed": False,
                "details": f"Recipient '{target_user.email}' does not currently have MFA enabled."
            })
            failures.append(f"Recipient must have MFA enabled to access {doc.classification} documents.")
            remediation_steps.append("The intended recipient must enable Multi-Factor Authentication (MFA) before access can be used.")
        else:
            checks.append({
                "name": "recipient_mfa_compliance",
                "rule": f"Multi-factor authentication (MFA) is required for {doc.classification}.",
                "passed": True,
                "details": "Recipient satisfies MFA requirement (or recipient identity pending)."
            })
    else:
        checks.append({
            "name": "recipient_mfa_compliance",
            "rule": "MFA requirement",
            "passed": True,
            "details": f"MFA is not strictly required for {doc.classification}."
        })

    is_allowed = len(failures) == 0
    status_label = "allowed" if is_allowed else "denied"

    return {
        "is_allowed": is_allowed,
        "status": status_label,
        "summary": "Proposal complies with current security policies." if is_allowed else f"Proposal denied: {failures[0]}",
        "failures": failures,
        "remediation": " ".join(remediation_steps) if remediation_steps else None,
        "evaluated_rules": checks,
        "classification": doc.classification,
        "policy_id": policy.id,
    }

def evaluate_download_access(
    doc: Document,
    user: User,
    policy: SecurityPolicy
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Evaluates whether a user can download a document under the active classification policy.
    Owners always retain download access.
    Non-owners are evaluated against allow_download and require_mfa rules.
    Returns (is_allowed, denial_reason, audit_action)
    """
    is_owner = doc.owner_id == user.id
    if is_owner:
        return True, None, None

    if not policy.allow_download:
        reason = f"Downloading is prohibited for {doc.classification} documents. Direct downloads are restricted by security policy."
        return False, reason, "document.download.policy_denied"

    if policy.require_mfa and not user.mfa_enabled:
        reason = f"Multi-factor authentication (MFA) is required to download {doc.classification} documents. Please enable MFA on your account."
        return False, reason, "document.download.mfa_required"

    return True, None, None

def can_user_change_classification(
    doc: Document,
    user: User,
    new_classification: str,
    current_policy: SecurityPolicy,
    target_policy: SecurityPolicy
) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether the user is authorized to change a document's classification.
    Viewers cannot change classification.
    If elevated_classification_change is required on current or target policy, only owner or admin can change.
    """
    is_owner = doc.owner_id == user.id
    is_admin = user.role == "admin"

    if not (is_owner or is_admin):
        return False, "Only document owners or system administrators can change document classification."

    if (current_policy.elevated_classification_change or target_policy.elevated_classification_change) and not (is_owner or is_admin):
        return False, f"Elevated authorization required to change classification involving '{doc.classification}' or '{new_classification}'."

    return True, None
