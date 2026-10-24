"""Central Authorization Service (Policy Decision Point)
Sole authority for access decisions across all routes and background tasks in TrustVault.
Enforces:
- Invariant I1: Admin Blindness (admin has ZERO content permissions without owner grant or break-glass)
- Invariant I2: Instant Revocation (synchronous DB query at read time)
- Invariant I3: Uniform 404 (No existence leaks across all unauthorized, malformed, nonexistent, expired requests)
- Invariant I4 & I5: Tamper resistance and audit logging
"""

import uuid
import time
import secrets
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any

from fastapi import HTTPException, status, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.config import settings
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.audit.service import log_audit_event
from app.notifications.service import check_and_notify_repeated_denials

NOT_FOUND_DETAIL = "Document not found"
UNIFORM_404_BODY = b'{"detail":"Document not found"}'
UNIFORM_404_HEADERS = {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store, private",
    "Pragma": "no-cache",
    "Cross-Origin-Resource-Policy": "same-origin",
}

class Action(str, Enum):
    VIEW = "VIEW"                       # Preview content or stream
    DOWNLOAD = "DOWNLOAD"               # Download original file or version
    EDIT = "EDIT"                       # Update metadata, upload new revision
    SHARE = "SHARE"                     # Grant sharing access (owner only)
    ROLLBACK = "ROLLBACK"               # Restore or rollback historical version (owner only)
    DELETE = "DELETE"                   # Soft-delete document (owner only)
    RESTORE = "RESTORE"                 # Restore from trash (owner only)
    MANAGE_GRANTS = "MANAGE_GRANTS"     # Revoke or alter existing grants (owner only)
    VIEW_METADATA = "VIEW_METADATA"     # Read document details, version list

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    action: Action
    principal_id: Optional[str]
    resource_id: Optional[str]
    document: Optional[Document] = None

class DocumentNotFoundException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NOT_FOUND_DETAIL,
            headers=UNIFORM_404_HEADERS
        )

def not_found_response() -> Response:
    """Returns the byte-identical 404 Response with nosniff and zero-cache headers."""
    return Response(
        content=UNIFORM_404_BODY,
        status_code=status.HTTP_404_NOT_FOUND,
        media_type="application/json",
        headers=UNIFORM_404_HEADERS
    )

def execute_dummy_queries(db: Session, principal_id: Optional[str] = None) -> None:
    """
    Executes dummy queries on DocumentPermission and User to equalize DB workload
    between nonexistent resources and existing-but-unauthorized resources.
    """
    try:
        dummy_id = "00000000-0000-0000-0000-000000000000"
        db.query(DocumentPermission).filter(
            DocumentPermission.document_id == dummy_id,
            DocumentPermission.user_id == (principal_id or dummy_id)
        ).first()
        db.query(User).filter(User.id == dummy_id).first()
    except Exception:
        pass

def equalize_timing(start_time: float) -> None:
    """
    Pads elapsed execution time to a constant-time floor plus cryptographic jitter
    to eliminate timing side-channel existence leaks on document routes.
    """
    if not getattr(settings, "TIMING_EQUALIZATION_ENABLED", True):
        return
    floor_ms = getattr(settings, "TIMING_LATENCY_FLOOR_MS", 30)
    jitter_max_ms = getattr(settings, "TIMING_JITTER_MAX_MS", 15)
    jitter_ms = secrets.randbelow(max(1, jitter_max_ms))
    target_seconds = (floor_ms + jitter_ms) / 1000.0
    elapsed = time.perf_counter() - start_time
    remaining = target_seconds - elapsed
    if remaining > 0:
        time.sleep(remaining)

def raise_not_found(
    db: Optional[Session] = None,
    principal_id: Optional[str] = None,
    start_time: Optional[float] = None
) -> None:
    """Raises the uniform 404 exception guaranteeing zero existence leakage and equalized timing."""
    if db is not None:
        execute_dummy_queries(db, principal_id)
    if start_time is not None:
        equalize_timing(start_time)
    raise DocumentNotFoundException()

def is_valid_uuid(val: Any) -> bool:
    if not val:
        return False
    try:
        val_str = str(val)
        val_uuid = uuid.UUID(val_str)
        return str(val_uuid) == val_str or len(val_str) == 36
    except (ValueError, AttributeError, TypeError):
        return False

class AuthorizationService:
    """
    Central Policy Decision Point (PDP).
    Every route and service touching documents, versions, permissions, access requests,
    or policy simulations MUST query this service. Direct DB queries or ad-hoc permission
    checks in route handlers are strictly prohibited.
    """

    @classmethod
    def decide(
        cls,
        db: Session,
        principal: Optional[User],
        action: Action,
        resource_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Decision:
        """
        Pure decision function: (principal, action, resource_id, context) -> Decision.
        Evaluates live database state within current transaction.
        """
        principal_id = principal.id if principal else None

        # 1. UUID validation (prevents 422 enumeration leaks on path parameters)
        if not is_valid_uuid(resource_id):
            execute_dummy_queries(db, principal_id)
            return Decision(
                allowed=False,
                reason="invalid_resource_id_format",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # 2. Principal authentication and active status check
        if not principal or not getattr(principal, "is_active", False):
            execute_dummy_queries(db, principal_id)
            return Decision(
                allowed=False,
                reason="unauthenticated_or_inactive_principal",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # Set transaction context for Postgres RLS if connected to PostgreSQL
        if db.bind and db.bind.dialect.name == "postgresql":
            try:
                from sqlalchemy import text
                db.execute(text("SET LOCAL app.current_user_id = :uid"), {"uid": str(principal.id)})
                db.execute(text("SET LOCAL app.current_org_id = :org"), {"org": str(getattr(principal, "org_id", "default-org"))})
            except Exception:
                pass

        # 3. Retrieve live document state
        doc = db.query(Document).filter(Document.id == resource_id).first()
        if not doc:
            execute_dummy_queries(db, principal_id)
            return Decision(
                allowed=False,
                reason="document_not_found",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # 4. Multi-tenant boundary check (org_id matching)
        principal_org = getattr(principal, "org_id", "default-org")
        doc_org = getattr(doc, "org_id", "default-org")
        if principal_org != doc_org:
            return Decision(
                allowed=False,
                reason="cross_tenant_access_denied",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # 5. Soft-deleted / Trashed handling
        if doc.deleted_at is not None:
            if action == Action.RESTORE and doc.owner_id == principal.id:
                return Decision(
                    allowed=True,
                    reason="owner_restore_allowed",
                    action=action,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    document=doc
                )
            return Decision(
                allowed=False,
                reason="document_in_trash",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # 6. Orphaned document protection: owner disabled or deleted
        # If the document owner is deactivated, documents are frozen to non-owners
        # and only visible via designated break-glass emergency activation
        owner = db.query(User).filter(User.id == doc.owner_id).first()
        if not owner or not owner.is_active:
            # Check if principal has active break-glass
            if principal.role == "admin" and action in [Action.VIEW, Action.DOWNLOAD, Action.VIEW_METADATA]:
                if cls._has_active_break_glass(db, principal.id, doc.id):
                    return Decision(
                        allowed=True,
                        reason="break_glass_orphaned_document_recovery",
                        action=action,
                        principal_id=principal_id,
                        resource_id=resource_id,
                        document=doc
                    )
            return Decision(
                allowed=False,
                reason="orphaned_document_frozen",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # 7. Owner Authorization
        if doc.owner_id == principal.id:
            # Document owner holds full authority across all lifecycle actions
            return Decision(
                allowed=True,
                reason="principal_is_owner",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=doc
            )

        # 8. Admin Blindness Enforced:
        # Global admins have ZERO content access unless holding an owner grant or active Break-Glass
        if principal.role == "admin":
            if cls._has_active_break_glass(db, principal.id, doc.id):
                if action in [Action.VIEW, Action.DOWNLOAD, Action.VIEW_METADATA]:
                    return Decision(
                        allowed=True,
                        reason="break_glass_emergency_access",
                        action=action,
                        principal_id=principal_id,
                        resource_id=resource_id,
                        document=doc
                    )
                else:
                    return Decision(
                        allowed=False,
                        reason="break_glass_is_read_only",
                        action=action,
                        principal_id=principal_id,
                        resource_id=resource_id,
                        document=None
                    )
            # For compliance and access review auditing, admins can inspect non-content operational metadata
            if action == Action.VIEW_METADATA:
                return Decision(
                    allowed=True,
                    reason="admin_metadata_governance_view",
                    action=action,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    document=doc
                )

        # 9. Non-Owner Grantee Evaluation
        now_utc = datetime.now(timezone.utc)
        perm = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == doc.id,
            DocumentPermission.user_id == principal.id,
            DocumentPermission.revoked_at.is_(None)
        ).first()

        if not perm:
            return Decision(
                allowed=False,
                reason="no_active_grant",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # Instant TTL Evaluation at read time inside authorization query (never cron alone)
        if perm.expires_at is not None:
            exp = perm.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= now_utc:
                return Decision(
                    allowed=False,
                    reason="grant_expired",
                    action=action,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    document=None
                )

        # Version range scoping check
        if context and "version_number" in context and context["version_number"] is not None:
            ver_num = int(context["version_number"])
            if perm.min_version_number is not None and ver_num < perm.min_version_number:
                return Decision(
                    allowed=False,
                    reason="version_below_scoped_range",
                    action=action,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    document=None
                )
            if perm.max_version_number is not None and ver_num > perm.max_version_number:
                return Decision(
                    allowed=False,
                    reason="version_above_scoped_range",
                    action=action,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    document=None
                )

        # Enforce action boundaries:
        # Owner-only actions CANNOT be delegated to grantees
        if action in [Action.SHARE, Action.ROLLBACK, Action.DELETE, Action.RESTORE, Action.MANAGE_GRANTS]:
            return Decision(
                allowed=False,
                reason="action_restricted_to_owner",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # EDIT requires 'edit' permission level
        if action == Action.EDIT:
            if perm.permission_level == "edit":
                return Decision(
                    allowed=True,
                    reason="grant_permits_edit",
                    action=action,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    document=doc
                )
            return Decision(
                allowed=False,
                reason="edit_denied_for_read_only_grant",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # DOWNLOAD: requires 'read' or 'edit' (preview/view cannot download)
        if action == Action.DOWNLOAD:
            if perm.permission_level in ["read", "edit"]:
                # Check classification download restrictions
                from app.services.classification_policy import evaluate_download_access, get_security_policy
                policy = get_security_policy(db, doc.classification)
                is_dl_allowed, dl_reason, dl_action = evaluate_download_access(doc, principal, policy)
                if not is_dl_allowed:
                    return Decision(
                        allowed=False,
                        reason="download_restricted_by_security_policy",
                        action=action,
                        principal_id=principal_id,
                        resource_id=resource_id,
                        document=None
                    )
                return Decision(
                    allowed=True,
                    reason="grant_permits_download",
                    action=action,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    document=doc
                )
            return Decision(
                allowed=False,
                reason="preview_grant_denied_download",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        # VIEW and VIEW_METADATA: permitted for view, preview, read, edit
        if action in [Action.VIEW, Action.VIEW_METADATA]:
            if perm.permission_level in ["view", "preview", "read", "edit"]:
                return Decision(
                    allowed=True,
                    reason="grant_permits_view",
                    action=action,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    document=doc
                )
            return Decision(
                allowed=False,
                reason="invalid_grant_level",
                action=action,
                principal_id=principal_id,
                resource_id=resource_id,
                document=None
            )

        return Decision(
            allowed=False,
            reason="action_not_permitted",
            action=action,
            principal_id=principal_id,
            resource_id=resource_id,
            document=None
        )

    @classmethod
    def enforce(
        cls,
        db: Session,
        principal: Optional[User],
        action: Action,
        resource_id: str,
        context: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None
    ) -> Document:
        """
        Policy Enforcement Point (PEP):
        Calls decide(). If denied, logs security audit event, equalizes timing,
        and raises uniform 404.
        """
        t0 = time.perf_counter()
        decision = cls.decide(db, principal, action, resource_id, context)
        if not decision.allowed:
            # Audit log unauthorized access attempts
            actor_id = principal.id if principal else None
            action_name = "document.access.expired" if decision.reason == "grant_expired" else f"document.{action.value.lower()}.denied"
            reason_text = "Access grant has expired" if decision.reason == "grant_expired" else decision.reason
            try:
                log_audit_event(
                    db=db,
                    action=action_name,
                    resource_type="document",
                    resource_id=resource_id,
                    outcome="denied",
                    actor_id=actor_id,
                    request_id=request_id or "auto-enforce",
                    metadata={"reason": reason_text, "action": action.value}
                )
                if actor_id:
                    check_and_notify_repeated_denials(
                        db=db,
                        user_id=actor_id,
                        resource_id=resource_id,
                        resource_title=None
                    )
            except Exception:
                pass
            equalize_timing(t0)
            raise_not_found()

        return decision.document

    @classmethod
    def transfer_ownership(
        cls,
        db: Session,
        document_id: str,
        current_owner: User,
        new_owner_id: str,
        request_id: Optional[str] = None
    ) -> Document:
        """
        Secure ownership transfer workflow:
        - Only the current document owner can transfer ownership.
        - Validates target recipient exists, is active, and is in the same tenant org.
        - Increments document permission_epoch to invalidate in-flight cached streams.
        - Emits tamper-evident audit record.
        """
        # 1. Enforce owner authority via MANAGE_GRANTS
        doc = cls.enforce(db, current_owner, Action.MANAGE_GRANTS, document_id, request_id=request_id)

        # 2. Validate target owner
        target_user = db.query(User).filter(User.id == new_owner_id).first()
        if not target_user or not target_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target recipient user not found or inactive"
            )

        if getattr(target_user, "org_id", "default-org") != getattr(current_owner, "org_id", "default-org"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot transfer ownership to a user outside your organization"
            )

        if target_user.id == current_owner.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Document is already owned by this user"
            )

        # 3. Apply transfer
        now = datetime.now(timezone.utc)
        doc.transferred_from_id = current_owner.id
        doc.transferred_at = now
        doc.owner_id = target_user.id
        doc.permission_epoch = (doc.permission_epoch or 1) + 1
        doc.updated_at = now

        # Remove previous permission record for new owner if one existed
        existing_perm = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == doc.id,
            DocumentPermission.user_id == target_user.id
        ).first()
        if existing_perm:
            db.delete(existing_perm)

        # Automatically grant edit permission to previous owner for business continuity
        prev_owner_perm = DocumentPermission(
            document_id=doc.id,
            user_id=current_owner.id,
            permission_level="edit",
            granted_by=target_user.id,
            granted_at=now
        )
        db.add(prev_owner_perm)

        db.commit()
        db.refresh(doc)

        log_audit_event(
            db=db,
            action="document.ownership_transferred",
            resource_type="document",
            resource_id=doc.id,
            outcome="success",
            actor_id=current_owner.id,
            request_id=request_id or "transfer",
            metadata={
                "transferred_from": current_owner.id,
                "transferred_to": target_user.id,
                "permission_epoch": doc.permission_epoch
            }
        )

        return doc

    @staticmethod
    def _has_active_break_glass(db: Session, admin_id: str, document_id: str) -> bool:
        """Checks if admin holds a verified, unexpired Break-Glass emergency activation."""
        from app.models.emergency_access import EmergencyAccess
        now_utc = datetime.now(timezone.utc)
        active = db.query(EmergencyAccess).filter(
            EmergencyAccess.admin_id == admin_id,
            EmergencyAccess.document_id == document_id,
            EmergencyAccess.status == "active",
            EmergencyAccess.revoked_at.is_(None)
        ).first()
        if not active:
            return False

        exp = active.expires_at.replace(tzinfo=timezone.utc) if active.expires_at.tzinfo is None else active.expires_at
        if exp > now_utc:
            return True
        else:
            active.status = "expired"
            try:
                db.commit()
            except Exception:
                db.rollback()
            return False

def get_admin_metadata_view(doc: Document) -> Dict[str, Any]:
    """
    Minimal non-sensitive operational view for administrative inventory.
    Admin Blindness guarantee: Hides filename, title, description, and preview content.
    Returns UUID, size bucket, category, classification, and status.
    """
    size = doc.file_size or 0
    if size < 1024 * 1024:
        size_bucket = "<1MB"
    elif size < 10 * 1024 * 1024:
        size_bucket = "1-10MB"
    elif size < 100 * 1024 * 1024:
        size_bucket = "10-100MB"
    else:
        size_bucket = ">100MB"

    return {
        "id": doc.id,
        "owner_id": doc.owner_id,
        "size_bucket": size_bucket,
        "file_size": doc.file_size,
        "category": doc.category,
        "classification": doc.classification,
        "status": "trashed" if doc.deleted_at else "active",
        "created_at": doc.created_at,
        "updated_at": doc.updated_at,
        "org_id": getattr(doc, "org_id", "default-org"),
        "permission_epoch": getattr(doc, "permission_epoch", 1),
        # Protected under Admin Blindness:
        "title": "[REDACTED - ADMIN BLINDNESS]",
        "original_filename": "[REDACTED - ADMIN BLINDNESS]"
    }
