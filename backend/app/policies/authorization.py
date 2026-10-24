"""Authorization Policy Compatibility Layer
Delegates all policy checks directly to the central AuthorizationService (PDP).
Maintained for backwards-compatibility while enforcing Invariants I1-I3 platform-wide.
"""

from typing import Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.services.authorization import (
    AuthorizationService,
    Action,
    raise_not_found,
    is_valid_uuid
)

class AuthorizationPolicy:
    """
    Compatibility wrapper delegating to AuthorizationService.
    """

    @staticmethod
    def get_active_permission(db: Session, document_id: str, user_id: str) -> Optional[DocumentPermission]:
        """
        Retrieves active (non-revoked, non-expired) permission for a user on a given document.
        Always queries live database state within current transaction.
        """
        now_utc = datetime.now(timezone.utc)
        perm = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
            DocumentPermission.revoked_at.is_(None)
        ).first()

        if not perm:
            return None

        if perm.expires_at is not None:
            exp = perm.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= now_utc:
                return None

        return perm

    @classmethod
    def can_read_document(cls, db: Session, user: User, document: Document) -> bool:
        """Evaluates whether user can read/view document."""
        if not document:
            return False
        decision = AuthorizationService.decide(db, user, Action.VIEW, document.id)
        return decision.allowed

    @classmethod
    def can_edit_document(cls, db: Session, user: User, document: Document) -> bool:
        """Evaluates whether user can edit document."""
        if not document:
            return False
        decision = AuthorizationService.decide(db, user, Action.EDIT, document.id)
        return decision.allowed

    @classmethod
    def can_delete_document(cls, db: Session, user: User, document: Document) -> bool:
        """Evaluates whether user can delete document."""
        if not document:
            return False
        decision = AuthorizationService.decide(db, user, Action.DELETE, document.id)
        return decision.allowed

    @classmethod
    def can_manage_permissions(cls, db: Session, user: User, document: Document) -> bool:
        """Evaluates whether user can manage permissions."""
        if not document:
            return False
        decision = AuthorizationService.decide(db, user, Action.MANAGE_GRANTS, document.id)
        return decision.allowed

    @classmethod
    def can_view_document_audit(cls, db: Session, user: User, document: Document) -> bool:
        """Admin or users with active access can view audit history."""
        if user.role == "admin":
            return True
        return cls.can_read_document(db, user, document)

    @classmethod
    def require_read(cls, db: Session, user: User, document: Optional[Document]) -> Document:
        """
        Requires read permission. Uniform 404 on any denial (Invariant I3).
        """
        doc_id = document.id if document else "00000000-0000-0000-0000-000000000000"
        return AuthorizationService.enforce(db, user, Action.VIEW, doc_id)

    @classmethod
    def require_edit(cls, db: Session, user: User, document: Optional[Document]) -> Document:
        """
        Requires edit permission. Uniform 404 on any denial (Invariant I3).
        """
        doc_id = document.id if document else "00000000-0000-0000-0000-000000000000"
        return AuthorizationService.enforce(db, user, Action.EDIT, doc_id)

    @classmethod
    def require_owner(cls, db: Session, user: User, document: Optional[Document]) -> Document:
        """
        Requires ownership. Uniform 404 on any denial (Invariant I3).
        """
        doc_id = document.id if document else "00000000-0000-0000-0000-000000000000"
        return AuthorizationService.enforce(db, user, Action.MANAGE_GRANTS, doc_id)

    @staticmethod
    def require_admin(user: User) -> None:
        """Requires global Admin role."""
        if not user or user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrative privilege required"
            )
