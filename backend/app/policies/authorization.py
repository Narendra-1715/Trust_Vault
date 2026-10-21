from typing import Optional, Tuple
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission

class AuthorizationPolicy:
    """
    Centralized server-side authorization engine.
    Sole authority for verifying user permissions against current database state.
    """

    @staticmethod
    def get_active_permission(db: Session, document_id: str, user_id: str) -> Optional[DocumentPermission]:
        """
        Retrieves active (non-revoked) permission for a user on a given document.
        Always queries live database state within current transaction.
        """
        return db.query(DocumentPermission).filter(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
            DocumentPermission.revoked_at.is_(None)
        ).first()

    @classmethod
    def can_read_document(cls, db: Session, user: User, document: Document) -> bool:
        """
        Returns True if user is the document owner OR has an active 'read' or 'edit' permission grant.
        Admins do not automatically have content access unless explicitly granted.
        """
        if document.deleted_at is not None:
            return False
            
        if document.owner_id == user.id:
            return True

        perm = cls.get_active_permission(db, document.id, user.id)
        if perm and perm.permission_level in ["read", "edit"]:
            return True

        return False

    @classmethod
    def can_edit_document(cls, db: Session, user: User, document: Document) -> bool:
        """
        Returns True if user is the document owner OR has active 'edit' permission.
        Viewers and non-permitted users cannot edit.
        """
        if document.deleted_at is not None:
            return False

        if document.owner_id == user.id:
            return True

        perm = cls.get_active_permission(db, document.id, user.id)
        if perm and perm.permission_level == "edit":
            return True

        return False

    @classmethod
    def can_delete_document(cls, db: Session, user: User, document: Document) -> bool:
        """
        Only the document owner can delete their document.
        Edit permission holders cannot delete.
        """
        if document.deleted_at is not None:
            return False
        return document.owner_id == user.id

    @classmethod
    def can_manage_permissions(cls, db: Session, user: User, document: Document) -> bool:
        """
        Only the document owner can grant or revoke permissions or request AI sharing recommendations.
        Viewers and editors cannot grant permissions to others.
        """
        if document.deleted_at is not None:
            return False
        return document.owner_id == user.id

    @classmethod
    def can_view_document_audit(cls, db: Session, user: User, document: Document) -> bool:
        """
        Owner, users with active permission, or system admins can view document-specific audit history.
        """
        if user.role == "admin":
            return True
        return cls.can_read_document(db, user, document)

    @classmethod
    def require_read(cls, db: Session, user: User, document: Optional[Document]) -> Document:
        """
        Requires read permission.
        Consistent 404 response if document does not exist OR user lacks permission
        to prevent information disclosure / resource enumeration.
        """
        if not document or not cls.can_read_document(db, user, document):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        return document

    @classmethod
    def require_edit(cls, db: Session, user: User, document: Optional[Document]) -> Document:
        """
        Requires edit permission.
        """
        if not document or not cls.can_read_document(db, user, document):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        if not cls.can_edit_document(db, user, document):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to edit this document"
            )
        return document

    @classmethod
    def require_owner(cls, db: Session, user: User, document: Optional[Document]) -> Document:
        """
        Requires ownership.
        """
        if not document or not cls.can_read_document(db, user, document):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        if not cls.can_manage_permissions(db, user, document):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the document owner can perform this operation"
            )
        return document

    @staticmethod
    def require_admin(user: User) -> None:
        """
        Requires global Admin role.
        """
        if user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrative privilege required"
            )
