import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.session import UserSession
from app.models.security_alert import SecurityAlert
from app.audit.service import log_audit_event

logger = logging.getLogger(__name__)

class IncidentService:
    """
    Phase 7 / Incident Response Service:
    Executes automated containment protocols during suspected compromises.
    """

    @classmethod
    def isolate_user(
        cls,
        db: Session,
        user_id: str,
        actor_id: str,
        reason: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Immediately isolates a compromised user account:
        1. Deactivates user account (is_active = False)
        2. Increments user session_version (invalidating active JWT tokens)
        3. Terminates all active user sessions in database
        4. Freezes all documents owned by the user (no one can read/write except via break-glass)
        5. Increments permission_epoch on all affected documents (severing active streams)
        6. Revokes all outgoing permissions issued by this user
        7. Logs tamper-evident audit record and generates critical SecurityAlert
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User '{user_id}' not found")

        now_utc = datetime.now(timezone.utc)

        # 1. Deactivate user account
        user.is_active = False

        # 2. Invalidate JWT sessions
        user.session_version = (user.session_version or 1) + 1

        # 3. Terminate active sessions
        active_sessions = db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.revoked_at.is_(None)
        ).all()
        for s in active_sessions:
            s.revoked_at = now_utc

        # 4. Freeze owned documents and increment permission epochs
        owned_docs = db.query(Document).filter(
            Document.owner_id == user.id,
            Document.deleted_at.is_(None)
        ).all()
        for doc in owned_docs:
            doc.is_frozen = True
            doc.permission_epoch = (doc.permission_epoch or 1) + 1

        # 5. Revoke outgoing permissions granted by this user
        outgoing_grants = db.query(DocumentPermission).filter(
            DocumentPermission.granted_by == user.id,
            DocumentPermission.revoked_at.is_(None)
        ).all()
        for p in outgoing_grants:
            p.revoked_at = now_utc

        db.commit()

        # Verify if actor_id corresponds to a valid User ID in database
        actor_user_id = None
        if actor_id:
            if db.query(User.id).filter(User.id == actor_id).first():
                actor_user_id = actor_id

        # 6. Immutable audit log
        log_audit_event(
            db=db,
            action="incident.user_isolated",
            resource_type="user",
            resource_id=user.id,
            outcome="success",
            actor_id=actor_user_id,
            request_id=request_id,
            metadata={
                "operator": actor_id,
                "target_user_email": user.email,
                "reason": reason or "Suspected credential or account compromise",
                "terminated_sessions_count": len(active_sessions),
                "frozen_documents_count": len(owned_docs),
                "revoked_outgoing_grants_count": len(outgoing_grants)
            }
        )

        # 7. Create critical security alert
        alert = SecurityAlert(
            event_type="USER_COMPROMISE_ISOLATION",
            severity="critical",
            status="open",
            actor_id=actor_user_id,
            target_user_id=user.id,
            request_id=request_id,
            summary=f"Incident Response: User {user.email} isolated due to suspected account compromise.",
            investigation_metadata={
                "operator": actor_id,
                "reason": reason,
                "user_id": user.id,
                "frozen_docs": len(owned_docs),
                "sessions_killed": len(active_sessions)
            }
        )
        db.add(alert)
        db.commit()

        return {
            "status": "isolated",
            "user_id": user.id,
            "user_email": user.email,
            "sessions_terminated": len(active_sessions),
            "documents_frozen": len(owned_docs),
            "outgoing_grants_revoked": len(outgoing_grants),
            "isolated_at": now_utc.isoformat()
        }
