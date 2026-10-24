import re
import logging
from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)

class AIWriteAccessForbiddenError(PermissionError):
    """Raised when any code in the AI module attempts to modify the database."""
    pass

class AIReadOnlySession:
    """
    Phase 6 / Invariant I6:
    Enforces absolute ZERO write access for the AI component at the code and session level.
    Intercepts and blocks any attempt to add, commit, delete, flush, or execute mutating SQL.
    In PostgreSQL environments, activates the restricted `ai_readonly` role.
    """

    WRITE_PATTERNS = re.compile(
        r"^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|REPLACE|GRANT|REVOKE)\b",
        re.IGNORECASE
    )

    def __init__(self, db: Session):
        self._db = db
        # Attempt to set PostgreSQL role if running on Postgres
        try:
            if self._db.bind and self._db.bind.dialect.name == "postgresql":
                sp = self._db.begin_nested()
                try:
                    self._db.execute(text("SET LOCAL ROLE ai_readonly;"))
                    sp.commit()
                except Exception as inner_e:
                    sp.rollback()
                    logger.debug(f"Could not SET LOCAL ROLE ai_readonly: {inner_e}")
        except Exception as e:
            logger.debug(f"Could not configure nested transaction for ai_readonly: {e}")

    def query(self, *entities, **kwargs):
        return self._db.query(*entities, **kwargs)

    def execute(self, statement: Any, *args, **kwargs):
        stmt_str = str(statement).strip()
        if self.WRITE_PATTERNS.search(stmt_str):
            raise AIWriteAccessForbiddenError(
                f"Invariant I6 violation: Mutating statement blocked for AI session: {stmt_str[:50]}..."
            )
        return self._db.execute(statement, *args, **kwargs)

    def add(self, instance: Any) -> None:
        raise AIWriteAccessForbiddenError(
            "Invariant I6 violation: AI component has ZERO write access (Session.add is forbidden)."
        )

    def add_all(self, instances: Any) -> None:
        raise AIWriteAccessForbiddenError(
            "Invariant I6 violation: AI component has ZERO write access (Session.add_all is forbidden)."
        )

    def delete(self, instance: Any) -> None:
        raise AIWriteAccessForbiddenError(
            "Invariant I6 violation: AI component has ZERO write access (Session.delete is forbidden)."
        )

    def commit(self) -> None:
        raise AIWriteAccessForbiddenError(
            "Invariant I6 violation: AI component has ZERO write access (Session.commit is forbidden)."
        )

    def flush(self, *args, **kwargs) -> None:
        raise AIWriteAccessForbiddenError(
            "Invariant I6 violation: AI component has ZERO write access (Session.flush is forbidden)."
        )

    def rollback(self) -> None:
        return self._db.rollback()

    def close(self) -> None:
        return self._db.close()

    def __getattr__(self, name: str) -> Any:
        # Safe passthrough for read-only inspectable attributes
        attr = getattr(self._db, name)
        if callable(attr) and name in {"merge", "refresh", "expire"}:
            raise AIWriteAccessForbiddenError(
                f"Invariant I6 violation: Session.{name} is not permitted for AI component."
            )
        return attr

def get_ai_readonly_session(db: Session) -> AIReadOnlySession:
    """Returns an AIReadOnlySession strictly barring database mutations."""
    return AIReadOnlySession(db)
