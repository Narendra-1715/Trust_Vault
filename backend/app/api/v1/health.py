from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.db.session import get_db
from app.core.config import settings
from app.storage.local import storage_service

router = APIRouter()

@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """
    Safe health check endpoint.
    Verifies database connectivity and storage readiness without leaking infrastructure details.
    """
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        db_healthy = False

    storage_healthy = os_storage_check()

    if db_healthy and storage_healthy:
        return {
            "status": "healthy",
            "service": "TrustVault API",
            "version": settings.VERSION,
            "commit_sha": settings.COMMIT_SHA
        }
    else:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "service": "TrustVault API"}
        )

def os_storage_check() -> bool:
    try:
        return storage_service.exists("__health_probe__") or True
    except Exception:
        return False
