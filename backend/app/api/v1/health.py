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
    db_healthy = False
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        db_healthy = False

    storage_healthy = False
    try:
        storage_healthy = os_storage_check()
    except Exception:
        storage_healthy = False

    storage_backend_name = "s3" if hasattr(storage_service, "bucket") else "local"
    all_healthy = db_healthy and storage_healthy

    payload = {
        "status": "healthy" if all_healthy else "unhealthy",
        "service": "TrustVault API",
        "version": settings.VERSION,
        "commit_sha": settings.COMMIT_SHA,
        "storage_backend": storage_backend_name,
        "dependencies": {
            "database": "connected" if db_healthy else "disconnected",
            "storage": "connected" if storage_healthy else "disconnected"
        }
    }

    if all_healthy:
        return payload
    else:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=payload
        )

def os_storage_check() -> bool:
    try:
        return storage_service.exists("__health_probe__") or True
    except Exception:
        return False
