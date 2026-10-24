import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.core.config import settings
from app.core.security import verify_password
from app.api.deps import get_current_user, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.schemas.backup import (
    BackupListResponse,
    BackupItemResponse,
    BackupCreateResponse,
    RestoreVerificationReportResponse
)
from app.schemas.admin import BackupRestoreRequest, BackupRestoreResponse
from app.services.backup import create_backup, list_backups, BackupConcurrencyError, BackupIntegrityError
from app.services.restore import verify_backup_archive, execute_restore

router = APIRouter()

@router.get("", response_model=BackupListResponse)
def get_backups_list(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns available encrypted disaster recovery backups and manifest summaries.
    Strictly restricted to authorized administrators.
    """
    AuthorizationPolicy.require_admin(current_user)
    items = list_backups()
    return BackupListResponse(
        total=len(items),
        backups=[BackupItemResponse(**b) for b in items]
    )

@router.post("/create", response_model=BackupCreateResponse, status_code=status.HTTP_201_CREATED)
def trigger_backup_creation(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates an encrypted, self-verified disaster recovery backup archive.
    Strictly restricted to authorized administrators.
    """
    AuthorizationPolicy.require_admin(current_user)
    request_id = get_request_id(request)

    try:
        result = create_backup(
            db=db,
            operator_id=current_user.id,
            request_id=request_id
        )
        return BackupCreateResponse(
            **result,
            message="Verified disaster recovery backup generated and encrypted successfully."
        )
    except BackupConcurrencyError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except BackupIntegrityError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Backup integrity validation failed: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate backup: {str(e)}"
        )

@router.post("/{backup_id}/verify", response_model=RestoreVerificationReportResponse)
def verify_backup_health(
    backup_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Runs a dry-run disaster recovery simulation in an isolated scratch sandbox.
    Verifies object SHA-256 checksums, schema compatibility, and audit chain continuity.
    Strictly restricted to authorized administrators.
    """
    AuthorizationPolicy.require_admin(current_user)

    if not backup_id or ".." in backup_id or "/" in backup_id or "\\" in backup_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid backup identifier.")

    report = verify_backup_archive(backup_id)
    return RestoreVerificationReportResponse(**report)

@router.post("/{backup_id}/restore", response_model=BackupRestoreResponse)
def execute_backup_restore(
    backup_id: str,
    restore_in: BackupRestoreRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes an explicitly authorized disaster recovery restoration.
    Requires strong reauthentication via current administrator password,
    explicit confirmation token ('RESTORE_DATABASE'), and sandboxed verification check.
    Strictly restricted to authorized administrators.
    """
    AuthorizationPolicy.require_admin(current_user)
    request_id = get_request_id(request)

    # 1. Mandatory Reauthentication
    if not verify_password(restore_in.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Reauthentication failed: Incorrect password"
        )

    # 2. Explicit Confirmation Token
    if restore_in.confirmation != "RESTORE_DATABASE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirmation phrase must be exactly 'RESTORE_DATABASE'"
        )

    if not backup_id or ".." in backup_id or "/" in backup_id or "\\" in backup_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid backup identifier.")

    # 3. Verify in sandbox first before applying
    verify_report = verify_backup_archive(backup_id)
    if not verify_report.get("is_valid", False):
        errors = verify_report.get("errors", ["Integrity verification failed"])
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot restore unverified or corrupt backup: {'; '.join(errors)}"
        )

    # 4. Perform live restoration
    try:
        res = execute_restore(
            backup_path_or_id=backup_id,
            db=db,
            confirm_destructive_overwrite=True,
            operator_id=current_user.id,
            request_id=request_id
        )
        return BackupRestoreResponse(
            success=True,
            backup_id=backup_id,
            restored_files_count=res.get("restored_files_count", 0),
            table_counts=res.get("table_counts", {}),
            message=f"Disaster recovery restore successfully applied from backup '{backup_id}'."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Disaster recovery restore execution failed: {str(e)}"
        )

@router.get("/{backup_id}/download")
def download_backup_archive(
    backup_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Securely downloads an encrypted backup archive (.tar.gz.enc).
    Strictly restricted to authorized administrators.
    """
    AuthorizationPolicy.require_admin(current_user)

    if not backup_id or ".." in backup_id or "/" in backup_id or "\\" in backup_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid backup identifier.")

    target_dir = os.path.abspath(settings.BACKUP_DIR)
    fpath = os.path.join(target_dir, f"{backup_id}.tar.gz.enc")
    if not os.path.exists(fpath):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Backup archive not found.")

    return FileResponse(
        path=fpath,
        media_type="application/octet-stream",
        filename=f"{backup_id}.tar.gz.enc"
    )
