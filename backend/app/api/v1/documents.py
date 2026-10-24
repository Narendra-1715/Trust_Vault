import os
import io
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.document_version import DocumentVersion
from app.models.permission import DocumentPermission
from app.models.document_key import DocumentKey
from app.schemas.document import DocumentResponse, DocumentListResponse, DocumentUpdate, OwnershipTransferRequest
from app.schemas.document_version import DocumentVersionResponse, DocumentVersionListResponse
from app.api.deps import get_current_user, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.services.authorization import AuthorizationService, Action, raise_not_found, get_admin_metadata_view
from app.services.content import ContentService
from app.services.preview import DocumentPreviewService
from app.storage.local import (
    storage_service,
    sanitize_filename,
    sanitize_content_disposition_filename,
    validate_file_content
)
from app.core.config import settings
from app.core.rate_limit import upload_limiter, check_rate_limit
from app.audit.service import log_audit_event
from app.notifications.service import create_security_notification, check_and_notify_repeated_denials
from app.services.classification_policy import get_security_policy, evaluate_download_access, VALID_CLASSIFICATIONS

router = APIRouter()

def build_document_response(doc: Document, user: User, db: Session) -> DocumentResponse:
    """Helper to compute effective permission for requesting user with Admin Blindness enforcement."""
    perm = None
    has_break_glass = False
    if doc.owner_id == user.id:
        eff_perm = "owner"
    else:
        perm = AuthorizationPolicy.get_active_permission(db, doc.id, user.id)
        if user.role == "admin":
            from app.services.authorization import AuthorizationService
            has_break_glass = AuthorizationService._has_active_break_glass(db, user.id, doc.id)
        eff_perm = perm.permission_level if perm else ("break_glass" if has_break_glass else "none")

    # Invariant I1: Admin Blindness
    # Admins without an explicit owner grant or active break-glass cannot view filenames or titles
    is_admin_blind = (user.role == "admin" and doc.owner_id != user.id and not perm and not has_break_glass)
    title = "[REDACTED - ADMIN BLINDNESS]" if is_admin_blind else doc.title
    filename = "[REDACTED - ADMIN BLINDNESS]" if is_admin_blind else doc.original_filename
    desc = None if is_admin_blind else doc.description

    owner = doc.owner
    current_ver = 1
    ver_count = 1
    if doc.versions:
        ver_count = len(doc.versions)
        for v in doc.versions:
            if v.is_current:
                current_ver = v.version_number
                break

    return DocumentResponse(
        id=doc.id,
        title=title,
        description=desc,
        category=doc.category,
        classification=doc.classification if hasattr(doc, "classification") and doc.classification else "Internal",
        owner_id=doc.owner_id,
        owner_email=owner.email if owner else None,
        owner_name=owner.display_name if owner else None,
        original_filename=filename,
        detected_media_type=doc.detected_media_type,
        file_size=doc.file_size,
        checksum=doc.checksum,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        deleted_at=doc.deleted_at,
        effective_permission=eff_perm,
        current_version_number=current_ver,
        version_count=ver_count
    )

@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    category: str = Form("General"),
    classification: str = Form("Internal"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Secure document upload endpoint:
    - Validates MIME type, extension, and magic-bytes
    - Calculates SHA-256 checksum during streaming
    - Stores file in private storage outside public root with randomized key
    - Records immutable audit event
    """
    request_id = get_request_id(request)
    check_rate_limit(request, upload_limiter, key_prefix="upload")

    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No file provided")

    safe_original_name = sanitize_filename(file.filename)
    _, ext = os.path.splitext(safe_original_name)

    # Read initial 512 bytes for signature validation
    header_bytes = await file.read(512)
    validate_file_content(header_bytes, ext, file.content_type or "")
    await file.seek(0)

    cleaned_classification = classification.strip() if classification else "Internal"
    if cleaned_classification not in VALID_CLASSIFICATIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid classification '{cleaned_classification}'. Allowed: {', '.join(VALID_CLASSIFICATIONS)}"
        )

    doc_id = str(uuid.uuid4())
    version_id = str(uuid.uuid4())

    try:
        storage_key, total_bytes, checksum = ContentService.encrypt_and_store(
            db=db,
            principal=current_user,
            document_id=doc_id,
            version_id=version_id,
            file_obj=file.file
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="File encryption and storage failed")

    # Save metadata in database
    new_doc = Document(
        id=doc_id,
        owner_id=current_user.id,
        title=title.strip(),
        description=description.strip() if description else None,
        original_filename=safe_original_name,
        internal_storage_key=storage_key,
        detected_media_type=file.content_type or "application/octet-stream",
        file_size=total_bytes,
        checksum=checksum,
        category=category.strip() or "General",
        classification=cleaned_classification,
        org_id=getattr(current_user, "org_id", "default-org")
    )
    db.add(new_doc)

    initial_version = DocumentVersion(
        id=version_id,
        document_id=new_doc.id,
        version_number=1,
        storage_key=storage_key,
        original_filename=safe_original_name,
        file_size=total_bytes,
        checksum=checksum,
        detected_media_type=new_doc.detected_media_type,
        change_summary="Initial upload",
        uploaded_by=current_user.id,
        is_current=True,
    )
    db.add(initial_version)
    db.commit()
    db.refresh(new_doc)

    log_audit_event(
        db=db,
        action="document.upload",
        resource_type="document",
        resource_id=new_doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "filename": safe_original_name,
            "file_size": total_bytes,
            "category": new_doc.category,
            "checksum": checksum
        }
    )

    return build_document_response(new_doc, current_user, db)

@router.get("", response_model=DocumentListResponse)
def list_documents(
    query: Optional[str] = Query(None, description="Search term for title, description, or filename"),
    category: Optional[str] = Query(None, description="Filter by category"),
    file_type: Optional[str] = Query(None, description="Filter by file extension or media type"),
    owner_id: Optional[str] = Query(None, description="Filter by owner user ID"),
    date_from: Optional[datetime] = Query(None, description="Filter documents created on or after this timestamp"),
    date_to: Optional[datetime] = Query(None, description="Filter documents created on or before this timestamp"),
    permission_filter: Optional[str] = Query(None, description="Filter by 'owned' or 'shared'"),
    sort_by: Optional[str] = Query("created_at", description="Sort field: created_at, title, file_size"),
    sort_order: Optional[str] = Query("desc", description="Sort direction: asc or desc"),
    admin_inventory: bool = Query(False, description="Admin inventory view"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists only authorized documents for the current user.
    Server-side authorization is applied before returning records.
    Supports advanced filtering and multi-attribute sorting with zero metadata leakage.
    """
    base_filter = [Document.deleted_at.is_(None)]

    # Authorization filtering
    if admin_inventory and current_user.role == "admin":
        # Admin inspecting inventory
        pass
    else:
        # User sees: 1) Owned documents, OR 2) Documents where user has an active, non-expired grant
        now_utc = datetime.now(timezone.utc)
        permitted_doc_ids = db.query(DocumentPermission.document_id).filter(
            DocumentPermission.user_id == current_user.id,
            DocumentPermission.revoked_at.is_(None),
            or_(
                DocumentPermission.expires_at.is_(None),
                DocumentPermission.expires_at > now_utc
            )
        ).scalar_subquery()

        base_filter.append(
            or_(
                Document.owner_id == current_user.id,
                Document.id.in_(permitted_doc_ids)
            )
        )

    # Search query
    if query and query.strip():
        search_term = f"%{query.strip()}%"
        base_filter.append(
            or_(
                Document.title.ilike(search_term),
                Document.description.ilike(search_term),
                Document.original_filename.ilike(search_term)
            )
        )

    # Category filter
    if category and category.lower() != "all":
        base_filter.append(Document.category.ilike(category.strip()))

    # File type / extension filter
    if file_type and file_type.strip() and file_type.lower() != "all":
        cleaned_ft = file_type.strip().lower()
        base_filter.append(
            or_(
                Document.detected_media_type.ilike(f"%{cleaned_ft}%"),
                Document.original_filename.ilike(f"%.{cleaned_ft}"),
                Document.original_filename.ilike(f"%{cleaned_ft}")
            )
        )

    # Specific owner filter
    if owner_id and owner_id.strip():
        base_filter.append(Document.owner_id == owner_id.strip())

    # Date range filters
    if date_from:
        base_filter.append(Document.created_at >= date_from)
    if date_to:
        base_filter.append(Document.created_at <= date_to)

    # Permission filter (owned vs shared)
    if permission_filter == "owned":
        base_filter.append(Document.owner_id == current_user.id)
    elif permission_filter == "shared":
        base_filter.append(Document.owner_id != current_user.id)

    # Sorting
    sort_column = Document.created_at
    if sort_by == "title":
        sort_column = Document.title
    elif sort_by == "file_size":
        sort_column = Document.file_size
    elif sort_by == "created_at":
        sort_column = Document.created_at

    if sort_order == "asc":
        order_clause = sort_column.asc()
    else:
        order_clause = sort_column.desc()

    total = db.query(Document).filter(*base_filter).count()
    documents = (
        db.query(Document)
        .filter(*base_filter)
        .order_by(order_clause)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    doc_responses = [build_document_response(d, current_user, db) for d in documents]
    return DocumentListResponse(
        total=total,
        page=page,
        page_size=page_size,
        documents=doc_responses
    )

@router.get("/trash", response_model=DocumentListResponse)
def list_trashed_documents(
    query: Optional[str] = Query(None, description="Search term for title, description, or filename"),
    category: Optional[str] = Query(None, description="Filter by category"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists soft-deleted documents.
    - Regular users see only their own deleted documents.
    - Administrators see all deleted documents across the organization.
    Storage payload binaries were shredded upon deletion; metadata is preserved for audit trail.
    """
    base_filter = [Document.deleted_at.isnot(None)]

    if current_user.role != "admin":
        base_filter.append(Document.owner_id == current_user.id)

    if query and query.strip():
        search_term = f"%{query.strip()}%"
        base_filter.append(
            or_(
                Document.title.ilike(search_term),
                Document.description.ilike(search_term),
                Document.original_filename.ilike(search_term)
            )
        )

    if category and category.strip() and category.lower() != "all":
        base_filter.append(Document.category.ilike(category.strip()))

    total = db.query(Document).filter(*base_filter).count()
    documents = (
        db.query(Document)
        .filter(*base_filter)
        .order_by(Document.deleted_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    doc_responses = [build_document_response(d, current_user, db) for d in documents]
    return DocumentListResponse(
        total=total,
        page=page,
        page_size=page_size,
        documents=doc_responses
    )

@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_details(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns document metadata.
    Enforces server-side authorization via central AuthorizationService.
    Unauthorized or nonexistent documents yield identical 404 responses.
    """
    doc = AuthorizationService.enforce(db, current_user, Action.VIEW, document_id)
    return build_document_response(doc, current_user, db)

@router.get("/{document_id}/download")
def download_document(
    document_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Authorized streaming download:
    - Central AuthorizationService verification against current database state
    - Returns streamed bytes with safe Content-Disposition headers and nosniff protection
    - Logs audit trail of download
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.DOWNLOAD, document_id, request_id=request_id)

    stream_gen = ContentService.stream(
        db=db,
        principal=current_user,
        document_id=document_id,
        request_id=request_id
    )

    log_audit_event(
        db=db,
        action="document.download",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={"filename": doc.original_filename, "checksum": doc.checksum}
    )

    safe_name = sanitize_content_disposition_filename(doc.original_filename)
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_name}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, private",
        "Pragma": "no-cache",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Content-Length": str(doc.file_size)
    }

    return StreamingResponse(
        stream_gen,
        media_type=doc.detected_media_type,
        headers=headers
    )

@router.get("/{document_id}/preview-info")
def get_document_preview_info(
    document_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns pagination and rendering metadata for document preview.
    Enforces Action.VIEW authorization (allowed for preview, view, read, edit, owner).
    """
    request_id = get_request_id(request)
    return DocumentPreviewService.get_preview_info(
        db=db,
        principal=current_user,
        document_id=document_id,
        request_id=request_id
    )

@router.get("/{document_id}/pages/{page_num}")
def get_document_page_preview(
    document_id: str,
    page_num: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Authorized Sandboxed Document Page Preview (Phase 8):
    - Converted to raster PNG image server-side in isolated memory pipeline.
    - Raw PDF/DOCX bytes are NEVER returned or exposed to client browser.
    - Dynamic forensic watermarking (requester email, UTC timestamp, request ID) burned into pixel array.
    - Strict Content Security Policy (CSP) blocking script execution and objects.
    - Enforces Action.VIEW (viewers/previewers can view, but cannot download).
    """
    request_id = get_request_id(request)
    png_bytes, total_pages = DocumentPreviewService.render_page(
        db=db,
        principal=current_user,
        document_id=document_id,
        page_num=page_num,
        request_id=request_id
    )

    headers = {
        "Content-Type": "image/png",
        "Content-Disposition": f'inline; filename="preview-page-{page_num}.png"',
        "Cache-Control": "no-store, private",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox; frame-ancestors 'none'",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-TrustVault-Page": str(page_num),
        "X-TrustVault-Total-Pages": str(total_pages),
        "X-TrustVault-Watermark": "applied",
        "Content-Length": str(len(png_bytes))
    }

    return StreamingResponse(
        io.BytesIO(png_bytes),
        media_type="image/png",
        headers=headers
    )

@router.patch("/{document_id}", response_model=DocumentResponse)
def update_document_metadata(
    document_id: str,
    update_data: DocumentUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Updates document metadata.
    Enforces 'edit' authorization level. Viewers cannot edit.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.EDIT, document_id, request_id=request_id)

    changes = {}
    if update_data.title is not None and update_data.title.strip():
        changes["old_title"] = doc.title
        doc.title = update_data.title.strip()
        changes["new_title"] = doc.title
    if update_data.description is not None:
        changes["description_updated"] = True
        doc.description = update_data.description.strip()
    if update_data.category is not None and update_data.category.strip():
        changes["old_category"] = doc.category
        doc.category = update_data.category.strip()
        changes["new_category"] = doc.category
    if update_data.classification is not None and update_data.classification.strip():
        target_cl = update_data.classification.strip()
        if target_cl not in VALID_CLASSIFICATIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid classification '{target_cl}'. Allowed: {', '.join(VALID_CLASSIFICATIONS)}"
            )
        from app.services.classification_policy import can_user_change_classification
        curr_pol = get_security_policy(db, doc.classification)
        targ_pol = get_security_policy(db, target_cl)
        allowed, reason = can_user_change_classification(doc, current_user, target_cl, curr_pol, targ_pol)
        if not allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
        changes["old_classification"] = doc.classification
        doc.classification = target_cl
        changes["new_classification"] = doc.classification

    db.commit()
    db.refresh(doc)

    log_audit_event(
        db=db,
        action="document.update",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={"changes": changes}
    )

    return build_document_response(doc, current_user, db)

@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_document(
    document_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deletes document.
    Enforces ownership requirement. Editors and Viewers cannot delete.
    Cleans up private storage and marks deleted_at in database.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.DELETE, document_id, request_id=request_id)

    # Remove underlying file from private storage
    storage_service.delete_file(doc.internal_storage_key)
    for v in doc.versions:
        if v.storage_key != doc.internal_storage_key:
            storage_service.delete_file(v.storage_key)
    # Crypto-shredding: destroy wrapped DEKs to render all backup/disk copies unrecoverable
    ContentService.crypto_shred(db, doc.id)
    doc.deleted_at = datetime.now(timezone.utc)
    db.commit()

    log_audit_event(
        db=db,
        action="document.delete",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={"title": doc.title}
    )
    return None

# ==============================================================================
# Document Version Control Endpoints
# ==============================================================================

@router.get("/{document_id}/versions", response_model=DocumentVersionListResponse)
def list_document_versions(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists version history for an authorized document.
    Enforces server-side VIEW_METADATA authorization via central AuthorizationService.
    """
    doc = AuthorizationService.enforce(db, current_user, Action.VIEW_METADATA, document_id)

    versions = (
        db.query(DocumentVersion)
        .filter(DocumentVersion.document_id == document_id)
        .order_by(DocumentVersion.version_number.desc())
        .all()
    )

    ver_responses = []
    for v in versions:
        ver_responses.append(
            DocumentVersionResponse(
                id=v.id,
                document_id=v.document_id,
                version_number=v.version_number,
                original_filename=v.original_filename,
                file_size=v.file_size,
                checksum=v.checksum,
                detected_media_type=v.detected_media_type,
                change_summary=v.change_summary,
                uploaded_by=v.uploaded_by,
                uploader_name=v.uploader.display_name if v.uploader else None,
                uploader_email=v.uploader.email if v.uploader else None,
                is_current=v.is_current,
                created_at=v.created_at,
            )
        )

    return DocumentVersionListResponse(
        total=len(ver_responses),
        versions=ver_responses
    )

@router.post("/{document_id}/versions", response_model=DocumentVersionResponse, status_code=status.HTTP_201_CREATED)
async def upload_document_version(
    document_id: str,
    request: Request,
    file: UploadFile = File(...),
    change_summary: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Upload a new revised document version:
    - Enforces 'edit' authorization level (viewers cannot upload revisions).
    - Preserves previous versions as immutable records.
    - Validates file content, extension, size, and calculates SHA-256.
    - Stores file in private storage under a new unique key.
    - Updates Document pointer to new current version.
    - Records audit event.
    """
    request_id = get_request_id(request)
    check_rate_limit(request, upload_limiter, key_prefix="upload")

    doc = AuthorizationService.enforce(db, current_user, Action.EDIT, document_id, request_id=request_id)

    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No file provided")

    safe_original_name = sanitize_filename(file.filename)
    _, ext = os.path.splitext(safe_original_name)

    # Read initial 512 bytes for signature validation
    header_bytes = await file.read(512)
    validate_file_content(header_bytes, ext, file.content_type or "")
    await file.seek(0)

    new_version_id = str(uuid.uuid4())
    try:
        storage_key, total_bytes, checksum = ContentService.encrypt_and_store(
            db=db,
            principal=current_user,
            document_id=doc.id,
            version_id=new_version_id,
            file_obj=file.file
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Version encryption and storage failed")

    # Determine next version number
    max_ver = db.query(func.max(DocumentVersion.version_number)).filter(DocumentVersion.document_id == doc.id).scalar() or 0
    next_ver = max_ver + 1

    # Mark existing versions as not current
    db.query(DocumentVersion).filter(DocumentVersion.document_id == doc.id).update({"is_current": False})

    new_version = DocumentVersion(
        id=new_version_id,
        document_id=doc.id,
        version_number=next_ver,
        storage_key=storage_key,
        original_filename=safe_original_name,
        file_size=total_bytes,
        checksum=checksum,
        detected_media_type=file.content_type or "application/octet-stream",
        change_summary=change_summary.strip() if change_summary else None,
        uploaded_by=current_user.id,
        is_current=True,
    )
    db.add(new_version)

    # Update document pointer
    doc.internal_storage_key = storage_key
    doc.checksum = checksum
    doc.file_size = total_bytes
    doc.original_filename = safe_original_name
    doc.detected_media_type = file.content_type or doc.detected_media_type
    doc.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(new_version)

    log_audit_event(
        db=db,
        action="document.version.create",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "version_number": next_ver,
            "filename": safe_original_name,
            "file_size": total_bytes,
            "checksum": checksum,
            "change_summary": change_summary
        }
    )

    return DocumentVersionResponse(
        id=new_version.id,
        document_id=new_version.document_id,
        version_number=new_version.version_number,
        original_filename=new_version.original_filename,
        file_size=new_version.file_size,
        checksum=new_version.checksum,
        detected_media_type=new_version.detected_media_type,
        change_summary=new_version.change_summary,
        uploaded_by=new_version.uploaded_by,
        uploader_name=current_user.display_name,
        uploader_email=current_user.email,
        is_current=True,
        created_at=new_version.created_at
    )

@router.get("/{document_id}/versions/{version_id}/download")
def download_document_version(
    document_id: str,
    version_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Authorized streaming download of a specific document version.
    Validates server-side permissions and storage checksum before streaming.
    """
    request_id = get_request_id(request)
    # Enforce authorization on document FIRST before probing versions
    doc = AuthorizationService.enforce(
        db,
        current_user,
        Action.DOWNLOAD,
        document_id,
        request_id=request_id
    )

    version = db.query(DocumentVersion).filter(
        DocumentVersion.id == version_id,
        DocumentVersion.document_id == document_id
    ).first()

    if not version:
        raise_not_found(db, current_user.id)

    # Re-verify version range scoping if grant is version-scoped
    AuthorizationService.enforce(
        db,
        current_user,
        Action.DOWNLOAD,
        document_id,
        context={"version_number": version.version_number},
        request_id=request_id
    )

    safe_name = sanitize_content_disposition_filename(version.original_filename)
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_name}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, private",
        "Pragma": "no-cache",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Content-Length": str(version.file_size)
    }

    stream_gen = ContentService.stream(
        db=db,
        principal=current_user,
        document_id=document_id,
        version_id=version_id,
        request_id=request_id
    )

    log_audit_event(
        db=db,
        action="document.version.download",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "version_id": version.id,
            "version_number": version.version_number,
            "filename": version.original_filename,
            "checksum": version.checksum
        }
    )

    return StreamingResponse(
        stream_gen,
        media_type=version.detected_media_type,
        headers=headers
    )

@router.post("/{document_id}/versions/{version_id}/restore", response_model=DocumentVersionResponse)
def restore_document_version(
    document_id: str,
    version_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Restores an earlier version by creating a new current version from its content,
    preserving immutable version history.
    Requires 'edit' authorization.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.ROLLBACK, document_id, request_id=request_id)

    version_to_restore = db.query(DocumentVersion).filter(
        DocumentVersion.id == version_id,
        DocumentVersion.document_id == document_id
    ).first()

    if not version_to_restore:
        raise_not_found(db, current_user.id)

    if not storage_service.exists(version_to_restore.storage_key):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Original version file missing from private storage. Cannot restore."
        )

    restored_version_id = str(uuid.uuid4())

    # Stream plaintext from version_to_restore and re-encrypt under restored_version_id
    try:
        plaintext_stream = ContentService.stream(
            db=db,
            principal=current_user,
            document_id=doc.id,
            version_id=version_to_restore.id,
            request_id=request_id
        )

        class PlaintextStreamWrapper:
            def __init__(self, gen):
                self.gen = gen
                self.buf = bytearray()
            def read(self, size=-1):
                if size == -1:
                    chunks = list(self.gen)
                    res = bytes(self.buf) + b"".join(chunks)
                    self.buf = bytearray()
                    return res
                while len(self.buf) < size:
                    try:
                        chunk = next(self.gen)
                        self.buf.extend(chunk)
                    except StopIteration:
                        break
                data = bytes(self.buf[:size])
                self.buf = self.buf[size:]
                return data

        new_storage_key, total_bytes, checksum = ContentService.encrypt_and_store(
            db=db,
            principal=current_user,
            document_id=doc.id,
            version_id=restored_version_id,
            file_obj=PlaintextStreamWrapper(plaintext_stream)
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to copy and re-encrypt version payload: {e}")

    max_ver = db.query(func.max(DocumentVersion.version_number)).filter(DocumentVersion.document_id == doc.id).scalar() or 0
    next_ver = max_ver + 1

    # Mark existing versions not current
    db.query(DocumentVersion).filter(DocumentVersion.document_id == doc.id).update({"is_current": False})

    restored_version = DocumentVersion(
        id=restored_version_id,
        document_id=doc.id,
        version_number=next_ver,
        storage_key=new_storage_key,
        original_filename=version_to_restore.original_filename,
        file_size=total_bytes,
        checksum=checksum,
        detected_media_type=version_to_restore.detected_media_type,
        change_summary=f"Restored from version {version_to_restore.version_number}",
        uploaded_by=current_user.id,
        is_current=True,
    )
    db.add(restored_version)

    doc.internal_storage_key = new_storage_key
    doc.checksum = checksum
    doc.file_size = total_bytes
    doc.original_filename = version_to_restore.original_filename
    doc.detected_media_type = version_to_restore.detected_media_type
    doc.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(restored_version)

    log_audit_event(
        db=db,
        action="document.version.restore",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={
            "restored_from_version": version_to_restore.version_number,
            "new_version_number": next_ver,
            "checksum": version_to_restore.checksum
        }
    )

    return DocumentVersionResponse(
        id=restored_version.id,
        document_id=restored_version.document_id,
        version_number=restored_version.version_number,
        original_filename=restored_version.original_filename,
        file_size=restored_version.file_size,
        checksum=restored_version.checksum,
        detected_media_type=restored_version.detected_media_type,
        change_summary=restored_version.change_summary,
        uploaded_by=restored_version.uploaded_by,
        uploader_name=current_user.display_name,
        uploader_email=current_user.email,
        is_current=True,
        created_at=restored_version.created_at
    )

@router.post("/{document_id}/transfer-ownership", response_model=DocumentResponse)
def transfer_document_ownership(
    document_id: str,
    req_body: OwnershipTransferRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ownership transfer workflow:
    - Only the current document owner can transfer ownership.
    - Scoped per organization tenant.
    - Increments permission_epoch and logs tamper-evident audit record.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.transfer_ownership(
        db=db,
        document_id=document_id,
        current_owner=current_user,
        new_owner_id=req_body.new_owner_id,
        request_id=request_id
    )
    return build_document_response(doc, current_user, db)

@router.post("/{document_id}/restore", response_model=DocumentResponse)
def restore_trashed_document(
    document_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Restores a soft-deleted document from trash.
    Only the document owner can restore their document.
    """
    request_id = get_request_id(request)
    doc = AuthorizationService.enforce(db, current_user, Action.RESTORE, document_id, request_id=request_id)
    doc.deleted_at = None
    doc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(doc)
    log_audit_event(
        db=db,
        action="document.restore",
        resource_type="document",
        resource_id=doc.id,
        outcome="success",
        actor_id=current_user.id,
        request_id=request_id,
        metadata={"title": doc.title}
    )
    return build_document_response(doc, current_user, db)

