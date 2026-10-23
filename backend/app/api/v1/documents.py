import os
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.db.session import get_db
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.schemas.document import DocumentResponse, DocumentListResponse, DocumentUpdate
from app.api.deps import get_current_user, get_request_id
from app.policies.authorization import AuthorizationPolicy
from app.storage.local import (
    storage_service,
    sanitize_filename,
    validate_file_content
)
from app.core.config import settings
from app.core.rate_limit import upload_limiter, check_rate_limit
from app.audit.service import log_audit_event

router = APIRouter()

def build_document_response(doc: Document, user: User, db: Session) -> DocumentResponse:
    """Helper to compute effective permission for requesting user."""
    if doc.owner_id == user.id:
        eff_perm = "owner"
    else:
        perm = AuthorizationPolicy.get_active_permission(db, doc.id, user.id)
        eff_perm = perm.permission_level if perm else ("admin" if user.role == "admin" else "none")

    owner = doc.owner
    return DocumentResponse(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        category=doc.category,
        owner_id=doc.owner_id,
        owner_email=owner.email if owner else None,
        owner_name=owner.display_name if owner else None,
        original_filename=doc.original_filename,
        detected_media_type=doc.detected_media_type,
        file_size=doc.file_size,
        checksum=doc.checksum,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        effective_permission=eff_perm
    )

@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    title: str = Form(...),
    description: Optional[str] = Form(None),
    category: str = Form("General"),
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

    # Stream to private storage and compute checksum
    storage_key = f"{uuid.uuid4().hex}.bin"
    hasher = hashlib.sha256()
    total_bytes = 0

    try:
        # Buffer into private storage
        def file_reader():
            nonlocal total_bytes
            while chunk := file.file.read(64 * 1024):
                total_bytes += len(chunk)
                if total_bytes > settings.MAX_FILE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="File exceeds maximum allowed size of 25MB"
                    )
                hasher.update(chunk)
                yield chunk

        # Write to local private storage
        class StreamWrapper:
            def __init__(self, gen):
                self.gen = gen
            def read(self, size=-1):
                try:
                    return next(self.gen)
                except StopIteration:
                    return b""

        total_bytes = storage_service.save_file(StreamWrapper(file_reader()), storage_key)
        checksum = hasher.hexdigest()

    except HTTPException:
        storage_service.delete_file(storage_key)
        raise
    except Exception as e:
        storage_service.delete_file(storage_key)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="File storage failed")

    # Save metadata in database
    new_doc = Document(
        owner_id=current_user.id,
        title=title.strip(),
        description=description.strip() if description else None,
        original_filename=safe_original_name,
        internal_storage_key=storage_key,
        detected_media_type=file.content_type or "application/octet-stream",
        file_size=total_bytes,
        checksum=checksum,
        category=category.strip() or "General"
    )

    db.add(new_doc)
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
    query: Optional[str] = Query(None, description="Search term for title or description"),
    category: Optional[str] = Query(None, description="Filter by category"),
    admin_inventory: bool = Query(False, description="Admin inventory view"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists only authorized documents for the current user.
    Server-side authorization is applied before returning records.
    """
    base_filter = [Document.deleted_at.is_(None)]

    # Authorization filtering
    if admin_inventory and current_user.role == "admin":
        # Admin inspecting inventory
        pass
    else:
        # User sees: 1) Owned documents, OR 2) Documents where user has an active grant
        permitted_doc_ids = db.query(DocumentPermission.document_id).filter(
            DocumentPermission.user_id == current_user.id,
            DocumentPermission.revoked_at.is_(None)
        ).scalar_subquery()

        base_filter.append(
            or_(
                Document.owner_id == current_user.id,
                Document.id.in_(permitted_doc_ids)
            )
        )

    if query:
        search_term = f"%{query.strip()}%"
        base_filter.append(
            or_(
                Document.title.ilike(search_term),
                Document.description.ilike(search_term),
                Document.original_filename.ilike(search_term)
            )
        )

    if category and category.lower() != "all":
        base_filter.append(Document.category.ilike(category.strip()))

    total = db.query(Document).filter(*base_filter).count()
    documents = (
        db.query(Document)
        .filter(*base_filter)
        .order_by(Document.created_at.desc())
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
    Enforces server-side authorization. Unauthorized access yields consistent 404.
    """
    doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
    AuthorizationPolicy.require_read(db, current_user, doc)
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
    - Live authorization verification against current database state (immediate revocation guarantee)
    - Returns streamed bytes with safe Content-Disposition headers and nosniff protection
    - Logs audit trail of download
    """
    request_id = get_request_id(request)
    doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
    
    # Live authorization check (will reject immediately if access was revoked)
    if not doc or not AuthorizationPolicy.can_read_document(db, current_user, doc):
        log_audit_event(
            db=db,
            action="document.download.denied",
            resource_type="document",
            resource_id=document_id,
            outcome="denied",
            actor_id=current_user.id,
            request_id=request_id,
            metadata={"reason": "Unauthorized download attempt"}
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if not storage_service.exists(doc.internal_storage_key):
        log_audit_event(
            db=db,
            action="document.download.error",
            resource_type="document",
            resource_id=doc.id,
            outcome="failure",
            actor_id=current_user.id,
            request_id=request_id,
            metadata={
                "error": "Storage payload missing from private volume",
                "storage_key": doc.internal_storage_key,
                "filename": doc.original_filename
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Storage object missing. Document data cannot be retrieved from private volume."
        )

    # Verify stored bytes against recorded checksum to catch any disk corruption
    if doc.checksum:
        actual_checksum = storage_service.compute_checksum(doc.internal_storage_key)
        if actual_checksum != doc.checksum:
            log_audit_event(
                db=db,
                action="document.download.corruption_error",
                resource_type="document",
                resource_id=doc.id,
                outcome="failure",
                actor_id=current_user.id,
                request_id=request_id,
                metadata={
                    "error": "Storage checksum mismatch detected. File data corrupted on volume.",
                    "expected_checksum": doc.checksum,
                    "actual_checksum": actual_checksum
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File integrity check failed. Stored checksum does not match volume bytes."
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

    safe_name = doc.original_filename.replace('"', '\\"')
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_name}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Length": str(doc.file_size)
    }

    return StreamingResponse(
        storage_service.read_file_stream(doc.internal_storage_key),
        media_type=doc.detected_media_type,
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
    doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
    AuthorizationPolicy.require_edit(db, current_user, doc)

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
    doc = db.query(Document).filter(Document.id == document_id, Document.deleted_at.is_(None)).first()
    AuthorizationPolicy.require_owner(db, current_user, doc)

    # Remove underlying file from private storage
    storage_service.delete_file(doc.internal_storage_key)
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
