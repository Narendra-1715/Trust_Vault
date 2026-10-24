"""Phase 3 Revocation and Streaming Automated Tests
Verifies:
1. Revoking a grant during an active streaming download cuts off the stream mid-flight.
2. A TTL grant expiring mid-stream cuts off the stream within the next check interval.
3. Strict zero-cache and security headers are present on all API and content routes.
4. Server-side session revocation with session_version immediately invalidates bearer tokens.
5. Permission epoch strictly increments on all grant lifecycle operations.
"""

import io
import time
from datetime import datetime, timedelta, timezone
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.session import UserSession
from app.models.audit import AuditEvent
from app.services.content import ContentService
from app.tests.conftest import get_auth_headers

def test_revoking_grant_during_streaming_terminates_stream(client: TestClient, test_users, test_db_session: Session):
    """
    Invariant I2 (Instant Revocation):
    Permission is verified synchronously against the database during streaming.
    A revoked user's stream is cut off mid-flight.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    viewer_user = test_users["viewer_a"]

    # 1. Owner uploads a multi-chunk document (e.g. 18 chunks = ~1.2 MB)
    content = b"%PDF-1.4 Multi-Chunk Dataset for Streaming Revocation Test\n" * 20000
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Midstream Revocation Doc", "category": "Legal"},
        files={"file": ("stream_doc.pdf", io.BytesIO(content), "application/pdf")}
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # 2. Owner grants read permission to viewer
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"email": viewer_user.email, "permission_level": "read"}
    )
    assert grant_res.status_code == 201

    # 3. Viewer requests stream generator with revalidate_chunks=1
    stream_gen = ContentService.stream(
        db=test_db_session,
        principal=viewer_user,
        document_id=doc_id,
        revalidate_chunks=1,
        revalidate_seconds=10.0
    )

    # 4. Viewer successfully consumes initial chunk
    chunk_1 = next(stream_gen)
    assert len(chunk_1) > 0

    # 5. Owner revokes viewer's permission mid-stream
    del_res = client.delete(
        f"/api/v1/documents/{doc_id}/permissions/{viewer_user.id}",
        headers=headers_owner
    )
    assert del_res.status_code == 204

    # 6. Viewer attempts to read subsequent chunks -> stream is cut off mid-flight!
    with pytest.raises(HTTPException) as exc_info:
        for _ in range(5):
            next(stream_gen)

    assert exc_info.value.status_code == 403
    assert "revoked" in exc_info.value.detail.lower()

    # 7. Verify audit event was recorded for mid-stream revocation
    test_db_session.expire_all()
    audit_ev = test_db_session.query(AuditEvent).filter(
        AuditEvent.resource_id == doc_id,
        AuditEvent.action == "document.download.revoked_mid_stream"
    ).first()
    assert audit_ev is not None

def test_ttl_grant_expiring_mid_stream_terminates_stream(client: TestClient, test_users, test_db_session: Session):
    """
    Invariant I2 (TTL Expiration Mid-Stream):
    A time-bound grant that expires mid-stream terminates the download stream immediately.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    viewer_user = test_users["viewer_a"]

    content = b"%PDF-1.4 Time-Limited Sensitive Report Content\n" * 20000
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "TTL Stream Doc", "category": "Finance"},
        files={"file": ("ttl_doc.pdf", io.BytesIO(content), "application/pdf")}
    )
    doc_id = upload_res.json()["id"]

    # Grant read permission with short TTL: expires in 1 second
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"email": viewer_user.email, "permission_level": "read", "expires_at": expires_at}
    )
    assert grant_res.status_code == 201

    # Viewer begins stream with short revalidation period (revalidate_seconds=0.2)
    stream_gen = ContentService.stream(
        db=test_db_session,
        principal=viewer_user,
        document_id=doc_id,
        revalidate_chunks=1,
        revalidate_seconds=0.2
    )

    # First chunk is allowed
    chunk_1 = next(stream_gen)
    assert len(chunk_1) > 0

    # Wait for TTL to expire
    time.sleep(1.2)

    # Next chunk consumption must fail due to expired TTL
    with pytest.raises(HTTPException) as exc_info:
        for _ in range(5):
            next(stream_gen)

    assert exc_info.value.status_code == 403
    assert "revoked" in exc_info.value.detail.lower() or "expired" in exc_info.value.detail.lower()

def test_security_headers_present_on_all_content_and_api_routes(client: TestClient, test_users, test_db_session: Session):
    """
    Verifies strict zero-cache security headers on both API routes and content download streams.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # 1. API endpoint check
    api_res = client.get("/api/v1/documents", headers=headers_owner)
    assert api_res.status_code == 200
    assert api_res.headers.get("Cache-Control") == "no-store, private"
    assert api_res.headers.get("Pragma") == "no-cache"
    assert api_res.headers.get("X-Content-Type-Options") == "nosniff"
    assert api_res.headers.get("Cross-Origin-Resource-Policy") == "same-origin"

    # 2. Content download endpoint check
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Headers Test Doc", "category": "Legal"},
        files={"file": ("headers.pdf", io.BytesIO(b"%PDF-1.4 Headers Payload"), "application/pdf")}
    )
    doc_id = upload_res.json()["id"]

    dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner)
    assert dl_res.status_code == 200
    assert dl_res.headers.get("Cache-Control") == "no-store, private"
    assert dl_res.headers.get("Pragma") == "no-cache"
    assert dl_res.headers.get("X-Content-Type-Options") == "nosniff"
    assert dl_res.headers.get("Cross-Origin-Resource-Policy") == "same-origin"
    assert dl_res.headers.get("Content-Disposition", "").startswith("attachment; filename=")

def test_immediate_session_revocation_invalidates_token(client: TestClient, test_users, test_db_session: Session):
    """
    Verifies that revoking a session record immediately invalidates the JWT bearer token without delay.
    """
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer_a@test.com", "password": "ViewerAPass123!"}
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    auth_header = {"Authorization": f"Bearer {token}"}

    # Verify session is valid
    me_res = client.get("/api/v1/auth/me", headers=auth_header)
    assert me_res.status_code == 200

    # Obtain current session id
    sessions_res = client.get("/api/v1/auth/sessions", headers=auth_header)
    assert sessions_res.status_code == 200
    session_id = sessions_res.json()[0]["id"]

    # Revoke this active session
    revoke_res = client.delete(f"/api/v1/auth/sessions/{session_id}", headers=auth_header)
    assert revoke_res.status_code == 204

    # Subsequent request with the same token must fail immediately (401 Unauthorized)
    me_after = client.get("/api/v1/auth/me", headers=auth_header)
    assert me_after.status_code == 401

def test_permission_epoch_increments_on_all_grant_changes(client: TestClient, test_users, test_db_session: Session):
    """
    Verifies that permission_epoch strictly increments on grant creation, modification, and revocation.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    viewer_email = "viewer_a@test.com"
    viewer_id = test_users["viewer_a"].id

    up = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Epoch Doc", "category": "General"},
        files={"file": ("epoch.pdf", io.BytesIO(b"%PDF-1.4 Epoch Payload"), "application/pdf")}
    )
    doc_id = up.json()["id"]

    doc = test_db_session.query(Document).filter(Document.id == doc_id).first()
    epoch_0 = doc.permission_epoch or 1

    # 1. Grant permission
    g1 = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"email": viewer_email, "permission_level": "view"}
    )
    assert g1.status_code == 201
    test_db_session.refresh(doc)
    epoch_1 = doc.permission_epoch
    assert epoch_1 > epoch_0

    # 2. Update permission
    g2 = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"email": viewer_email, "permission_level": "read"}
    )
    assert g2.status_code == 201
    test_db_session.refresh(doc)
    epoch_2 = doc.permission_epoch
    assert epoch_2 > epoch_1

    # 3. Revoke permission
    g3 = client.delete(
        f"/api/v1/documents/{doc_id}/permissions/{viewer_id}",
        headers=headers_owner
    )
    assert g3.status_code == 204
    test_db_session.refresh(doc)
    epoch_3 = doc.permission_epoch
    assert epoch_3 > epoch_2
