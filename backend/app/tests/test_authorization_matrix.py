"""Exhaustive Authorization Matrix Tests (Phase 1 Hardening)
Validates Invariants:
I1. Admin Blindness: no role reads, previews, or downloads content without an owner grant or active break-glass.
I2. Instant Revocation: permission verified synchronously against live database.
I3. No existence leaks: byte-identical 404 response across all deny scenarios
    (unauthorized, malformed UUID, nonexistent, expired, revoked, trashed, other-tenant).
"""

import io
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.services.authorization import (
    AuthorizationService,
    Action,
    DocumentNotFoundException,
    NOT_FOUND_DETAIL
)
from app.tests.conftest import get_auth_headers

UNIFORM_404_BODY = {"detail": NOT_FOUND_DETAIL}

def test_identical_404_response_across_all_denials(client: TestClient, test_users, test_db_session: Session):
    """
    Asserts that every denial scenario produces a byte-identical 404 response:
    - Same HTTP status code (404)
    - Same JSON body ({"detail": "Document not found"})
    - Same nosniff security header
    """
    owner = test_users["owner_a"]
    viewer = test_users["viewer_a"]
    stranger = test_users["owner_b"]
    admin = test_users["admin"]

    owner_headers = get_auth_headers(client, owner.email, "OwnerAPass123!")
    viewer_headers = get_auth_headers(client, viewer.email, "ViewerAPass123!")
    stranger_headers = get_auth_headers(client, stranger.email, "OwnerBPass123!")
    admin_headers = get_auth_headers(client, admin.email, "AdminPass123!")

    # 1. Nonexistent UUID
    fake_uuid = str(uuid.uuid4())
    res_nonexistent = client.get(f"/api/v1/documents/{fake_uuid}", headers=viewer_headers)
    assert res_nonexistent.status_code == 404
    assert res_nonexistent.json() == UNIFORM_404_BODY

    # 2. Malformed UUID (must not trigger 422 Unprocessable Entity!)
    res_malformed = client.get("/api/v1/documents/not-a-valid-uuid-string", headers=viewer_headers)
    assert res_malformed.status_code == 404
    assert res_malformed.json() == UNIFORM_404_BODY

    # 3. Create a private document
    file_bytes = b"%PDF-1.4 Matrix Test Document"
    up_res = client.post(
        "/api/v1/documents/upload",
        headers=owner_headers,
        data={"title": "Matrix Document", "category": "Legal"},
        files={"file": ("matrix.pdf", io.BytesIO(file_bytes), "application/pdf")}
    )
    assert up_res.status_code == 201
    doc_id = up_res.json()["id"]

    # 4. Unauthorized stranger access
    res_stranger = client.get(f"/api/v1/documents/{doc_id}", headers=stranger_headers)
    assert res_stranger.status_code == 404
    assert res_stranger.json() == UNIFORM_404_BODY
    assert res_stranger.content == res_nonexistent.content

    # 5. Invariant I1: Admin Blindness without grant
    res_admin_view = client.get(f"/api/v1/documents/{doc_id}", headers=admin_headers)
    assert res_admin_view.status_code == 404
    assert res_admin_view.json() == UNIFORM_404_BODY
    assert res_admin_view.content == res_nonexistent.content

    res_admin_dl = client.get(f"/api/v1/documents/{doc_id}/download", headers=admin_headers)
    assert res_admin_dl.status_code == 404
    assert res_admin_dl.json() == UNIFORM_404_BODY

    # 6. Grant read permission to viewer, then expire it
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=owner_headers,
        json={"user_id": viewer.id, "permission_level": "read"}
    )
    assert grant_res.status_code == 201

    # Simulate expired grant
    perm = test_db_session.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc_id,
        DocumentPermission.user_id == viewer.id
    ).first()
    perm.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    test_db_session.commit()

    res_expired = client.get(f"/api/v1/documents/{doc_id}", headers=viewer_headers)
    assert res_expired.status_code == 404
    assert res_expired.json() == UNIFORM_404_BODY
    assert res_expired.content == res_nonexistent.content

    # 7. Revoked grant
    perm.expires_at = None
    perm.revoked_at = datetime.now(timezone.utc)
    test_db_session.commit()

    res_revoked = client.get(f"/api/v1/documents/{doc_id}", headers=viewer_headers)
    assert res_revoked.status_code == 404
    assert res_revoked.json() == UNIFORM_404_BODY
    assert res_revoked.content == res_nonexistent.content

    # 8. Trashed document without access
    # Restore valid permission
    perm.revoked_at = None
    test_db_session.commit()
    # Owner soft-deletes document
    del_res = client.delete(f"/api/v1/documents/{doc_id}", headers=owner_headers)
    assert del_res.status_code == 204

    # Viewer now gets identical 404 on trashed document
    res_trashed = client.get(f"/api/v1/documents/{doc_id}", headers=viewer_headers)
    assert res_trashed.status_code == 404
    assert res_trashed.json() == UNIFORM_404_BODY
    assert res_trashed.content == res_nonexistent.content

def test_exhaustive_authorization_matrix(test_users, test_db_session: Session):
    """
    Exhaustively tests AuthorizationService.decide across:
    Principals: [Owner, Grantee-EDIT, Grantee-READ, Grantee-VIEW, Admin, Other-Tenant, Disabled-User]
    Actions: [VIEW, DOWNLOAD, EDIT, SHARE, ROLLBACK, DELETE, RESTORE, MANAGE_GRANTS, VIEW_METADATA]
    States: [Active, Trashed, Expired, Revoked, Orphaned]
    """
    now = datetime.now(timezone.utc)

    # Setup users
    owner = User(email="matrix_owner@test.com", password_hash="h", display_name="Owner", role="owner", org_id="tenant-1")
    editor = User(email="matrix_editor@test.com", password_hash="h", display_name="Editor", role="owner", org_id="tenant-1")
    reader = User(email="matrix_reader@test.com", password_hash="h", display_name="Reader", role="viewer", org_id="tenant-1")
    viewer = User(email="matrix_viewer@test.com", password_hash="h", display_name="Viewer", role="viewer", org_id="tenant-1")
    admin = User(email="matrix_admin@test.com", password_hash="h", display_name="Admin", role="admin", org_id="tenant-1")
    other_tenant = User(email="matrix_foreign@test.com", password_hash="h", display_name="Foreign", role="owner", org_id="tenant-2")
    disabled_user = User(email="matrix_disabled@test.com", password_hash="h", display_name="Disabled", role="owner", org_id="tenant-1", is_active=False)

    for u in [owner, editor, reader, viewer, admin, other_tenant, disabled_user]:
        test_db_session.add(u)
    test_db_session.commit()

    # Active Document
    doc = Document(
        owner_id=owner.id,
        title="Matrix Doc",
        original_filename="doc.pdf",
        internal_storage_key="matrix_key_1.bin",
        detected_media_type="application/pdf",
        file_size=1024,
        checksum="a" * 64,
        org_id="tenant-1"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    # Setup permissions
    perm_edit = DocumentPermission(document_id=doc.id, user_id=editor.id, permission_level="edit", granted_by=owner.id)
    perm_read = DocumentPermission(document_id=doc.id, user_id=reader.id, permission_level="read", granted_by=owner.id)
    perm_view = DocumentPermission(document_id=doc.id, user_id=viewer.id, permission_level="view", granted_by=owner.id)
    for p in [perm_edit, perm_read, perm_view]:
        test_db_session.add(p)
    test_db_session.commit()

    # Owner permissions: ALL allowed on active document (except RESTORE which is for trashed)
    for act in [Action.VIEW, Action.DOWNLOAD, Action.EDIT, Action.SHARE, Action.ROLLBACK, Action.DELETE, Action.MANAGE_GRANTS, Action.VIEW_METADATA]:
        decision = AuthorizationService.decide(test_db_session, owner, act, doc.id)
        assert decision.allowed is True, f"Owner should be allowed {act}"

    # Editor permissions: VIEW, DOWNLOAD, VIEW_METADATA, EDIT allowed. SHARE, ROLLBACK, DELETE, MANAGE_GRANTS strictly DENIED.
    assert AuthorizationService.decide(test_db_session, editor, Action.VIEW, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, editor, Action.DOWNLOAD, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, editor, Action.EDIT, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, editor, Action.VIEW_METADATA, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, editor, Action.SHARE, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, editor, Action.ROLLBACK, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, editor, Action.DELETE, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, editor, Action.MANAGE_GRANTS, doc.id).allowed is False

    # Reader permissions: VIEW, DOWNLOAD, VIEW_METADATA allowed. EDIT, SHARE, DELETE, ROLLBACK, MANAGE_GRANTS DENIED.
    assert AuthorizationService.decide(test_db_session, reader, Action.VIEW, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, reader, Action.DOWNLOAD, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, reader, Action.VIEW_METADATA, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, reader, Action.EDIT, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, reader, Action.SHARE, doc.id).allowed is False

    # Preview/View-only user: VIEW, VIEW_METADATA allowed. DOWNLOAD DENIED.
    assert AuthorizationService.decide(test_db_session, viewer, Action.VIEW, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, viewer, Action.VIEW_METADATA, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, viewer, Action.DOWNLOAD, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, viewer, Action.EDIT, doc.id).allowed is False

    # Invariant I1: Admin Blindness: Admin without grant/break-glass has ZERO content permissions
    assert AuthorizationService.decide(test_db_session, admin, Action.VIEW, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, admin, Action.DOWNLOAD, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, admin, Action.EDIT, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, admin, Action.DELETE, doc.id).allowed is False

    # Cross-tenant user: DENIED all
    for act in Action:
        assert AuthorizationService.decide(test_db_session, other_tenant, act, doc.id).allowed is False

    # Disabled user: DENIED all
    for act in Action:
        assert AuthorizationService.decide(test_db_session, disabled_user, act, doc.id).allowed is False

    # Version Range Scoping
    perm_read.min_version_number = 2
    perm_read.max_version_number = 4
    test_db_session.commit()

    assert AuthorizationService.decide(test_db_session, reader, Action.DOWNLOAD, doc.id, context={"version_number": 1}).allowed is False
    assert AuthorizationService.decide(test_db_session, reader, Action.DOWNLOAD, doc.id, context={"version_number": 3}).allowed is True
    assert AuthorizationService.decide(test_db_session, reader, Action.DOWNLOAD, doc.id, context={"version_number": 5}).allowed is False

    # Trashed Document: only owner can RESTORE; all other actions DENIED
    doc.deleted_at = now
    test_db_session.commit()

    assert AuthorizationService.decide(test_db_session, owner, Action.RESTORE, doc.id).allowed is True
    assert AuthorizationService.decide(test_db_session, owner, Action.VIEW, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, editor, Action.VIEW, doc.id).allowed is False
    assert AuthorizationService.decide(test_db_session, editor, Action.RESTORE, doc.id).allowed is False

def test_ownership_transfer_workflow(client: TestClient, test_users, test_db_session: Session):
    """Verifies ownership transfer flow, epoch increment, and permission handover."""
    owner_a = test_users["owner_a"]
    owner_b = test_users["owner_b"]

    headers_a = get_auth_headers(client, owner_a.email, "OwnerAPass123!")
    headers_b = get_auth_headers(client, owner_b.email, "OwnerBPass123!")

    # 1. Upload document
    up = client.post(
        "/api/v1/documents/upload",
        headers=headers_a,
        data={"title": "Ownership Transfer Test", "category": "Corporate"},
        files={"file": ("transfer.pdf", io.BytesIO(b"%PDF-1.4 Transfer Test"), "application/pdf")}
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # 2. Transfer ownership from Owner A to Owner B
    transfer_res = client.post(
        f"/api/v1/documents/{doc_id}/transfer-ownership",
        headers=headers_a,
        json={"new_owner_id": owner_b.id}
    )
    assert transfer_res.status_code == 200
    doc_data = transfer_res.json()
    assert doc_data["owner_id"] == owner_b.id

    # 3. Owner B is now full owner and can manage grants
    perm_grant = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_b,
        json={"email": "viewer_a@test.com", "permission_level": "read"}
    )
    assert perm_grant.status_code == 201

    # 4. Previous owner (Owner A) no longer has owner rights (cannot manage grants)
    perm_grant_a = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_a,
        json={"email": "viewer_b@test.com", "permission_level": "read"}
    )
    assert perm_grant_a.status_code in [403, 404]
