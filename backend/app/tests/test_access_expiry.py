import io
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers

def test_access_expiry_lifecycle(client: TestClient, test_users):
    """
    Verifies that:
    1. A grant without expiry works permanently.
    2. A grant with a future expiry works before expiration.
    3. An expired grant immediately denies access (404) for download & metadata read.
    4. Past expiry on creation is rejected (400).
    5. Revocation overrides future expiry.
    6. Non-owner cannot grant access.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    viewer_id = test_users["viewer_a"].id

    # 1. Upload a test document
    file_content = b"%PDF-1.4 confidential quarterly financial report"
    files = {"file": ("report.pdf", io.BytesIO(file_content), "application/pdf")}
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Quarterly Financials", "category": "Financial"},
        files=files
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # 2. Reject grant with past expiration date
    past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    past_grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read", "expires_at": past_time}
    )
    assert past_grant_res.status_code == 400
    assert "future" in past_grant_res.json()["detail"].lower()

    # 3. Grant with future expiration date
    future_time = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read", "expires_at": future_time}
    )
    assert grant_res.status_code == 201
    grant_data = grant_res.json()
    assert grant_data["status"] == "active"
    assert grant_data["is_expired"] is False
    assert grant_data["expires_at"] is not None

    # 4. Viewer can read and download while active
    assert client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer).status_code == 200
    dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert dl_res.status_code == 200
    assert dl_res.content == file_content

    # 5. List permissions as owner verifies expiry date and active status
    perms_res = client.get(f"/api/v1/documents/{doc_id}/permissions", headers=headers_owner)
    assert perms_res.status_code == 200
    perms_list = perms_res.json()
    assert len(perms_list) == 1
    assert perms_list[0]["status"] == "active"
    assert perms_list[0]["expires_at"] is not None

    # 6. Revocation overrides future expiration
    revoke_res = client.delete(
        f"/api/v1/documents/{doc_id}/permissions/{viewer_id}",
        headers=headers_owner
    )
    assert revoke_res.status_code == 204
    assert client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer).status_code == 404

def test_expired_grant_denial_and_audit(client: TestClient, test_users, test_db_session):
    """
    Directly tests that once expires_at is reached/passed, access is denied and
    audit event document.access.expired is generated.
    """
    from app.models.permission import DocumentPermission
    from app.models.audit import AuditEvent

    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    viewer_id = test_users["viewer_a"].id

    # Upload document
    files = {"file": ("secret.txt", io.BytesIO(b"top secret content"), "text/plain")}
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Secret", "category": "General"},
        files=files
    )
    doc_id = upload_res.json()["id"]

    # Grant with future expiry
    future_time = datetime.now(timezone.utc) + timedelta(minutes=5)
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read", "expires_at": future_time.isoformat()}
    )
    assert grant_res.status_code == 201

    # Simulate expiration by setting expires_at to 10 seconds ago directly in DB
    perm = test_db_session.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc_id,
        DocumentPermission.user_id == viewer_id
    ).first()
    perm.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    test_db_session.commit()

    # Now viewer tries to read metadata and download
    read_res = client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer)
    assert read_res.status_code == 404

    dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert dl_res.status_code == 404

    # Verify audit event document.access.expired was recorded
    audit_ev = test_db_session.query(AuditEvent).filter(
        AuditEvent.resource_id == doc_id,
        AuditEvent.action == "document.access.expired"
    ).first()
    assert audit_ev is not None
    assert audit_ev.outcome == "denied"
    assert audit_ev.actor_id == viewer_id
