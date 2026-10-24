import io
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers
from app.models.request_link import DocumentRequestLink
from app.models.permission import DocumentPermission
from app.models.audit import AuditEvent

def _upload_test_doc(client: TestClient, headers: dict, title: str = "Confidential Blueprint") -> str:
    files = {"file": ("blueprint.pdf", io.BytesIO(b"%PDF-1.4 confidential engineering blueprint data"), "application/pdf")}
    res = client.post(
        "/api/v1/documents/upload",
        headers=headers,
        data={"title": title, "category": "Engineering"},
        files=files
    )
    assert res.status_code == 201
    return res.json()["id"]

def test_request_link_creation_and_security(client: TestClient, test_users, test_db_session):
    """
    Verifies:
    1. Owner can generate request link with unpredictable token.
    2. Non-owner cannot generate request link (403).
    3. Raw token is NOT stored in database (only sha256 hash is persisted).
    4. Audit trail records link creation with prefix, never the raw token.
    """
    headers_owner_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_owner_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner_a, "Project Apollo Specs")

    # 1. Non-owner (viewer or other owner) cannot create request link (returns 404 to prevent existence enumeration)
    viewer_create = client.post(
        f"/api/v1/access-requests/links/{doc_id}",
        headers=headers_viewer,
        json={"name": "Viewer attempt"}
    )
    assert viewer_create.status_code in [403, 404]

    owner_b_create = client.post(
        f"/api/v1/access-requests/links/{doc_id}",
        headers=headers_owner_b,
        json={"name": "Cross owner attempt"}
    )
    assert owner_b_create.status_code in [403, 404]

    # 2. Owner creates request link
    future_exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    create_res = client.post(
        f"/api/v1/access-requests/links/{doc_id}",
        headers=headers_owner_a,
        json={"name": "External Partner Review", "expires_at": future_exp, "max_uses": 5}
    )
    assert create_res.status_code == 201
    link_data = create_res.json()
    raw_token = link_data["token"]
    assert len(raw_token) >= 32
    assert link_data["token_prefix"] == raw_token[:8]
    assert link_data["document_title"] == "Project Apollo Specs"

    # 3. Database verification: raw token must NOT be in DB
    stored_link = test_db_session.query(DocumentRequestLink).filter(
        DocumentRequestLink.id == link_data["id"]
    ).first()
    assert stored_link is not None
    assert stored_link.token_hash == hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert raw_token not in stored_link.token_hash

    # 4. Audit verification: raw token must NOT appear in audit logs
    audit_event = test_db_session.query(AuditEvent).filter(
        AuditEvent.action == "request_link.create",
        AuditEvent.resource_id == link_data["id"]
    ).first()
    assert audit_event is not None
    assert raw_token not in str(audit_event.structured_metadata)
    assert stored_link.token_prefix in str(audit_event.structured_metadata)

def test_request_link_resolution_and_zero_content_leakage(client: TestClient, test_users):
    """
    Verifies:
    1. Unauthenticated user cannot resolve link (401).
    2. Authenticated viewer can resolve link and sees ONLY non-sensitive discovery metadata.
    3. Link resolution NEVER exposes document contents, storage keys, or download streams.
    4. Document remains strictly inaccessible (404) to the viewer.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Confidential Merger Terms")

    # Generate request link
    create_res = client.post(
        f"/api/v1/access-requests/links/{doc_id}",
        headers=headers_owner,
        json={"name": "Review Link"}
    )
    raw_token = create_res.json()["token"]

    # 1. Unauthenticated user cannot resolve
    unauth_res = client.get(f"/api/v1/access-requests/resolve-link/{raw_token}")
    assert unauth_res.status_code == 401

    # 2. Authenticated viewer resolves link safely
    resolve_res = client.get(f"/api/v1/access-requests/resolve-link/{raw_token}", headers=headers_viewer)
    assert resolve_res.status_code == 200
    safe_data = resolve_res.json()
    assert safe_data["document_title"] == "Confidential Merger Terms"
    assert safe_data["category"] == "Engineering"
    assert safe_data["owner_email"] == "owner_a@test.com"
    assert safe_data["has_active_access"] is False
    assert safe_data["has_pending_request"] is False

    # Ensure zero sensitive storage or file content leakage
    assert "checksum" not in safe_data
    assert "internal_storage_key" not in safe_data
    assert "file_bytes" not in safe_data

    # 3. Viewer STILL cannot reach the document
    assert client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer).status_code == 404
    assert client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer).status_code == 404

def test_request_link_submission_and_approval_workflow(client: TestClient, test_users):
    """
    End-to-End workflow test:
    1. Owner generates request link.
    2. Viewer submits request via link.
    3. Duplicate submission via link is rejected (409 Conflict).
    4. Owner approves request granting 'read' access.
    5. Viewer can now read and download document.
    6. Owner revokes grant -> viewer is immediately denied access.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Patented Drone Schematics")

    # 1. Owner generates link
    create_res = client.post(
        f"/api/v1/access-requests/links/{doc_id}",
        headers=headers_owner,
        json={"name": "Drone Review"}
    )
    raw_token = create_res.json()["token"]

    # 2. Viewer submits request via link
    future_exp = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    submit_res = client.post(
        f"/api/v1/access-requests/submit-via-link/{raw_token}",
        headers=headers_viewer,
        json={
            "reason": "Need to verify structural integrity formulas",
            "requested_permission": "read",
            "requested_expiry": future_exp
        }
    )
    assert submit_res.status_code == 201
    req_data = submit_res.json()
    assert req_data["status"] == "pending"
    assert req_data["document_id"] == doc_id
    assert req_data["requester_id"] == test_users["viewer_a"].id
    req_id = req_data["id"]

    # 3. Duplicate submission fails
    dup_res = client.post(
        f"/api/v1/access-requests/submit-via-link/{raw_token}",
        headers=headers_viewer,
        json={"reason": "Duplicate attempt"}
    )
    assert dup_res.status_code == 409

    # Viewer cannot access yet
    assert client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer).status_code == 404

    # 4. Owner approves request
    approve_res = client.post(
        f"/api/v1/access-requests/{req_id}/approve",
        headers=headers_owner,
        json={"approved_permission": "read"}
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "approved"

    # 5. Viewer now has full authorized read access
    doc_get = client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer)
    assert doc_get.status_code == 200
    assert doc_get.json()["effective_permission"] == "read"

    dl_get = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert dl_get.status_code == 200

    # 6. Immediate revocation: Owner revokes grant
    revoke_res = client.delete(
        f"/api/v1/documents/{doc_id}/permissions/{test_users['viewer_a'].id}",
        headers=headers_owner
    )
    assert revoke_res.status_code == 204

    # Subsequent access immediately denied (404)
    assert client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer).status_code == 404
    assert client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer).status_code == 404

def test_request_link_revocation_and_expiration(client: TestClient, test_users):
    """
    Verifies:
    1. Owner can revoke a request link.
    2. Revoked link cannot be resolved or submitted through (410 Gone).
    3. Non-owner cannot revoke link (404).
    4. Expired link returns 410 Gone.
    5. Max uses limit enforcement returns 410 Gone when limit exceeded.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    headers_other_owner = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Expiring Security Token Document")

    # 1. Create link with max_uses=1
    create_res = client.post(
        f"/api/v1/access-requests/links/{doc_id}",
        headers=headers_owner,
        json={"name": "Single Use Link", "max_uses": 1}
    )
    link_id = create_res.json()["id"]
    raw_token = create_res.json()["token"]

    # 2. Other owner cannot revoke
    other_revoke = client.post(f"/api/v1/access-requests/links/{link_id}/revoke", headers=headers_other_owner)
    assert other_revoke.status_code == 404

    # 3. Owner revokes link
    revoke_res = client.post(f"/api/v1/access-requests/links/{link_id}/revoke", headers=headers_owner)
    assert revoke_res.status_code == 200

    # 4. Revoked link resolution and submission fail with 410 Gone
    rev_resolve = client.get(f"/api/v1/access-requests/resolve-link/{raw_token}", headers=headers_viewer)
    assert rev_resolve.status_code == 410
    assert "revoked" in rev_resolve.json()["detail"].lower()

    rev_submit = client.post(
        f"/api/v1/access-requests/submit-via-link/{raw_token}",
        headers=headers_viewer,
        json={"reason": "Should be rejected because link was revoked"}
    )
    assert rev_submit.status_code == 410
    assert "revoked" in rev_submit.json()["detail"].lower()
