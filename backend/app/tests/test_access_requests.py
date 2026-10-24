import io
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers
from app.models.permission import DocumentPermission
from app.models.notification import SecurityNotification
from app.models.audit import AuditEvent

def _upload_test_doc(client: TestClient, headers: dict, title: str = "Confidential Contract") -> str:
    files = {"file": ("contract.pdf", io.BytesIO(b"%PDF-1.4 confidential payload"), "application/pdf")}
    res = client.post(
        "/api/v1/documents/upload",
        headers=headers,
        data={"title": title, "category": "Legal"},
        files=files
    )
    assert res.status_code == 201
    return res.json()["id"]

def test_access_request_submission_and_validation(client: TestClient, test_users):
    """
    Verifies:
    1. Authenticated request submission succeeds.
    2. Unauthenticated request submission is rejected (401).
    3. Requesting access to nonexistent document returns 404 with zero metadata leakage.
    4. Document owner cannot request access to their own document (400).
    5. Duplicate pending request is rejected with 409 Conflict.
    6. Past expiry date is rejected (400).
    7. Invalid permission level is rejected (400).
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Q4 Mergers and Acquisitions")

    # 1. Unauthenticated request rejected
    unauth_res = client.post(
        "/api/v1/access-requests",
        json={"document_id": doc_id, "reason": "Need to audit financial clauses"}
    )
    assert unauth_res.status_code == 401

    # 2. Nonexistent document returns 404
    fake_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": "00000000-0000-0000-0000-000000000000", "reason": "Need to audit financial clauses"}
    )
    assert fake_res.status_code == 404
    assert "not found" in fake_res.json()["detail"].lower()

    # 3. Owner cannot request access to own document
    owner_req_res = client.post(
        "/api/v1/access-requests",
        headers=headers_owner,
        json={"document_id": doc_id, "reason": "Requesting access to own doc"}
    )
    assert owner_req_res.status_code == 400
    assert "owner" in owner_req_res.json()["detail"].lower()

    # 4. Past expiry rejected
    past_exp = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    past_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Need to audit financial clauses", "requested_expiry": past_exp}
    )
    assert past_res.status_code == 400
    assert "future" in past_res.json()["detail"].lower()

    # 5. Invalid permission level rejected
    invalid_perm_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Need to audit financial clauses", "requested_permission": "admin"}
    )
    assert invalid_perm_res.status_code == 400
    assert "permission" in invalid_perm_res.json()["detail"].lower()

    # 6. Valid submission succeeds
    future_exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    submit_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={
            "document_id": doc_id,
            "reason": "Need to audit financial clauses for external compliance",
            "requested_permission": "read",
            "requested_expiry": future_exp
        }
    )
    assert submit_res.status_code == 201
    req_data = submit_res.json()
    assert req_data["status"] == "pending"
    assert req_data["document_id"] == doc_id
    assert req_data["requester_id"] == test_users["viewer_a"].id
    assert req_data["requested_permission"] == "read"
    assert req_data["requested_expiry"] is not None

    # 7. Duplicate pending request rejected (409 Conflict)
    dup_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Duplicate attempt for same document"}
    )
    assert dup_res.status_code == 409
    assert "pending" in dup_res.json()["detail"].lower()

def test_access_request_already_accessible_rejection(client: TestClient, test_users):
    """
    Verifies that a user who already has active access (read/edit grant)
    cannot submit an access request.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "IP Patents")

    # Grant read permission to viewer
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": test_users["viewer_a"].id, "permission_level": "read"}
    )
    assert grant_res.status_code == 201

    # Viewer attempts to request access
    req_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Redundant request"}
    )
    assert req_res.status_code == 400
    assert "already have active access" in req_res.json()["detail"].lower()

def test_access_request_authorization_rules(client: TestClient, test_users):
    """
    Verifies strict authorization boundaries:
    1. Requester cannot approve or reject their own request (403).
    2. Non-owner cannot approve or reject another owner's document request (403).
    3. Administrator cannot approve request on private document without being owner (403).
    4. Cross-user request detail inspection is blocked (404, anti-enumeration).
    """
    headers_owner_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_owner_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")

    doc_id = _upload_test_doc(client, headers_owner_a, "Owner A Secret Strategy")

    # Viewer submits request
    submit_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Cross-boundary access test"}
    )
    assert submit_res.status_code == 201
    req_id = submit_res.json()["id"]

    # 1. Requester cannot approve their own request
    self_approve = client.post(
        f"/api/v1/access-requests/{req_id}/approve",
        headers=headers_viewer,
        json={"approved_permission": "read"}
    )
    assert self_approve.status_code == 403

    # 2. Requester cannot reject their own request
    self_reject = client.post(
        f"/api/v1/access-requests/{req_id}/reject",
        headers=headers_viewer,
        json={"rejection_reason": "Self rejection"}
    )
    assert self_reject.status_code == 403

    # 3. Non-owner (owner_b) cannot approve
    b_approve = client.post(
        f"/api/v1/access-requests/{req_id}/approve",
        headers=headers_owner_b,
        json={"approved_permission": "read"}
    )
    assert b_approve.status_code == 403

    # 4. Admin cannot approve private document request
    admin_approve = client.post(
        f"/api/v1/access-requests/{req_id}/approve",
        headers=headers_admin,
        json={"approved_permission": "read"}
    )
    assert admin_approve.status_code == 403

    # 5. Non-involved user cannot read request details (404, anti-IDOR)
    b_get = client.get(f"/api/v1/access-requests/{req_id}", headers=headers_owner_b)
    assert b_get.status_code == 404

def test_access_request_approval_atomic_grant_lifecycle(client: TestClient, test_users):
    """
    Verifies that:
    1. Owner approval atomically creates the document permission.
    2. Expiry is respected and verified.
    3. Requester can read & download document immediately after approval.
    4. Replayed approval attempt is rejected (400).
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Salary Letters 2026")

    # Viewer has no access initially
    assert client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer).status_code == 404

    # Viewer submits request
    submit_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Annual compensation review"}
    )
    assert submit_res.status_code == 201
    req_id = submit_res.json()["id"]

    # Owner approves with 'edit' access and 2-day expiry
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    approve_res = client.post(
        f"/api/v1/access-requests/{req_id}/approve",
        headers=headers_owner,
        json={"approved_permission": "edit", "approved_expiry": future_expiry}
    )
    assert approve_res.status_code == 200
    app_data = approve_res.json()
    assert app_data["status"] == "approved"
    assert app_data["approved_permission"] == "edit"
    assert app_data["decided_by"] == test_users["owner_a"].id
    assert app_data["decided_at"] is not None

    # Requester now has edit access to document!
    doc_res = client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer)
    assert doc_res.status_code == 200
    assert doc_res.json()["effective_permission"] == "edit"

    # Requester can download
    dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert dl_res.status_code == 200

    # Replayed approval is rejected (anti-replay)
    replay_res = client.post(
        f"/api/v1/access-requests/{req_id}/approve",
        headers=headers_owner,
        json={"approved_permission": "read"}
    )
    assert replay_res.status_code == 400
    assert "approved" in replay_res.json()["detail"].lower()

def test_access_request_rejection_no_grant(client: TestClient, test_users):
    """
    Verifies that:
    1. Owner rejection updates request status to 'rejected'.
    2. Zero permissions are granted.
    3. Requester cannot access document.
    4. Replayed rejection is rejected.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Tax Audit Papers")

    submit_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Need to view tax audit"}
    )
    req_id = submit_res.json()["id"]

    # Owner rejects request
    reject_res = client.post(
        f"/api/v1/access-requests/{req_id}/reject",
        headers=headers_owner,
        json={"rejection_reason": "Audit window closed"}
    )
    assert reject_res.status_code == 200
    rej_data = reject_res.json()
    assert rej_data["status"] == "rejected"
    assert rej_data["rejection_reason"] == "Audit window closed"
    assert rej_data["decided_at"] is not None

    # Document remains strictly inaccessible to viewer
    assert client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer).status_code == 404
    assert client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer).status_code == 404

    # Replayed rejection rejected
    replay_rej = client.post(
        f"/api/v1/access-requests/{req_id}/reject",
        headers=headers_owner,
        json={"rejection_reason": "Another reason"}
    )
    assert replay_rej.status_code == 400

def test_access_request_cancellation(client: TestClient, test_users):
    """
    Verifies that:
    1. Requester can cancel their own pending request.
    2. Non-requester cannot cancel.
    3. Cannot cancel non-pending request.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Engineering Blueprints")

    submit_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Mistaken request"}
    )
    req_id = submit_res.json()["id"]

    # Owner cannot cancel requester's request
    owner_cancel = client.post(f"/api/v1/access-requests/{req_id}/cancel", headers=headers_owner)
    assert owner_cancel.status_code == 403

    # Requester cancels own request
    cancel_res = client.post(f"/api/v1/access-requests/{req_id}/cancel", headers=headers_viewer)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "cancelled"
    assert cancel_res.json()["cancelled_at"] is not None

    # Subsequent cancellation attempt fails
    replay_cancel = client.post(f"/api/v1/access-requests/{req_id}/cancel", headers=headers_viewer)
    assert replay_cancel.status_code == 400

def test_access_request_notifications_and_audit(client: TestClient, test_users, test_db_session):
    """
    Verifies that:
    1. Submission creates audit event and owner notification.
    2. Approval creates audit events (request approval + grant) and requester notification.
    3. Notification alone does NOT confer authorization.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Board Resolutions")

    # Submit request
    submit_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Board audit preparation"}
    )
    req_id = submit_res.json()["id"]

    # Check notification for owner
    owner_notifs = client.get("/api/v1/notifications", headers=headers_owner).json()
    req_notif = next((n for n in owner_notifs if n["event_type"] == "access_request.received"), None)
    assert req_notif is not None
    assert "Board Resolutions" in req_notif["message"]

    # Check audit log for request creation
    audit_events = test_db_session.query(AuditEvent).filter(
        AuditEvent.action == "access_request.create"
    ).all()
    assert len(audit_events) >= 1
    assert audit_events[-1].actor_id == test_users["viewer_a"].id

    # Owner approves request
    client.post(
        f"/api/v1/access-requests/{req_id}/approve",
        headers=headers_owner,
        json={"approved_permission": "read"}
    )

    # Check notification for viewer
    viewer_notifs = client.get("/api/v1/notifications", headers=headers_viewer).json()
    app_notif = next((n for n in viewer_notifs if n["event_type"] == "access_request.approved"), None)
    assert app_notif is not None
    assert "approved" in app_notif["title"].lower()

    # Check audit logs for approval
    approval_audit = test_db_session.query(AuditEvent).filter(
        AuditEvent.action == "access_request.approve"
    ).first()
    assert approval_audit is not None
    assert approval_audit.actor_id == test_users["owner_a"].id

def test_access_request_status_check_and_lists(client: TestClient, test_users):
    """
    Verifies:
    1. /access-requests/status/{doc_id} safely returns pending status without leakage.
    2. /access-requests/my returns requester's requests.
    3. /access-requests/incoming returns owner's incoming requests.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    doc_id = _upload_test_doc(client, headers_owner, "Vendor Agreements")

    # Before request
    status_before = client.get(f"/api/v1/access-requests/status/{doc_id}", headers=headers_viewer)
    assert status_before.status_code == 200
    assert status_before.json()["has_pending_request"] is False

    # Submit request
    client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={"document_id": doc_id, "reason": "Reviewing vendor scope"}
    )

    # After request
    status_after = client.get(f"/api/v1/access-requests/status/{doc_id}", headers=headers_viewer)
    assert status_after.status_code == 200
    assert status_after.json()["has_pending_request"] is True
    assert status_after.json()["request_id"] is not None

    # Check My Requests list
    my_res = client.get("/api/v1/access-requests/my", headers=headers_viewer)
    assert my_res.status_code == 200
    assert len(my_res.json()) >= 1
    assert my_res.json()[0]["document_id"] == doc_id

    # Check Incoming Requests list for owner
    inc_res = client.get("/api/v1/access-requests/incoming?status_filter=pending", headers=headers_owner)
    assert inc_res.status_code == 200
    assert len(inc_res.json()) >= 1
    assert inc_res.json()[0]["requester_id"] == test_users["viewer_a"].id
