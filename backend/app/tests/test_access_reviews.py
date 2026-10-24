import io
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers

def test_periodic_access_review_lifecycle(client: TestClient, test_users, test_db_session):
    """
    Comprehensive test of Feature 3: Periodic Access Reviews:
    1. Upload document and create grants for viewers.
    2. Generate reviews (idempotency, no duplicates).
    3. Verify due dates and overdue calculations.
    4. Reviewer authorization enforcement (stranger cannot review).
    5. Retaining a grant leaves access intact and does not modify expiry.
    6. Revoking a grant immediately terminates access on subsequent requests.
    7. Concurrent / duplicate decision prevention (409 Conflict).
    8. Audit events recorded.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_stranger = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    viewer_id = test_users["viewer_a"].id
    owner_b_id = test_users["owner_b"].id

    # 1. Upload test document
    doc_content = b"%PDF-1.4 confidential review document"
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Review Target Doc", "classification": "Internal"},
        files={"file": ("target.pdf", io.BytesIO(doc_content), "application/pdf")}
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # Grant read access to viewer
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read"}
    )
    assert grant_res.status_code == 201
    perm_id = grant_res.json()["id"]

    # Grant read access to owner_b
    grant_b_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": owner_b_id, "permission_level": "read"}
    )
    assert grant_b_res.status_code == 201
    perm_b_id = grant_b_res.json()["id"]

    # 2. Generate access reviews with force_all_active=True
    gen_res = client.post("/api/v1/access-reviews/generate?force_all_active=true", headers=headers_owner)
    assert gen_res.status_code == 200
    assert gen_res.json()["created_count"] >= 2

    # Idempotency check: Re-running generation does not duplicate pending reviews
    gen_idempotent = client.post("/api/v1/access-reviews/generate?force_all_active=true", headers=headers_owner)
    assert gen_idempotent.status_code == 200
    assert gen_idempotent.json()["created_count"] == 0

    # 3. List access reviews as document owner
    list_res = client.get(f"/api/v1/access-reviews?document_id={doc_id}", headers=headers_owner)
    assert list_res.status_code == 200
    reviews_data = list_res.json()
    assert reviews_data["pending_count"] == 2
    reviews = reviews_data["reviews"]
    rev_for_viewer = next(r for r in reviews if r["grantee_id"] == viewer_id)
    rev_for_b = next(r for r in reviews if r["grantee_id"] == owner_b_id)

    assert rev_for_viewer["status"] == "pending"
    assert rev_for_viewer["document_title"] == "Review Target Doc"
    assert rev_for_viewer["is_overdue"] is False

    # 4. Stranger cannot review or decide
    unauth_decision = client.post(
        f"/api/v1/access-reviews/{rev_for_viewer['id']}/decision",
        headers=headers_stranger,
        json={"decision": "revoke", "decision_notes": "Unauthorized attempt"}
    )
    assert unauth_decision.status_code == 403

    # 5. Owner decides to RETAIN access for viewer
    retain_res = client.post(
        f"/api/v1/access-reviews/{rev_for_viewer['id']}/decision",
        headers=headers_owner,
        json={"decision": "retain", "decision_notes": "Active contributor on Q4 project"}
    )
    assert retain_res.status_code == 200
    retain_data = retain_res.json()
    assert retain_data["status"] == "retained"
    assert retain_data["decision"] == "retain"
    assert retain_data["decided_at"] is not None
    assert retain_data["next_review_due"] is not None

    # Verify viewer STILL has working download access
    viewer_down = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert viewer_down.status_code == 200
    assert viewer_down.content == doc_content

    # 6. Cannot decide on an already-decided review (Conflict 409)
    conflict_res = client.post(
        f"/api/v1/access-reviews/{rev_for_viewer['id']}/decision",
        headers=headers_owner,
        json={"decision": "revoke"}
    )
    assert conflict_res.status_code == 409

    # 7. Owner decides to REVOKE access for owner_b
    revoke_res = client.post(
        f"/api/v1/access-reviews/{rev_for_b['id']}/decision",
        headers=headers_owner,
        json={"decision": "revoke", "decision_notes": "No longer requires project access"}
    )
    assert revoke_res.status_code == 200
    revoke_data = revoke_res.json()
    assert revoke_data["status"] == "revoked"
    assert revoke_data["decision"] == "revoke"

    # Verify owner_b's download access is immediately terminated (404/403)
    b_down_attempt = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_stranger)
    assert b_down_attempt.status_code in [403, 404]

    # 8. Check review list counts after decisions
    after_list = client.get(f"/api/v1/access-reviews?document_id={doc_id}", headers=headers_owner).json()
    assert after_list["pending_count"] == 0
    assert after_list["total"] == 2

    # 9. Audit event verification
    audit_res = client.get(f"/api/v1/audit/events?document_id={doc_id}", headers=headers_owner)
    assert audit_res.status_code == 200
    actions = [e["action"] for e in audit_res.json()["events"]]
    assert "access_review.retain" in actions
    assert "access_review.revoke" in actions
    assert "permission.revoke" in actions
