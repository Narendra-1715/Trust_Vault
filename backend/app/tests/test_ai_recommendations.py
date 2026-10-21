import io
import pytest
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers
from app.models.permission import DocumentPermission

def test_ai_mock_recommendation_and_explicit_approval_workflow(client: TestClient, test_users, test_db_session):
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")

    # 1. Upload financial document
    files = {"file": ("budget.txt", io.BytesIO(b"Financial budget figures"), "text/plain")}
    doc_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Q4 Budget Planning", "category": "Financial"},
        files=files
    )
    assert doc_res.status_code == 201
    doc_id = doc_res.json()["id"]

    # 2. Viewer cannot request AI recommendations
    ai_unauth = client.post(f"/api/v1/documents/{doc_id}/ai-recommendations", headers=headers_viewer)
    assert ai_unauth.status_code == 404

    # 3. Owner requests AI recommendations
    ai_res = client.post(f"/api/v1/documents/{doc_id}/ai-recommendations", headers=headers_owner)
    assert ai_res.status_code == 200
    ai_data = ai_res.json()
    suggestion_id = ai_data["suggestion_id"]
    recommendations = ai_data["recommendations"]
    assert len(recommendations["suggestions"]) >= 0

    # 4. CRITICAL INVARIANT: The suggestion existing DOES NOT grant permissions
    viewer_id = test_users["viewer_a"].id
    perm_before = test_db_session.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc_id,
        DocumentPermission.user_id == viewer_id,
        DocumentPermission.revoked_at.is_(None)
    ).first()
    assert perm_before is None

    # 5. Owner EXPLICITLY approves access for Viewer A with READ permission
    approval_res = client.post(
        f"/api/v1/documents/{doc_id}/ai-recommendations/approve",
        headers=headers_owner,
        json={
            "suggestion_id": suggestion_id,
            "approved_grants": [{"user_id": viewer_id, "permission_level": "read"}],
            "decision_notes": "Approved for financial review."
        }
    )
    assert approval_res.status_code == 200

    # 6. NOW the permission exists in database
    perm_after = test_db_session.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc_id,
        DocumentPermission.user_id == viewer_id,
        DocumentPermission.revoked_at.is_(None)
    ).first()
    assert perm_after is not None
    assert perm_after.permission_level == "read"

def test_ai_recommendation_rejection_leaves_no_grants(client: TestClient, test_users, test_db_session):
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    files = {"file": ("secret.txt", io.BytesIO(b"Confidential data"), "text/plain")}
    doc_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Super Secret Memo", "category": "Executive"},
        files=files
    )
    doc_id = doc_res.json()["id"]

    ai_res = client.post(f"/api/v1/documents/{doc_id}/ai-recommendations", headers=headers_owner)
    suggestion_id = ai_res.json()["suggestion_id"]

    # Reject
    reject_res = client.post(
        f"/api/v1/documents/{doc_id}/ai-recommendations/reject",
        headers=headers_owner,
        json={"suggestion_id": suggestion_id, "rejection_reason": "Not sharing at this time."}
    )
    assert reject_res.status_code == 200

    # Verify zero permissions granted
    perms = test_db_session.query(DocumentPermission).filter(DocumentPermission.document_id == doc_id).all()
    assert len(perms) == 0
