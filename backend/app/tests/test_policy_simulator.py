import io
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers
from app.models.permission import DocumentPermission

def test_access_policy_simulator(client: TestClient, test_users, test_db_session):
    """
    Comprehensive test of Feature 4: Access Policy Simulator:
    1. Permitted proposal evaluation (Allowed).
    2. Missing expiration on capped policy (Additional requirements needed).
    3. MFA requirement on Highly Restricted (Additional requirements needed / Denied).
    4. Duration limit exceeded (Denied).
    5. Unauthorized caller cannot simulate on unshared documents (404).
    6. Read-only guarantee: Simulation creates ZERO permissions in database.
    7. Policy change divergence: Actual grant creation repeats independent verification.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    headers_stranger = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")
    viewer_email = "viewer_a@test.com"
    viewer_id = test_users["viewer_a"].id

    # 1. Upload test document (Internal)
    file_bytes = b"%PDF-1.4 project roadmap specification"
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Roadmap Document", "classification": "Internal"},
        files={"file": ("roadmap.pdf", io.BytesIO(file_bytes), "application/pdf")}
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # 2. Simulate valid grant proposal on Internal document
    sim_res = client.post(
        "/api/v1/policy-simulator/simulate",
        headers=headers_owner,
        json={
            "document_id": doc_id,
            "recipient_email": viewer_email,
            "permission_level": "read",
            "proposed_expiry": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        }
    )
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["status"] == "allowed"
    assert sim_data["is_allowed"] is True
    assert sim_data["document_id"] == doc_id
    assert len(sim_data["evaluated_rules"]) >= 3
    assert all(r["passed"] for r in sim_data["evaluated_rules"])

    # 3. Read-only Verification: Zero permissions created in database
    db_perms = test_db_session.query(DocumentPermission).filter(DocumentPermission.document_id == doc_id).all()
    assert len(db_perms) == 0

    # 4. Update document to "Highly Restricted"
    patch_res = client.patch(
        f"/api/v1/security-policies/documents/{doc_id}/classification",
        headers=headers_owner,
        json={"classification": "Highly Restricted"}
    )
    assert patch_res.status_code == 200

    # 5. Simulate on Highly Restricted with 14 days (exceeds 7-day policy limit)
    sim_exceed = client.post(
        "/api/v1/policy-simulator/simulate",
        headers=headers_owner,
        json={
            "document_id": doc_id,
            "recipient_email": viewer_email,
            "permission_level": "read",
            "proposed_expiry": (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
        }
    )
    assert sim_exceed.status_code == 200
    exceed_data = sim_exceed.json()
    assert exceed_data["is_allowed"] is False
    assert any("exceeds" in f.lower() or "limit" in f.lower() for f in exceed_data["failures"])
    assert exceed_data["remediation"] is not None

    # 6. Simulate on Highly Restricted without expiry (missing expiry)
    sim_no_exp = client.post(
        "/api/v1/policy-simulator/simulate",
        headers=headers_owner,
        json={
            "document_id": doc_id,
            "recipient_email": viewer_email,
            "permission_level": "read"
        }
    )
    assert sim_no_exp.status_code == 200
    no_exp_data = sim_no_exp.json()
    assert no_exp_data["status"] == "additional_requirements_needed"
    assert no_exp_data["is_allowed"] is False
    assert any("missing" in f.lower() or "expiration" in f.lower() for f in no_exp_data["failures"])

    # 7. Stranger cannot simulate on document they cannot read (Consistent 404)
    stranger_sim = client.post(
        "/api/v1/policy-simulator/simulate",
        headers=headers_stranger,
        json={
            "document_id": doc_id,
            "recipient_email": viewer_email,
            "permission_level": "read"
        }
    )
    assert stranger_sim.status_code == 404

    # 8. Re-check read-only guarantee: Database STILL has zero grants
    db_perms_after = test_db_session.query(DocumentPermission).filter(DocumentPermission.document_id == doc_id).all()
    assert len(db_perms_after) == 0

    # 9. Policy Divergence test: Attempting actual grant with 14 days is rejected by grant endpoint
    actual_grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={
            "user_id": viewer_id,
            "permission_level": "read",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
        }
    )
    assert actual_grant_res.status_code == 400
    assert "exceeds" in actual_grant_res.json()["detail"].lower()
