import io
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers

def test_document_classification_and_security_policies(client: TestClient, test_users, test_db_session):
    """
    Comprehensive test of Feature 2: Document Classification & Security Policies:
    1. Default policies verification.
    2. Admin configuration of policies and RBAC restrictions.
    3. Document upload with classification.
    4. Changing classification and authorization enforcement (viewer denied).
    5. Highly Restricted download restrictions (policy_denied for non-owner).
    6. MFA requirement enforcement.
    7. Maximum grant duration enforcement.
    8. Policy precedence rule: older grants immediately subject to stricter new policy.
    9. Audit trail verification.
    """
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    viewer_id = test_users["viewer_a"].id
    owner_id = test_users["owner_a"].id

    # 1. Verify default security policies
    pol_list_res = client.get("/api/v1/security-policies", headers=headers_owner)
    assert pol_list_res.status_code == 200
    policies = {p["classification"]: p for p in pol_list_res.json()}
    assert "Internal" in policies
    assert "Confidential" in policies
    assert "Highly Restricted" in policies
    assert policies["Internal"]["allow_download"] is True
    assert policies["Highly Restricted"]["allow_download"] is False
    assert policies["Highly Restricted"]["max_grant_duration_days"] == 7
    assert policies["Highly Restricted"]["require_mfa"] is True

    # 2. RBAC: Only admin can update security policy rules
    viewer_update = client.put(
        "/api/v1/security-policies/Internal",
        headers=headers_viewer,
        json={"allow_download": False}
    )
    assert viewer_update.status_code == 403

    owner_update = client.put(
        "/api/v1/security-policies/Internal",
        headers=headers_owner,
        json={"allow_download": False}
    )
    assert owner_update.status_code == 403

    # 3. Upload document with classification "Internal"
    file_bytes = b"%PDF-1.4 classified executive document content"
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Classified Doc", "classification": "Internal"},
        files={"file": ("classified.pdf", io.BytesIO(file_bytes), "application/pdf")}
    )
    assert upload_res.status_code == 201
    doc_data = upload_res.json()
    doc_id = doc_data["id"]
    assert doc_data["classification"] == "Internal"

    # Grant read access to viewer for 30 days
    exp_30d = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read", "expires_at": exp_30d}
    )
    assert grant_res.status_code == 201

    # Viewer can download Internal document
    down_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert down_res.status_code == 200
    assert down_res.content == file_bytes

    # 4. Viewer cannot change classification
    viewer_change = client.patch(
        f"/api/v1/security-policies/documents/{doc_id}/classification",
        headers=headers_viewer,
        json={"classification": "Highly Restricted"}
    )
    assert viewer_change.status_code == 403

    # Invalid classification rejected
    invalid_change = client.patch(
        f"/api/v1/security-policies/documents/{doc_id}/classification",
        headers=headers_owner,
        json={"classification": "Top Secret"}
    )
    assert invalid_change.status_code == 400

    # 5. Policy Precedence: Owner upgrades classification to "Highly Restricted"
    upgrade_res = client.patch(
        f"/api/v1/security-policies/documents/{doc_id}/classification",
        headers=headers_owner,
        json={"classification": "Highly Restricted", "reason": "Contains trade secret IP"}
    )
    assert upgrade_res.status_code == 200
    assert upgrade_res.json()["classification"] == "Highly Restricted"

    # Now viewer tries to download using previous 30-day grant:
    # Highly Restricted has allow_download = False -> immediately denied!
    restricted_down = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert restricted_down.status_code == 403
    assert "prohibited" in restricted_down.json()["detail"].lower()

    # Owner can still download their own document
    owner_down = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner)
    assert owner_down.status_code == 200

    # 6. Admin configures Highly Restricted to allow download IF MFA is verified
    admin_pol_res = client.put(
        "/api/v1/security-policies/Highly Restricted",
        headers=headers_admin,
        json={"allow_download": True, "require_mfa": True}
    )
    assert admin_pol_res.status_code == 200
    assert admin_pol_res.json()["allow_download"] is True

    # Viewer without MFA is rejected due to MFA requirement
    mfa_down_attempt = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert mfa_down_attempt.status_code == 403
    assert "mfa" in mfa_down_attempt.json()["detail"].lower()

    # Enable MFA for viewer
    mfa_enable = client.patch(f"/api/v1/security-policies/users/{viewer_id}/mfa?enabled=true", headers=headers_admin)
    assert mfa_enable.status_code == 200
    assert mfa_enable.json()["mfa_enabled"] is True

    # Viewer with MFA can now download
    mfa_success_down = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert mfa_success_down.status_code == 200

    # 7. Grant duration enforcement on Highly Restricted (max 7 days)
    # Attempting to grant with 14 days is rejected
    exp_14d = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
    reject_grant = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read", "expires_at": exp_14d}
    )
    assert reject_grant.status_code == 400
    assert "exceeds" in reject_grant.json()["detail"].lower()

    # Attempting to grant without expiry is rejected
    no_exp_grant = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read"}
    )
    assert no_exp_grant.status_code == 400
    assert "missing" in no_exp_grant.json()["detail"].lower()

    # Granting within 7 days limit (e.g. 5 days) succeeds
    exp_5d = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    ok_grant = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read", "expires_at": exp_5d}
    )
    assert ok_grant.status_code in [200, 201]

    # 8. Check audit events recorded
    audit_res = client.get(f"/api/v1/audit/events?document_id={doc_id}", headers=headers_owner)
    assert audit_res.status_code == 200
    events = audit_res.json()["events"]
    actions = [e["action"] for e in events]
    assert "document.classification.update" in actions
