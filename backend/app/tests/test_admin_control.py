import io
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers
from app.models.user import User
from app.models.document import Document
from app.models.session import UserSession
from app.models.emergency_access import EmergencyAccess

def test_admin_control_full_lifecycle(client: TestClient, test_users, test_db_session):
    """
    Comprehensive verification of TrustVault Admin Administrative Control:
    1. Rejection of unauthenticated, Viewer, and Owner on admin endpoints.
    2. Admin user provisioning (POST /api/v1/users).
    3. Prevention of self-registration as admin (POST /api/v1/auth/register).
    4. Safeguard preventing removal or demotion of the last active administrator.
    5. Admin inspection of user security metadata and session revocation.
    6. Default private document isolation: Admin cannot download private document.
    7. Emergency Break-Glass access lifecycle:
       - Password reauthentication failure rejection.
       - Valid activation with justification and time-limit.
       - Content access granted during emergency window.
       - Early revocation immediately restores isolation.
       - Post-incident review recording.
    8. System status inspection and system setting modification.
    9. Reviewing document grant metadata.
    10. Disaster recovery authorized restoration verification.
    """
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    admin_id = test_users["admin"].id
    owner_id = test_users["owner_a"].id
    viewer_id = test_users["viewer_a"].id

    # 1. Non-admin rejection on admin endpoints
    res_viewer_status = client.get("/api/v1/admin/system-status", headers=headers_viewer)
    assert res_viewer_status.status_code == 403
    res_owner_status = client.get("/api/v1/admin/system-status", headers=headers_owner)
    assert res_owner_status.status_code == 403
    res_unauth_status = client.get("/api/v1/admin/system-status")
    assert res_unauth_status.status_code == 401

    # 2. Admin inspects system status
    admin_status = client.get("/api/v1/admin/system-status", headers=headers_admin)
    assert admin_status.status_code == 200
    status_data = admin_status.json()
    assert status_data["database"]["status"] == "connected"
    assert status_data["storage"]["status"] == "connected"
    assert "users_count" in status_data
    assert "active_sessions_count" in status_data

    # 3. Prevent self-registration as admin
    self_reg = client.post(
        "/api/v1/auth/register",
        json={
            "email": "hacker_admin@test.com",
            "password": "Password123!",
            "display_name": "Hacker Admin",
            "role": "admin"
        }
    )
    assert self_reg.status_code == 403
    assert "not permitted" in self_reg.json()["detail"].lower()

    # 4. Admin provisions a new user with 'owner' role
    create_user_res = client.post(
        "/api/v1/users",
        headers=headers_admin,
        json={
            "email": "provisioned_user@test.com",
            "password": "SecurePassword123!",
            "display_name": "Provisioned User",
            "role": "owner",
            "is_active": True,
            "mfa_enabled": True
        }
    )
    assert create_user_res.status_code == 201
    prov_user_data = create_user_res.json()
    prov_user_id = prov_user_data["id"]
    assert prov_user_data["email"] == "provisioned_user@test.com"

    # 5. Admin inspects user security metadata
    detail_res = client.get(f"/api/v1/users/{prov_user_id}", headers=headers_admin)
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert detail_data["mfa_enabled"] is True
    assert "active_sessions_count" in detail_data

    # 6. Admin creates a session for provisioned user, then inspects and revokes it
    headers_prov = get_auth_headers(client, "provisioned_user@test.com", "SecurePassword123!")
    sess_list_res = client.get(f"/api/v1/users/{prov_user_id}/sessions", headers=headers_admin)
    assert sess_list_res.status_code == 200
    sessions = sess_list_res.json()
    assert len(sessions) >= 1
    session_id = sessions[0]["id"]

    # Revoke sessions for provisioned user
    revoke_sess_res = client.delete(f"/api/v1/users/{prov_user_id}/sessions", headers=headers_admin)
    assert revoke_sess_res.status_code == 200
    assert revoke_sess_res.json()["revoked_count"] >= 1

    # Verify session is now revoked
    me_after_revoke = client.get("/api/v1/auth/me", headers=headers_prov)
    assert me_after_revoke.status_code == 401

    # 7. Safeguard: Prevent removing or demoting the last usable admin
    # Ensure there is only 1 admin currently
    active_admins = test_db_session.query(User).filter(User.role == "admin", User.is_active == True).all()
    assert len(active_admins) == 1
    sole_admin_id = active_admins[0].id

    # Attempt to demote sole admin to viewer -> rejected
    demote_res = client.patch(
        f"/api/v1/users/{sole_admin_id}",
        headers=headers_admin,
        json={"role": "viewer"}
    )
    assert demote_res.status_code == 400
    assert "last usable administrative account" in demote_res.json()["detail"].lower()

    # Attempt to deactivate sole admin -> rejected
    disable_res = client.patch(
        f"/api/v1/users/{sole_admin_id}",
        headers=headers_admin,
        json={"is_active": False}
    )
    assert disable_res.status_code == 400
    assert "last usable administrative account" in disable_res.json()["detail"].lower()

    # 8. Upload a private document as Owner A
    doc_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Strictly Confidential Financial Audit", "classification": "Confidential"},
        files={"file": ("audit.pdf", io.BytesIO(b"%PDF-1.4 financial proprietary data"), "application/pdf")}
    )
    assert doc_res.status_code == 201
    doc_id = doc_res.json()["id"]

    # 9. Private Isolation check: Admin CANNOT download private document by default
    admin_dl_denied = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin)
    assert admin_dl_denied.status_code in [403, 404]

    # Admin CAN review document grant metadata without having content access
    admin_grants_res = client.get(f"/api/v1/documents/{doc_id}/permissions", headers=headers_admin)
    assert admin_grants_res.status_code == 200

    # 10. Break-Glass Emergency Access:
    # A. Failed password reauthentication -> Rejected
    bg_wrong_pw = client.post(
        "/api/v1/admin/break-glass",
        headers=headers_admin,
        json={
            "document_id": doc_id,
            "justification": "Urgent compliance subpoena investigation for regulator",
            "duration_minutes": 30,
            "password": "WrongPassword!"
        }
    )
    assert bg_wrong_pw.status_code == 401
    assert "reauthentication failed" in bg_wrong_pw.json()["detail"].lower()

    # B. Successful break-glass activation
    bg_success = client.post(
        "/api/v1/admin/break-glass",
        headers=headers_admin,
        json={
            "document_id": doc_id,
            "justification": "Urgent compliance subpoena investigation for regulator audit",
            "duration_minutes": 30,
            "password": "AdminPass123!"
        }
    )
    assert bg_success.status_code == 201
    bg_data = bg_success.json()
    assert bg_data["status"] == "active"
    assert bg_data["document_id"] == doc_id
    bg_id = bg_data["id"]

    # C. With active break-glass, Admin CAN now download document content
    admin_dl_emergency = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin)
    assert admin_dl_emergency.status_code == 200
    assert admin_dl_emergency.content == b"%PDF-1.4 financial proprietary data"

    # D. Admin revokes emergency access early
    bg_revoke = client.post(f"/api/v1/admin/break-glass/{bg_id}/revoke", headers=headers_admin)
    assert bg_revoke.status_code == 200
    assert bg_revoke.json()["status"] == "revoked"

    # E. Content access is immediately cut off again
    admin_dl_revoked = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin)
    assert admin_dl_revoked.status_code in [403, 404]

    # F. Admin records post-incident review notes
    bg_review = client.post(
        f"/api/v1/admin/break-glass/{bg_id}/review",
        headers=headers_admin,
        json={"review_notes": "Investigation completed. Document content verified for subpoena."}
    )
    assert bg_review.status_code == 200
    assert bg_review.json()["review_notes"] == "Investigation completed. Document content verified for subpoena."

    # 11. System settings update
    settings_res = client.get("/api/v1/admin/settings", headers=headers_admin)
    assert settings_res.status_code == 200
    settings_list = settings_res.json()
    assert len(settings_list) >= 4

    # Update session_timeout_minutes setting
    update_setting_res = client.patch(
        "/api/v1/admin/settings/session_timeout_minutes",
        headers=headers_admin,
        json={"value": "45"}
    )
    assert update_setting_res.status_code == 200
    assert update_setting_res.json()["value"] == "45"

    # 12. Disaster Recovery: verify backup and authorized restore
    backup_create_res = client.post("/api/v1/backups/create", headers=headers_admin)
    assert backup_create_res.status_code == 201
    backup_id = backup_create_res.json()["backup_id"]

    # Verification simulation in sandbox
    verify_res = client.post(f"/api/v1/backups/{backup_id}/verify", headers=headers_admin)
    assert verify_res.status_code == 200
    assert verify_res.json()["is_valid"] is True

    # Restore rejected without valid confirmation token
    restore_bad_token = client.post(
        f"/api/v1/backups/{backup_id}/restore",
        headers=headers_admin,
        json={"confirmation": "RESTORE_NOW", "password": "AdminPass123!"}
    )
    assert restore_bad_token.status_code == 400

    # Restore rejected with invalid password
    restore_bad_pw = client.post(
        f"/api/v1/backups/{backup_id}/restore",
        headers=headers_admin,
        json={"confirmation": "RESTORE_DATABASE", "password": "WrongPassword!"}
    )
    assert restore_bad_pw.status_code == 401

    # Authorized restore succeeds
    restore_success = client.post(
        f"/api/v1/backups/{backup_id}/restore",
        headers=headers_admin,
        json={"confirmation": "RESTORE_DATABASE", "password": "AdminPass123!"}
    )
    assert restore_success.status_code == 200
    assert restore_success.json()["success"] is True
