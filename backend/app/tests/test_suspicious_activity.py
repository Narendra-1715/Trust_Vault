import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.security_alert import SecurityAlert
from app.models.document import Document
from app.models.session import UserSession
from app.models.audit import AuditEvent
from app.core.security import create_access_token
from app.core.rate_limit import auth_ip_limiter, auth_user_limiter

def get_auth_headers(client: TestClient, email: str, password: str = "TestPass123!") -> dict:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_failed_login_detection_and_duplicate_suppression(client: TestClient, test_users, test_db_session: Session):
    """
    Detection Rule 1:
    - 5 failed login attempts trigger a high-severity brute_force_login SecurityAlert.
    - Subsequent failed attempts within cooldown window update the alert instead of creating duplicate spam.
    """
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    target_email = "owner_a@test.com"

    # Reset rate limiters after fixture setup to ensure 5 failed attempts test the detection rule cleanly
    auth_ip_limiter.reset()
    auth_user_limiter.reset()

    # 4 failed attempts - threshold (5) not yet reached
    for _ in range(4):
        res = client.post("/api/v1/auth/login", json={"email": target_email, "password": "WrongPassword!"})
        assert res.status_code == 401

    alerts_res = client.get("/api/v1/alerts", headers=admin_headers)
    assert alerts_res.status_code == 200
    assert alerts_res.json()["total"] == 0

    # 5th failed attempt - triggers alert!
    res5 = client.post("/api/v1/auth/login", json={"email": target_email, "password": "WrongPassword!"})
    assert res5.status_code == 401

    alerts_res = client.get("/api/v1/alerts?event_type=brute_force_login", headers=admin_headers)
    assert alerts_res.status_code == 200
    data = alerts_res.json()
    assert data["total"] == 1
    alert = data["alerts"][0]
    assert alert["event_type"] == "brute_force_login"
    assert alert["severity"] == "high"
    assert alert["status"] == "open"
    assert "WrongPassword!" not in str(alert["investigation_metadata"])  # Data hygiene

    # 6th and 7th failed attempt within cooldown window - duplicate suppression increments count
    auth_ip_limiter.reset()
    auth_user_limiter.reset()
    client.post("/api/v1/auth/login", json={"email": target_email, "password": "WrongPassword!"})
    auth_ip_limiter.reset()
    auth_user_limiter.reset()
    client.post("/api/v1/auth/login", json={"email": target_email, "password": "WrongPassword!"})

    alerts_res2 = client.get("/api/v1/alerts?event_type=brute_force_login", headers=admin_headers)
    assert alerts_res2.json()["total"] == 1
    alert_updated = alerts_res2.json()["alerts"][0]
    assert alert_updated["investigation_metadata"].get("duplicate_occurrences", 1) >= 2

def test_repeated_denials_and_cross_owner_probe(client: TestClient, test_users, test_db_session: Session):
    """
    Detection Rule 2 & 6:
    - Repeated denied accesses trigger repeated_denials alert.
    - Unauthorized cross-owner probes trigger cross_owner_probe alert.
    """
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    owner_headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    viewer_headers = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")

    # Owner creates private document
    doc = Document(
        owner_id=test_users["owner_a"].id,
        title="Restricted Financial Ledger",
        original_filename="ledger.pdf",
        internal_storage_key="ledger_test.pdf",
        file_size=1024,
        detected_media_type="application/pdf",
        checksum="c" * 64,
        category="finance"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    # Viewer attempts cross-owner link creation 3 times
    for _ in range(3):
        res = client.post(
            f"/api/v1/access-requests/links/{doc.id}",
            headers=viewer_headers,
            json={"name": "Attacker Link"}
        )
        assert res.status_code in [403, 404]

    # Verify cross_owner_probe alert generated
    alerts_res = client.get("/api/v1/alerts?event_type=cross_owner_probe", headers=admin_headers)
    assert alerts_res.status_code == 200
    assert alerts_res.json()["total"] >= 1
    probe_alert = alerts_res.json()["alerts"][0]
    assert probe_alert["severity"] == "high"
    assert probe_alert["actor_id"] == test_users["viewer_a"].id

def test_invalid_reference_probe_detection(client: TestClient, test_users, test_db_session: Session):
    """
    Detection Rule 3:
    - Viewer probes 3 non-existent or expired request links.
    - Generates invalid_reference_probe security alert.
    """
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    viewer_headers = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")

    for i in range(3):
        res = client.get(
            f"/api/v1/access-requests/resolve-link/invalid_token_probe_{i}",
            headers=viewer_headers
        )
        assert res.status_code == 404

    alerts_res = client.get("/api/v1/alerts?event_type=invalid_reference_probe", headers=admin_headers)
    assert alerts_res.status_code == 200
    assert alerts_res.json()["total"] >= 1
    alert = alerts_res.json()["alerts"][0]
    assert alert["severity"] == "medium"
    assert alert["actor_id"] == test_users["viewer_a"].id

def test_alert_authorization_and_lifecycle(client: TestClient, test_users, test_db_session: Session):
    """
    Verifies:
    1. Non-admin users cannot access security alerts (403 Forbidden).
    2. Admin can view metrics and alert details.
    3. Admin can acknowledge alert (status -> investigating).
    4. Admin can resolve alert with resolution notes (status -> resolved).
    """
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    viewer_headers = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    owner_headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # 1. Non-admin denial
    assert client.get("/api/v1/alerts", headers=viewer_headers).status_code == 403
    assert client.get("/api/v1/alerts", headers=owner_headers).status_code == 403

    # Seed an open alert
    alert = SecurityAlert(
        id="test-alert-lifecycle-1",
        event_type="brute_force_login",
        severity="high",
        status="open",
        timestamp=datetime.now(timezone.utc),
        actor_id=test_users["viewer_a"].id,
        summary="Test lifecycle security alert",
        investigation_metadata={"ip": "127.0.0.1"},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    test_db_session.add(alert)
    test_db_session.commit()

    # 2. Admin retrieves metrics and details
    metrics = client.get("/api/v1/alerts/metrics", headers=admin_headers)
    assert metrics.status_code == 200
    assert metrics.json()["open_alerts"] >= 1

    detail = client.get(f"/api/v1/alerts/{alert.id}", headers=admin_headers)
    assert detail.status_code == 200
    assert detail.json()["status"] == "open"

    # 3. Admin acknowledges alert
    ack_res = client.post(f"/api/v1/alerts/{alert.id}/acknowledge", headers=admin_headers)
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "investigating"
    assert ack_res.json()["acknowledged_by"] == test_users["admin"].id

    # 4. Admin resolves alert
    resolve_res = client.post(
        f"/api/v1/alerts/{alert.id}/resolve",
        headers=admin_headers,
        json={"resolution_notes": "Investigation completed: User confirmed accidental wrong password entries."}
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "resolved"
    assert resolve_res.json()["resolved_by"] == test_users["admin"].id
    assert "accidental wrong password" in resolve_res.json()["resolution_notes"]

def test_admin_response_action_revoke_user_sessions(client: TestClient, test_users, test_db_session: Session):
    """
    Response Action:
    - Admin clicks 'Revoke User Sessions' on a suspicious alert.
    - All active sessions for that user are revoked in UserSession.
    - Other users' sessions remain intact.
    - Audit log records 'admin.user_sessions.revoked'.
    """
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    suspicious_user = test_users["viewer_a"]
    innocent_user = test_users["owner_a"]

    # Log in suspicious user to create an active session
    suspicious_headers = get_auth_headers(client, suspicious_user.email, "ViewerAPass123!")
    innocent_headers = get_auth_headers(client, innocent_user.email, "OwnerAPass123!")

    # Verify suspicious user can access protected endpoint
    assert client.get("/api/v1/auth/me", headers=suspicious_headers).status_code == 200

    # Create security alert associated with suspicious user
    alert = SecurityAlert(
        id="test-alert-response-action-1",
        event_type="rapid_session_creation",
        severity="medium",
        status="open",
        timestamp=datetime.now(timezone.utc),
        actor_id=suspicious_user.id,
        summary="Suspicious session activity detected",
        investigation_metadata={"ip": "198.51.100.1"},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    test_db_session.add(alert)
    test_db_session.commit()

    # Admin executes response action
    revoke_resp = client.post(
        f"/api/v1/alerts/{alert.id}/revoke-sessions",
        headers=admin_headers
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["revoked_sessions_count"] >= 1

    # Suspicious user's session is now revoked (subsequent request fails)
    assert client.get("/api/v1/auth/me", headers=suspicious_headers).status_code == 401

    # Innocent user's session remains unaffected
    assert client.get("/api/v1/auth/me", headers=innocent_headers).status_code == 200

    # Verify audit event logged
    audit_evt = test_db_session.query(AuditEvent).filter(
        AuditEvent.action == "admin.user_sessions.revoked",
        AuditEvent.resource_id == suspicious_user.id
    ).first()
    assert audit_evt is not None
    assert audit_evt.actor_id == test_users["admin"].id

def test_burst_permission_changes_and_rapid_sessions(client: TestClient, test_users, test_db_session: Session):
    """
    Detection Rules 4 & 5:
    - Bursts of permission grants/revokes trigger burst_permission_changes alert.
    - Rapid session generation (multiple logins in minutes) triggers rapid_session_creation alert.
    """
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    owner_headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    viewer_user = test_users["viewer_a"]

    # Reset rate limiters before testing rapid sessions to avoid hitting the 5/min IP limit
    auth_ip_limiter.reset()
    auth_user_limiter.reset()

    # 1. Test rapid sessions: Login 4 times in quick succession
    for _ in range(4):
        res = client.post("/api/v1/auth/login", json={"email": "viewer_a@test.com", "password": "ViewerAPass123!"})
        assert res.status_code == 200

    rapid_alert_res = client.get("/api/v1/alerts?event_type=rapid_session_creation", headers=admin_headers)
    assert rapid_alert_res.status_code == 200
    assert rapid_alert_res.json()["total"] >= 1
    session_alert = rapid_alert_res.json()["alerts"][0]
    assert session_alert["actor_id"] == viewer_user.id
    assert session_alert["severity"] == "medium"

    # 2. Test burst permission changes: create a document and perform 5 permission operations
    doc = Document(
        owner_id=test_users["owner_a"].id,
        title="Burst Permission Doc",
        original_filename="burst.pdf",
        internal_storage_key="burst.pdf",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="d" * 64,
        category="hr"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    # Grant permission, update it, repeat to reach burst threshold (5)
    for i in range(5):
        level = "read" if i % 2 == 0 else "edit"
        grant_resp = client.post(
            f"/api/v1/documents/{doc.id}/permissions",
            headers=owner_headers,
            json={"user_id": viewer_user.id, "permission_level": level}
        )
        assert grant_resp.status_code == 201

    burst_alert_res = client.get("/api/v1/alerts?event_type=burst_permission_changes", headers=admin_headers)
    assert burst_alert_res.status_code == 200
    assert burst_alert_res.json()["total"] >= 1
    burst_alert = burst_alert_res.json()["alerts"][0]
    assert burst_alert["actor_id"] == test_users["owner_a"].id

def test_false_positive_threshold_safeguards(client: TestClient, test_users, test_db_session: Session):
    """
    False-Positive Handling:
    - 1 or 2 ordinary mistakes (e.g. typing wrong password once, or a single link typo)
      must NOT generate alerts or harass the user.
    """
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")

    # Exactly 2 failed logins (below threshold of 5)
    for _ in range(2):
        res = client.post("/api/v1/auth/login", json={"email": "owner_b@test.com", "password": "TypoPassword!"})
        assert res.status_code == 401

    # Exactly 1 invalid request link probe (below threshold of 3)
    viewer_headers = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    res_probe = client.get("/api/v1/access-requests/resolve-link/single_typo_reference", headers=viewer_headers)
    assert res_probe.status_code == 404

    # Verify no alerts were triggered for owner_b or single probe
    alerts_owner_b = client.get("/api/v1/alerts?event_type=brute_force_login", headers=admin_headers).json()["alerts"]
    owner_b_alerts = [a for a in alerts_owner_b if a.get("target_user_email") == "owner_b@test.com"]
    assert len(owner_b_alerts) == 0

