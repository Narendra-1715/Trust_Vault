import pytest
from fastapi.testclient import TestClient
from app.models.session import UserSession
from app.models.audit import AuditEvent

def test_login_creates_session_and_audit(client: TestClient, test_db_session, test_users):
    """Verifies login creates a session record and logs session.created audit event."""
    resp = client.post("/api/v1/auth/login", json={
        "email": test_users["viewer_a"].email,
        "password": "ViewerAPass123!"
    }, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"})
    assert resp.status_code == 200
    data = resp.json()
    token = data["access_token"]
    assert token is not None

    # Check database session
    session = test_db_session.query(UserSession).filter(
        UserSession.user_id == test_users["viewer_a"].id
    ).first()
    assert session is not None
    assert session.revoked_at is None
    assert "Chrome" in session.device_info
    assert "Windows" in session.device_info

    # Check audit trail
    audit = test_db_session.query(AuditEvent).filter(
        AuditEvent.action == "session.created",
        AuditEvent.actor_id == test_users["viewer_a"].id
    ).first()
    assert audit is not None
    assert audit.outcome == "success"

def test_list_and_revoke_remote_session(client: TestClient, test_db_session, test_users):
    """Verifies listing active sessions and immediate revocation of remote session."""
    user = test_users["owner_a"]

    # Login 1 (Desktop)
    resp1 = client.post("/api/v1/auth/login", json={
        "email": user.email,
        "password": "OwnerAPass123!"
    }, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"})
    assert resp1.status_code == 200
    token1 = resp1.json()["access_token"]

    # Login 2 (Mobile)
    resp2 = client.post("/api/v1/auth/login", json={
        "email": user.email,
        "password": "OwnerAPass123!"
    }, headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1"})
    assert resp2.status_code == 200
    token2 = resp2.json()["access_token"]

    # Both tokens work initially
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"}).status_code == 200
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token2}"}).status_code == 200

    # From Desktop (token1), list sessions
    list_resp = client.get("/api/v1/auth/sessions", headers={"Authorization": f"Bearer {token1}"})
    assert list_resp.status_code == 200
    sessions = list_resp.json()
    assert len(sessions) >= 2

    current_sess = next((s for s in sessions if s["is_current"]), None)
    remote_sess = next((s for s in sessions if not s["is_current"] and "iPhone" in (s["device_info"] or "")), None)
    assert current_sess is not None
    assert remote_sess is not None

    # Revoke mobile session from desktop
    del_resp = client.delete(f"/api/v1/auth/sessions/{remote_sess['id']}", headers={"Authorization": f"Bearer {token1}"})
    assert del_resp.status_code == 204

    # Immediately, mobile session token2 must be rejected with 401
    verify_revoked = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token2}"})
    assert verify_revoked.status_code == 401

    # Desktop session token1 continues working
    verify_current = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"})
    assert verify_current.status_code == 200

    # Verify audit event
    revoke_audit = test_db_session.query(AuditEvent).filter(
        AuditEvent.action == "session.revoked",
        AuditEvent.actor_id == user.id
    ).first()
    assert revoke_audit is not None

def test_revoke_all_other_sessions(client: TestClient, test_db_session, test_users):
    """Verifies bulk revocation of all other active sessions while preserving current."""
    user = test_users["admin"]

    # Login on 3 devices
    resp1 = client.post("/api/v1/auth/login", json={"email": user.email, "password": "AdminPass123!"}, headers={"User-Agent": "Client1"})
    resp2 = client.post("/api/v1/auth/login", json={"email": user.email, "password": "AdminPass123!"}, headers={"User-Agent": "Client2"})
    resp3 = client.post("/api/v1/auth/login", json={"email": user.email, "password": "AdminPass123!"}, headers={"User-Agent": "Client3"})

    token1 = resp1.json()["access_token"]
    token2 = resp2.json()["access_token"]
    token3 = resp3.json()["access_token"]

    # Revoke all other sessions from token1
    bulk_resp = client.delete("/api/v1/auth/sessions?exclude_current=true", headers={"Authorization": f"Bearer {token1}"})
    assert bulk_resp.status_code == 200
    assert bulk_resp.json()["revoked_count"] >= 2

    # Token 1 still works
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"}).status_code == 200

    # Token 2 and 3 are immediately rejected
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token2}"}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token3}"}).status_code == 401
