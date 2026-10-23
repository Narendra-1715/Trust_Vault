import pytest
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers

def test_unauthenticated_request_rejected(client: TestClient):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401

def test_valid_login_success(client: TestClient, test_users):
    response = client.post("/api/v1/auth/login", json={
        "email": "owner_a@test.com",
        "password": "OwnerAPass123!"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["email"] == "owner_a@test.com"
    assert data["role"] == "owner"

def test_invalid_password_rejected_with_generic_message(client: TestClient, test_users):
    response = client.post("/api/v1/auth/login", json={
        "email": "owner_a@test.com",
        "password": "WrongPassword999!"
    })
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]

def test_nonexistent_user_rejected_with_generic_message(client: TestClient, test_users):
    response = client.post("/api/v1/auth/login", json={
        "email": "nonexistent@test.com",
        "password": "SomePassword123!"
    })
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]

def test_disabled_user_login_prevented(client: TestClient, test_users):
    response = client.post("/api/v1/auth/login", json={
        "email": "disabled@test.com",
        "password": "DisabledPass123!"
    })
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"].lower()

def test_tampered_bearer_token_rejected(client: TestClient, test_users):
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    # Tamper token
    tampered_headers = {"Authorization": headers["Authorization"] + "tampered"}
    response = client.get("/api/v1/auth/me", headers=tampered_headers)
    assert response.status_code == 401

def test_admin_self_registration_rejected(client: TestClient):
    """Verifies that an unauthenticated attacker cannot self-register with role 'admin'."""
    response = client.post("/api/v1/auth/register", json={
        "email": "attacker_admin@test.com",
        "password": "AttackerPass123!",
        "display_name": "Attacker Admin",
        "role": "admin"
    })
    # Either 422 Unprocessable Entity (schema validation) or 403 Forbidden
    assert response.status_code in [403, 422], f"Expected 403 or 422, got {response.status_code}: {response.text}"
