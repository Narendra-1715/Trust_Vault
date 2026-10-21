import io
import pytest
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers
from app.models.audit import AuditEvent
from app.audit.verifier import verify_audit_integrity

def test_audit_event_generation_and_valid_hash_chain(client: TestClient, test_users, test_db_session):
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # Perform actions
    files = {"file": ("audit_test.txt", io.BytesIO(b"audit test file"), "text/plain")}
    res = client.post("/api/v1/documents/upload", headers=headers, data={"title": "Audited Doc"}, files=files)
    assert res.status_code == 201

    # Verify audit verification endpoint
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    v_res = client.get("/api/v1/audit/verify", headers=admin_headers)
    assert v_res.status_code == 200
    report = v_res.json()
    assert report["is_valid"] is True
    assert report["total_events"] >= 2  # Login + upload

def test_tampering_event_payload_detected(client: TestClient, test_users, test_db_session):
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    files = {"file": ("tamper_test.txt", io.BytesIO(b"content"), "text/plain")}
    client.post("/api/v1/documents/upload", headers=headers, data={"title": "Doc to Tamper"}, files=files)

    # Maliciously alter an event's action in database
    target_event = test_db_session.query(AuditEvent).first()
    assert target_event is not None
    target_event.action = "document.maliciously_modified_action"
    test_db_session.commit()

    # Integrity verification must catch the tampering
    result = verify_audit_integrity(test_db_session)
    assert result["is_valid"] is False
    assert result["tampered_event_id"] == target_event.id
    assert "Tampered content" in result["error_reason"]

def test_tampering_event_deletion_detected(client: TestClient, test_users, test_db_session):
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    for i in range(3):
        files = {"file": (f"chain_{i}.txt", io.BytesIO(f"content {i}".encode()), "text/plain")}
        client.post("/api/v1/documents/upload", headers=headers, data={"title": f"Doc {i}"}, files=files)

    events = test_db_session.query(AuditEvent).order_by(AuditEvent.timestamp.asc()).all()
    assert len(events) >= 3

    # Maliciously delete middle event
    middle_event = events[1]
    test_db_session.delete(middle_event)
    test_db_session.commit()

    # Integrity verification must catch the broken link
    result = verify_audit_integrity(test_db_session)
    assert result["is_valid"] is False
    assert "Chain break" in result["error_reason"]
