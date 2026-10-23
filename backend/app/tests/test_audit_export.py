import io
import csv
import json
import pytest
from fastapi.testclient import TestClient
from app.models.document import Document
from app.models.audit import AuditEvent
from app.core.security import create_access_token
from app.audit.service import log_audit_event

def test_admin_export_csv_and_json(client: TestClient, test_db_session, test_users):
    """Verifies CSV and JSON export endpoints for administrators."""
    admin = test_users["admin"]
    token = create_access_token(subject=admin.id, role=admin.role)

    # Seed an audit event
    log_audit_event(
        db=test_db_session,
        action="system.startup",
        resource_type="system",
        resource_id="core",
        outcome="success",
        actor_id=admin.id
    )

    # 1. Export as JSON
    res_json = client.get(
        "/api/v1/audit/export?format=json",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]
    assert "attachment; filename=" in res_json.headers["content-disposition"]
    data = res_json.json()
    assert isinstance(data, list)
    assert len(data) >= 1

    # 2. Export as CSV
    res_csv = client.get(
        "/api/v1/audit/export?format=csv",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    csv_text = res_csv.text
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) >= 2  # Header + at least 1 record
    assert rows[0][0] == "Event ID"
    assert rows[0][4] == "Action"

def test_csv_formula_injection_mitigation(client: TestClient, test_db_session, test_users):
    """Verifies that cells starting with =, +, -, @, \\t, \\r are safely prefixed with a quote."""
    admin = test_users["admin"]
    token = create_access_token(subject=admin.id, role=admin.role)

    # Log an audit event with potentially malicious formula injection payloads
    log_audit_event(
        db=test_db_session,
        action="=cmd|'/C calc'!A0",
        resource_type="+malicious_type",
        resource_id="-sensitive_id",
        outcome="success",
        actor_id=admin.id,
        metadata={"formula": "@SUM(1+1)"}
    )

    res = client.get(
        "/api/v1/audit/export?format=csv",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    reader = csv.reader(io.StringIO(res.text))
    rows = list(reader)

    # Find the malicious row
    malicious_row = next((r for r in rows if "calc" in r[4] or "malicious" in r[5]), None)
    assert malicious_row is not None
    assert malicious_row[4].startswith("'=")
    assert malicious_row[5].startswith("'+")
    assert malicious_row[6].startswith("'-")

def test_owner_export_scoped_to_own_documents(client: TestClient, test_db_session, test_users):
    """Verifies document owners only receive events within their authorized document scope."""
    alice = test_users["owner_a"]
    bob = test_users["owner_b"]
    alice_token = create_access_token(subject=alice.id, role=alice.role)

    # Log event for Bob's private document
    log_audit_event(
        db=test_db_session,
        action="document.secret.view",
        resource_type="document",
        resource_id="bob_secret_doc_id",
        outcome="success",
        actor_id=bob.id
    )

    # Alice exports JSON
    res = client.get(
        "/api/v1/audit/export?format=json",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert res.status_code == 200
    events = res.json()
    bob_events = [e for e in events if e.get("resource_id") == "bob_secret_doc_id"]
    assert len(bob_events) == 0

def test_hash_chain_verification_endpoint(client: TestClient, test_db_session, test_users):
    """Verifies GET /audit/verify reports valid cryptographic chain."""
    admin = test_users["admin"]
    token = create_access_token(subject=admin.id, role=admin.role)

    log_audit_event(
        db=test_db_session,
        action="system.check",
        resource_type="system",
        resource_id="node_1",
        outcome="success",
        actor_id=admin.id
    )

    res = client.get(
        "/api/v1/audit/verify",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    report = res.json()
    assert report["is_valid"] is True
    assert report["total_events"] > 0
