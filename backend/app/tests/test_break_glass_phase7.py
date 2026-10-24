import io
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.tests.conftest import get_auth_headers
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.emergency_access import EmergencyAccess
from app.models.session import UserSession
from app.models.audit import AuditEvent
from app.models.security_alert import SecurityAlert
from app.services.incident import IncidentService
from app.incident.cli import main as incident_cli_main
from app.core.security import hash_password

@pytest.fixture
def second_admin(test_db_session: Session) -> User:
    """Creates a second distinct administrative officer for multi-party approvals."""
    admin_2 = test_db_session.query(User).filter(User.email == "security_officer_2@test.com").first()
    if not admin_2:
        admin_2 = User(
            email="security_officer_2@test.com",
            password_hash=hash_password("SecOfficerPass123!"),
            display_name="Security Officer Beta",
            role="admin",
            is_active=True
        )
        test_db_session.add(admin_2)
        test_db_session.commit()
        test_db_session.refresh(admin_2)
    return admin_2

def test_complete_break_glass_flow(
    client: TestClient,
    test_users,
    second_admin: User,
    test_db_session: Session
):
    """
    Phase 7 / Invariant I1 Test 1:
    Complete Multi-Party Break-Glass lifecycle:
    1. Admin A requests break-glass with ticket ID, reason, and time limit.
    2. Status enters pending_approval. Admin A cannot self-approve.
    3. Admin B (second security officer) approves the request -> status becomes active.
    4. Admin A can now access and download document content with is_break_glass audit tracking.
    5. Synchronous revocation immediately severs access.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_admin_a = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    headers_admin_b = get_auth_headers(client, "security_officer_2@test.com", "SecOfficerPass123!")

    # 1. Upload sensitive document
    files = {"file": ("classified.txt", io.BytesIO(b"Classified operational intelligence"), "text/plain")}
    doc_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Classified Intelligence", "category": "Legal"},
        files=files
    )
    assert doc_res.status_code == 201
    doc_id = doc_res.json()["id"]

    # Invariant I1: Admin Blindness - Admin A has ZERO access initially
    dl_blind = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin_a)
    assert dl_blind.status_code == 404

    # 2. Admin A initiates multi-party break-glass request
    bg_req = client.post(
        "/api/v1/admin/break-glass",
        headers=headers_admin_a,
        json={
            "document_id": doc_id,
            "justification": "Court order subpoena compliance verification",
            "ticket_id": "SEC-TICKET-8891",
            "duration_minutes": 60,
            "password": "AdminPass123!",
            "approval_mode": "multi_party"
        }
    )
    assert bg_req.status_code == 201
    bg_data = bg_req.json()
    bg_id = bg_data["id"]
    assert bg_data["status"] == "pending_approval"
    assert bg_data["ticket_id"] == "SEC-TICKET-8891"

    # While pending approval, Admin A still CANNOT access document content
    dl_pending = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin_a)
    assert dl_pending.status_code == 404

    # 3. Admin A attempting to self-approve is strictly forbidden
    self_approve = client.post(f"/api/v1/admin/break-glass/{bg_id}/approve", headers=headers_admin_a)
    assert self_approve.status_code == 403
    assert "requester cannot self-approve" in self_approve.json()["detail"].lower()

    # 4. Admin B (second officer) approves the break-glass request
    approve_res = client.post(f"/api/v1/admin/break-glass/{bg_id}/approve", headers=headers_admin_b)
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "active"
    assert approve_res.json()["approved_by"] == second_admin.id

    # 5. Admin A CAN now download document content under active break-glass
    dl_active = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin_a)
    assert dl_active.status_code == 200
    assert dl_active.content == b"Classified operational intelligence"

    # Verify is_break_glass audit event was recorded
    bg_audit = test_db_session.query(AuditEvent).filter(
        AuditEvent.resource_id == doc_id,
        AuditEvent.actor_id == test_users["admin"].id,
        AuditEvent.action == "break_glass.download"
    ).first()
    assert bg_audit is not None
    assert bg_audit.structured_metadata.get("is_break_glass") is True

    # 6. Synchronous revocation cut-off
    revoke_res = client.post(f"/api/v1/admin/break-glass/{bg_id}/revoke", headers=headers_admin_b)
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "revoked"

    # Verify content access is immediately cut off (Invariant I1 & I2)
    dl_revoked = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin_a)
    assert dl_revoked.status_code == 404

def test_break_glass_cannot_grant_wildcard_access(
    client: TestClient,
    test_users
):
    """
    Phase 7 / Invariant I1 Test 2:
    Break-glass cannot grant wildcard access (e.g. '*' or 'all').
    Must target an explicit, valid document UUID.
    """
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")

    # 1. Attempt wildcard '*'
    res_wildcard = client.post(
        "/api/v1/admin/break-glass",
        headers=headers_admin,
        json={
            "document_id": "*",
            "justification": "Attempting full platform administrative audit",
            "password": "AdminPass123!"
        }
    )
    assert res_wildcard.status_code == 400
    assert "wildcard" in res_wildcard.json()["detail"].lower()

    # 2. Attempt wildcard 'all'
    res_all = client.post(
        "/api/v1/admin/break-glass",
        headers=headers_admin,
        json={
            "document_id": "all",
            "justification": "Attempting all document dump for forensic sweep",
            "password": "AdminPass123!"
        }
    )
    assert res_all.status_code == 400
    assert "wildcard" in res_all.json()["detail"].lower()

def test_owner_can_cancel_pending_break_glass_during_delay(
    client: TestClient,
    test_users,
    test_db_session: Session
):
    """
    Phase 7 / Invariant I1 Test 3:
    In time-delay mode, an active cancellation window is established.
    The document owner is notified and can cancel the pending break-glass request,
    preventing any emergency access.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")

    # 1. Owner uploads document
    files = {"file": ("patents.txt", io.BytesIO(b"Proprietary patent formulas"), "text/plain")}
    doc_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Patents and Trade Secrets", "category": "IP"},
        files=files
    )
    doc_id = doc_res.json()["id"]

    # 2. Admin requests break-glass with time delay
    bg_res = client.post(
        "/api/v1/admin/break-glass",
        headers=headers_admin,
        json={
            "document_id": doc_id,
            "justification": "Emergency patent verification for patent office",
            "approval_mode": "time_delay",
            "delay_hours": 4,
            "password": "AdminPass123!"
        }
    )
    assert bg_res.status_code == 201
    bg_id = bg_res.json()["id"]
    assert bg_res.json()["status"] == "pending_delay"

    # 3. Document owner receives notification and cancels the break-glass request
    cancel_res = client.post(
        f"/api/v1/admin/break-glass/{bg_id}/cancel",
        headers=headers_owner
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "cancelled"

    # 4. Admin CANNOT access document content
    dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin)
    assert dl_res.status_code == 404

def test_isolate_user_freezes_documents_and_kills_sessions(
    client: TestClient,
    test_users,
    second_admin: User,
    test_db_session: Session
):
    """
    Phase 7 / Incident Response Test 4:
    Isolating a compromised user:
    - Terminates all user sessions immediately
    - Increments user session_version (invalidating active JWTs)
    - Freezes all owned documents (is_frozen = True)
    - Revokes all outgoing permissions issued by the user
    - Ordinary viewers cannot access frozen documents (uniform 404)
    - Only approved emergency break-glass permits access to frozen documents
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")

    owner_id = test_users["owner_a"].id
    viewer_id = test_users["viewer_a"].id

    # 1. Owner uploads a document and grants access to Viewer A
    files = {"file": ("project_alpha.txt", io.BytesIO(b"Alpha project blueprints"), "text/plain")}
    doc_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Project Alpha", "category": "Engineering"},
        files=files
    )
    doc_id = doc_res.json()["id"]

    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read"}
    )
    assert grant_res.status_code == 201

    # Verify Viewer A can initially read document
    v_read_init = client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer)
    assert v_read_init.status_code == 200

    # 2. Execute CLI isolation command for Owner A
    exit_code = incident_cli_main(["isolate-user", owner_id, "--reason", "Compromised credential leak detected"], db_session=test_db_session)
    assert exit_code == 0

    # 3. Verify owner is deactivated and session_version incremented
    test_db_session.expire_all()
    isolated_owner = test_db_session.query(User).filter(User.id == owner_id).first()
    assert isolated_owner.is_active is False
    assert isolated_owner.session_version >= 2

    # Verify active sessions terminated
    active_sessions = test_db_session.query(UserSession).filter(
        UserSession.user_id == owner_id,
        UserSession.revoked_at.is_(None)
    ).all()
    assert len(active_sessions) == 0

    # 4. Verify owner documents are frozen
    doc = test_db_session.query(Document).filter(Document.id == doc_id).first()
    assert doc.is_frozen is True

    # 5. Verify outgoing grants issued by owner were revoked
    outgoing_grant = test_db_session.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc_id,
        DocumentPermission.user_id == viewer_id
    ).first()
    assert outgoing_grant.revoked_at is not None

    # 6. Viewer A attempting to read now receives uniform 404
    v_read_after = client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer)
    assert v_read_after.status_code == 404

    # Owner attempting to access receives denied response (401/403/404)
    owner_read = client.get(f"/api/v1/documents/{doc_id}", headers=headers_owner)
    assert owner_read.status_code in [401, 403, 404]

    # 7. Recovery: An approved emergency break-glass permits administrator to inspect the frozen document
    bg_res = client.post(
        "/api/v1/admin/break-glass",
        headers=headers_admin,
        json={
            "document_id": doc_id,
            "justification": "Incident containment forensic document recovery",
            "password": "AdminPass123!"
        }
    )
    assert bg_res.status_code == 201

    admin_recovery = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_admin)
    assert admin_recovery.status_code == 200
    assert admin_recovery.content == b"Alpha project blueprints"
