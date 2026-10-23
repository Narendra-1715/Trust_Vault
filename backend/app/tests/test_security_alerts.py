import pytest
from fastapi.testclient import TestClient
from app.models.document import Document
from app.models.notification import SecurityNotification
from app.core.security import create_access_token

def test_permission_lifecycle_creates_alerts(client: TestClient, test_db_session, test_users):
    """Verifies grant and revoke generate recipient-specific notifications with read-state management."""
    owner = test_users["owner_a"]
    viewer = test_users["viewer_a"]

    owner_token = create_access_token(subject=owner.id, role=owner.role)
    viewer_token = create_access_token(subject=viewer.id, role=viewer.role)

    # Create document
    doc = Document(
        owner_id=owner.id,
        title="Quarterly Security Review",
        original_filename="review.pdf",
        internal_storage_key="sec_rev_1.pdf",
        file_size=1024,
        detected_media_type="application/pdf",
        checksum="a" * 64,
        category="security"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    # 1. Owner grants permission to viewer
    grant_resp = client.post(
        f"/api/v1/documents/{doc.id}/permissions",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"email": viewer.email, "permission_level": "read"}
    )
    assert grant_resp.status_code == 201

    # 2. Viewer checks notifications
    notif_resp = client.get(
        "/api/v1/notifications",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert notif_resp.status_code == 200
    notifs = notif_resp.json()
    assert len(notifs) >= 1

    grant_notif = next((n for n in notifs if n["event_type"] == "document.permission.granted"), None)
    assert grant_notif is not None
    assert "Quarterly Security Review" in grant_notif["message"]
    assert grant_notif["is_read"] is False

    # 3. Check unread count
    count_resp = client.get(
        "/api/v1/notifications/unread-count",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert count_resp.status_code == 200
    assert count_resp.json()["unread_count"] >= 1

    # 4. Mark notification read
    mark_resp = client.patch(
        f"/api/v1/notifications/{grant_notif['id']}/read",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert mark_resp.status_code == 200
    assert mark_resp.json()["is_read"] is True

    # 5. Owner revokes permission
    revoke_resp = client.delete(
        f"/api/v1/documents/{doc.id}/permissions/{viewer.id}",
        headers={"Authorization": f"Bearer {owner_token}"}
    )
    assert revoke_resp.status_code == 204

    # 6. Viewer checks new revoke alert
    notif_resp2 = client.get(
        "/api/v1/notifications?unread_only=true",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert notif_resp2.status_code == 200
    unread_notifs = notif_resp2.json()
    revoke_notif = next((n for n in unread_notifs if n["event_type"] == "document.permission.revoked"), None)
    assert revoke_notif is not None
    assert revoke_notif["severity"] == "warning"

def test_mark_all_read(client: TestClient, test_db_session, test_users):
    """Verifies bulk marking all notifications as read."""
    user = test_users["viewer_a"]
    token = create_access_token(subject=user.id, role=user.role)

    # Seed 2 unread notifications
    n1 = SecurityNotification(
        user_id=user.id,
        title="Notice 1",
        message="Message 1",
        severity="info",
        event_type="test",
        is_read=False
    )
    n2 = SecurityNotification(
        user_id=user.id,
        title="Notice 2",
        message="Message 2",
        severity="warning",
        event_type="test",
        is_read=False
    )
    test_db_session.add_all([n1, n2])
    test_db_session.commit()

    mark_all_resp = client.post(
        "/api/v1/notifications/mark-all-read",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert mark_all_resp.status_code == 200
    assert mark_all_resp.json()["marked_count"] >= 2

    count_resp = client.get(
        "/api/v1/notifications/unread-count",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert count_resp.json()["unread_count"] == 0

def test_repeated_access_denials_generate_alert(client: TestClient, test_db_session, test_users):
    """Verifies repeated unauthorized download attempts trigger a danger-level security alert."""
    owner = test_users["owner_a"]
    viewer = test_users["viewer_a"]
    viewer_token = create_access_token(subject=viewer.id, role=viewer.role)

    doc = Document(
        owner_id=owner.id,
        title="Top Secret Blueprint",
        original_filename="blueprint.pdf",
        internal_storage_key="bp_1.pdf",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="b" * 64,
        category="engineering"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    # Viewer attempts 3 unauthorized downloads
    for _ in range(3):
        res = client.get(
            f"/api/v1/documents/{doc.id}/download",
            headers={"Authorization": f"Bearer {viewer_token}"}
        )
        assert res.status_code == 404

    # Viewer checks notifications for repeated access alert
    notifs = client.get(
        "/api/v1/notifications",
        headers={"Authorization": f"Bearer {viewer_token}"}
    ).json()

    threshold_alert = next((n for n in notifs if n["event_type"] == "security.denial.threshold"), None)
    assert threshold_alert is not None
    assert threshold_alert["severity"] == "danger"
    assert "Repeated Access Denial" in threshold_alert["title"]
