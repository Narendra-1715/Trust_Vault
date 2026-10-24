import io
import pytest
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers

def upload_sample_doc(client: TestClient, headers: dict, title: str = "Confidential Financials") -> dict:
    file_bytes = b"%PDF-1.4 sample pdf content for unit test"
    files = {"file": ("test.pdf", io.BytesIO(file_bytes), "application/pdf")}
    data = {"title": title, "category": "Financial", "description": "Strictly confidential"}
    res = client.post("/api/v1/documents/upload", headers=headers, data=data, files=files)
    assert res.status_code == 201
    return res.json()

def test_cross_user_read_isolation_returns_404(client: TestClient, test_users):
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")

    doc_a = upload_sample_doc(client, headers_a, "Owner A Secret Document")
    doc_id = doc_a["id"]

    # Owner B attempts to read Owner A's document details -> 404 Not Found
    res = client.get(f"/api/v1/documents/{doc_id}", headers=headers_b)
    assert res.status_code == 404
    assert res.json()["detail"] == "Document not found"

def test_cross_user_download_isolation_returns_404(client: TestClient, test_users):
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")

    doc_a = upload_sample_doc(client, headers_a, "Owner A Payroll")
    doc_id = doc_a["id"]

    # Owner B attempts to download Owner A's document -> 404
    res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_b)
    assert res.status_code == 404

def test_cross_user_edit_denied(client: TestClient, test_users):
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")

    doc_a = upload_sample_doc(client, headers_a, "Owner A Architecture")
    doc_id = doc_a["id"]

    # Owner B attempts to patch metadata -> 404 (does not disclose existence)
    res = client.patch(f"/api/v1/documents/{doc_id}", headers=headers_b, json={"title": "Hacked Title"})
    assert res.status_code == 404

def test_cross_user_delete_denied(client: TestClient, test_users):
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")

    doc_a = upload_sample_doc(client, headers_a, "Owner A Core IP")
    doc_id = doc_a["id"]

    # Owner B attempts to delete -> 404
    res = client.delete(f"/api/v1/documents/{doc_id}", headers=headers_b)
    assert res.status_code == 404

def test_viewer_with_read_access_cannot_edit(client: TestClient, test_users):
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_v = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")

    doc = upload_sample_doc(client, headers_a, "Quarterly Review")
    doc_id = doc["id"]

    # Owner A grants Viewer A READ access
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_a,
        json={"email": "viewer_a@test.com", "permission_level": "read"}
    )
    assert grant_res.status_code == 201

    # Viewer A can read
    read_res = client.get(f"/api/v1/documents/{doc_id}", headers=headers_v)
    assert read_res.status_code == 200

    # Viewer A CANNOT edit -> 404 (Invariant I3 uniform not-found)
    edit_res = client.patch(
        f"/api/v1/documents/{doc_id}",
        headers=headers_v,
        json={"title": "Viewer Altered Title"}
    )
    assert edit_res.status_code in [403, 404]

def test_viewer_cannot_grant_permissions(client: TestClient, test_users):
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_v = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")

    doc = upload_sample_doc(client, headers_a, "Board Minutes")
    doc_id = doc["id"]

    # Grant Viewer A read permission
    client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_a,
        json={"email": "viewer_a@test.com", "permission_level": "read"}
    )

    # Viewer A attempts to grant permissions to Owner B -> 403 Forbidden
    grant_attempt = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_v,
        json={"email": "owner_b@test.com", "permission_level": "read"}
    )
    assert grant_attempt.status_code in [403, 404]

def test_search_never_reveals_unauthorized_documents(client: TestClient, test_users):
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")

    # Owner A uploads private document with unique keyword
    upload_sample_doc(client, headers_a, "Project_Falcon_Top_Secret")

    # Owner B searches for "Falcon"
    search_res = client.get("/api/v1/documents?query=Falcon", headers=headers_b)
    assert search_res.status_code == 200
    data = search_res.json()
    assert data["total"] == 0

def test_viewer_cannot_enumerate_users(client: TestClient, test_users):
    """Verifies that ordinary viewers cannot enumerate organizational members."""
    headers_v = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    res = client.get("/api/v1/users", headers=headers_v)
    assert res.status_code == 403
    assert "Viewers are not authorized" in res.json()["detail"]

def test_owner_gets_minimal_user_directory(client: TestClient, test_users):
    """Verifies that authorized owners receive only minimal directory items without internal timestamps."""
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    res = client.get("/api/v1/users", headers=headers_a)
    assert res.status_code == 200
    users = res.json()
    assert len(users) > 0
    first_user = users[0]
    assert "id" in first_user
    assert "email" in first_user
    assert "display_name" in first_user
    assert "role" in first_user
    assert "created_at" not in first_user
    assert "updated_at" not in first_user

def test_admin_only_users_all_endpoint(client: TestClient, test_users):
    """Verifies that GET /api/v1/users/all is strictly restricted to system administrators."""
    headers_v = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    headers_o = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")

    assert client.get("/api/v1/users/all", headers=headers_v).status_code == 403
    assert client.get("/api/v1/users/all", headers=headers_o).status_code == 403
    assert client.get("/api/v1/users/all", headers=headers_admin).status_code == 200

def test_storage_checksum_corruption_detection(client: TestClient, test_users, test_db_session):
    """Verifies that altered or corrupted file bytes on disk fail checksum validation upon download."""
    import os
    from app.storage.local import storage_service
    from app.models.document import Document

    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    doc = upload_sample_doc(client, headers_a, "Tamper Target")
    doc_id = doc["id"]

    db_doc = test_db_session.query(Document).filter(Document.id == doc_id).first()
    file_path = storage_service._resolve_safe_path(db_doc.internal_storage_key)

    # Tamper with the file bytes directly on disk
    with open(file_path, "wb") as f:
        f.write(b"%PDF-1.4 TAMPERED CONTENT CORRUPTED ON DISK %%EOF")

    # Download must fail with 500 Checksum mismatch
    dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_a)
    assert dl_res.status_code == 500
    assert "File integrity check failed" in dl_res.json()["detail"]

def test_peer_owner_isolation_in_same_organization(client: TestClient, test_users):
    """
    Verifies that peer document owners in the same organization can view the sharing directory
    but are strictly isolated from accessing each other's unshared documents.
    """
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")

    # 1. Both owners can access the company user directory for document sharing
    users_a = client.get("/api/v1/users", headers=headers_a).json()
    users_b = client.get("/api/v1/users", headers=headers_b).json()
    assert len(users_a) > 0
    assert len(users_b) > 0

    # 2. Owner A uploads private confidential document
    doc_a = upload_sample_doc(client, headers_a, "Owner A Confidential Patent")
    doc_a_id = doc_a["id"]

    # 3. Peer Owner B is denied all access (returns 404 Not Found to prevent enumeration)
    assert client.get(f"/api/v1/documents/{doc_a_id}", headers=headers_b).status_code == 404
    assert client.get(f"/api/v1/documents/{doc_a_id}/download", headers=headers_b).status_code == 404
    assert client.patch(f"/api/v1/documents/{doc_a_id}", headers=headers_b, json={"title": "Hacked"}).status_code == 404
    assert client.delete(f"/api/v1/documents/{doc_a_id}", headers=headers_b).status_code == 404

    # 4. Search isolation: Owner B cannot discover Owner A's document via search
    search_res = client.get("/api/v1/documents?query=Patent", headers=headers_b).json()
    assert search_res["total"] == 0
