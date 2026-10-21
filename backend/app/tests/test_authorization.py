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

    # Viewer A CANNOT edit -> 403 Forbidden
    edit_res = client.patch(
        f"/api/v1/documents/{doc_id}",
        headers=headers_v,
        json={"title": "Viewer Altered Title"}
    )
    assert edit_res.status_code == 403

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
    assert grant_attempt.status_code == 403
    assert "Only the document owner" in grant_attempt.json()["detail"]

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
    assert len(data["documents"]) == 0
