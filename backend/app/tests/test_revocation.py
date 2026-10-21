import io
import pytest
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers

def test_immediate_permission_revocation_lifecycle(client: TestClient, test_users):
    """
    Verifies that permission revocation immediately prevents download and read requests
    on subsequent attempts without requiring session reset or server restart.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")

    # 1. Owner uploads confidential document
    file_content = b"%PDF-1.4 confidential contract bytes"
    files = {"file": ("contract.pdf", io.BytesIO(file_content), "application/pdf")}
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Master Services Agreement", "category": "Legal"},
        files=files
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # 2. Before grant, viewer is denied
    assert client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer).status_code == 404
    assert client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer).status_code == 404

    # 3. Owner grants Viewer A READ permission
    viewer_id = test_users["viewer_a"].id
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read"}
    )
    assert grant_res.status_code == 201

    # 4. Viewer A can now read metadata and download the actual file
    meta_res = client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer)
    assert meta_res.status_code == 200
    assert meta_res.json()["title"] == "Master Services Agreement"

    download_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert download_res.status_code == 200
    assert download_res.content == file_content

    # 5. Owner REVOKES Viewer A's permission
    revoke_res = client.delete(
        f"/api/v1/documents/{doc_id}/permissions/{viewer_id}",
        headers=headers_owner
    )
    assert revoke_res.status_code == 204

    # 6. IMMEDIATELY on the very next request, download is DENIED
    next_download = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert next_download.status_code == 404

    # 7. IMMEDIATELY on the very next request, metadata read is DENIED
    next_meta = client.get(f"/api/v1/documents/{doc_id}", headers=headers_viewer)
    assert next_meta.status_code == 404
