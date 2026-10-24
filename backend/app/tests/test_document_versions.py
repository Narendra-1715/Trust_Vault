import io
import hashlib
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers
from app.storage.local import storage_service

def test_document_version_lifecycle(client: TestClient, test_users, test_db_session):
    """
    Comprehensive test of Document Version Control:
    1. Upload document creates version 1.
    2. Upload version 2 updates document pointers and marks v1 not current.
    3. List versions returns both versions with uploader metadata.
    4. Historical download of v1 returns v1 content.
    5. Download of v2 returns v2 content.
    6. Restore v1 creates v3 with v1 content.
    7. Viewer cannot upload new version or restore.
    8. Unauthorized user cannot view or download versions.
    9. Integrity check detects corrupt storage.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    headers_stranger = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")
    viewer_id = test_users["viewer_a"].id

    # 1. Upload initial document (v1)
    v1_content = b"%PDF-1.4 Version 1 content of secret project"
    v1_hash = hashlib.sha256(v1_content).hexdigest()
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Versioned Document", "category": "Engineering"},
        files={"file": ("project_v1.pdf", io.BytesIO(v1_content), "application/pdf")}
    )
    assert upload_res.status_code == 201
    doc_data = upload_res.json()
    doc_id = doc_data["id"]
    assert doc_data["current_version_number"] == 1
    assert doc_data["version_count"] == 1
    assert doc_data["checksum"] == v1_hash

    # Grant read permission to viewer
    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"user_id": viewer_id, "permission_level": "read"}
    )
    assert grant_res.status_code == 201

    # 2. Check initial version list
    ver_list_res = client.get(f"/api/v1/documents/{doc_id}/versions", headers=headers_owner)
    assert ver_list_res.status_code == 200
    versions = ver_list_res.json()["versions"]
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1
    assert versions[0]["is_current"] is True
    assert versions[0]["checksum"] == v1_hash
    v1_id = versions[0]["id"]

    # 3. Upload version 2 as owner
    v2_content = b"%PDF-1.4 Version 2 revised specifications"
    v2_hash = hashlib.sha256(v2_content).hexdigest()
    v2_res = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers=headers_owner,
        data={"change_summary": "Added architectural diagrams"},
        files={"file": ("project_v2.pdf", io.BytesIO(v2_content), "application/pdf")}
    )
    assert v2_res.status_code == 201
    v2_data = v2_res.json()
    assert v2_data["version_number"] == 2
    assert v2_data["is_current"] is True
    assert v2_data["checksum"] == v2_hash
    assert v2_data["change_summary"] == "Added architectural diagrams"
    v2_id = v2_data["id"]

    # Verify document details updated to v2
    doc_detail = client.get(f"/api/v1/documents/{doc_id}", headers=headers_owner).json()
    assert doc_detail["current_version_number"] == 2
    assert doc_detail["version_count"] == 2
    assert doc_detail["checksum"] == v2_hash

    # 4. List versions now returns [v2, v1]
    ver_list_res = client.get(f"/api/v1/documents/{doc_id}/versions", headers=headers_owner)
    versions = ver_list_res.json()["versions"]
    assert len(versions) == 2
    assert versions[0]["version_number"] == 2
    assert versions[0]["is_current"] is True
    assert versions[1]["version_number"] == 1
    assert versions[1]["is_current"] is False

    # 5. Viewer can read version list and download historical v1 & v2
    viewer_ver_list = client.get(f"/api/v1/documents/{doc_id}/versions", headers=headers_viewer)
    assert viewer_ver_list.status_code == 200

    v1_download = client.get(f"/api/v1/documents/{doc_id}/versions/{v1_id}/download", headers=headers_viewer)
    assert v1_download.status_code == 200
    assert v1_download.content == v1_content

    v2_download = client.get(f"/api/v1/documents/{doc_id}/versions/{v2_id}/download", headers=headers_viewer)
    assert v2_download.status_code == 200
    assert v2_download.content == v2_content

    # Current main download endpoint returns current v2
    main_download = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert main_download.status_code == 200
    assert main_download.content == v2_content

    # 6. Viewer (read-only) cannot upload new version
    v3_attempt = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers=headers_viewer,
        files={"file": ("hack.pdf", io.BytesIO(b"%PDF-1.4 malicious"), "application/pdf")}
    )
    assert v3_attempt.status_code == 403

    # Viewer cannot restore version
    restore_attempt = client.post(
        f"/api/v1/documents/{doc_id}/versions/{v1_id}/restore",
        headers=headers_viewer
    )
    assert restore_attempt.status_code == 403

    # 7. Stranger cannot access version list or download
    stranger_list = client.get(f"/api/v1/documents/{doc_id}/versions", headers=headers_stranger)
    assert stranger_list.status_code == 404

    stranger_down = client.get(f"/api/v1/documents/{doc_id}/versions/{v1_id}/download", headers=headers_stranger)
    assert stranger_down.status_code == 404

    # 8. Restore v1 creates v3 as current
    restore_res = client.post(
        f"/api/v1/documents/{doc_id}/versions/{v1_id}/restore",
        headers=headers_owner
    )
    assert restore_res.status_code == 200
    v3_data = restore_res.json()
    assert v3_data["version_number"] == 3
    assert v3_data["is_current"] is True
    assert v3_data["checksum"] == v1_hash
    assert "Restored from version 1" in v3_data["change_summary"]

    # Verify list now has 3 versions: v3 (current), v2, v1
    ver_list_res = client.get(f"/api/v1/documents/{doc_id}/versions", headers=headers_owner)
    versions = ver_list_res.json()["versions"]
    assert len(versions) == 3
    assert [v["version_number"] for v in versions] == [3, 2, 1]
    assert versions[0]["is_current"] is True
    assert versions[1]["is_current"] is False
    assert versions[2]["is_current"] is False

    # Download of v3 yields v1_content
    v3_download = client.get(f"/api/v1/documents/{doc_id}/versions/{v3_data['id']}/download", headers=headers_owner)
    assert v3_download.status_code == 200
    assert v3_download.content == v1_content

    # 9. Integrity detection: Corrupt a version file in storage
    from app.models.document_version import DocumentVersion
    ver_record = test_db_session.query(DocumentVersion).filter(DocumentVersion.id == v2_id).first()
    storage_key = ver_record.storage_key
    storage_service.save_file(io.BytesIO(b"%PDF-1.4 CORRUPTED BYTES"), storage_key)

    corrupt_download = client.get(f"/api/v1/documents/{doc_id}/versions/{v2_id}/download", headers=headers_owner)
    assert corrupt_download.status_code == 500
    assert "integrity" in corrupt_download.json()["detail"].lower()
