import io
import pytest
from fastapi.testclient import TestClient
from app.tests.conftest import get_auth_headers
from app.storage.local import sanitize_filename

def test_executable_upload_rejected(client: TestClient, test_users):
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    fake_exe = io.BytesIO(b"MZ executable header dummy bytes")
    files = {"file": ("malware.exe", fake_exe, "application/octet-stream")}
    res = client.post("/api/v1/documents/upload", headers=headers, data={"title": "Malware"}, files=files)
    assert res.status_code == 400
    assert "not permitted" in res.json()["detail"].lower()

def test_mime_magic_byte_spoofing_rejected(client: TestClient, test_users):
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    # Send plain text with a .pdf extension
    fake_pdf = io.BytesIO(b"This is completely plain text with no PDF header")
    files = {"file": ("fake.pdf", fake_pdf, "application/pdf")}
    res = client.post("/api/v1/documents/upload", headers=headers, data={"title": "Fake PDF"}, files=files)
    assert res.status_code == 400
    assert "does not match expected format" in res.json()["detail"]

def test_filename_sanitization_strips_path_traversal():
    dangerous_names = [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\calc.exe",
        "nested/path/to/file.pdf",
        "file\0nullbyte.pdf"
    ]
    for d in dangerous_names:
        clean = sanitize_filename(d)
        assert "/" not in clean
        assert "\\" not in clean
        assert "\0" not in clean
        assert ".." not in clean

def test_document_deletion_removes_private_file(client: TestClient, test_users):
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    files = {"file": ("doc.txt", io.BytesIO(b"Temporary confidential content"), "text/plain")}
    res = client.post("/api/v1/documents/upload", headers=headers, data={"title": "To Delete"}, files=files)
    assert res.status_code == 201
    doc_id = res.json()["id"]

    # Delete
    del_res = client.delete(f"/api/v1/documents/{doc_id}", headers=headers)
    assert del_res.status_code == 204

    # Subsequent read is 404
    assert client.get(f"/api/v1/documents/{doc_id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/documents/{doc_id}/download", headers=headers).status_code == 404

    # Verify document appears in owner's trash archive with deleted_at populated
    trash_res = client.get("/api/v1/documents/trash", headers=headers)
    assert trash_res.status_code == 200
    trashed_docs = trash_res.json()["documents"]
    matching = [d for d in trashed_docs if d["id"] == doc_id]
    assert len(matching) == 1
    assert matching[0]["deleted_at"] is not None
    assert matching[0]["title"] == "To Delete"

    # Unrelated viewer cannot see owner's trashed document
    viewer_headers = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    viewer_trash = client.get("/api/v1/documents/trash", headers=viewer_headers)
    assert viewer_trash.status_code == 200
    assert not any(d["id"] == doc_id for d in viewer_trash.json()["documents"])

    # Administrator can inspect organization-wide trashed documents
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    admin_trash = client.get("/api/v1/documents/trash", headers=admin_headers)
    assert admin_trash.status_code == 200
    assert any(d["id"] == doc_id for d in admin_trash.json()["documents"])

def test_missing_storage_file_fails_safely_without_silent_fabrication(client: TestClient, test_users, test_db_session, test_storage):
    """Verifies that missing storage objects produce visible 500 errors rather than silently fabricating fake bytes."""
    from app.models.document import Document
    from app.models.user import User

    owner = test_db_session.query(User).filter(User.email == "owner_a@test.com").first()
    # Create doc record pointing to non-existent storage key
    missing_key = "non_existent_key_99999.bin"
    orphan_doc = Document(
        owner_id=owner.id,
        title="Orphan Document",
        description="Missing storage file",
        original_filename="orphan.pdf",
        internal_storage_key=missing_key,
        detected_media_type="application/pdf",
        file_size=1024,
        checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        category="General"
    )
    test_db_session.add(orphan_doc)
    test_db_session.commit()
    test_db_session.refresh(orphan_doc)

    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    dl_res = client.get(f"/api/v1/documents/{orphan_doc.id}/download", headers=headers)
    
    # Must fail with 500 rather than 200 with fake placeholder bytes
    assert dl_res.status_code == 500, f"Expected 500, got {dl_res.status_code}: {dl_res.text}"
    assert "Storage object missing" in dl_res.json()["detail"]
