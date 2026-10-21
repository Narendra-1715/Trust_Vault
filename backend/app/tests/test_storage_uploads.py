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
