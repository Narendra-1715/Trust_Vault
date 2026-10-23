import urllib.request
import urllib.error
import json
import uuid
import hashlib

BASE_URL = "https://trustvault-api-s6ba.onrender.com/api/v1"

def probe_s3():
    # 1. Login as owner_a
    login_body = json.dumps({"email": "owner_a@trustvault.com", "password": "OwnerAPass123!"}).encode("utf-8")
    res = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/auth/login", data=login_body, headers={"Content-Type": "application/json"}))
    token_a = json.loads(res.read().decode())["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 2. Upload unique document
    unique_id = uuid.uuid4().hex[:8]
    payload = f"%PDF-1.4\n% Test S3 Active Backend\n% UUID: {unique_id}\n" + ("Z" * 500) + "\n%%EOF"
    payload_bytes = payload.encode("utf-8")
    expected_checksum = hashlib.sha256(payload_bytes).hexdigest()

    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nS3 Active Probe {unique_id}\r\n".encode("utf-8"),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"category\"\r\n\r\nLegal\r\n".encode("utf-8"),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"probe_{unique_id}.pdf\"\r\nContent-Type: application/pdf\r\n\r\n".encode("utf-8"),
        payload_bytes,
        f"\r\n--{boundary}--\r\n".encode("utf-8")
    ]
    body = b"".join(parts)

    req = urllib.request.Request(f"{BASE_URL}/documents/upload", data=body, headers={"Authorization": f"Bearer {token_a}", "Content-Type": f"multipart/form-data; boundary={boundary}"})
    upload_res = urllib.request.urlopen(req)
    doc_data = json.loads(upload_res.read().decode())
    print("Upload Status:", upload_res.status)
    doc_id = doc_data["id"]
    print("Document ID:", doc_id)
    print("Stored Checksum:", doc_data["checksum"])

    # 3. Download and verify
    dl_req = urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_a)
    dl_res = urllib.request.urlopen(dl_req)
    dl_bytes = dl_res.read()
    dl_checksum = hashlib.sha256(dl_bytes).hexdigest()
    print("Download Status:", dl_res.status)
    print("Downloaded Bytes:", len(dl_bytes))
    print("Checksum Match:", dl_checksum == expected_checksum)
    assert dl_checksum == expected_checksum, "Checksum mismatch!"

    return doc_id, expected_checksum, len(payload_bytes)

if __name__ == "__main__":
    probe_s3()
