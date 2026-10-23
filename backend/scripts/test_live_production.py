import urllib.request
import urllib.error
import json
import os
import hashlib
import uuid

BASE_URL = "https://trustvault-api-s6ba.onrender.com/api/v1"

def run_test():
    print("=" * 70)
    print("TRUSTVAULT LIVE PRODUCTION INDEPENDENT VERIFICATION")
    print("Target API:", BASE_URL)
    print("=" * 70)

    # 1. Health check
    print("\n[1/7] Probing Production Health Telemetry...")
    req = urllib.request.urlopen(f"{BASE_URL}/health", timeout=20)
    health_data = json.loads(req.read().decode())
    print(f"  Service: {health_data.get('service')}")
    print(f"  Status: {health_data.get('status')}")
    print(f"  Live Commit SHA: {health_data.get('commit_sha')}")

    # 2. Login as Owner A
    print("\n[2/7] Authenticating as Alice Owner (owner_a@trustvault.com)...")
    login_body = json.dumps({"email": "owner_a@trustvault.com", "password": "OwnerAPass123!"}).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_body, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req, timeout=20)
    token_a = json.loads(res.read().decode())["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    print("  [PASS] Owner authenticated successfully.")

    # 3. Upload Unique Test Document
    print("\n[3/7] Uploading Unique Verification Document with Known Checksum...")
    unique_marker = uuid.uuid4().hex[:12]
    unique_content = f"%PDF-1.4\n% TrustVault S3 Cloud Storage Live Verification Payload\n% Unique Token: {unique_marker}\n" + ("X" * 1024) + "\n%%EOF"
    test_bytes = unique_content.encode("utf-8")
    expected_checksum = hashlib.sha256(test_bytes).hexdigest()
    expected_size = len(test_bytes)
    print(f"  Generated Payload: {expected_size} bytes")
    print(f"  Expected SHA-256: {expected_checksum}")

    # Build multipart/form-data
    boundary = "----WebKitBoundary" + uuid.uuid4().hex
    parts = []
    
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nLive Supabase Storage Test {unique_marker}\r\n".encode("utf-8"))
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"category\"\r\n\r\nLegal\r\n".encode("utf-8"))
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"live_test_{unique_marker}.pdf\"\r\nContent-Type: application/pdf\r\n\r\n".encode("utf-8"))
    parts.append(test_bytes)
    parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(parts)

    upload_req = urllib.request.Request(
        f"{BASE_URL}/documents/upload",
        data=body,
        headers={
            "Authorization": f"Bearer {token_a}",
            "Content-Type": f"multipart/form-data; boundary={boundary}"
        }
    )
    upload_res = urllib.request.urlopen(upload_req, timeout=25)
    doc = json.loads(upload_res.read().decode())
    doc_id = doc["id"]
    print(f"  [PASS] Upload Succeeded!")
    print(f"  Document ID: {doc_id}")
    print(f"  Server Title: {doc['title']}")
    print(f"  Server Checksum: {doc['checksum']}")
    assert doc["checksum"] == expected_checksum, "Checksum returned by server does not match original!"

    # 4. Download and verify exact bytes & SHA-256
    print("\n[4/7] Downloading Stored Document Bytes via Owner A...")
    dl_req = urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_a)
    dl_res = urllib.request.urlopen(dl_req, timeout=25)
    assert dl_res.status == 200, f"Expected 200 OK, got {dl_res.status}"
    downloaded_bytes = dl_res.read()
    downloaded_checksum = hashlib.sha256(downloaded_bytes).hexdigest()
    print(f"  Downloaded Size: {len(downloaded_bytes)} bytes")
    print(f"  Downloaded Checksum: {downloaded_checksum}")
    assert len(downloaded_bytes) == expected_size, f"Size mismatch! Expected {expected_size}, got {len(downloaded_bytes)}"
    assert downloaded_checksum == expected_checksum, "Downloaded SHA-256 does not match original payload!"
    print("  [PASS] 100% Exact byte parity & SHA-256 match verified!")

    # 5. Share with Viewer A
    print("\n[5/7] Granting Viewer A (Carol) Read Permission...")
    users_req = urllib.request.Request(f"{BASE_URL}/users", headers=headers_a)
    users = json.loads(urllib.request.urlopen(users_req, timeout=15).read().decode())
    viewer_user = next((u for u in users if u["email"] == "viewer_a@trustvault.com"), None)
    assert viewer_user is not None, "viewer_a not found in user directory"
    viewer_id = viewer_user["id"]

    perm_body = json.dumps({"user_id": viewer_id, "permission_level": "read"}).encode("utf-8")
    perm_req = urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/permissions", data=perm_body, headers={"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"})
    perm_res = urllib.request.urlopen(perm_req, timeout=15)
    print(f"  [PASS] Permission granted: HTTP {perm_res.status}")

    # 6. Viewer A Login and Download
    print("\n[6/7] Authenticating as Viewer A & Downloading...")
    login_viewer = json.dumps({"email": "viewer_a@trustvault.com", "password": "ViewerAPass123!"}).encode("utf-8")
    res_v = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/auth/login", data=login_viewer, headers={"Content-Type": "application/json"}), timeout=15)
    token_v = json.loads(res_v.read().decode())["access_token"]
    headers_v = {"Authorization": f"Bearer {token_v}"}

    dl_v = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_v), timeout=20)
    assert dl_v.status == 200
    dl_v_bytes = dl_v.read()
    assert hashlib.sha256(dl_v_bytes).hexdigest() == expected_checksum
    print("  [PASS] Viewer A downloaded document with exact SHA-256 match!")

    # 7. Owner Revocation & Immediate Denial
    print("\n[7/7] Revoking Viewer A Access & Verifying Immediate Denial...")
    del_req = urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/permissions/{viewer_id}", headers=headers_a, method="DELETE")
    del_res = urllib.request.urlopen(del_req, timeout=15)
    print(f"  Revoke API Call: HTTP {del_res.status}")

    try:
        urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_v), timeout=15)
        raise AssertionError("Security Failure: Revoked user was still able to download!")
    except urllib.error.HTTPError as e:
        print(f"  [PASS] Viewer download immediately rejected with HTTP {e.code} ({e.reason})!")

    # 8. Check Audit Ledger
    print("\n[Audit Check] Inspecting Security Audit Events for Document...")
    audit_req = urllib.request.Request(f"{BASE_URL}/audit/events?document_id={doc_id}", headers=headers_a)
    audit_data = json.loads(urllib.request.urlopen(audit_req, timeout=15).read().decode())
    actions = [evt["action"] for evt in audit_data.get("events", [])]
    print(f"  Recorded Actions: {actions}")
    assert "document.upload" in actions
    assert "document.download" in actions
    assert "document.download.denied" in actions
    print("  [PASS] Complete audit trail verified (upload, download, denial)!")

    print("\n" + "=" * 70)
    print("ALL 7 LIVE PRODUCTION VERIFICATION TESTS PASSED 100%!")
    print(f"Verified Document ID: {doc_id}")
    print(f"Title: Live Supabase Storage Test {unique_marker}")
    print("=" * 70)

if __name__ == "__main__":
    run_test()
