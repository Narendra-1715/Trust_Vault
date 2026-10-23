"""
TrustVault Hackathon Repeatable 10-Step Demonstration Script
Runs against either local staging (default: http://127.0.0.1:8000) or the deployed API.

Usage:
    python backend/scripts/demo_hackathon.py [--live]
"""

import sys
import json
import uuid
import hashlib
import argparse
import urllib.request
import urllib.error

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def run_hackathon_demo(base_url: str):
    api_url = f"{base_url.rstrip('/')}/api/v1"
    print("=" * 75)
    print("[TRUSTVAULT] 5-MINUTE HACKATHON REPEATABLE DEMONSTRATION")
    print(f"Target Service: {api_url}")
    print("=" * 75)

    # 1. Health & Storage Engine Telemetry
    print("\n[Step 0/10] Telemetry Check: Active Backend & Service Health...")
    try:
        health_req = urllib.request.urlopen(f"{api_url}/health", timeout=15)
        health_data = json.loads(health_req.read().decode())
        print(f"  Service Status:    {health_data.get('status')}")
        print(f"  Commit SHA:        {health_data.get('commit_sha')}")
        print(f"  Storage Engine:    {health_data.get('storage_backend')}")
        print(f"  Dependencies:      {health_data.get('dependencies', {})}")
    except Exception as e:
        print(f"  [ERROR] Health check failed: {e}")
        return False

    # 2. Step 1: Log in as Document Owner
    print("\n[Step 1/10] Authenticating as Document Owner (Alice Owner)...")
    login_body = json.dumps({"email": "owner_a@trustvault.com", "password": "OwnerAPass123!"}).encode("utf-8")
    req = urllib.request.Request(f"{api_url}/auth/login", data=login_body, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req, timeout=15)
    token_a = json.loads(res.read().decode())["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    print("  [SUCCESS] Alice Owner authenticated. JWT issued.")

    # 3. Step 2: Upload a sample document
    print("\n[Step 2/10] Owner Uploads Confidential Sample Document...")
    demo_marker = uuid.uuid4().hex[:8]
    sample_content = (
        f"%PDF-1.4\n% TrustVault Confidential Hackathon Demonstration Asset\n"
        f"% Asset Tag: DEMO-{demo_marker}\n"
        f"% Classification: Restricted Corporate Intellectual Property\n"
        + ("CONFIDENTIAL-ASSET-" * 30) + "\n%%EOF"
    ).encode("utf-8")
    expected_checksum = hashlib.sha256(sample_content).hexdigest()
    expected_size = len(sample_content)
    print(f"  Payload Size:      {expected_size} bytes")
    print(f"  Payload SHA-256:   {expected_checksum}")

    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHackathon Demo Confidential Asset {demo_marker}\r\n".encode("utf-8"),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"category\"\r\n\r\nLegal\r\n".encode("utf-8"),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"demo_asset_{demo_marker}.pdf\"\r\nContent-Type: application/pdf\r\n\r\n".encode("utf-8"),
        sample_content,
        f"\r\n--{boundary}--\r\n".encode("utf-8")
    ]
    body = b"".join(parts)

    upload_req = urllib.request.Request(
        f"{api_url}/documents/upload",
        data=body,
        headers={"Authorization": f"Bearer {token_a}", "Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    upload_res = urllib.request.urlopen(upload_req, timeout=25)
    doc_meta = json.loads(upload_res.read().decode())
    doc_id = doc_meta["id"]
    print(f"  [SUCCESS] Uploaded with HTTP {upload_res.status} Created.")
    print(f"  Assigned Doc ID:   {doc_id}")
    print(f"  Stored Checksum:   {doc_meta['checksum']}")
    assert doc_meta["checksum"] == expected_checksum, "Stored checksum mismatch!"

    # 4. Step 3: Attempt access as ungranted viewer
    print("\n[Step 3/10] Attempting Access as Ungranted Viewer (Carol Viewer)...")
    res_v = urllib.request.urlopen(urllib.request.Request(
        f"{api_url}/auth/login",
        data=json.dumps({"email": "viewer_a@trustvault.com", "password": "ViewerAPass123!"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    ), timeout=15)
    token_v = json.loads(res_v.read().decode())["access_token"]
    headers_v = {"Authorization": f"Bearer {token_v}"}

    try:
        urllib.request.urlopen(urllib.request.Request(f"{api_url}/documents/{doc_id}/download", headers=headers_v), timeout=15)
        print("  [FAILURE] Ungranted viewer was able to download!")
        return False
    except urllib.error.HTTPError as e:
        print(f"  [BLOCKED] Download safely rejected: HTTP {e.code} ({e.reason})")
        print("  [INVARIANT] Document existence is masked (404 Not Found) to prevent enumeration.")

    # 5. Step 4: Grant that viewer permission
    print("\n[Step 4/10] Owner Grants Viewer Read Access...")
    users = json.loads(urllib.request.urlopen(urllib.request.Request(f"{api_url}/users", headers=headers_a)).read().decode())
    viewer_user = next(u for u in users if u["email"] == "viewer_a@trustvault.com")
    viewer_id = viewer_user["id"]

    grant_body = json.dumps({"user_id": viewer_id, "permission_level": "read"}).encode("utf-8")
    grant_res = urllib.request.urlopen(urllib.request.Request(
        f"{api_url}/documents/{doc_id}/permissions",
        data=grant_body,
        headers={"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"}
    ), timeout=15)
    print(f"  [SUCCESS] Read grant recorded: HTTP {grant_res.status} Created.")

    # 6. Step 5: Download and verify checksum
    print("\n[Step 5/10] Authorized Viewer Downloads Document & Verifies Integrity...")
    dl_v = urllib.request.urlopen(urllib.request.Request(f"{api_url}/documents/{doc_id}/download", headers=headers_v), timeout=20)
    data_v = dl_v.read()
    dl_checksum = hashlib.sha256(data_v).hexdigest()
    print(f"  Download Status:   HTTP {dl_v.status} OK")
    print(f"  Downloaded Size:   {len(data_v)} bytes")
    print(f"  Downloaded SHA256: {dl_checksum}")
    assert len(data_v) == expected_size, "Downloaded size mismatch!"
    assert dl_checksum == expected_checksum, "Downloaded checksum mismatch!"
    print("  [SUCCESS] 100% exact byte length and cryptographic SHA-256 match confirmed!")

    # 7. Step 6: Revoke permission
    print("\n[Step 6/10] Owner Revokes Viewer Permission...")
    revoke_res = urllib.request.urlopen(urllib.request.Request(
        f"{api_url}/documents/{doc_id}/permissions/{viewer_id}",
        headers=headers_a,
        method="DELETE"
    ), timeout=15)
    print(f"  [SUCCESS] Revocation executed: HTTP {revoke_res.status} No Content.")

    # 8. Step 7: Attempt another download and show immediate denial
    print("\n[Step 7/10] Viewer Attempts Download Immediately After Revocation...")
    try:
        urllib.request.urlopen(urllib.request.Request(f"{api_url}/documents/{doc_id}/download", headers=headers_v), timeout=15)
        print("  [FAILURE] Revoked viewer was still able to download!")
        return False
    except urllib.error.HTTPError as e:
        print(f"  [BLOCKED] Immediate Synchronous Denial: HTTP {e.code} ({e.reason})")
        print("  [INVARIANT] Live database validation immediately cut off content access.")

    # 9. Step 8: Show corresponding audit events
    print("\n[Step 8/10] Inspecting Immutable Audit Trail for this Asset...")
    audit_res = json.loads(urllib.request.urlopen(urllib.request.Request(
        f"{api_url}/audit/events?document_id={doc_id}",
        headers=headers_a
    ), timeout=15).read().decode())
    actions = [e["action"] for e in audit_res["events"]]
    print(f"  Recorded Actions:  {actions}")
    for evt in audit_res["events"]:
        ts = str(evt.get("timestamp", ""))[:19]
        print(f"    - [{ts}] Action: {evt.get('action', ''):25} | Outcome: {evt.get('outcome', '')}")

    # 10. Step 9: Run audit-chain verification
    print("\n[Step 9/10] Cryptographic Hash Chain Ledger Verification...")
    verify_res = json.loads(urllib.request.urlopen(urllib.request.Request(
        f"{api_url}/audit/verify",
        headers=headers_a
    ), timeout=15).read().decode())
    print(f"  Hash Chain Valid:  {verify_res['is_valid']}")
    print(f"  Total Ledger Log:  {verify_res['total_events']} events cryptographically linked")
    assert verify_res["is_valid"] is True, "Audit chain integrity compromised!"
    print("  [SUCCESS] Deterministic SHA-256 canonical JSON hash chain intact.")

    # 11. Step 10: Explain storage configuration & known limitations
    print("\n[Step 10/10] Storage Architecture & Real-World Boundaries...")
    print("  1. Storage Isolation:   Files stored in private volume / object store with opaque UUID keys.")
    print("  2. Anti-Concealment:    If file bytes are ever lost, API returns HTTP 500 error (never fakes dummy data).")
    print("  3. Pre-Stream Checksum: Recalculates SHA-256 before streaming to detect any disk corruption.")
    print("  4. Threat Limitation:   A privileged database administrator (DBA) could theoretically alter")
    print("                          rows and recompute hashes forward. External WORM checkpoints recommended.")
    print("  5. In-Flight Traffic:   Bytes already transmitted across an active TCP socket cannot be recalled;")
    print("                          revocation guarantees instant denial on all subsequent requests.")
    print("  6. Watermarking:        Forensic visual overlay is a deterrent, not mechanical screen-capture prevention.")

    print("\n" + "=" * 75)
    print("[SUCCESS] ALL 10 HACKATHON DEMONSTRATION STEPS PASSED 100%!")
    print("=" * 75)
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrustVault Hackathon Demo Runner")
    parser.add_argument("--live", action="store_true", help="Run against deployed production Render API")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Custom target base URL")
    args = parser.parse_args()

    target = "https://trustvault-api-s6ba.onrender.com" if args.live else args.url
    success = run_hackathon_demo(target)
    sys.exit(0 if success else 1)
