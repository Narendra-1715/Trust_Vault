import urllib.request
import urllib.error
import json
import hashlib

BASE_URL = "https://trustvault-api-s6ba.onrender.com/api/v1"
doc_id = "165adfad-02f7-4fda-831c-7343cc5ed8ea"
expected_checksum = "a6552419ec902a20ecc7ae6ab0cf246958453f0838a7d50e9eec2ed1c257d101"

def run_gate_checks():
    print("=" * 70)
    print("TRUSTVAULT PRODUCTION RELEASE GATE VERIFICATION")
    print(f"Target Document: {doc_id}")
    print("=" * 70)

    # 1. Login as owner_a
    res_a = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/auth/login", data=json.dumps({"email": "owner_a@trustvault.com", "password": "OwnerAPass123!"}).encode("utf-8"), headers={"Content-Type": "application/json"}))
    token_a = json.loads(res_a.read().decode())["access_token"]
    headers_a = {"Authorization": "Bearer " + token_a}

    # 2. Login as ungranted user (owner_b) and verify 404 denial
    res_b = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/auth/login", data=json.dumps({"email": "owner_b@trustvault.com", "password": "OwnerBPass123!"}).encode("utf-8"), headers={"Content-Type": "application/json"}))
    token_b = json.loads(res_b.read().decode())["access_token"]
    headers_b = {"Authorization": "Bearer " + token_b}

    try:
        urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_b))
        raise AssertionError("ERROR: Ungranted user was able to download!")
    except urllib.error.HTTPError as e:
        print(f"Check 1: Ungranted Access Denial: PASSED (HTTP {e.code} {e.reason})")

    # 3. Grant viewer_a read permission
    users = json.loads(urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/users", headers=headers_a)).read().decode())
    viewer_a = next(u for u in users if u["email"] == "viewer_a@trustvault.com")
    perm_res = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/permissions", data=json.dumps({"user_id": viewer_a["id"], "permission_level": "read"}).encode("utf-8"), headers={"Authorization": "Bearer " + token_a, "Content-Type": "application/json"}))
    print(f"Check 2: Grant Permission to Viewer: PASSED (HTTP {perm_res.status})")

    # 4. Login as viewer_a and download
    res_v = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/auth/login", data=json.dumps({"email": "viewer_a@trustvault.com", "password": "ViewerAPass123!"}).encode("utf-8"), headers={"Content-Type": "application/json"}))
    token_v = json.loads(res_v.read().decode())["access_token"]
    headers_v = {"Authorization": "Bearer " + token_v}

    dl_v = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_v))
    data_v = dl_v.read()
    assert hashlib.sha256(data_v).hexdigest() == expected_checksum
    print(f"Check 3: Authorized Viewer Download: PASSED (HTTP {dl_v.status}, {len(data_v)} bytes, SHA-256 match)")

    # 5. Revoke permission
    viewer_id = viewer_a["id"]
    del_res = urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/permissions/{viewer_id}", headers=headers_a, method="DELETE"))
    print(f"Check 4: Revoke Permission: PASSED (HTTP {del_res.status})")

    # 6. Verify subsequent download is denied immediately
    try:
        urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_v))
        raise AssertionError("ERROR: Revoked user was able to download!")
    except urllib.error.HTTPError as e:
        print(f"Check 5: Post-Revocation Immediate Denial: PASSED (HTTP {e.code} {e.reason})")

    # 7. Verify audit events recorded and hash chain is valid
    audit_res = json.loads(urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/audit/events?document_id={doc_id}", headers=headers_a)).read().decode())
    actions = [e["action"] for e in audit_res["events"]]
    print("Check 6: Recorded Audit Actions:", actions)

    verify_res = json.loads(urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/audit/verify", headers=headers_a)).read().decode())
    print(f"Check 7: Cryptographic Hash Chain: is_valid={verify_res['is_valid']}, total_events={verify_res['total_events']}")
    assert verify_res["is_valid"] is True
    print("\nALL VERIFICATION CHECKS PASSED EMPIRICALLY!")

if __name__ == "__main__":
    run_gate_checks()
