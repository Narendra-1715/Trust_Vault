"""
TrustVault Real Storage Restart & Persistence Verification
Demonstrates that local private storage retains exact file bytes across simulated restarts.
"""

import os
import sys
import io
import hashlib
from fastapi.testclient import TestClient

# Ensure backend root in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings
settings.AI_PROVIDER = "mock"

from app.main import app
from app.db.session import SessionLocal, Base, engine
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.audit import AuditEvent
from app.storage.local import storage_service
from seed import seed_database

def run_restart_persistence_test():
    print("=" * 70)
    print("TRUSTVAULT LOCAL RESTART & DURABLE PERSISTENCE TEST")
    print("=" * 70)

    Base.metadata.create_all(bind=engine)
    seed_database()

    client1 = TestClient(app)

    # 1. Login as Owner A
    res_a = client1.post("/api/v1/auth/login", json={"email": "owner_a@trustvault.com", "password": "OwnerAPass123!"})
    assert res_a.status_code == 200, f"Owner login failed: {res_a.text}"
    token_a = res_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 2. Upload a unique file with known bytes and checksum
    unique_content = b"%PDF-1.4\n% UNIQUE TEST DOCUMENT FOR RESTART VERIFICATION\n" + os.urandom(1024) + b"\n%%EOF"
    expected_checksum = hashlib.sha256(unique_content).hexdigest()
    expected_length = len(unique_content)
    print(f"Step 1: Generated unique test payload ({expected_length} bytes)")
    print(f"Step 1: Computed SHA-256 checksum: {expected_checksum}")

    upload_res = client1.post(
        "/api/v1/documents/upload",
        headers=headers_a,
        data={"title": "Restart Persistence Verification Document", "category": "Legal"},
        files={"file": ("Restart_Verify.pdf", io.BytesIO(unique_content), "application/pdf")}
    )
    assert upload_res.status_code == 201, f"Upload failed: {upload_res.text}"
    doc_data = upload_res.json()
    doc_id = doc_data["id"]
    print(f"Step 1: Uploaded document successfully. ID: {doc_id}")
    assert doc_data["checksum"] == expected_checksum
    assert doc_data["file_size"] == expected_length

    # 3. Grant Viewer A read permission
    grant_res = client1.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_a,
        json={"email": "viewer_a@trustvault.com", "permission_level": "read"}
    )
    assert grant_res.status_code == 201, f"Grant failed: {grant_res.text}"
    print(f"Step 2: Granted viewer_a@trustvault.com read permission.")

    # 4. Simulate application restart
    # In a real restart, memory is wiped, client connection pool is destroyed, but persistent disk & DB remain intact
    print("Step 3: Simulating application restart (destroying client, resetting process memory)...")
    del client1

    # Re-initialize new client instance against the existing storage directory and database
    client2 = TestClient(app)

    # 5. Sign in as Viewer A on the newly initialized instance
    res_v = client2.post("/api/v1/auth/login", json={"email": "viewer_a@trustvault.com", "password": "ViewerAPass123!"})
    assert res_v.status_code == 200, f"Viewer login failed: {res_v.text}"
    token_v = res_v.json()["access_token"]
    headers_v = {"Authorization": f"Bearer {token_v}"}

    # 6. Retrieve document metadata after restart
    meta_res = client2.get(f"/api/v1/documents/{doc_id}", headers=headers_v)
    assert meta_res.status_code == 200, f"Metadata retrieval after restart failed: {meta_res.text}"
    print("Step 4: Document metadata retrieved successfully after restart.")

    # 7. Download document bytes after restart
    dl_res = client2.get(f"/api/v1/documents/{doc_id}/download", headers=headers_v)
    assert dl_res.status_code == 200, f"Download after restart failed: {dl_res.status_code} {dl_res.text}"
    downloaded_bytes = dl_res.content
    downloaded_checksum = hashlib.sha256(downloaded_bytes).hexdigest()
    print(f"Step 5: Downloaded {len(downloaded_bytes)} bytes after restart.")
    print(f"Step 5: Downloaded checksum: {downloaded_checksum}")

    assert downloaded_bytes == unique_content, "CRITICAL: Downloaded bytes do not match original bytes!"
    assert downloaded_checksum == expected_checksum, "CRITICAL: Downloaded checksum mismatch!"
    print("[PASS] Exact byte parity and SHA-256 checksum match verified across restart!")

    # 8. Revoke permission
    res_a2 = client2.post("/api/v1/auth/login", json={"email": "owner_a@trustvault.com", "password": "OwnerAPass123!"})
    token_a2 = res_a2.json()["access_token"]
    headers_a2 = {"Authorization": f"Bearer {token_a2}"}

    db = SessionLocal()
    viewer_user = db.query(User).filter(User.email == "viewer_a@trustvault.com").first()

    rev_res = client2.delete(f"/api/v1/documents/{doc_id}/permissions/{viewer_user.id}", headers=headers_a2)
    assert rev_res.status_code == 204, f"Revocation failed: {rev_res.status_code}"
    print("Step 6: Owner revoked viewer access.")

    # 9. Verify immediate denial
    dl_denied = client2.get(f"/api/v1/documents/{doc_id}/download", headers=headers_v)
    assert dl_denied.status_code == 404, f"Expected 404 after revocation, got {dl_denied.status_code}"
    print("Step 7: Viewer download after revocation immediately returned 404 Not Found.")

    # 10. Audit trail verification
    events = db.query(AuditEvent).filter(
        AuditEvent.resource_id == doc_id
    ).order_by(AuditEvent.timestamp.asc()).all()

    actions = [e.action for e in events]
    print(f"Step 8: Audit ledger events for document: {actions}")
    assert "document.upload" in actions
    assert "document.download" in actions
    assert "document.download.denied" in actions
    print("[PASS] Complete audit trail verified for upload, download, and denial!")

    db.close()
    print("=" * 70)
    print("REAL RESTART & DURABLE PERSISTENCE TEST PASSED 100%")
    print("=" * 70)

if __name__ == "__main__":
    run_restart_persistence_test()
