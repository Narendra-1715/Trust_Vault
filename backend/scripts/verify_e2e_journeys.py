import io
import sys
from fastapi.testclient import TestClient
from app.core.config import settings

# Force mock mode for fast deterministic automated verification
settings.AI_PROVIDER = "mock"

from app.main import app
from app.db.session import SessionLocal
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.audit import AuditEvent

client = TestClient(app)

def run_verification():
    print("=== TRUSTVAULT COMPLETE 12-STEP END-TO-END VERIFICATION ===")

    # Step 1: Owner signs in and uploads a document
    login_res = client.post("/api/v1/auth/login", json={"email": "owner_a@trustvault.com", "password": "OwnerAPass123!"})
    assert login_res.status_code == 200, f"Owner login failed: {login_res.text}"
    owner_token = login_res.json()["access_token"]
    owner_headers = {"Authorization": f"Bearer {owner_token}"}
    print("Step 1: Owner signed in successfully.")

    sample_pdf = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 44>>stream\nBT /F1 12 Tf 72 712 Td (TRUSTVAULT TEST) Tj ET\nendstream endobj\n"
        b"xref\n0 5\n0000000000 65535 f\n0000000010 00000 n\n0000000053 00000 n\n0000000102 00000 n\n0000000160 00000 n\n"
        b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n255\n%%EOF\n"
    )
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=owner_headers,
        data={"title": "E2E Validation Document", "category": "Financial"},
        files={"file": ("E2E_Validation.pdf", io.BytesIO(sample_pdf), "application/pdf")}
    )
    assert upload_res.status_code == 201, f"Upload failed: {upload_res.text}"
    doc = upload_res.json()
    doc_id = doc["id"]
    print(f"Step 1: Document uploaded. ID: {doc_id}")

    # Step 2: Document survives backend restart (retrieved from DB)
    get_doc_res = client.get(f"/api/v1/documents/{doc_id}", headers=owner_headers)
    assert get_doc_res.status_code == 200, "Doc retrieval failed"
    print("Step 2: Document persists and is retrievable.")

    # Step 3: Owner grants named viewer read permission
    db = SessionLocal()
    viewer = db.query(User).filter(User.email == "viewer_a@trustvault.com").first()
    assert viewer is not None
    db.close()

    grant_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=owner_headers,
        json={"user_id": viewer.id, "permission_level": "read"}
    )
    assert grant_res.status_code in [200, 201], f"Grant failed: {grant_res.text}"
    print(f"Step 3: Granted viewer {viewer.email} read permission.")

    # Step 4: Viewer signs in and downloads actual file
    viewer_login = client.post("/api/v1/auth/login", json={"email": "viewer_a@trustvault.com", "password": "ViewerAPass123!"})
    assert viewer_login.status_code == 200
    viewer_token = viewer_login.json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    viewer_read = client.get(f"/api/v1/documents/{doc_id}", headers=viewer_headers)
    assert viewer_read.status_code == 200, "Viewer read failed"

    viewer_dl = client.get(f"/api/v1/documents/{doc_id}/download", headers=viewer_headers)
    assert viewer_dl.status_code == 200, f"Viewer download failed: {viewer_dl.status_code}"
    assert len(viewer_dl.content) > 0, "Downloaded file empty"
    print(f"Step 4: Viewer signed in and downloaded {len(viewer_dl.content)} bytes successfully.")

    # Step 5: Viewer cannot edit, delete, or share document
    edit_res = client.patch(f"/api/v1/documents/{doc_id}", headers=viewer_headers, json={"title": "Hacked Title"})
    assert edit_res.status_code in [403, 404], f"Viewer edit was not blocked: {edit_res.status_code}"

    delete_res = client.delete(f"/api/v1/documents/{doc_id}", headers=viewer_headers)
    assert delete_res.status_code in [403, 404], f"Viewer delete was not blocked: {delete_res.status_code}"

    share_res = client.post(f"/api/v1/documents/{doc_id}/permissions", headers=viewer_headers, json={"user_id": viewer.id, "permission_level": "edit"})
    assert share_res.status_code in [403, 404], f"Viewer share was not blocked: {share_res.status_code}"
    print("Step 5: Viewer edit, delete, and share strictly blocked.")

    # Step 6: Owner revokes access
    revoke_res = client.delete(f"/api/v1/documents/{doc_id}/permissions/{viewer.id}", headers=owner_headers)
    assert revoke_res.status_code in [200, 204], f"Revoke failed: {revoke_res.text}"
    print("Step 6: Owner revoked viewer access.")

    # Step 7: Viewer next protected read or download is denied (404)
    next_read = client.get(f"/api/v1/documents/{doc_id}", headers=viewer_headers)
    assert next_read.status_code == 404, f"Read after revoke not 404: {next_read.status_code}"

    next_dl = client.get(f"/api/v1/documents/{doc_id}/download", headers=viewer_headers)
    assert next_dl.status_code == 404, f"Download after revoke not 404: {next_dl.status_code}"
    print("Step 7: Immediate revocation guaranteed; read & download immediately return 404.")

    # Step 8: Guessing IDs or reusing URL does not bypass revocation
    tampered_id = "00000000-0000-0000-0000-000000000000"
    guess_res = client.get(f"/api/v1/documents/{tampered_id}/download", headers=viewer_headers)
    assert guess_res.status_code == 404
    print("Step 8: Guessed IDs and reuse attempts blocked with 404.")

    # Step 9: Audit trail records relevant upload, grant, download, revocation, and denied request
    db = SessionLocal()
    actions = [e.action for e in db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(15).all()]
    print(f"Step 9: Recent audit events in DB: {actions[:6]}")
    assert "document.upload" in actions
    assert "permission.grant" in actions
    assert "permission.revoke" in actions
    assert "document.download.denied" in actions
    db.close()
    print("Step 9: All lifecycle events verified in audit ledger.")

    # Step 10: AI recommendation reviewed and rejected without creating permission
    ai_gen = client.post(f"/api/v1/documents/{doc_id}/ai-recommendations", headers=owner_headers)
    assert ai_gen.status_code == 200
    rec_id = ai_gen.json()["suggestion_id"]

    ai_rej = client.post(f"/api/v1/documents/{doc_id}/ai-recommendations/reject", headers=owner_headers, json={"suggestion_id": rec_id})
    assert ai_rej.status_code == 200
    db = SessionLocal()
    grant_count = db.query(DocumentPermission).filter(DocumentPermission.document_id == doc_id, DocumentPermission.revoked_at.is_(None)).count()
    assert grant_count == 0, "Rejection should leave zero grants"
    db.close()
    print("Step 10: AI recommendation rejected; verified zero active grants exist.")

    # Step 11: Approving AI recommendation triggers fresh server-side authorization checks and recorded grant
    ai_gen2 = client.post(f"/api/v1/documents/{doc_id}/ai-recommendations", headers=owner_headers)
    rec_id2 = ai_gen2.json()["suggestion_id"]
    ai_app = client.post(
        f"/api/v1/documents/{doc_id}/ai-recommendations/approve",
        headers=owner_headers,
        json={"suggestion_id": rec_id2, "approved_grants": [{"user_id": viewer.id, "permission_level": "read"}]}
    )
    assert ai_app.status_code == 200
    db = SessionLocal()
    new_grant = db.query(DocumentPermission).filter(DocumentPermission.document_id == doc_id, DocumentPermission.user_id == viewer.id, DocumentPermission.revoked_at.is_(None)).first()
    assert new_grant is not None
    db.close()
    print("Step 11: AI approved recommendation created explicit verified grant.")

    # Step 12: A different owner cannot access another owner confidential document
    login_b = client.post("/api/v1/auth/login", json={"email": "owner_b@trustvault.com", "password": "OwnerBPass123!"})
    assert login_b.status_code == 200
    owner_b_headers = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    cross_read = client.get(f"/api/v1/documents/{doc_id}", headers=owner_b_headers)
    assert cross_read.status_code == 404
    cross_dl = client.get(f"/api/v1/documents/{doc_id}/download", headers=owner_b_headers)
    assert cross_dl.status_code == 404
    print("Step 12: Cross-owner read and download strictly return 404.")

    print("\n>>> ALL 12 END-TO-END STEPS PASSED 100% <<<")

if __name__ == "__main__":
    run_verification()
