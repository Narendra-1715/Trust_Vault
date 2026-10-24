"""Phase 8 Test Suite: Client-side rendering, export, and preview sandboxing.
Validates:
1. Previewing a document with an embedded macro/script produces inert raster images.
2. Formula injection attempts in CSV export are neutralized (leading =, +, -, @, \\t, \\r).
3. Preview images contain watermark metadata and burned pixel accountability.
4. Raw file bytes are completely unreachable via preview routes.
5. Preview-only users can view pages but are denied download (uniform 404).
6. Content-Disposition filename sanitization eliminates traversal, null bytes, quotes, and control chars.
7. Anti-clickjacking (X-Frame-Options: DENY, frame-ancestors 'none') and strict CSP headers.
"""

import io
import csv
import re
import pytest
from PIL import Image
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.tests.conftest import get_auth_headers
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.storage.local import sanitize_content_disposition_filename
from app.audit.service import log_audit_event


def test_sandboxed_preview_returns_raster_image_and_never_raw_bytes(
    client: TestClient,
    test_users,
    test_db_session: Session
):
    """
    Phase 8 Requirement:
    - Files are converted to raster PNG page images server-side.
    - The client NEVER receives raw PDF/DOCX bytes for preview.
    - Raw file bytes are unreachable via preview routes.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # 1. Upload confidential document with a unique secret canary string
    canary = "CONFIDENTIAL_CANARY_RAW_SECRET_BYTES_99881122"
    doc_payload = f"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n{canary}".encode("utf-8")
    files = {"file": ("sensitive_report.pdf", io.BytesIO(doc_payload), "application/pdf")}

    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Sensitive Report", "category": "Finance"},
        files=files
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # 2. Query preview info
    info_res = client.get(f"/api/v1/documents/{doc_id}/preview-info", headers=headers_owner)
    assert info_res.status_code == 200
    info_data = info_res.json()
    assert info_data["document_id"] == doc_id
    assert info_data["total_pages"] >= 1
    assert info_data["media_type"] == "image/png"
    assert info_data["watermarked_for"] == "owner_a@test.com"

    # 3. Fetch Page 1 preview
    preview_res = client.get(f"/api/v1/documents/{doc_id}/pages/1", headers=headers_owner)
    assert preview_res.status_code == 200
    assert preview_res.headers["content-type"] == "image/png"
    assert "default-src 'none'" in preview_res.headers["content-security-policy"]
    assert "sandbox" in preview_res.headers["content-security-policy"]
    assert preview_res.headers["x-frame-options"] == "DENY"
    assert preview_res.headers["x-trustvault-watermark"] == "applied"
    assert preview_res.headers["x-trustvault-page"] == "1"

    # 4. Critical Invariant: Raw file bytes are NEVER returned via preview routes
    assert canary.encode("utf-8") not in preview_res.content
    assert b"%PDF-1.4" not in preview_res.content

    # 5. Verify the payload is a valid PNG image
    img = Image.open(io.BytesIO(preview_res.content))
    assert img.format == "PNG"
    assert img.width > 0
    assert img.height > 0


def test_embedded_script_and_macro_neutralized(
    client: TestClient,
    test_users,
    test_db_session: Session
):
    """
    Phase 8 Requirement:
    Previewing a document with an embedded macro/script does not execute;
    rendered output is purely a passive raster pixel array with strict CSP.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # Malicious payload with script tags and VBA macro tokens
    malicious_content = (
        "Sub AutoOpen()\n"
        "    MsgBox \"VBA Macro Executed\"\n"
        "End Sub\n"
        "<script>alert('XSS Exploit In Browser');</script>\n"
        "<object data='data:text/html,<script>evil()</script>'></object>"
    ).encode("utf-8")

    files = {"file": ("malicious_macro.txt", io.BytesIO(malicious_content), "text/plain")}
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Macro Document", "category": "IT"},
        files=files
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # Preview page
    preview_res = client.get(f"/api/v1/documents/{doc_id}/pages/1", headers=headers_owner)
    assert preview_res.status_code == 200
    assert preview_res.headers["content-type"] == "image/png"
    # Strict CSP guarantees zero script or object execution
    csp = preview_res.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "sandbox" in csp
    assert preview_res.content.startswith(b"\x89PNG\r\n\x1a\n")


def test_preview_only_grant_allows_view_but_blocks_download(
    client: TestClient,
    test_users,
    test_db_session: Session
):
    """
    Phase 8 / Invariant I1 & I2:
    A user with 'preview' grant permission can view raster pages,
    but is strictly DENIED downloading raw file bytes (returns uniform 404).
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    viewer = test_users["viewer_a"]

    # 1. Owner uploads document
    files = {"file": ("preview_only.txt", io.BytesIO(b"Confidential board notes"), "text/plain")}
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Preview Only Document", "category": "Board"},
        files=files
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # 2. Owner grants 'preview' permission level to viewer
    share_res = client.post(
        f"/api/v1/documents/{doc_id}/permissions",
        headers=headers_owner,
        json={"email": viewer.email, "permission_level": "preview"}
    )
    assert share_res.status_code == 201

    # 3. Viewer requests preview info -> ALLOWED
    info_res = client.get(f"/api/v1/documents/{doc_id}/preview-info", headers=headers_viewer)
    assert info_res.status_code == 200
    assert info_res.json()["watermarked_for"] == viewer.email

    # 4. Viewer requests raster preview page -> ALLOWED (with viewer's email in watermark metadata)
    page_res = client.get(f"/api/v1/documents/{doc_id}/pages/1", headers=headers_viewer)
    assert page_res.status_code == 200
    assert page_res.headers["content-type"] == "image/png"
    assert page_res.headers["x-trustvault-watermark"] == "applied"

    # 5. Viewer attempts download -> DENIED with uniform 404 (Invariant I1 & I3)
    download_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_viewer)
    assert download_res.status_code == 404
    assert download_res.json() == {"detail": "Document not found"}


def test_preview_denied_for_unauthorized_users(
    client: TestClient,
    test_users,
    test_db_session: Session
):
    """
    Phase 8 / Invariant I3:
    Non-granted users, admins without break-glass, or out-of-bounds pages
    receive the identical uniform 404 response.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")

    # Owner uploads document
    files = {"file": ("vault_secrets.txt", io.BytesIO(b"Private keys & credentials"), "text/plain")}
    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Vault Secrets", "category": "Security"},
        files=files
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # 1. Unshared viewer requests page -> 404
    v_res = client.get(f"/api/v1/documents/{doc_id}/pages/1", headers=headers_viewer)
    assert v_res.status_code == 404
    assert v_res.json() == {"detail": "Document not found"}

    # 2. Admin without break-glass requests page -> 404 (Admin Blindness)
    a_res = client.get(f"/api/v1/documents/{doc_id}/pages/1", headers=headers_admin)
    assert a_res.status_code == 404
    assert a_res.json() == {"detail": "Document not found"}

    # 3. Owner requests out-of-bounds page -> 404
    o_res = client.get(f"/api/v1/documents/{doc_id}/pages/999", headers=headers_owner)
    assert o_res.status_code == 404
    assert o_res.json() == {"detail": "Document not found"}

    # 4. Out-of-bounds page 0 -> 404
    zero_res = client.get(f"/api/v1/documents/{doc_id}/pages/0", headers=headers_owner)
    assert zero_res.status_code == 404


def test_formula_injection_defense_in_csv_export(
    client: TestClient,
    test_users,
    test_db_session: Session
):
    """
    Phase 8 Requirement:
    Formula injection defense: any CSV or spreadsheet export sanitizes leading
    '=', '+', '-', '@', '\\t', '\\r' by prefixing with a single quote.
    """
    admin = test_users["admin"]
    from app.core.security import create_access_token
    admin_token = create_access_token(subject=admin.id, role=admin.role)

    # Seed events with each injection character
    injection_payloads = [
        "=cmd|'/C calc'!A0",
        "+cmd.exe",
        "-1+1;cmd",
        "@SUM(1+1)",
        "\t=2+2",
        "\r=3+3",
        "   =cmd|payload"
    ]

    for payload in injection_payloads:
        log_audit_event(
            db=test_db_session,
            action=payload,
            resource_type="document",
            resource_id="inj-test",
            outcome="success",
            actor_id=admin.id,
            metadata={"test_field": payload}
        )

    export_res = client.get(
        "/api/v1/audit/export?format=csv",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert export_res.status_code == 200
    assert export_res.headers["content-type"].startswith("text/csv")
    assert export_res.headers["x-content-type-options"] == "nosniff"
    assert "attachment; filename=" in export_res.headers["content-disposition"]

    reader = csv.reader(io.StringIO(export_res.text))
    rows = list(reader)

    # Verify that all action fields corresponding to the injected payloads start with single quote
    for row in rows[1:]:  # skip header
        action_val = row[4]
        for inj in injection_payloads:
            if inj.strip() in action_val:
                assert action_val.startswith("'"), f"Cell '{action_val}' was not sanitized against formula injection"


def test_content_disposition_filename_sanitization():
    """
    Phase 8 Requirement:
    Content-Disposition: always attachment; filename=\"<sanitized>\".
    Never allow user-controlled filenames with path separators, null bytes, quotes, or control characters.
    """
    # 1. Directory traversal
    assert sanitize_content_disposition_filename("../../../etc/passwd") == "passwd"
    assert sanitize_content_disposition_filename("..\\..\\windows\\system32\\calc.exe") == "calc.exe"

    # 2. Null bytes and control characters
    assert sanitize_content_disposition_filename("report\x00\x1f\x7f.pdf") == "report.pdf"

    # 3. Quotes, semicolons, and header injection attempts
    assert sanitize_content_disposition_filename('test"; filename="evil.exe') == "test filenameevil.exe"
    assert sanitize_content_disposition_filename("doc\r\nSet-Cookie: evil=1\r\n.pdf") == "docSet-Cookie evil1.pdf"

    # 4. Empty or only illegal characters
    assert sanitize_content_disposition_filename("") == "document.bin"
    assert sanitize_content_disposition_filename("   ") == "document.bin"
    assert sanitize_content_disposition_filename("../..") == "document.bin"


def test_clickjacking_and_csp_headers(client: TestClient, test_users):
    """
    Phase 8 Requirement:
    Frontend & API hardening: strict CSP header, defend against clickjacking
    with X-Frame-Options: DENY and frame-ancestors 'none'.
    """
    headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # Verify on standard document route
    res = client.get("/api/v1/documents", headers=headers)
    assert res.status_code == 200
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in res.headers["content-security-policy"]
    assert "default-src 'self'" in res.headers["content-security-policy"]
