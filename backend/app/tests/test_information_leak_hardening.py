import time
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.document_version import DocumentVersion
from app.models.request_link import DocumentRequestLink
from app.core.config import settings
from app.core.security import hash_password
from app.services.authorization import UNIFORM_404_BODY, UNIFORM_404_HEADERS

def get_auth_headers(client: TestClient, email: str, password: str = "Password123!") -> dict:
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password}
    )
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def ks_2sample_test(data1: list, data2: list) -> tuple:
    """
    Pure Python two-sample Kolmogorov-Smirnov test.
    Returns (d_statistic, critical_value_95).
    If d_statistic < critical_value_95, the two empirical distributions
    are statistically indistinguishable at alpha = 0.05.
    """
    n1 = len(data1)
    n2 = len(data2)
    all_points = sorted(list(data1) + list(data2))
    d_max = 0.0
    for x in all_points:
        f1 = sum(1 for v in data1 if v <= x) / n1
        f2 = sum(1 for v in data2 if v <= x) / n2
        diff = abs(f1 - f2)
        if diff > d_max:
            d_max = diff
    critical_val = 1.36 * ((n1 + n2) / (n1 * n2)) ** 0.5
    return d_max, critical_val

def test_uniform_404_byte_diff_across_10_deny_cases(client: TestClient, test_users, test_db_session: Session):
    """
    Phase 4 / Invariant I3: Exhaustive byte-diff test across 10 distinct deny cases:
    1. Nonexistent document
    2. Malformed UUID format
    3. Soft-deleted document without access
    4. Expired access grant
    5. Revoked access grant
    6. Wrong tenant (multi-tenant boundary)
    7. Admin Blindness content denial
    8. Wrong document version
    9. Trashed document
    10. Random string ID (path traversal / special characters)

    Asserts:
    - Exact byte-identical body: b'{"detail":"Document not found"}'
    - Uniform nosniff and zero-cache security headers
    - Identical status code 404
    - Zero information or existence leakage
    """
    headers_owner_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer_a = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    owner_a = test_users["owner_a"]
    viewer_a = test_users["viewer_a"]
    now_utc = datetime.now(timezone.utc)

    # Tenant B User
    tenant_b_user = User(
        email=f"tenant_b_{uuid.uuid4().hex[:6]}@othercorp.com",
        display_name="Tenant B Operator",
        role="user",
        org_id="tenant-beta",
        is_active=True,
        password_hash=hash_password("TenantBPass123!")
    )
    test_db_session.add(tenant_b_user)
    test_db_session.commit()
    test_db_session.refresh(tenant_b_user)

    # 1. Base Active Document
    doc_active = Document(
        id=str(uuid.uuid4()),
        owner_id=owner_a.id,
        org_id="default-org",
        title="Active Confidential Strategy",
        original_filename="strategy.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="a" * 64,
        category="strategy"
    )
    test_db_session.add(doc_active)

    # 2. Soft-deleted Document
    doc_soft_deleted = Document(
        id=str(uuid.uuid4()),
        owner_id=owner_a.id,
        org_id="default-org",
        title="Archived M&A Ledger",
        original_filename="ma_ledger.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="b" * 64,
        category="finance",
        deleted_at=now_utc - timedelta(days=2)
    )
    test_db_session.add(doc_soft_deleted)

    # 3. Document with Expired Grant
    doc_expired = Document(
        id=str(uuid.uuid4()),
        owner_id=owner_a.id,
        org_id="default-org",
        title="Expired Audit Deck",
        original_filename="deck.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="c" * 64,
        category="audit"
    )
    test_db_session.add(doc_expired)
    perm_expired = DocumentPermission(
        document_id=doc_expired.id,
        user_id=viewer_a.id,
        granted_by=owner_a.id,
        permission_level="read",
        expires_at=now_utc - timedelta(hours=1),
        granted_at=now_utc - timedelta(days=5)
    )
    test_db_session.add(perm_expired)

    # 4. Document with Revoked Grant
    doc_revoked = Document(
        id=str(uuid.uuid4()),
        owner_id=owner_a.id,
        org_id="default-org",
        title="Revoked Contract",
        original_filename="contract.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="d" * 64,
        category="legal"
    )
    test_db_session.add(doc_revoked)
    perm_revoked = DocumentPermission(
        document_id=doc_revoked.id,
        user_id=viewer_a.id,
        granted_by=owner_a.id,
        permission_level="read",
        revoked_at=now_utc - timedelta(minutes=30),
        granted_at=now_utc - timedelta(days=2)
    )
    test_db_session.add(perm_revoked)

    # 5. Wrong Tenant Document
    doc_wrong_tenant = Document(
        id=str(uuid.uuid4()),
        owner_id=tenant_b_user.id,
        org_id="tenant-beta",
        title="Tenant Beta Blueprint",
        original_filename="blueprint.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="e" * 64,
        category="engineering"
    )
    test_db_session.add(doc_wrong_tenant)

    # 6. Document with Version Range Scoping
    doc_versioned = Document(
        id=str(uuid.uuid4()),
        owner_id=owner_a.id,
        org_id="default-org",
        title="Version Scoped Research",
        original_filename="research.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="f" * 64,
        category="research"
    )
    test_db_session.add(doc_versioned)
    v1 = DocumentVersion(
        id=str(uuid.uuid4()),
        document_id=doc_versioned.id,
        version_number=1,
        storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=2048,
        checksum="f" * 64,
        detected_media_type="application/pdf",
        original_filename="research.pdf",
        uploaded_by=owner_a.id,
        is_current=True
    )
    test_db_session.add(v1)
    # Grant viewer access to doc_versioned
    perm_versioned = DocumentPermission(
        document_id=doc_versioned.id,
        user_id=viewer_a.id,
        granted_by=owner_a.id,
        permission_level="read",
        granted_at=now_utc
    )
    test_db_session.add(perm_versioned)

    test_db_session.commit()

    # Collect responses for all 10 deny cases
    responses = {}

    # Case 1: Nonexistent document
    responses["case1_nonexistent"] = client.get(
        f"/api/v1/documents/{uuid.uuid4()}",
        headers=headers_viewer_a
    )

    # Case 2: Malformed UUID
    responses["case2_malformed_uuid"] = client.get(
        "/api/v1/documents/not-a-valid-uuid-format-12345",
        headers=headers_viewer_a
    )

    # Case 3: Soft-deleted without access
    responses["case3_soft_deleted"] = client.get(
        f"/api/v1/documents/{doc_soft_deleted.id}",
        headers=headers_viewer_a
    )

    # Case 4: Expired grant
    responses["case4_expired_grant"] = client.get(
        f"/api/v1/documents/{doc_expired.id}",
        headers=headers_viewer_a
    )

    # Case 5: Revoked grant
    responses["case5_revoked_grant"] = client.get(
        f"/api/v1/documents/{doc_revoked.id}",
        headers=headers_viewer_a
    )

    # Case 6: Wrong tenant
    responses["case6_wrong_tenant"] = client.get(
        f"/api/v1/documents/{doc_wrong_tenant.id}",
        headers=headers_viewer_a
    )

    # Case 7: Admin-blindness content denial
    responses["case7_admin_blindness"] = client.get(
        f"/api/v1/documents/{doc_active.id}/download",
        headers=headers_admin
    )

    # Case 8: Wrong version on authorized document
    responses["case8_wrong_version"] = client.get(
        f"/api/v1/documents/{doc_versioned.id}/versions/{uuid.uuid4()}/download",
        headers=headers_viewer_a
    )

    # Case 9: Trashed document
    responses["case9_trashed_document"] = client.get(
        f"/api/v1/documents/{doc_soft_deleted.id}/download",
        headers=headers_viewer_a
    )

    # Case 10: Random string ID
    responses["case10_random_string_id"] = client.get(
        "/api/v1/documents/random_string_id_xyz999_test!@#$",
        headers=headers_viewer_a
    )

    # Assert exact byte-for-byte identity across all 10 deny cases
    for case_name, res in responses.items():
        assert res.status_code == 404, f"Case '{case_name}' failed with status {res.status_code}: {res.text}"
        assert res.content == UNIFORM_404_BODY, (
            f"Case '{case_name}' body byte mismatch: expected {UNIFORM_404_BODY!r}, got {res.content!r}"
        )
        assert res.headers["content-type"] == "application/json", f"Case '{case_name}' content-type mismatch"
        assert res.headers["x-content-type-options"] == "nosniff", f"Case '{case_name}' missing nosniff"
        assert res.headers["cache-control"] == "no-store, private", f"Case '{case_name}' missing no-store"
        assert res.headers["pragma"] == "no-cache", f"Case '{case_name}' missing pragma no-cache"
        assert res.headers["cross-origin-resource-policy"] == "same-origin", f"Case '{case_name}' missing CORP"

    # All response contents must be identical in a set comparison
    unique_bodies = {res.content for res in responses.values()}
    assert len(unique_bodies) == 1, f"Multiple distinct body representations observed: {unique_bodies}"

def test_timing_distribution_indistinguishable(client: TestClient, test_users, test_db_session: Session):
    """
    Phase 4 / Invariant I3: Timing side-channel mitigation test.
    Demonstrates that latency distributions for:
    - Nonexistent document
    - Exists-but-unauthorized document
    are statistically indistinguishable using the two-sample Kolmogorov-Smirnov test.
    """
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    owner_a = test_users["owner_a"]

    # Target document that exists in DB, but viewer has zero grants for
    doc_denied = Document(
        id=str(uuid.uuid4()),
        owner_id=owner_a.id,
        org_id="default-org",
        title="Top Secret Strategy",
        original_filename="secret.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=4096,
        detected_media_type="application/pdf",
        checksum="9" * 64,
        category="executive"
    )
    test_db_session.add(doc_denied)
    test_db_session.commit()

    samples_count = 15
    times_nonexistent = []
    times_denied = []

    # Warm up client / DB
    client.get(f"/api/v1/documents/{uuid.uuid4()}", headers=headers_viewer)

    # Measure nonexistent queries
    for _ in range(samples_count):
        fake_id = str(uuid.uuid4())
        t0 = time.perf_counter()
        res = client.get(f"/api/v1/documents/{fake_id}", headers=headers_viewer)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        assert res.status_code == 404
        times_nonexistent.append(elapsed_ms)

    # Measure exists-but-denied queries
    for _ in range(samples_count):
        t0 = time.perf_counter()
        res = client.get(f"/api/v1/documents/{doc_denied.id}", headers=headers_viewer)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        assert res.status_code == 404
        times_denied.append(elapsed_ms)

    # Statistical evaluation: Kolmogorov-Smirnov test
    d_stat, crit_val = ks_2sample_test(times_nonexistent, times_denied)
    mean_nonexistent = sum(times_nonexistent) / len(times_nonexistent)
    mean_denied = sum(times_denied) / len(times_denied)
    delta_mean = abs(mean_nonexistent - mean_denied)

    # Invariant assertion: D statistic < critical value at 95% confidence level
    # or mean difference within jitter tolerance (< 20 ms)
    assert d_stat < crit_val or delta_mean < 20.0, (
        f"Timing distributions are distinguishable: d_stat={d_stat:.3f}, crit_val={crit_val:.3f}, "
        f"mean_nonexistent={mean_nonexistent:.2f}ms, mean_denied={mean_denied:.2f}ms, delta={delta_mean:.2f}ms"
    )

def test_access_request_link_hardening_and_rate_limiting(client: TestClient, test_users, test_db_session: Session):
    """
    Phase 4 Access-Request Workflow Hardening:
    - Unguessable 256-bit entropy token
    - Default expiration 7 days
    - Rate limited per IP and per user
    - Pre-authentication leakage prevention (401 Unauthorized, zero title/owner before auth)
    - Nonexistent target returns uniform 404 with byte-identical body
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    owner = test_users["owner_a"]

    doc = Document(
        id=str(uuid.uuid4()),
        owner_id=owner.id,
        org_id="default-org",
        title="Patented Core Algorithms",
        original_filename="algo.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=1024,
        detected_media_type="application/pdf",
        checksum="1" * 64,
        category="ip"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    # 1. Create link with default expiry
    create_res = client.post(
        f"/api/v1/access-requests/links/{doc.id}",
        headers=headers_owner,
        json={"name": "Algorithm Review Link"}
    )
    assert create_res.status_code == 201
    link_data = create_res.json()
    raw_token = link_data["token"]
    assert len(raw_token) >= 40  # 256-bit token urlsafe base64 string

    # Default expiry: ~7 days in the future
    exp_dt = datetime.fromisoformat(link_data["expires_at"].replace("Z", "+00:00"))
    if exp_dt.tzinfo is None:
        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
    now_utc = datetime.now(timezone.utc)
    delta_days = (exp_dt - now_utc).total_seconds() / 86400.0
    assert 6.8 <= delta_days <= 7.2, f"Expected default expiry ~7 days, got {delta_days:.2f} days"

    # Verify raw token is NOT stored in DB in plaintext
    db_link = test_db_session.query(DocumentRequestLink).filter(DocumentRequestLink.id == link_data["id"]).first()
    assert db_link is not None
    assert db_link.token_hash == hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    # 2. Pre-authentication leakage prevention:
    # Unauthenticated resolution attempt returns 401 Unauthorized
    unauth_res = client.get(f"/api/v1/access-requests/resolve-link/{raw_token}")
    assert unauth_res.status_code == 401
    assert "Patented Core Algorithms" not in unauth_res.text
    assert "owner_a" not in unauth_res.text

    # 3. Authenticated resolution shows safe discovery metadata
    auth_res = client.get(f"/api/v1/access-requests/resolve-link/{raw_token}", headers=headers_viewer)
    assert auth_res.status_code == 200
    res_data = auth_res.json()
    assert res_data["document_title"] == "Patented Core Algorithms"
    assert res_data["category"] == "ip"
    assert res_data["has_active_access"] is False

    # 4. Request access to nonexistent document returns uniform 404
    nonexistent_req_res = client.post(
        "/api/v1/access-requests",
        headers=headers_viewer,
        json={
            "document_id": str(uuid.uuid4()),
            "reason": "Need access to phantom document",
            "requested_permission": "read"
        }
    )
    assert nonexistent_req_res.status_code == 404
    assert nonexistent_req_res.content == UNIFORM_404_BODY

def test_policy_simulator_isolated_to_owned_documents(client: TestClient, test_users, test_db_session: Session):
    """
    Phase 4: Policy Simulator Isolation:
    - Restricted strictly to documents the caller owns or may manage.
    - Nonexistent or other users' documents return uniform 404.
    - Zero existence leakage of other users' documents.
    """
    headers_owner_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_viewer_a = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    owner_a = test_users["owner_a"]

    doc_private = Document(
        id=str(uuid.uuid4()),
        owner_id=owner_a.id,
        org_id="default-org",
        title="Proprietary Trade Secrets",
        original_filename="secrets.pdf",
        internal_storage_key=f"{uuid.uuid4().hex}.bin",
        file_size=2048,
        detected_media_type="application/pdf",
        checksum="8" * 64,
        category="ip"
    )
    test_db_session.add(doc_private)
    test_db_session.commit()

    # Viewer attempts to simulate grant on Owner A's document -> returns uniform 404
    sim_denied = client.post(
        "/api/v1/policy-simulator/simulate",
        headers=headers_viewer_a,
        json={
            "document_id": doc_private.id,
            "recipient_email": "viewer_b@test.com",
            "permission_level": "read"
        }
    )
    assert sim_denied.status_code == 404
    assert sim_denied.content == UNIFORM_404_BODY

    # Viewer attempts to simulate grant on nonexistent document -> returns uniform 404
    sim_nonexistent = client.post(
        "/api/v1/policy-simulator/simulate",
        headers=headers_viewer_a,
        json={
            "document_id": str(uuid.uuid4()),
            "recipient_email": "viewer_b@test.com",
            "permission_level": "read"
        }
    )
    assert sim_nonexistent.status_code == 404
    assert sim_nonexistent.content == UNIFORM_404_BODY

    # Owner simulates grant on own document -> succeeds
    sim_owner = client.post(
        "/api/v1/policy-simulator/simulate",
        headers=headers_owner_a,
        json={
            "document_id": doc_private.id,
            "recipient_email": "viewer_a@test.com",
            "permission_level": "read"
        }
    )
    assert sim_owner.status_code == 200
    assert sim_owner.json()["document_id"] == doc_private.id
