import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.core.security import create_access_token

def test_advanced_search_filtering(client: TestClient, test_db_session, test_users):
    """Verifies advanced search filters: file_type, category, date range, and sorting."""
    owner = test_users["owner_a"]
    owner_token = create_access_token(subject=owner.id, role=owner.role)

    now = datetime.now(timezone.utc)

    d1 = Document(
        owner_id=owner.id,
        title="Alpha Financial Statement",
        original_filename="statement.pdf",
        internal_storage_key="k1.pdf",
        file_size=1000,
        detected_media_type="application/pdf",
        checksum="1" * 64,
        category="finance",
        created_at=now - timedelta(days=5)
    )
    d2 = Document(
        owner_id=owner.id,
        title="Beta Security Audit",
        original_filename="audit.docx",
        internal_storage_key="k2.docx",
        file_size=5000,
        detected_media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        checksum="2" * 64,
        category="security",
        created_at=now - timedelta(days=2)
    )
    d3 = Document(
        owner_id=owner.id,
        title="Gamma Employee Roster",
        original_filename="roster.csv",
        internal_storage_key="k3.csv",
        file_size=3000,
        detected_media_type="text/csv",
        checksum="3" * 64,
        category="hr",
        created_at=now
    )
    test_db_session.add_all([d1, d2, d3])
    test_db_session.commit()

    # 1. Filter by file_type = pdf
    res_pdf = client.get("/api/v1/documents?file_type=pdf", headers={"Authorization": f"Bearer {owner_token}"})
    assert res_pdf.status_code == 200
    docs = res_pdf.json()["documents"]
    assert len(docs) == 1
    assert docs[0]["original_filename"] == "statement.pdf"

    # 2. Filter by category = hr
    res_hr = client.get("/api/v1/documents?category=hr", headers={"Authorization": f"Bearer {owner_token}"})
    assert res_hr.status_code == 200
    docs_hr = res_hr.json()["documents"]
    assert len(docs_hr) == 1
    assert docs_hr[0]["title"] == "Gamma Employee Roster"

    # 3. Sort by file_size ascending
    res_sort = client.get("/api/v1/documents?sort_by=file_size&sort_order=asc", headers={"Authorization": f"Bearer {owner_token}"})
    assert res_sort.status_code == 200
    sorted_docs = res_sort.json()["documents"]
    assert len(sorted_docs) == 3
    assert sorted_docs[0]["file_size"] == 1000
    assert sorted_docs[1]["file_size"] == 3000
    assert sorted_docs[2]["file_size"] == 5000

    # 4. Sort by title ascending
    res_title = client.get("/api/v1/documents?sort_by=title&sort_order=asc", headers={"Authorization": f"Bearer {owner_token}"})
    assert res_title.status_code == 200
    title_docs = res_title.json()["documents"]
    assert title_docs[0]["title"] == "Alpha Financial Statement"
    assert title_docs[1]["title"] == "Beta Security Audit"
    assert title_docs[2]["title"] == "Gamma Employee Roster"

def test_owned_vs_shared_and_zero_leakage(client: TestClient, test_db_session, test_users):
    """Verifies owned vs shared filtering and zero metadata leakage for unauthorized documents."""
    alice = test_users["owner_a"]
    bob = test_users["owner_b"]
    charlie = test_users["viewer_a"]

    alice_token = create_access_token(subject=alice.id, role=alice.role)
    charlie_token = create_access_token(subject=charlie.id, role=charlie.role)

    # Alice's doc (shared with Charlie)
    d_alice = Document(
        owner_id=alice.id,
        title="Public Project Spec",
        original_filename="spec.pdf",
        internal_storage_key="spec.pdf",
        file_size=2000,
        detected_media_type="application/pdf",
        checksum="4" * 64,
        category="engineering"
    )
    # Bob's private doc (never shared with Charlie)
    d_bob = Document(
        owner_id=bob.id,
        title="Secret M&A Valuation",
        original_filename="valuation.pdf",
        internal_storage_key="val.pdf",
        file_size=9000,
        detected_media_type="application/pdf",
        checksum="5" * 64,
        category="finance"
    )
    test_db_session.add_all([d_alice, d_bob])
    test_db_session.commit()

    # Share d_alice with charlie
    perm = DocumentPermission(
        document_id=d_alice.id,
        user_id=charlie.id,
        permission_level="read",
        granted_by=alice.id
    )
    test_db_session.add(perm)
    test_db_session.commit()

    # Charlie searches with query "Secret" or "valuation" (Bob's private document)
    res_leak = client.get("/api/v1/documents?query=valuation", headers={"Authorization": f"Bearer {charlie_token}"})
    assert res_leak.status_code == 200
    assert res_leak.json()["total"] == 0
    assert len(res_leak.json()["documents"]) == 0

    # Charlie searches with file_type=pdf: should ONLY see d_alice, NEVER d_bob
    res_charlie = client.get("/api/v1/documents?file_type=pdf", headers={"Authorization": f"Bearer {charlie_token}"})
    assert res_charlie.status_code == 200
    charlie_docs = res_charlie.json()["documents"]
    assert len(charlie_docs) == 1
    assert charlie_docs[0]["id"] == d_alice.id

    # Charlie filters by permission_filter=shared
    res_shared = client.get("/api/v1/documents?permission_filter=shared", headers={"Authorization": f"Bearer {charlie_token}"})
    assert res_shared.status_code == 200
    assert len(res_shared.json()["documents"]) == 1

    # Charlie filters by permission_filter=owned (owns nothing)
    res_owned = client.get("/api/v1/documents?permission_filter=owned", headers={"Authorization": f"Bearer {charlie_token}"})
    assert res_owned.status_code == 200
    assert len(res_owned.json()["documents"]) == 0
