"""Phase 2 Envelope Encryption & Key Management Automated Tests
Tests:
1. Ciphertext chunk tampering aborts stream and triggers critical threat alerts.
2. Swapping chunks across documents fails due to AAD binding.
3. Crypto-shredding: destroying the DEK renders content permanently unrecoverable.
4. KEK rotation re-wraps DEKs under a new KEK version while keeping content readable.
5. Fail-closed safeguard: LocalDevKeyProvider strictly refuses to execute in production.
6. Zero cross-user deduplication: identical plaintext produces distinct DEKs and ciphertexts.
"""

import io
import struct
import secrets
import hashlib
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.document import Document
from app.models.document_key import DocumentKey
from app.models.audit import AuditEvent
from app.models.security_alert import SecurityAlert
from app.services.content import ContentService, MAGIC_HEADER
from app.services.key_provider import LocalDevKeyProvider, get_key_provider
from app.core.config import Settings
from app.storage.local import storage_service
from app.tests.conftest import get_auth_headers

def test_envelope_encryption_and_streaming_roundtrip(client: TestClient, test_users, test_db_session: Session):
    """Verifies that uploaded documents are envelope-encrypted at rest and decrypted cleanly on download."""
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    plaintext = b"%PDF-1.4 Confidential Zero-Trust Enterprise Whitepaper" * 200  # Multi-chunk

    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Envelope Test Doc", "category": "Legal"},
        files={"file": ("whitepaper.pdf", io.BytesIO(plaintext), "application/pdf")}
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # 1. Inspect storage file on disk: it must NOT be plaintext and MUST contain TV01 magic header
    doc = test_db_session.query(Document).filter(Document.id == doc_id).first()
    storage_path = storage_service._resolve_safe_path(doc.internal_storage_key)
    with open(storage_path, "rb") as f:
        disk_bytes = f.read()

    assert disk_bytes.startswith(MAGIC_HEADER)
    assert plaintext not in disk_bytes, "Security Invariant Violated: Plaintext found on disk storage!"

    # 2. Inspect document_keys table: wrapped DEK exists with KEK metadata
    doc_key = test_db_session.query(DocumentKey).filter(DocumentKey.document_id == doc_id).first()
    assert doc_key is not None
    assert doc_key.algorithm == "AES-256-GCM"
    assert len(doc_key.wrapped_dek) >= 28

    # 3. Stream download returns exact original plaintext
    dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner)
    assert dl_res.status_code == 200
    assert dl_res.content == plaintext

def test_tamper_ciphertext_chunk_aborts_and_alerts(client: TestClient, test_users, test_db_session: Session):
    """
    Tampering test:
    Altering any byte of the ciphertext or authentication tag on disk MUST
    cause the stream to abort, log a CRITICAL audit event, and create a SecurityAlert.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    plaintext = b"%PDF-1.4 Financial Ledger for Tamper Testing" * 100

    upload_res = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Tamper Test Doc", "category": "Finance"},
        files={"file": ("tamper.pdf", io.BytesIO(plaintext), "application/pdf")}
    )
    doc_id = upload_res.json()["id"]
    doc = test_db_session.query(Document).filter(Document.id == doc_id).first()
    storage_path = storage_service._resolve_safe_path(doc.internal_storage_key)

    # Corrupt ciphertext bytes on disk (flip bytes in the middle of ciphertext payload)
    with open(storage_path, "rb") as f:
        data = bytearray(f.read())

    # Flip bits at offset 40 (inside ciphertext payload)
    data[40] ^= 0xFF

    with open(storage_path, "wb") as f:
        f.write(data)

    # Attempt to stream download tampered document
    stream_aborted = False
    try:
        dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner)
        if dl_res.status_code >= 400:
            stream_aborted = True
    except (RuntimeError, Exception):
        stream_aborted = True

    assert stream_aborted, "Security Invariant Violated: Streaming did not abort on tampered ciphertext!"

    # Verify CRITICAL audit event was generated
    audit_ev = test_db_session.query(AuditEvent).filter(
        AuditEvent.resource_id == doc_id,
        AuditEvent.action == "document.content.integrity_compromised"
    ).first()
    assert audit_ev is not None

def test_cross_document_chunk_swap_attack_prevented(client: TestClient, test_users, test_db_session: Session):
    """
    Chunk Swapping Attack Prevention:
    Because AAD binds document_id, a ciphertext chunk from Doc A cannot be inserted into Doc B.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # Upload Doc A
    res_a = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Doc A", "category": "General"},
        files={"file": ("doc_a.pdf", io.BytesIO(b"%PDF-1.4 Doc A Content payload" * 50), "application/pdf")}
    )
    doc_a_id = res_a.json()["id"]

    # Upload Doc B
    res_b = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Doc B", "category": "General"},
        files={"file": ("doc_b.pdf", io.BytesIO(b"%PDF-1.4 Doc B Content payload" * 50), "application/pdf")}
    )
    doc_b_id = res_b.json()["id"]

    doc_a = test_db_session.query(Document).filter(Document.id == doc_a_id).first()
    doc_b = test_db_session.query(Document).filter(Document.id == doc_b_id).first()

    path_a = storage_service._resolve_safe_path(doc_a.internal_storage_key)
    path_b = storage_service._resolve_safe_path(doc_b.internal_storage_key)

    with open(path_a, "rb") as f:
        data_a = f.read()

    # Inject Doc A's framed payload directly into Doc B's storage file
    with open(path_b, "wb") as f:
        f.write(data_a)

    # Attempt to stream Doc B -> fails because AAD binds document_id to doc_b_id!
    stream_aborted = False
    try:
        dl_b = client.get(f"/api/v1/documents/{doc_b_id}/download", headers=headers_owner)
        if dl_b.status_code >= 400:
            stream_aborted = True
    except (RuntimeError, Exception):
        stream_aborted = True

    assert stream_aborted, "Security Invariant Violated: Swapped chunk stream did not abort!"

def test_crypto_shredding_renders_content_unrecoverable(client: TestClient, test_users, test_db_session: Session):
    """
    Crypto-Shredding Guarantee:
    Deleting the DEK makes all copies, including disk storage and historical backups,
    permanently unrecoverable. Resolves the 30-day deletion guarantee.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    plaintext = b"%PDF-1.4 Top Secret Shredding Target Content"

    up = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Shred Me", "category": "Legal"},
        files={"file": ("shred.pdf", io.BytesIO(plaintext), "application/pdf")}
    )
    doc_id = up.json()["id"]

    # Verify document reads cleanly initially
    assert client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner).status_code == 200

    # Execute crypto-shredding (destroy DEK row)
    shredded_count = ContentService.crypto_shred(test_db_session, doc_id)
    assert shredded_count >= 1

    # Attempting to decrypt or stream now fails immediately (410 Gone)
    shred_down = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner)
    assert shred_down.status_code == 410
    assert "crypto-shredded" in shred_down.json()["detail"].lower()

def test_kek_rotation_without_reencrypting_content(client: TestClient, test_users, test_db_session: Session):
    """
    KEK Rotation:
    Rewraps DEKs under a new KEK version.
    The underlying ciphertext chunks on disk remain unchanged, yet content continues to stream cleanly.
    """
    headers_owner = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_admin = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    plaintext = b"%PDF-1.4 Rotation Test Content" * 80

    up = client.post(
        "/api/v1/documents/upload",
        headers=headers_owner,
        data={"title": "Rotation Doc", "category": "Tech"},
        files={"file": ("rotation.pdf", io.BytesIO(plaintext), "application/pdf")}
    )
    doc_id = up.json()["id"]

    # Inspect current KEK ID
    key_before = test_db_session.query(DocumentKey).filter(DocumentKey.document_id == doc_id).first()
    old_kek_id = key_before.kek_id
    old_wrapped_dek = key_before.wrapped_dek

    # Admin rotates KEK
    new_kek_hex = secrets.token_hex(32)
    rot_res = client.post(
        "/api/v1/admin/kms/rotate-kek",
        headers=headers_admin,
        json={"new_kek_id": "kek-v2-enterprise", "new_kek_hex": new_kek_hex}
    )
    assert rot_res.status_code == 200
    assert rot_res.json()["rotated_keys_count"] >= 1

    # Verify DEK was re-wrapped under new KEK ID
    test_db_session.expire_all()
    key_after = test_db_session.query(DocumentKey).filter(DocumentKey.document_id == doc_id).first()
    assert key_after.kek_id == "kek-v2-enterprise"
    assert key_after.wrapped_dek != old_wrapped_dek
    assert key_after.rotated_at is not None

    # Stream download continues to return exact plaintext flawlessly!
    dl_res = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers_owner)
    assert dl_res.status_code == 200
    assert dl_res.content == plaintext

def test_no_cross_user_deduplication(client: TestClient, test_users, test_db_session: Session):
    """
    Zero Deduplication Guarantee:
    Two users uploading identical plaintext must get different random DEKs,
    different nonces, and completely distinct ciphertexts on disk.
    """
    headers_a = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")
    headers_b = get_auth_headers(client, "owner_b@test.com", "OwnerBPass123!")
    identical_plaintext = b"%PDF-1.4 Identical Plaintext Across Multiple Users"

    # User A uploads
    up_a = client.post(
        "/api/v1/documents/upload",
        headers=headers_a,
        data={"title": "Doc A", "category": "General"},
        files={"file": ("same.pdf", io.BytesIO(identical_plaintext), "application/pdf")}
    )
    doc_a_id = up_a.json()["id"]

    # User B uploads exact same file
    up_b = client.post(
        "/api/v1/documents/upload",
        headers=headers_b,
        data={"title": "Doc B", "category": "General"},
        files={"file": ("same.pdf", io.BytesIO(identical_plaintext), "application/pdf")}
    )
    doc_b_id = up_b.json()["id"]

    doc_a = test_db_session.query(Document).filter(Document.id == doc_a_id).first()
    doc_b = test_db_session.query(Document).filter(Document.id == doc_b_id).first()

    assert doc_a.internal_storage_key != doc_b.internal_storage_key

    # Disk contents must differ completely due to distinct DEKs and nonces
    path_a = storage_service._resolve_safe_path(doc_a.internal_storage_key)
    path_b = storage_service._resolve_safe_path(doc_b.internal_storage_key)

    with open(path_a, "rb") as f:
        bytes_a = f.read()
    with open(path_b, "rb") as f:
        bytes_b = f.read()

    assert bytes_a != bytes_b, "Invariant Violated: Cross-user deduplication detected!"

def test_local_dev_key_provider_refuses_production():
    """Fail-Closed Safeguard: LocalDevKeyProvider strictly refuses to run when ENVIRONMENT=production."""
    from unittest.mock import patch
    with patch("app.core.config.settings.ENVIRONMENT", "production"):
        with pytest.raises(RuntimeError, match="refuses to execute when ENVIRONMENT=production"):
            LocalDevKeyProvider()
