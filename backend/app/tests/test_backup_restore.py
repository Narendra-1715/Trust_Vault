import os
import io
import json
import tarfile
import pytest
import tempfile
import shutil
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.audit import AuditEvent
from app.storage.local import storage_service
from app.services.backup import (
    create_backup,
    list_backups,
    prune_older_backups,
    BackupLock,
    BackupConcurrencyError,
    BackupIntegrityError,
    decrypt_archive_payload,
    encrypt_archive_payload
)
from app.services.restore import verify_backup_archive, execute_restore

def get_auth_headers(client: TestClient, email: str, password: str = "TestPass123!") -> dict:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def temp_backup_dir():
    d = tempfile.mkdtemp(prefix="trustvault_test_backups_")
    yield d
    shutil.rmtree(d, ignore_errors=True)

def test_backup_creation_and_isolated_verification(client: TestClient, test_users, test_db_session: Session, temp_backup_dir):
    """
    Round-trip Test:
    1. Creates a private document with content and valid SHA-256 in storage.
    2. Generates an encrypted backup archive.
    3. Executes isolated dry-run disaster recovery verification.
    4. Validates document checksums, database schema, and audit chain continuity.
    """
    owner = test_users["owner_a"]
    file_bytes = b"CONFIDENTIAL_TRUSTVAULT_PAYROLL_2026_DATA"
    import hashlib
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    storage_key = f"test_payroll_{file_hash[:12]}.txt"

    # Save to storage
    storage_service.save_file(io.BytesIO(file_bytes), storage_key)

    doc = Document(
        owner_id=owner.id,
        title="Executive Payroll 2026",
        original_filename="payroll.txt",
        internal_storage_key=storage_key,
        file_size=len(file_bytes),
        detected_media_type="text/plain",
        checksum=file_hash,
        category="finance"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    # Create backup
    backup_meta = create_backup(
        db=test_db_session,
        backup_dir=temp_backup_dir
    )
    assert backup_meta["verified"] is True
    assert backup_meta["total_documents"] >= 1
    assert os.path.exists(backup_meta["path"])

    # Run isolated verification
    report = verify_backup_archive(
        backup_path_or_id=backup_meta["backup_id"],
        backup_dir=temp_backup_dir
    )
    assert report["is_valid"] is True
    assert report["objects_verified"] >= 1
    assert len(report["missing_objects"]) == 0
    assert len(report["corrupt_objects"]) == 0
    assert report["audit_chain_valid"] is True
    assert report["rto_seconds"] > 0
    assert len(report["errors"]) == 0

def test_backup_concurrency_lock(temp_backup_dir):
    """
    Verifies that simultaneous backup jobs are prevented via BackupLock.
    """
    with BackupLock(temp_backup_dir):
        # Attempting second lock should raise BackupConcurrencyError
        with pytest.raises(BackupConcurrencyError):
            with BackupLock(temp_backup_dir):
                pass

def test_corrupt_object_detection(client: TestClient, test_users, test_db_session: Session, temp_backup_dir):
    """
    Verifies that mutating even a single byte in a restored document triggers
    an explicit SHA-256 checksum mismatch failure during disaster recovery audit.
    """
    owner = test_users["owner_a"]
    file_bytes = b"ORIGINAL_INTEGRITY_PROTECTED_DATA"
    import hashlib
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    storage_key = f"integrity_test_{file_hash[:12]}.txt"

    storage_service.save_file(io.BytesIO(file_bytes), storage_key)

    doc = Document(
        owner_id=owner.id,
        title="Integrity Spec",
        original_filename="spec.txt",
        internal_storage_key=storage_key,
        file_size=len(file_bytes),
        detected_media_type="text/plain",
        checksum=file_hash,
        category="tech"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    backup_meta = create_backup(db=test_db_session, backup_dir=temp_backup_dir)
    archive_path = backup_meta["path"]
    backup_id = backup_meta["backup_id"]

    # Tamper with archive: decrypt, corrupt the file bytes in objects/, repack and re-encrypt
    with open(archive_path, "rb") as f:
        enc_data = f.read()

    plaintext_tar = decrypt_archive_payload(enc_data, backup_id)
    scratch_dir = tempfile.mkdtemp(prefix="tamper_test_")

    try:
        with tarfile.open(fileobj=io.BytesIO(plaintext_tar), mode="r:gz") as tar:
            tar.extractall(path=scratch_dir)

        # Corrupt file in objects/
        corrupt_file_path = os.path.join(scratch_dir, "objects", storage_key)
        with open(corrupt_file_path, "wb") as f_obj:
            f_obj.write(b"CORRUPTED_MALICIOUS_TAMPERED_BYTES")

        # Repack
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
            for item in os.listdir(scratch_dir):
                tar.add(os.path.join(scratch_dir, item), arcname=item)

        re_encrypted = encrypt_archive_payload(tar_buf.getvalue(), backup_id)
        with open(archive_path, "wb") as f:
            f.write(re_encrypted)

        # Run verification - MUST FAIL!
        report = verify_backup_archive(backup_id, backup_dir=temp_backup_dir)
        assert report["is_valid"] is False
        assert len(report["corrupt_objects"]) >= 1
        assert report["corrupt_objects"][0]["storage_key"] == storage_key
        assert any("Corrupt object" in err or "checksum" in err.lower() for err in report["errors"])

    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)

def test_missing_object_detection(client: TestClient, test_users, test_db_session: Session, temp_backup_dir):
    """
    Verifies that a missing storage object in an archive fails verification immediately.
    """
    owner = test_users["owner_a"]
    file_bytes = b"FILE_THAT_WILL_GO_MISSING"
    import hashlib
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    storage_key = f"missing_{file_hash[:12]}.txt"

    storage_service.save_file(io.BytesIO(file_bytes), storage_key)

    doc = Document(
        owner_id=owner.id,
        title="Missing Spec",
        original_filename="missing.txt",
        internal_storage_key=storage_key,
        file_size=len(file_bytes),
        detected_media_type="text/plain",
        checksum=file_hash,
        category="tech"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    backup_meta = create_backup(db=test_db_session, backup_dir=temp_backup_dir)
    archive_path = backup_meta["path"]
    backup_id = backup_meta["backup_id"]

    # Tamper with archive: delete the file from objects/
    with open(archive_path, "rb") as f:
        enc_data = f.read()

    plaintext_tar = decrypt_archive_payload(enc_data, backup_id)
    scratch_dir = tempfile.mkdtemp(prefix="tamper_missing_")

    try:
        with tarfile.open(fileobj=io.BytesIO(plaintext_tar), mode="r:gz") as tar:
            tar.extractall(path=scratch_dir)

        # Delete the file
        file_to_remove = os.path.join(scratch_dir, "objects", storage_key)
        if os.path.exists(file_to_remove):
            os.remove(file_to_remove)

        # Repack
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
            for item in os.listdir(scratch_dir):
                tar.add(os.path.join(scratch_dir, item), arcname=item)

        re_encrypted = encrypt_archive_payload(tar_buf.getvalue(), backup_id)
        with open(archive_path, "wb") as f:
            f.write(re_encrypted)

        report = verify_backup_archive(backup_id, backup_dir=temp_backup_dir)
        assert report["is_valid"] is False
        assert storage_key in report["missing_objects"]

    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)

def test_invalid_encryption_key_rejected(client: TestClient, test_users, test_db_session: Session, temp_backup_dir):
    """
    Verifies that attempting verification with an incorrect passphrase fails authenticated decryption.
    """
    backup_meta = create_backup(
        db=test_db_session,
        backup_dir=temp_backup_dir,
        encryption_key="CorrectMasterKey2026!"
    )

    report = verify_backup_archive(
        backup_path_or_id=backup_meta["backup_id"],
        encryption_key="WRONG_ATTACKER_KEY_999!",
        backup_dir=temp_backup_dir
    )
    assert report["is_valid"] is False
    assert any("Decryption failed" in err for err in report["errors"])

def test_backup_retention_pruning(temp_backup_dir):
    """
    Verifies that backups older than the retention threshold are cleanly pruned.
    """
    # Create 5 fake backup files
    for i in range(5):
        fpath = os.path.join(temp_backup_dir, f"tv_backup_2026010{i+1}_000000_abc{i}.tar.gz.enc")
        with open(fpath, "wb") as f:
            f.write(b"data")
        # Ensure different mtimes
        os.utime(fpath, (1000 + i * 100, 1000 + i * 100))

    assert len(os.listdir(temp_backup_dir)) == 5
    prune_older_backups(temp_backup_dir, keep_count=3)
    remaining = os.listdir(temp_backup_dir)
    assert len(remaining) == 3
    # Oldest 2 should have been deleted
    assert "tv_backup_20260101_000000_abc0.tar.gz.enc" not in remaining
    assert "tv_backup_20260102_000000_abc1.tar.gz.enc" not in remaining
    assert "tv_backup_20260105_000000_abc4.tar.gz.enc" in remaining

def test_admin_api_endpoints_authorization(client: TestClient, test_users, temp_backup_dir, monkeypatch):
    """
    Verifies that:
    1. Viewers and Owners receive 403 Forbidden on backup endpoints.
    2. Only Administrators can list, create, and verify backups.
    """
    from app.core.config import settings
    monkeypatch.setattr(settings, "BACKUP_DIR", temp_backup_dir)

    admin_headers = get_auth_headers(client, "admin@test.com", "AdminPass123!")
    viewer_headers = get_auth_headers(client, "viewer_a@test.com", "ViewerAPass123!")
    owner_headers = get_auth_headers(client, "owner_a@test.com", "OwnerAPass123!")

    # 1. Non-admin access denied
    assert client.get("/api/v1/backups", headers=viewer_headers).status_code == 403
    assert client.get("/api/v1/backups", headers=owner_headers).status_code == 403
    assert client.post("/api/v1/backups/create", headers=viewer_headers).status_code == 403

    # 2. Admin creates backup
    create_res = client.post("/api/v1/backups/create", headers=admin_headers)
    assert create_res.status_code == 201, f"Failed to create backup: {create_res.text}"
    created_id = create_res.json()["backup_id"]

    # 3. Admin lists backups
    list_res = client.get("/api/v1/backups", headers=admin_headers)
    assert list_res.status_code == 200
    assert list_res.json()["total"] >= 1

    # 4. Admin verifies backup health
    verify_res = client.post(f"/api/v1/backups/{created_id}/verify", headers=admin_headers)
    assert verify_res.status_code == 200
    assert verify_res.json()["is_valid"] is True

def test_disaster_recovery_execute_restore_barrier_and_execution(test_users, test_db_session: Session, temp_backup_dir):
    """
    Verifies that:
    1. Restoration into production without confirm_destructive_overwrite is strictly blocked (HTTPException 400).
    2. Restoration with confirm_destructive_overwrite=True re-populates all entities and files cleanly.
    """
    from fastapi import HTTPException
    owner = test_users["owner_a"]
    file_bytes = b"PAYROLL_CONFIDENTIAL_STATE_BEFORE_CRASH"
    import hashlib
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    storage_key = f"crash_test_{file_hash[:12]}.txt"

    storage_service.save_file(io.BytesIO(file_bytes), storage_key)

    doc = Document(
        id="test-doc-dr-crash-1",
        owner_id=owner.id,
        title="Disaster Recovery Test Document",
        original_filename="dr_crash.txt",
        internal_storage_key=storage_key,
        file_size=len(file_bytes),
        detected_media_type="text/plain",
        checksum=file_hash,
        category="finance"
    )
    test_db_session.add(doc)
    test_db_session.commit()

    # Create verified backup
    backup_meta = create_backup(db=test_db_session, backup_dir=temp_backup_dir)
    backup_id = backup_meta["backup_id"]

    # 1. Test safety barrier: Without confirm flag, restoration MUST fail!
    with pytest.raises(HTTPException) as exc_info:
        execute_restore(
            backup_path_or_id=backup_id,
            db=test_db_session,
            backup_dir=temp_backup_dir,
            confirm_destructive_overwrite=False
        )
    assert exc_info.value.status_code == 400

    # Simulate catastrophic corruption: Delete file from storage and delete document from DB
    storage_service.delete_file(storage_key)
    assert not storage_service.exists(storage_key)
    test_db_session.query(Document).filter(Document.id == doc.id).delete()
    test_db_session.commit()
    assert test_db_session.query(Document).filter(Document.id == doc.id).first() is None

    # 2. Execute actual disaster recovery restore with confirm_destructive_overwrite=True
    restore_res = execute_restore(
        backup_path_or_id=backup_id,
        db=test_db_session,
        backup_dir=temp_backup_dir,
        confirm_destructive_overwrite=True
    )
    assert restore_res["success"] is True

    # Verify document and file are restored!
    restored_doc = test_db_session.query(Document).filter(Document.id == doc.id).first()
    assert restored_doc is not None
    assert restored_doc.title == "Disaster Recovery Test Document"
    assert storage_service.exists(storage_key)
    assert storage_service.compute_checksum(storage_key) == file_hash

