import os
import uuid
import tempfile
import json
from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent
from app.audit.service import log_audit_event
from app.audit.verifier import verify_audit_integrity
from app.audit.checkpoint import create_signed_checkpoint, verify_checkpoint, verify_checkpoint_files
from app.audit.cli import main as cli_main

def test_append_100_events_verify_chain_passes(test_db_session: Session):
    """
    Phase 5 / Invariant I5 Test 1:
    Appends 100 events into the cryptographic ledger, asserts:
    - Sequence numbers are strictly monotonic: 1..100
    - Each record binds the previous record's HMAC hash
    - Full chain verification passes with 100% integrity
    - Checkpoint anchor generation and verification pass
    """
    test_db_session.query(AuditEvent).delete()
    test_db_session.commit()

    # Append 100 events
    for i in range(100):
        log_audit_event(
            db=test_db_session,
            action=f"document.operation.{i}",
            resource_type="document",
            outcome="success",
            resource_id=f"doc-test-{i}",
            actor_id=None,
            request_id=f"req-{i}",
            client_ip="192.168.1.100",
            user_agent="TrustVault-Agent/1.0",
            metadata={"step": i, "batch": "test_100"}
        )

    # Verify chain integrity
    res = verify_audit_integrity(test_db_session)
    assert res["is_valid"] is True, f"Audit verification failed: {res.get('error_reason')}"
    assert res["total_events"] == 100

    # Verify signed checkpoint creation
    with tempfile.TemporaryDirectory() as tmp_dir:
        cp = create_signed_checkpoint(db=test_db_session, output_dir=tmp_dir)
        assert cp["sequence_number"] == 100
        assert cp["total_records"] == 100
        assert "signature" in cp

        # Verify checkpoint file
        cp_verify = verify_checkpoint(cp, db=test_db_session)
        assert cp_verify["is_valid"] is True

        # Verify directory
        dir_verify = verify_checkpoint_files(db=test_db_session, checkpoint_dir=tmp_dir)
        assert dir_verify["is_valid"] is True
        assert dir_verify["checkpoints_verified"] == 1

def test_modify_one_bit_of_old_record_detected(test_db_session: Session):
    """
    Phase 5 / Invariant I5 Test 2:
    Modifying even a single bit of historical event content invalidates the HMAC signature
    and is flagged immediately by the verifier.
    """
    test_db_session.query(AuditEvent).delete()
    test_db_session.commit()

    for i in range(20):
        log_audit_event(
            db=test_db_session,
            action=f"security.event.{i}",
            resource_type="document",
            outcome="success",
            metadata={"index": i}
        )

    # Pick record 10 and tamper with one bit
    event_10 = test_db_session.query(AuditEvent).filter(AuditEvent.sequence_number == 10).first()
    assert event_10 is not None

    # Tamper with outcome: success -> denied
    event_10.outcome = "denied"
    test_db_session.commit()

    # Verify tampering is detected
    res = verify_audit_integrity(test_db_session)
    assert res["is_valid"] is False
    assert res["tampered_event_id"] == event_10.id
    assert "Tampered content or invalid HMAC" in res["error_reason"]

def test_delete_record_verify_gap_detection(test_db_session: Session):
    """
    Phase 5 / Invariant I5 Test 3:
    Deleting an intermediate record creates a sequence gap and breaks the cryptographic hash chain.
    """
    test_db_session.query(AuditEvent).delete()
    test_db_session.commit()

    for i in range(15):
        log_audit_event(
            db=test_db_session,
            action=f"document.access.{i}",
            resource_type="document",
            outcome="success"
        )

    # Delete record 8
    event_8 = test_db_session.query(AuditEvent).filter(AuditEvent.sequence_number == 8).first()
    assert event_8 is not None
    test_db_session.delete(event_8)
    test_db_session.commit()

    # Verify gap is detected
    res = verify_audit_integrity(test_db_session)
    assert res["is_valid"] is False
    assert "Sequence gap or record deletion detected" in res["error_reason"]

def test_insert_out_of_order_record_verify_failure(test_db_session: Session):
    """
    Phase 5 / Invariant I5 Test 4:
    Inserting an out-of-order record or duplicate sequence number breaks monotonic integrity.
    """
    test_db_session.query(AuditEvent).delete()
    test_db_session.commit()

    for i in range(10):
        log_audit_event(
            db=test_db_session,
            action=f"session.login.{i}",
            resource_type="user_session",
            outcome="success"
        )

    # Attempt to insert an out-of-order record with sequence_number 5
    fake_event = AuditEvent(
        id=str(uuid.uuid4()),
        sequence_number=5,
        org_id="default-org",
        timestamp=datetime.now(timezone.utc),
        action="unauthorized.injection",
        resource_type="document",
        outcome="failure",
        structured_metadata={"injected": True},
        previous_event_hash="0" * 64,
        event_hash="f" * 64
    )
    test_db_session.add(fake_event)
    test_db_session.commit()

    # Verify failure is flagged
    res = verify_audit_integrity(test_db_session)
    assert res["is_valid"] is False

def test_cli_returns_non_zero_on_corrupt_chains(test_db_session: Session):
    """
    Phase 5 / Invariant I5 Test 5:
    The verification CLI returns exit code 0 on authentic chains and non-zero on corrupt chains
    or tampered checkpoints.
    """
    test_db_session.query(AuditEvent).delete()
    test_db_session.commit()

    for i in range(10):
        log_audit_event(
            db=test_db_session,
            action=f"auth.logout.{i}",
            resource_type="auth",
            outcome="success"
        )

    with tempfile.TemporaryDirectory() as empty_cp_dir:
        # 1. Clean chain -> CLI returns 0
        exit_code_clean = cli_main(["verify", "--checkpoints-dir", empty_cp_dir], db_session=test_db_session)
        assert exit_code_clean == 0

        # 2. Tampered record -> CLI returns 1 (non-zero)
        event_5 = test_db_session.query(AuditEvent).filter(AuditEvent.sequence_number == 5).first()
        event_5.action = "tampered.action"
        test_db_session.commit()

        exit_code_corrupt = cli_main(["verify", "--checkpoints-dir", empty_cp_dir], db_session=test_db_session)
        assert exit_code_corrupt != 0

    # Revert record 5
    event_5.action = "auth.logout.4"
    test_db_session.commit()

    # 3. Checkpoint signature tampering -> CLI returns 2 (non-zero)
    with tempfile.TemporaryDirectory() as tmp_dir:
        cp = create_signed_checkpoint(db=test_db_session, output_dir=tmp_dir)
        # Verify valid checkpoint exits 0
        assert cli_main(["verify", "--checkpoints-dir", tmp_dir], db_session=test_db_session) == 0

        # Tamper checkpoint signature
        cp_file = cp["filepath"]
        with open(cp_file, "r") as f:
            data = json.load(f)
        data["signature"] = "deadbeef" * 8
        with open(cp_file, "w") as f:
            json.dump(data, f)

        # CLI detects tampered checkpoint and returns non-zero
        exit_code_bad_cp = cli_main(["verify", "--checkpoints-dir", tmp_dir], db_session=test_db_session)
        assert exit_code_bad_cp != 0
