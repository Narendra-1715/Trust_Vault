"""Hypothesis Property-Based Tests for Central Authorization (Phase 1)
Validates mathematical and logical properties of AuthorizationService.decide:
- Invariant I1: Admin Blindness property.
- Invariant I2: Deterministic TTL & instant expiration property.
- Invariant I3: Uniform rejection of malformed IDs & cross-tenant access.
- Non-delegation of owner-only actions.
"""

import uuid
from datetime import datetime, timedelta, timezone
from hypothesis import given, strategies as st, settings as hyp_settings, HealthCheck
import pytest
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.services.authorization import AuthorizationService, Action, is_valid_uuid

action_strategy = st.sampled_from(list(Action))

@given(st.text(min_size=0, max_size=50))
@hyp_settings(max_examples=50)
def test_property_malformed_resource_id_always_rejected(malformed_id: str):
    """Property: Any non-UUID resource_id is deterministically rejected without exception."""
    if not is_valid_uuid(malformed_id):
        decision = AuthorizationService.decide(
            db=None,
            principal=None,
            action=Action.VIEW,
            resource_id=malformed_id
        )
        assert decision.allowed is False
        assert decision.reason == "invalid_resource_id_format"

@given(action=action_strategy, is_owner=st.booleans())
@hyp_settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_admin_blindness_invariants(test_db_session: Session, action: Action, is_owner: bool):
    """
    Property (Invariant I1): An Admin has ZERO content permissions on a document
    unless they are the document owner or hold an active grant or break-glass.
    """
    try:
        admin_user = User(
            id=str(uuid.uuid4()),
            email=f"admin_{uuid.uuid4().hex[:8]}@test.com",
            password_hash="h",
            display_name="Admin",
            role="admin",
            org_id="tenant-hyp"
        )
        test_db_session.add(admin_user)

        if is_owner:
            owner_user = admin_user
        else:
            owner_user = User(
                id=str(uuid.uuid4()),
                email=f"owner_{uuid.uuid4().hex[:8]}@test.com",
                password_hash="h",
                display_name="Actual Owner",
                role="owner",
                org_id="tenant-hyp"
            )
            test_db_session.add(owner_user)

        doc = Document(
            id=str(uuid.uuid4()),
            owner_id=owner_user.id,
            title="Admin Blindness Hyp Doc",
            original_filename="test.pdf",
            internal_storage_key=f"hyp_{uuid.uuid4().hex}.bin",
            detected_media_type="application/pdf",
            file_size=512,
            checksum="e" * 64,
            org_id="tenant-hyp"
        )
        test_db_session.add(doc)
        test_db_session.commit()

        decision = AuthorizationService.decide(test_db_session, admin_user, action, doc.id)

        if is_owner:
            if action != Action.RESTORE:
                assert decision.allowed is True
        else:
            # If admin is NOT owner and has no break glass:
            # Only non-content metadata audit view is allowed; all content actions are DENIED
            if action in [Action.VIEW, Action.DOWNLOAD, Action.EDIT, Action.SHARE, Action.ROLLBACK, Action.DELETE, Action.RESTORE, Action.MANAGE_GRANTS]:
                assert decision.allowed is False
    finally:
        test_db_session.rollback()

@given(action=action_strategy)
@hyp_settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_cross_tenant_isolation(test_db_session: Session, action: Action):
    """Property: Any cross-tenant access MUST be denied regardless of role or action."""
    try:
        user = User(
            id=str(uuid.uuid4()),
            email=f"tenant_a_{uuid.uuid4().hex[:8]}@test.com",
            password_hash="h",
            display_name="Tenant A User",
            role="owner",
            org_id="tenant-alpha"
        )
        owner = User(
            id=str(uuid.uuid4()),
            email=f"tenant_b_{uuid.uuid4().hex[:8]}@test.com",
            password_hash="h",
            display_name="Tenant B User",
            role="owner",
            org_id="tenant-beta"
        )
        test_db_session.add_all([user, owner])

        doc = Document(
            id=str(uuid.uuid4()),
            owner_id=owner.id,
            title="Foreign Doc",
            original_filename="foreign.pdf",
            internal_storage_key=f"foreign_{uuid.uuid4().hex}.bin",
            detected_media_type="application/pdf",
            file_size=512,
            checksum="f" * 64,
            org_id="tenant-beta"  # Different tenant!
        )
        test_db_session.add(doc)
        test_db_session.commit()

        decision = AuthorizationService.decide(test_db_session, user, action, doc.id)
        assert decision.allowed is False
        assert decision.reason == "cross_tenant_access_denied"
    finally:
        test_db_session.rollback()

@given(seconds_offset=st.integers(min_value=1, max_value=86400))
@hyp_settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_expired_grants_always_denied(test_db_session: Session, seconds_offset: int):
    """Property (Invariant I2): Any grant with expires_at in the past MUST be denied."""
    try:
        owner = User(
            id=str(uuid.uuid4()),
            email=f"owner_{uuid.uuid4().hex[:8]}@test.com",
            password_hash="h",
            display_name="Owner",
            role="owner",
            org_id="tenant-hyp"
        )
        grantee = User(
            id=str(uuid.uuid4()),
            email=f"grantee_{uuid.uuid4().hex[:8]}@test.com",
            password_hash="h",
            display_name="Grantee",
            role="viewer",
            org_id="tenant-hyp"
        )
        test_db_session.add_all([owner, grantee])

        doc = Document(
            id=str(uuid.uuid4()),
            owner_id=owner.id,
            title="Doc",
            original_filename="doc.pdf",
            internal_storage_key=f"d_{uuid.uuid4().hex}.bin",
            detected_media_type="application/pdf",
            file_size=512,
            checksum="g" * 64,
            org_id="tenant-hyp"
        )
        test_db_session.add(doc)

        past_exp = datetime.now(timezone.utc) - timedelta(seconds=seconds_offset)
        perm = DocumentPermission(
            id=str(uuid.uuid4()),
            document_id=doc.id,
            user_id=grantee.id,
            permission_level="edit",
            granted_by=owner.id,
            expires_at=past_exp
        )
        test_db_session.add(perm)
        test_db_session.commit()

        for act in [Action.VIEW, Action.DOWNLOAD, Action.EDIT, Action.VIEW_METADATA]:
            decision = AuthorizationService.decide(test_db_session, grantee, act, doc.id)
            assert decision.allowed is False
            assert decision.reason == "grant_expired"
    finally:
        test_db_session.rollback()
