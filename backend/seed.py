import os
import io
import sys
import uuid
import hashlib
from datetime import datetime, timezone

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.db.session import SessionLocal, Base, engine
from app.core.security import hash_password
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.storage.local import storage_service
from app.audit.service import log_audit_event
from app.audit.verifier import verify_audit_integrity

def seed_database():
    """
    Seeds local database with demonstration accounts, sample documents, and permissions.
    Distinct roles:
    1. Admin: admin@trustvault.com / AdminPass123!
    2. Owner A: owner_a@trustvault.com / OwnerAPass123!
    3. Owner B: owner_b@trustvault.com / OwnerBPass123!
    4. Viewer A: viewer_a@trustvault.com / ViewerAPass123!
    """
    from app.core.config import settings
    if settings.ENVIRONMENT == "production" and not getattr(settings, "SEED_DEMO_DATA", False):
        print("[TrustVault Seeder] Production environment detected and SEED_DEMO_DATA is False. Skipping demo fixtures.")
        return

    print("[TrustVault Seeder] Initializing database...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:

        # Check if users already seeded
        existing_admin = db.query(User).filter(User.email == "admin@trustvault.com").first()
        if existing_admin:
            print("[TrustVault Seeder] Seed data already present. Skipping.")
            return

        print("[TrustVault Seeder] Creating demo users...")
        admin = User(
            id=str(uuid.uuid4()),
            email="admin@trustvault.com",
            password_hash=hash_password("AdminPass123!"),
            display_name="Security Admin",
            role="admin",
            is_active=True
        )
        owner_a = User(
            id=str(uuid.uuid4()),
            email="owner_a@trustvault.com",
            password_hash=hash_password("OwnerAPass123!"),
            display_name="Alice Owner",
            role="owner",
            is_active=True
        )
        owner_b = User(
            id=str(uuid.uuid4()),
            email="owner_b@trustvault.com",
            password_hash=hash_password("OwnerBPass123!"),
            display_name="Bob Executive",
            role="owner",
            is_active=True
        )
        viewer_a = User(
            id=str(uuid.uuid4()),
            email="viewer_a@trustvault.com",
            password_hash=hash_password("ViewerAPass123!"),
            display_name="Carol Viewer",
            role="viewer",
            is_active=True
        )

        db.add_all([admin, owner_a, owner_b, viewer_a])
        db.commit()

        # Log user creations in audit log
        for u in [admin, owner_a, owner_b, viewer_a]:
            log_audit_event(
                db=db,
                action="auth.register",
                resource_type="user",
                resource_id=u.id,
                outcome="success",
                actor_id=admin.id,
                metadata={"email": u.email, "role": u.role, "seeder": True}
            )

        print("[TrustVault Seeder] Creating sample documents in private storage...")
        os.makedirs(storage_service.base_dir, exist_ok=True)
        # 1. Document 1 for Owner A: Financial PDF
        doc1_content = (
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
            b"4 0 obj<</Length 68>>stream\n"
            b"BT /F1 12 Tf 72 712 Td (TRUSTVAULT CONFIDENTIAL: Q3 Financial Audit) Tj ET\n"
            b"endstream endobj\n"
            b"xref\n0 5\n0000000000 65535 f\n0000000010 00000 n\n0000000053 00000 n\n0000000102 00000 n\n0000000160 00000 n\n"
            b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n279\n%%EOF\n"
        )
        key1 = f"{uuid.uuid4().hex}.bin"
        storage_service.save_file(io.BytesIO(doc1_content), key1)
        checksum1 = hashlib.sha256(doc1_content).hexdigest()

        doc1 = Document(
            id=str(uuid.uuid4()),
            owner_id=owner_a.id,
            title="Q3 Financial Audit & Compliance Report",
            description="Confidential quarterly financial audit results with balance sheets and variance analysis.",
            original_filename="Q3_Financial_Audit.pdf",
            internal_storage_key=key1,
            detected_media_type="application/pdf",
            file_size=len(doc1_content),
            checksum=checksum1,
            category="Financial"
        )

        # 2. Document 2 for Owner A: Strategy text document
        doc2_content = b"TRUSTVAULT CONFIDENTIAL STRATEGIC PLAN 2026\n1. Enterprise expansion\n2. Cryptographic auditing"
        key2 = f"{uuid.uuid4().hex}.bin"
        storage_service.save_file(io.BytesIO(doc2_content), key2)
        checksum2 = hashlib.sha256(doc2_content).hexdigest()

        doc2 = Document(
            id=str(uuid.uuid4()),
            owner_id=owner_a.id,
            title="2026 Executive Strategic Roadmap",
            description="Board-level executive strategy roadmap and confidential expansion targets.",
            original_filename="Strategy_Roadmap_2026.txt",
            internal_storage_key=key2,
            detected_media_type="text/plain",
            file_size=len(doc2_content),
            checksum=checksum2,
            category="Executive"
        )

        # 3. Document 3 for Owner B: Security Analysis
        doc3_content = b"TRUSTVAULT PRIVATE SECURITY MODEL: Threat vectors, isolation boundaries, zero-trust."
        key3 = f"{uuid.uuid4().hex}.bin"
        storage_service.save_file(io.BytesIO(doc3_content), key3)
        checksum3 = hashlib.sha256(doc3_content).hexdigest()

        doc3 = Document(
            id=str(uuid.uuid4()),
            owner_id=owner_b.id,
            title="Internal Security Architecture Review",
            description="Architecture analysis, cryptographic boundaries, and penetration test findings.",
            original_filename="Security_Architecture_2026.txt",
            internal_storage_key=key3,
            detected_media_type="text/plain",
            file_size=len(doc3_content),
            checksum=checksum3,
            category="Engineering"
        )

        db.add_all([doc1, doc2, doc3])
        db.commit()

        # Log document uploads in audit
        for d in [doc1, doc2, doc3]:
            log_audit_event(
                db=db,
                action="document.upload",
                resource_type="document",
                resource_id=d.id,
                outcome="success",
                actor_id=d.owner_id,
                metadata={"title": d.title, "filename": d.original_filename, "checksum": d.checksum}
            )

        print("[TrustVault Seeder] Setting up sample permission grant...")
        # Owner A grants Viewer A explicit READ permission on Doc 1
        perm1 = DocumentPermission(
            id=str(uuid.uuid4()),
            document_id=doc1.id,
            user_id=viewer_a.id,
            permission_level="read",
            granted_by=owner_a.id,
            granted_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(perm1)
        db.commit()

        log_audit_event(
            db=db,
            action="permission.grant",
            resource_type="permission",
            resource_id=perm1.id,
            outcome="success",
            actor_id=owner_a.id,
            metadata={
                "target_user_email": viewer_a.email,
                "document_title": doc1.title,
                "permission_level": "read"
            }
        )

        print("[TrustVault Seeder] Verifying audit hash chain integrity...")
        verification = verify_audit_integrity(db)
        print(f"[TrustVault Seeder] Audit integrity verified: is_valid={verification['is_valid']}, total_events={verification['total_events']}")

        print("[TrustVault Seeder] Seeding completed successfully!")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
