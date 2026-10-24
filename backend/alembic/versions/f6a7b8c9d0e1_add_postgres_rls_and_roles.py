"""Phase 1 Postgres Row-Level Security (RLS) and Security Roles

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-24 17:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name == 'postgresql':
        # 1. Provision security roles if not present
        op.execute(sa.text("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_rw') THEN
                CREATE ROLE app_rw WITH NOBYPASSRLS;
            END IF;
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'migrator') THEN
                CREATE ROLE migrator;
            END IF;
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_writer') THEN
                CREATE ROLE audit_writer;
            END IF;
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ai_readonly') THEN
                CREATE ROLE ai_readonly;
            END IF;
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'backup_ro') THEN
                CREATE ROLE backup_ro;
            END IF;
        END
        $$;
        """))

        # 2. Enable Row-Level Security on core tables
        op.execute(sa.text("ALTER TABLE documents ENABLE ROW LEVEL SECURITY;"))
        op.execute(sa.text("ALTER TABLE document_versions ENABLE ROW LEVEL SECURITY;"))
        op.execute(sa.text("ALTER TABLE document_permissions ENABLE ROW LEVEL SECURITY;"))

        # 3. Create RLS Policies for documents
        op.execute(sa.text("""
        DROP POLICY IF EXISTS documents_tenant_and_access_policy ON documents;
        CREATE POLICY documents_tenant_and_access_policy ON documents
        FOR ALL
        USING (
            (
                current_setting('app.current_user_id', true) IS NULL
                OR current_setting('app.current_user_id', true) = ''
                OR (
                    (org_id = COALESCE(NULLIF(current_setting('app.current_org_id', true), ''), 'default-org'))
                    AND (
                        owner_id = current_setting('app.current_user_id', true)
                        OR id IN (
                            SELECT p.document_id
                            FROM document_permissions p
                            WHERE p.user_id = current_setting('app.current_user_id', true)
                              AND p.revoked_at IS NULL
                              AND (p.expires_at IS NULL OR p.expires_at > CURRENT_TIMESTAMP)
                        )
                    )
                )
            )
        );
        """))

        # 4. Create RLS Policies for document_permissions
        op.execute(sa.text("""
        DROP POLICY IF EXISTS permissions_owner_or_recipient_policy ON document_permissions;
        CREATE POLICY permissions_owner_or_recipient_policy ON document_permissions
        FOR ALL
        USING (
            (
                current_setting('app.current_user_id', true) IS NULL
                OR current_setting('app.current_user_id', true) = ''
                OR user_id = current_setting('app.current_user_id', true)
                OR document_id IN (
                    SELECT d.id FROM documents d WHERE d.owner_id = current_setting('app.current_user_id', true)
                )
            )
        );
        """))

def downgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name == 'postgresql':
        op.execute(sa.text("DROP POLICY IF EXISTS permissions_owner_or_recipient_policy ON document_permissions;"))
        op.execute(sa.text("DROP POLICY IF EXISTS documents_tenant_and_access_policy ON documents;"))
        op.execute(sa.text("ALTER TABLE document_permissions DISABLE ROW LEVEL SECURITY;"))
        op.execute(sa.text("ALTER TABLE document_versions DISABLE ROW LEVEL SECURITY;"))
        op.execute(sa.text("ALTER TABLE documents DISABLE ROW LEVEL SECURITY;"))
