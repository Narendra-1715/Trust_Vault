"""Phase 6: AI component boundary, metadata view, and ai_readonly role

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-10-24 20:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, Sequence[str], None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)

    # 1. Add action_type column to ai_access_suggestions if not present
    ai_cols = [c['name'] for c in insp.get_columns('ai_access_suggestions')]
    if 'action_type' not in ai_cols:
        op.add_column(
            'ai_access_suggestions',
            sa.Column('action_type', sa.String(50), server_default='RECOMMEND_READ_GRANT', nullable=False)
        )

    # 2. Create ai_document_metadata_view
    # Strictly omits internal_storage_key, DEKs, checksum, and raw content bytes
    if conn.dialect.name == "postgresql":
        op.execute("""
            CREATE OR REPLACE VIEW ai_document_metadata_view AS
            SELECT 
                id AS document_id,
                owner_id,
                category,
                file_size,
                created_at,
                updated_at,
                org_id
            FROM documents
            WHERE deleted_at IS NULL;
        """)

        # Database-level enforcement for ai_readonly role (handled safely in managed Postgres)
        op.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = current_user AND (rolcreaterole OR rolsuper)) THEN
                    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ai_readonly') THEN
                        CREATE ROLE ai_readonly WITH LOGIN;
                    END IF;
                    -- Revoke all table modifications in public schema
                    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ai_readonly;
                    -- Grant SELECT ONLY on the sanitized metadata view and pending suggestions
                    GRANT SELECT ON ai_document_metadata_view TO ai_readonly;
                    GRANT SELECT ON ai_access_suggestions TO ai_readonly;
                    -- Explicitly forbid access to sensitive tables
                    REVOKE ALL ON documents FROM ai_readonly;
                    REVOKE ALL ON audit_events FROM ai_readonly;
                    REVOKE ALL ON users FROM ai_readonly;
                ELSE
                    RAISE NOTICE 'Skipping ai_readonly role creation: current user % lacks CREATEROLE', current_user;
                END IF;
            EXCEPTION WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping ai_readonly role configuration due to insufficient privilege';
            END
            $$;
        """)
    else:
        # SQLite support for local dev and testing
        op.execute("""
            CREATE VIEW IF NOT EXISTS ai_document_metadata_view AS
            SELECT 
                id AS document_id,
                owner_id,
                category,
                file_size,
                created_at,
                updated_at,
                org_id
            FROM documents
            WHERE deleted_at IS NULL;
        """)

def downgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name == "postgresql":
        op.execute("REVOKE ALL ON ai_document_metadata_view FROM ai_readonly;")
        op.execute("DROP VIEW IF EXISTS ai_document_metadata_view;")
    else:
        op.execute("DROP VIEW IF EXISTS ai_document_metadata_view;")

    insp = sa.inspect(conn)
    ai_cols = [c['name'] for c in insp.get_columns('ai_access_suggestions')]
    if 'action_type' in ai_cols:
        op.drop_column('ai_access_suggestions', 'action_type')
