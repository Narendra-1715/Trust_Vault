"""Phase 2: Add document_keys table for envelope encryption and crypto-shredding

Revision ID: a2b3c4d5e6f7
Revises: f6a7b8c9d0e1
Create Date: 2026-10-24 18:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'a2b3c4d5e6f7'
down_revision: Union[str, Sequence[str], None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    tables = insp.get_table_names()

    if 'document_keys' not in tables:
        op.create_table(
            'document_keys',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
            sa.Column('version_id', sa.String(length=36), sa.ForeignKey('document_versions.id', ondelete='CASCADE'), nullable=True),
            sa.Column('wrapped_dek', sa.LargeBinary(), nullable=False),
            sa.Column('kek_id', sa.String(length=100), nullable=False),
            sa.Column('algorithm', sa.String(length=50), server_default='AES-256-GCM', nullable=False),
            sa.Column('chunk_size', sa.Integer(), server_default='65536', nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('rotated_at', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_document_keys_document_id', 'document_keys', ['document_id'])
        op.create_index('ix_document_keys_version_id', 'document_keys', ['version_id'])
        op.create_index('ix_document_keys_kek_id', 'document_keys', ['kek_id'])

        if conn.dialect.name == 'postgresql':
            op.execute(sa.text("ALTER TABLE document_keys ENABLE ROW LEVEL SECURITY;"))
            op.execute(sa.text("""
            DROP POLICY IF EXISTS document_keys_policy ON document_keys;
            CREATE POLICY document_keys_policy ON document_keys
            FOR ALL
            USING (
                document_id IN (
                    SELECT id FROM documents
                    WHERE owner_id = NULLIF(current_setting('app.current_user_id', true), '')
                    OR id IN (
                        SELECT p.document_id FROM document_permissions p
                        WHERE p.user_id = NULLIF(current_setting('app.current_user_id', true), '')
                          AND p.revoked_at IS NULL
                          AND (p.expires_at IS NULL OR p.expires_at > CURRENT_TIMESTAMP)
                    )
                )
            );
            """))

def downgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    tables = insp.get_table_names()

    if 'document_keys' in tables:
        if conn.dialect.name == 'postgresql':
            op.execute(sa.text("DROP POLICY IF EXISTS document_keys_policy ON document_keys;"))
            op.execute(sa.text("ALTER TABLE document_keys DISABLE ROW LEVEL SECURITY;"))
        op.drop_index('ix_document_keys_kek_id', table_name='document_keys')
        op.drop_index('ix_document_keys_version_id', table_name='document_keys')
        op.drop_index('ix_document_keys_document_id', table_name='document_keys')
        op.drop_table('document_keys')
