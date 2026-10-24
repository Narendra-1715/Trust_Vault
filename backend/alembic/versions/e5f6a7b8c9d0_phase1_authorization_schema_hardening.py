"""Phase 1 Authorization Schema Hardening: permission_epoch, org_id, version scoping, ownership transfer

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-10-24 17:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    tables = insp.get_table_names()

    # 1. Update documents table
    if 'documents' in tables:
        doc_cols = [c['name'] for c in insp.get_columns('documents')]
        if 'permission_epoch' not in doc_cols:
            op.add_column('documents', sa.Column('permission_epoch', sa.Integer(), server_default='1', nullable=False))
        if 'org_id' not in doc_cols:
            op.add_column('documents', sa.Column('org_id', sa.String(length=50), server_default='default-org', nullable=False))
        if 'transferred_at' not in doc_cols:
            op.add_column('documents', sa.Column('transferred_at', sa.DateTime(), nullable=True))
        if 'transferred_from_id' not in doc_cols:
            op.add_column('documents', sa.Column('transferred_from_id', sa.String(length=36), nullable=True))
            # SQLite does not support adding foreign key constraints via ALTER TABLE easily
            if conn.dialect.name != 'sqlite':
                op.create_foreign_key(
                    'fk_documents_transferred_from',
                    'documents', 'users',
                    ['transferred_from_id'], ['id'],
                    ondelete='SET NULL'
                )

    # 2. Update users table
    if 'users' in tables:
        user_cols = [c['name'] for c in insp.get_columns('users')]
        if 'org_id' not in user_cols:
            op.add_column('users', sa.Column('org_id', sa.String(length=50), server_default='default-org', nullable=False))

    # 3. Update document_permissions table
    if 'document_permissions' in tables:
        perm_cols = [c['name'] for c in insp.get_columns('document_permissions')]
        if 'min_version_number' not in perm_cols:
            op.add_column('document_permissions', sa.Column('min_version_number', sa.Integer(), nullable=True))
        if 'max_version_number' not in perm_cols:
            op.add_column('document_permissions', sa.Column('max_version_number', sa.Integer(), nullable=True))

def downgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    tables = insp.get_table_names()

    if 'document_permissions' in tables:
        perm_cols = [c['name'] for c in insp.get_columns('document_permissions')]
        if 'max_version_number' in perm_cols:
            op.drop_column('document_permissions', 'max_version_number')
        if 'min_version_number' in perm_cols:
            op.drop_column('document_permissions', 'min_version_number')

    if 'users' in tables:
        user_cols = [c['name'] for c in insp.get_columns('users')]
        if 'org_id' in user_cols:
            op.drop_column('users', 'org_id')

    if 'documents' in tables:
        doc_cols = [c['name'] for c in insp.get_columns('documents')]
        if 'transferred_from_id' in doc_cols:
            if conn.dialect.name != 'sqlite':
                op.drop_constraint('fk_documents_transferred_from', 'documents', type_='foreignkey')
            op.drop_column('documents', 'transferred_from_id')
        if 'transferred_at' in doc_cols:
            op.drop_column('documents', 'transferred_at')
        if 'org_id' in doc_cols:
            op.drop_column('documents', 'org_id')
        if 'permission_epoch' in doc_cols:
            op.drop_column('documents', 'permission_epoch')
