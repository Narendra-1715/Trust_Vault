"""Add document request links table

Revision ID: e1f2a345bc67
Revises: d9f1e310ab45
Create Date: 2026-10-24 11:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'e1f2a345bc67'
down_revision: Union[str, Sequence[str], None] = 'd9f1e310ab45'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        'document_request_links',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('document_id', sa.String(length=36), nullable=False),
        sa.Column('owner_id', sa.String(length=36), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=True),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('token_prefix', sa.String(length=10), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('use_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('max_uses', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['document_id'], ['documents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('document_request_links', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_document_request_links_document_id'), ['document_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_document_request_links_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_document_request_links_token_hash'), ['token_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_document_request_links_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_document_request_links_revoked_at'), ['revoked_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_document_request_links_created_at'), ['created_at'], unique=False)
        batch_op.create_index('ix_request_link_doc_status', ['document_id', 'revoked_at', 'expires_at'], unique=False)
        batch_op.create_index('ix_request_link_owner_created', ['owner_id', 'created_at'], unique=False)

def downgrade() -> None:
    with op.batch_alter_table('document_request_links', schema=None) as batch_op:
        batch_op.drop_index('ix_request_link_owner_created')
        batch_op.drop_index('ix_request_link_doc_status')
        batch_op.drop_index(batch_op.f('ix_document_request_links_created_at'))
        batch_op.drop_index(batch_op.f('ix_document_request_links_revoked_at'))
        batch_op.drop_index(batch_op.f('ix_document_request_links_expires_at'))
        batch_op.drop_index(batch_op.f('ix_document_request_links_token_hash'))
        batch_op.drop_index(batch_op.f('ix_document_request_links_owner_id'))
        batch_op.drop_index(batch_op.f('ix_document_request_links_document_id'))
    op.drop_table('document_request_links')
