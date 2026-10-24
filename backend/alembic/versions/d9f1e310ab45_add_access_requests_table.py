"""Add access requests table

Revision ID: d9f1e310ab45
Revises: c8f1e290ab34
Create Date: 2026-10-24 11:27:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'd9f1e310ab45'
down_revision: Union[str, Sequence[str], None] = 'c8f1e290ab34'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        'access_requests',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('document_id', sa.String(length=36), nullable=False),
        sa.Column('requester_id', sa.String(length=36), nullable=False),
        sa.Column('owner_id', sa.String(length=36), nullable=False),
        sa.Column('reason', sa.String(length=1000), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=False),
        sa.Column('requested_permission', sa.String(length=20), server_default='read', nullable=False),
        sa.Column('requested_expiry', sa.DateTime(), nullable=True),
        sa.Column('approved_permission', sa.String(length=20), nullable=True),
        sa.Column('approved_expiry', sa.DateTime(), nullable=True),
        sa.Column('rejection_reason', sa.String(length=500), nullable=True),
        sa.Column('decided_by', sa.String(length=36), nullable=True),
        sa.Column('decided_at', sa.DateTime(), nullable=True),
        sa.Column('cancelled_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['document_id'], ['documents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['requester_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['decided_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('access_requests', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_access_requests_document_id'), ['document_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_access_requests_requester_id'), ['requester_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_access_requests_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_access_requests_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_access_requests_created_at'), ['created_at'], unique=False)
        batch_op.create_index('ix_access_request_doc_requester', ['document_id', 'requester_id', 'status'], unique=False)
        batch_op.create_index('ix_access_request_owner_status', ['owner_id', 'status'], unique=False)
        batch_op.create_index('ix_access_request_requester_created', ['requester_id', 'created_at'], unique=False)

def downgrade() -> None:
    with op.batch_alter_table('access_requests', schema=None) as batch_op:
        batch_op.drop_index('ix_access_request_requester_created')
        batch_op.drop_index('ix_access_request_owner_status')
        batch_op.drop_index('ix_access_request_doc_requester')
        batch_op.drop_index(batch_op.f('ix_access_requests_created_at'))
        batch_op.drop_index(batch_op.f('ix_access_requests_status'))
        batch_op.drop_index(batch_op.f('ix_access_requests_owner_id'))
        batch_op.drop_index(batch_op.f('ix_access_requests_requester_id'))
        batch_op.drop_index(batch_op.f('ix_access_requests_document_id'))
    op.drop_table('access_requests')
