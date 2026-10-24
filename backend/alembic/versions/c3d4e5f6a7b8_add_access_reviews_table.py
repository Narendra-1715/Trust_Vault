"""Add access reviews table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-10-24 15:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        'access_reviews',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), nullable=False),
        sa.Column('permission_id', sa.String(length=36), nullable=False),
        sa.Column('reviewer_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=False),
        sa.Column('due_date', sa.DateTime(), nullable=False),
        sa.Column('decision', sa.String(length=20), nullable=True),
        sa.Column('decided_at', sa.DateTime(), nullable=True),
        sa.Column('decision_notes', sa.Text(), nullable=True),
        sa.Column('next_review_due', sa.DateTime(), nullable=True),
        sa.Column('reminder_sent_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['document_id'], ['documents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['permission_id'], ['document_permissions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['reviewer_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_access_reviews_reviewer_status', 'access_reviews', ['reviewer_id', 'status'])
    op.create_index('ix_access_reviews_perm_status', 'access_reviews', ['permission_id', 'status'])
    op.create_index('ix_access_reviews_due_date', 'access_reviews', ['due_date'])

def downgrade() -> None:
    op.drop_index('ix_access_reviews_due_date', table_name='access_reviews')
    op.drop_index('ix_access_reviews_perm_status', table_name='access_reviews')
    op.drop_index('ix_access_reviews_reviewer_status', table_name='access_reviews')
    op.drop_table('access_reviews')
