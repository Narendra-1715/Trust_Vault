"""Phase 7: Break-glass multi-party approval, document freezing, and incident response

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-10-24 20:25:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'e6f7a8b9c0d1'
down_revision: Union[str, Sequence[str], None] = 'd5e6f7a8b9c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)

    # 1. Add is_frozen to documents table
    doc_cols = [c['name'] for c in insp.get_columns('documents')]
    if 'is_frozen' not in doc_cols:
        with op.batch_alter_table('documents') as batch_op:
            batch_op.add_column(
                sa.Column('is_frozen', sa.Boolean(), server_default=sa.text('false'), nullable=False)
            )

    # 2. Add columns to emergency_accesses table
    ea_cols = [c['name'] for c in insp.get_columns('emergency_accesses')]
    with op.batch_alter_table('emergency_accesses') as batch_op:
        if 'ticket_id' not in ea_cols:
            batch_op.add_column(
                sa.Column('ticket_id', sa.String(100), nullable=True)
            )
        if 'approval_mode' not in ea_cols:
            batch_op.add_column(
                sa.Column('approval_mode', sa.String(30), server_default='direct', nullable=False)
            )
        if 'delay_until' not in ea_cols:
            batch_op.add_column(
                sa.Column('delay_until', sa.DateTime(), nullable=True)
            )
        if 'approved_by' not in ea_cols:
            batch_op.add_column(
                sa.Column('approved_by', sa.String(36), nullable=True)
            )

def downgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)

    ea_cols = [c['name'] for c in insp.get_columns('emergency_accesses')]
    with op.batch_alter_table('emergency_accesses') as batch_op:
        for col in ['approved_by', 'delay_until', 'approval_mode', 'ticket_id']:
            if col in ea_cols:
                batch_op.drop_column(col)

    doc_cols = [c['name'] for c in insp.get_columns('documents')]
    if 'is_frozen' in doc_cols:
        with op.batch_alter_table('documents') as batch_op:
            batch_op.drop_column('is_frozen')
