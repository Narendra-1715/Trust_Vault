"""Phase 3: Add session_version and ensure permission_epoch

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-10-24 19:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b3c4d5e6f7a8'
down_revision: Union[str, Sequence[str], None] = 'a2b3c4d5e6f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)

    # 1. users.session_version
    user_cols = [c['name'] for c in insp.get_columns('users')]
    if 'session_version' not in user_cols:
        op.add_column('users', sa.Column('session_version', sa.Integer(), server_default='1', nullable=False))

    # 2. user_sessions.session_version
    session_cols = [c['name'] for c in insp.get_columns('user_sessions')]
    if 'session_version' not in session_cols:
        op.add_column('user_sessions', sa.Column('session_version', sa.Integer(), server_default='1', nullable=False))

    # 3. documents.permission_epoch
    doc_cols = [c['name'] for c in insp.get_columns('documents')]
    if 'permission_epoch' not in doc_cols:
        op.add_column('documents', sa.Column('permission_epoch', sa.BigInteger(), server_default='1', nullable=False))

def downgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)

    doc_cols = [c['name'] for c in insp.get_columns('documents')]
    if 'permission_epoch' in doc_cols:
        op.drop_column('documents', 'permission_epoch')

    session_cols = [c['name'] for c in insp.get_columns('user_sessions')]
    if 'session_version' in session_cols:
        op.drop_column('user_sessions', 'session_version')

    user_cols = [c['name'] for c in insp.get_columns('users')]
    if 'session_version' in user_cols:
        op.drop_column('users', 'session_version')
