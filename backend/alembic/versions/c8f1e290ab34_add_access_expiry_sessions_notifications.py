"""Add access expiry sessions and notifications

Revision ID: c8f1e290ab34
Revises: bd7569ef1c23
Create Date: 2026-10-24 02:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'c8f1e290ab34'
down_revision: Union[str, Sequence[str], None] = 'bd7569ef1c23'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # 1. Add expires_at column to document_permissions
    with op.batch_alter_table('document_permissions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('expires_at', sa.DateTime(), nullable=True))
        batch_op.create_index(batch_op.f('ix_document_permissions_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index('ix_doc_user_revoked_expires', ['document_id', 'user_id', 'revoked_at', 'expires_at'], unique=False)

    # 2. Create user_sessions table
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('session_token_jti', sa.String(length=64), nullable=False),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('device_info', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_active_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_sessions_session_token_jti'), ['session_token_jti'], unique=True)
        batch_op.create_index(batch_op.f('ix_user_sessions_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_sessions_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_sessions_revoked_at'), ['revoked_at'], unique=False)
        batch_op.create_index('ix_user_session_active', ['user_id', 'revoked_at', 'expires_at'], unique=False)

    # 3. Create security_notifications table
    op.create_table(
        'security_notifications',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('resource_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('read_at', sa.DateTime(), nullable=True),
        sa.Column('is_read', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('security_notifications', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_security_notifications_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_notifications_event_type'), ['event_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_notifications_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_notifications_read_at'), ['read_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_notifications_is_read'), ['is_read'], unique=False)
        batch_op.create_index('ix_user_notif_unread', ['user_id', 'is_read', 'created_at'], unique=False)

def downgrade() -> None:
    op.drop_table('security_notifications')
    op.drop_table('user_sessions')
    with op.batch_alter_table('document_permissions', schema=None) as batch_op:
        batch_op.drop_index('ix_doc_user_revoked_expires')
        batch_op.drop_index(batch_op.f('ix_document_permissions_expires_at'))
        batch_op.drop_column('expires_at')
