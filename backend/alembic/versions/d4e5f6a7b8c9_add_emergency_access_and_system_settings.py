"""Add emergency access and system settings tables

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-10-24 15:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # 1. emergency_accesses table
    op.create_table(
        'emergency_accesses',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('admin_id', sa.String(length=36), nullable=False),
        sa.Column('document_id', sa.String(length=36), nullable=False),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='active', nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(), nullable=True),
        sa.Column('reviewed_by', sa.String(length=36), nullable=True),
        sa.Column('review_notes', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['admin_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['document_id'], ['documents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['reviewed_by'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_emergency_accesses_admin_id', 'emergency_accesses', ['admin_id'])
    op.create_index('ix_emergency_accesses_doc_id', 'emergency_accesses', ['document_id'])
    op.create_index('ix_emergency_accesses_expires_at', 'emergency_accesses', ['expires_at'])

    # 2. system_settings table
    op.create_table(
        'system_settings',
        sa.Column('key', sa.String(length=64), primary_key=True),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('updated_by', sa.String(length=36), nullable=True),
    )

    # Seed default system settings
    system_settings_table = sa.table(
        'system_settings',
        sa.column('key', sa.String),
        sa.column('value', sa.Text),
        sa.column('description', sa.Text),
        sa.column('updated_at', sa.DateTime),
        sa.column('updated_by', sa.String)
    )

    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    op.bulk_insert(
        system_settings_table,
        [
            {
                "key": "session_timeout_minutes",
                "value": "60",
                "description": "Inactivity timeout for authenticated user sessions",
                "updated_at": now,
                "updated_by": "SYSTEM"
            },
            {
                "key": "max_failed_logins",
                "value": "5",
                "description": "Threshold of consecutive failed logins before triggering security alerts",
                "updated_at": now,
                "updated_by": "SYSTEM"
            },
            {
                "key": "mfa_enforced_for_admins",
                "value": "true",
                "description": "Mandatory multi-factor authentication enforcement for privileged administrative accounts",
                "updated_at": now,
                "updated_by": "SYSTEM"
            },
            {
                "key": "document_retention_days",
                "value": "365",
                "description": "Baseline retention period for historical revisions and deleted document records",
                "updated_at": now,
                "updated_by": "SYSTEM"
            }
        ]
    )

def downgrade() -> None:
    op.drop_table('system_settings')
    op.drop_table('emergency_accesses')
