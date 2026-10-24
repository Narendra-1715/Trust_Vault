"""Add document classification and security policies

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-24 14:30:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # 1. Add classification column to documents
    with op.batch_alter_table('documents') as batch_op:
        batch_op.add_column(sa.Column('classification', sa.String(length=50), server_default='Internal', nullable=False))
        batch_op.create_index('ix_documents_classification_deleted', ['classification', 'deleted_at'], unique=False)

    # 2. Add mfa_enabled column to users
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('mfa_enabled', sa.Boolean(), server_default='0', nullable=False))

    # 3. Create security_policies table
    sec_pol_table = op.create_table(
        'security_policies',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('classification', sa.String(length=50), nullable=False, unique=True),
        sa.Column('allow_download', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('allow_sharing', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('max_grant_duration_days', sa.Integer(), nullable=True),
        sa.Column('require_mfa', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('elevated_classification_change', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )

    # 4. Seed default policies
    now = datetime.now(timezone.utc)
    op.bulk_insert(
        sec_pol_table,
        [
            {
                "id": str(uuid.uuid4()),
                "classification": "Internal",
                "allow_download": True,
                "allow_sharing": True,
                "max_grant_duration_days": None,
                "require_mfa": False,
                "elevated_classification_change": False,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid.uuid4()),
                "classification": "Confidential",
                "allow_download": True,
                "allow_sharing": True,
                "max_grant_duration_days": 90,
                "require_mfa": False,
                "elevated_classification_change": False,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid.uuid4()),
                "classification": "Highly Restricted",
                "allow_download": False,
                "allow_sharing": True,
                "max_grant_duration_days": 7,
                "require_mfa": True,
                "elevated_classification_change": True,
                "created_at": now,
                "updated_at": now,
            },
        ]
    )

def downgrade() -> None:
    op.drop_table('security_policies')
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('mfa_enabled')
    with op.batch_alter_table('documents') as batch_op:
        batch_op.drop_index('ix_documents_classification_deleted')
        batch_op.drop_column('classification')
