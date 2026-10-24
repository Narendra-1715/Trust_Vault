"""Add security alerts table

Revision ID: f2a3b4c5d6e7
Revises: e1f2a345bc67
Create Date: 2026-10-24 12:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'f2a3b4c5d6e7'
down_revision: Union[str, Sequence[str], None] = 'e1f2a345bc67'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        'security_alerts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), server_default='medium', nullable=False),
        sa.Column('status', sa.String(length=20), server_default='open', nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=True),
        sa.Column('target_user_id', sa.String(length=36), nullable=True),
        sa.Column('target_document_id', sa.String(length=36), nullable=True),
        sa.Column('session_id', sa.String(length=64), nullable=True),
        sa.Column('request_id', sa.String(length=64), nullable=True),
        sa.Column('summary', sa.String(length=500), nullable=False),
        sa.Column('investigation_metadata', sa.JSON(), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('acknowledged_by', sa.String(length=36), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_by', sa.String(length=36), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['target_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['target_document_id'], ['documents.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['acknowledged_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('security_alerts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_security_alerts_event_type'), ['event_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_timestamp'), ['timestamp'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_actor_id'), ['actor_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_target_user_id'), ['target_user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_target_document_id'), ['target_document_id'], unique=False)
        batch_op.create_index('ix_alert_status_severity', ['status', 'severity', 'timestamp'], unique=False)
        batch_op.create_index('ix_alert_event_timestamp', ['event_type', 'timestamp'], unique=False)
        batch_op.create_index('ix_alert_actor_status', ['actor_id', 'status'], unique=False)

def downgrade() -> None:
    with op.batch_alter_table('security_alerts', schema=None) as batch_op:
        batch_op.drop_index('ix_alert_actor_status')
        batch_op.drop_index('ix_alert_event_timestamp')
        batch_op.drop_index('ix_alert_status_severity')
        batch_op.drop_index(batch_op.f('ix_security_alerts_target_document_id'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_target_user_id'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_actor_id'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_timestamp'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_status'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_severity'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_event_type'))
    op.drop_table('security_alerts')
