"""Phase 5: Audit ledger hardening and audit_writer role enforcement

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-10-24 19:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, Sequence[str], None] = 'b3c4d5e6f7a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    cols = [c['name'] for c in insp.get_columns('audit_events')]

    # 1. sequence_number
    if 'sequence_number' not in cols:
        op.add_column('audit_events', sa.Column('sequence_number', sa.Integer(), server_default='1', nullable=False))
        op.create_index('ix_audit_events_sequence_number', 'audit_events', ['sequence_number'])

    # 2. org_id
    if 'org_id' not in cols:
        op.add_column('audit_events', sa.Column('org_id', sa.String(64), server_default='default-org', nullable=False))
        op.create_index('ix_audit_events_org_id', 'audit_events', ['org_id'])

    # 3. ip_hash (privacy-preserving HMAC of client IP)
    if 'ip_hash' not in cols:
        op.add_column('audit_events', sa.Column('ip_hash', sa.String(64), nullable=True))

    # 4. user_agent_hash
    if 'user_agent_hash' not in cols:
        op.add_column('audit_events', sa.Column('user_agent_hash', sa.String(64), nullable=True))

    # 5. PostgreSQL-specific role enforcement: audit_writer (INSERT only)
    if conn.dialect.name == "postgresql":
        op.execute(text("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_writer') THEN
                CREATE ROLE audit_writer NOLOGIN;
            END IF;
        END
        $$;
        """))
        op.execute(text("GRANT USAGE ON SCHEMA public TO audit_writer;"))
        op.execute(text("GRANT INSERT ON TABLE audit_events TO audit_writer;"))
        op.execute(text("REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_events FROM audit_writer;"))

    # 6. Backfill monotonic sequence numbers for existing records
    rows = conn.execute(text("SELECT id FROM audit_events ORDER BY timestamp ASC, id ASC")).fetchall()
    for seq, row in enumerate(rows, 1):
        conn.execute(text("UPDATE audit_events SET sequence_number = :seq WHERE id = :id"), {"seq": seq, "id": row[0]})

def downgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    cols = [c['name'] for c in insp.get_columns('audit_events')]

    if conn.dialect.name == "postgresql":
        op.execute(text("REVOKE ALL PRIVILEGES ON TABLE audit_events FROM audit_writer;"))
        op.execute(text("DROP ROLE IF EXISTS audit_writer;"))

    if 'user_agent_hash' in cols:
        op.drop_column('audit_events', 'user_agent_hash')
    if 'ip_hash' in cols:
        op.drop_column('audit_events', 'ip_hash')
    if 'org_id' in cols:
        op.drop_index('ix_audit_events_org_id', table_name='audit_events')
        op.drop_column('audit_events', 'org_id')
    if 'sequence_number' in cols:
        op.drop_index('ix_audit_events_sequence_number', table_name='audit_events')
        op.drop_column('audit_events', 'sequence_number')
