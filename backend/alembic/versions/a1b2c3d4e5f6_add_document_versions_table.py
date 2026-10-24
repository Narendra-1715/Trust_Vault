"""Add document versions table with initial version backfill

Revision ID: a1b2c3d4e5f6
Revises: f2a3b4c5d6e7
Create Date: 2026-10-24 14:10:00.000000

"""
import uuid
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'f2a3b4c5d6e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    tables = insp.get_table_names()

    if 'document_versions' not in tables:
        op.create_table(
            'document_versions',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('document_id', sa.String(length=36), nullable=False),
            sa.Column('version_number', sa.Integer(), nullable=False),
            sa.Column('storage_key', sa.String(length=255), nullable=False),
            sa.Column('original_filename', sa.String(length=255), nullable=False),
            sa.Column('file_size', sa.BigInteger(), nullable=False),
            sa.Column('checksum', sa.String(length=64), nullable=False),
            sa.Column('detected_media_type', sa.String(length=100), nullable=False),
            sa.Column('change_summary', sa.Text(), nullable=True),
            sa.Column('uploaded_by', sa.String(length=36), nullable=True),
            sa.Column('is_current', sa.Boolean(), server_default=sa.text('false'), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['document_id'], ['documents.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ondelete='SET NULL'),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('storage_key')
        )
        op.create_index('ix_doc_versions_doc_ver', 'document_versions', ['document_id', 'version_number'], unique=True)
        op.create_index('ix_doc_versions_doc_current', 'document_versions', ['document_id', 'is_current'])
        op.create_index('ix_doc_versions_uploaded_by', 'document_versions', ['uploaded_by'])

        # Backfill initial version (v1) for pre-existing documents safely
        try:
            existing_docs = conn.execute(sa.text(
                "SELECT id, owner_id, original_filename, internal_storage_key, detected_media_type, file_size, checksum, created_at FROM documents"
            )).fetchall()
            for doc in existing_docs:
                conn.execute(
                    sa.text("""
                        INSERT INTO document_versions (id, document_id, version_number, storage_key, original_filename, file_size, checksum, detected_media_type, change_summary, uploaded_by, is_current, created_at)
                        VALUES (:id, :doc_id, 1, :storage_key, :filename, :file_size, :checksum, :media_type, 'Initial version', :uploaded_by, :is_current, :created_at)
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "doc_id": doc[0],
                        "storage_key": doc[3],
                        "filename": doc[2],
                        "file_size": doc[5],
                        "checksum": doc[6],
                        "media_type": doc[4],
                        "uploaded_by": doc[1],
                        "is_current": True,
                        "created_at": doc[7]
                    }
                )
        except Exception:
            pass

def downgrade() -> None:
    op.drop_index('ix_doc_versions_uploaded_by', table_name='document_versions')
    op.drop_index('ix_doc_versions_doc_current', table_name='document_versions')
    op.drop_index('ix_doc_versions_doc_ver', table_name='document_versions')
    op.drop_table('document_versions')
