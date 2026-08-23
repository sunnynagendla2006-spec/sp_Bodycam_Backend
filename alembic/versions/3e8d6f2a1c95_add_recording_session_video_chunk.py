"""add recording session and video chunk tables

Revision ID: 3e8d6f2a1c95
Revises: 7c4e9b1a5f38
Create Date: 2026-08-22 00:00:00.000000

Phase 2 of the body-camera system: RecordingSession + VideoChunk.

recording_sessions.incident_id is nullable and ON DELETE SET NULL --
RecordingSession deliberately never requires an Incident to exist (per the
approved Phase 2 specification: a constable must be able to start an
emergency recording without any Incident existing first).

video_chunks has a MANDATORY composite unique index on
(recording_session_id, chunk_number) -- this is the genuine database-level
constraint protecting against concurrent duplicate chunk uploads (see the
application-level SAVEPOINT-retry logic in
app/routers/recordings.py::upload_chunk, which is the fast-path/safety-net
pattern already proven for uq_open_battery_alert_per_device in Phase 1).

Purely additive; no existing table/column is touched.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '3e8d6f2a1c95'
down_revision: Union[str, None] = '7c4e9b1a5f38'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'recording_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('constable_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            'trigger_type',
            postgresql.ENUM('emergency_button', 'manual', 'remote', name='recordingtriggertype'),
            nullable=False,
        ),
        sa.Column(
            'status',
            postgresql.ENUM('recording', 'completed', 'cancelled', 'failed', name='recordingstatus'),
            nullable=False,
            server_default='recording',
        ),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('incident_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['constable_id'], ['constables.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_recording_sessions_constable_id', 'recording_sessions', ['constable_id'], unique=False)
    op.create_index('ix_recording_sessions_device_id', 'recording_sessions', ['device_id'], unique=False)
    op.create_index('ix_recording_sessions_status', 'recording_sessions', ['status'], unique=False)
    op.create_index('ix_recording_sessions_created_at', 'recording_sessions', ['created_at'], unique=False)

    op.create_table(
        'video_chunks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('recording_session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('chunk_number', sa.Integer(), nullable=False),
        sa.Column('storage_key', sa.String(), nullable=False),
        sa.Column('file_size', sa.BigInteger(), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('file_hash', sa.String(), nullable=True),
        sa.Column('mime_type', sa.String(), nullable=True),
        sa.Column('is_last_chunk', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column(
            'upload_status',
            postgresql.ENUM('uploaded', name='chunkuploadstatus'),
            nullable=False,
            server_default='uploaded',
        ),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['recording_session_id'], ['recording_sessions.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'uq_chunk_number_per_recording',
        'video_chunks',
        ['recording_session_id', 'chunk_number'],
        unique=True,
    )
    op.create_index('ix_video_chunks_created_at', 'video_chunks', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_video_chunks_created_at', table_name='video_chunks')
    op.drop_index('uq_chunk_number_per_recording', table_name='video_chunks')
    op.drop_table('video_chunks')

    op.drop_index('ix_recording_sessions_created_at', table_name='recording_sessions')
    op.drop_index('ix_recording_sessions_status', table_name='recording_sessions')
    op.drop_index('ix_recording_sessions_device_id', table_name='recording_sessions')
    op.drop_index('ix_recording_sessions_constable_id', table_name='recording_sessions')
    op.drop_table('recording_sessions')

    bind = op.get_bind()
    postgresql.ENUM(name='chunkuploadstatus').drop(bind, checkfirst=True)
    postgresql.ENUM(name='recordingstatus').drop(bind, checkfirst=True)
    postgresql.ENUM(name='recordingtriggertype').drop(bind, checkfirst=True)
