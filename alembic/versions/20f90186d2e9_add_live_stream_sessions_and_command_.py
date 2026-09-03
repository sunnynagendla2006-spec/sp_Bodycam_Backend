"""add live stream sessions and command types

Revision ID: 20f90186d2e9
Revises: 6b1f4a9d3e72
Create Date: 2026-09-03 00:00:00.000000

Adds live camera streaming (ephemeral only, never recorded/stored): two new
`remotecommandtype` enum values (start_live_stream/stop_live_stream), reusing
the existing RemoteCommand lifecycle unchanged, plus a new
`live_stream_sessions` table holding pure session metadata (who is live, on
which device, since when) -- the video itself never touches this database,
it flows through an external LiveKit SFU.

Uses the same `autocommit_block()` + `ALTER TYPE ... ADD VALUE IF NOT
EXISTS` pattern as 6b1f4a9d3e72 for the enum extension, since a new enum
value cannot be referenced within the same transaction that added it.

device_id/constable_id use ON DELETE RESTRICT (matching RecordingSession)
-- a live-stream session is an audit-relevant record of who was live and on
which device, so deleting either should not silently orphan/destroy that
attribution. triggering_command_id uses ON DELETE SET NULL: the command's
own lifecycle is independent of this session's lifetime.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '20f90186d2e9'
down_revision: Union[str, None] = '6b1f4a9d3e72'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_COMMAND_VALUES = ["start_live_stream", "stop_live_stream"]


def upgrade() -> None:
    with op.get_context().autocommit_block():
        for value in _NEW_COMMAND_VALUES:
            op.execute(f"ALTER TYPE remotecommandtype ADD VALUE IF NOT EXISTS '{value}'")

    op.create_table(
        'live_stream_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('constable_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('room_name', sa.String(), nullable=False),
        sa.Column('status', postgresql.ENUM('live', 'ended', name='livestreamstatus'), nullable=False, server_default='live'),
        sa.Column('started_by', postgresql.ENUM('self', 'remote_command', name='livestreamstartedby'), nullable=False),
        sa.Column('triggering_command_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['constable_id'], ['constables.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['triggering_command_id'], ['remote_commands.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_live_stream_sessions_device_id', 'live_stream_sessions', ['device_id'], unique=False)
    op.create_index('ix_live_stream_sessions_constable_id', 'live_stream_sessions', ['constable_id'], unique=False)
    op.create_index('ix_live_stream_sessions_status', 'live_stream_sessions', ['status'], unique=False)
    op.create_index('ix_live_stream_sessions_started_at', 'live_stream_sessions', ['started_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_live_stream_sessions_started_at', table_name='live_stream_sessions')
    op.drop_index('ix_live_stream_sessions_status', table_name='live_stream_sessions')
    op.drop_index('ix_live_stream_sessions_constable_id', table_name='live_stream_sessions')
    op.drop_index('ix_live_stream_sessions_device_id', table_name='live_stream_sessions')
    op.drop_table('live_stream_sessions')

    bind = op.get_bind()
    postgresql.ENUM(name='livestreamstartedby').drop(bind, checkfirst=True)
    postgresql.ENUM(name='livestreamstatus').drop(bind, checkfirst=True)

    # NOTE: PostgreSQL cannot remove a value from an existing ENUM type --
    # the two remotecommandtype values added in upgrade() are NOT removed
    # here, same documented limitation as 6b1f4a9d3e72's downgrade.
