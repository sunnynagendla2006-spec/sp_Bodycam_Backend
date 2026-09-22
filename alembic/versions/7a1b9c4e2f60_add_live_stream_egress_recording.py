"""add live_stream_sessions egress_id/recording_session_id + live_stream trigger type

Revision ID: 7a1b9c4e2f60
Revises: 9c2f4e8a1b3d
Create Date: 2026-09-16 00:00:00.000000

Requirement 2: a live stream's room can now be recorded server-side via
LiveKit Egress (see app/routers/live_stream.py). The result is stored as an
ordinary recording_sessions row (trigger_type='live_stream') so it reuses
the exact same playable-recording pipeline Requirement 1 already built --
no second video table, no second player. This migration only adds:
  - the new 'live_stream' value to the existing recordingtriggertype enum
  - egress_id / recording_session_id tracking columns on
    live_stream_sessions, both nullable (a session that never got recorded,
    e.g. because the egress infrastructure was unavailable at start time,
    is unaffected -- recording is always best-effort, never a requirement
    for live viewing to work).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '7a1b9c4e2f60'
down_revision: Union[str, None] = '9c2f4e8a1b3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Postgres 12+ allows ADD VALUE inside a transaction as long as the new
    # value isn't used in the same transaction -- it isn't here.
    op.execute("ALTER TYPE recordingtriggertype ADD VALUE IF NOT EXISTS 'live_stream'")
    op.add_column("live_stream_sessions", sa.Column("egress_id", sa.String(), nullable=True))
    op.add_column(
        "live_stream_sessions",
        sa.Column("recording_session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("recording_sessions.id", ondelete="SET NULL"), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("live_stream_sessions", "recording_session_id")
    op.drop_column("live_stream_sessions", "egress_id")
    # Postgres has no ALTER TYPE ... DROP VALUE -- 'live_stream' stays
    # defined on the enum type but simply goes unused again.
