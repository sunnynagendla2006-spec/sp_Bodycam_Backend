"""add recording_sessions playable_status/playable_storage_key

Revision ID: 9c2f4e8a1b3d
Revises: 20f90186d2e9
Create Date: 2026-09-16 00:00:00.000000

Additive columns supporting server-side playback: a completed recording
with no missing chunks gets its chunks concatenated (stream-copied, never
byte-sliced) into one playable file via ffmpeg, tracked here. The existing
chunk files/rows are untouched either way -- this is purely a new,
best-effort derived artifact, not a replacement for anything.

Nullable/defaulted; safe for any existing recording_sessions rows (they
simply start at "not_ready", exactly matching their real current state --
no playable file has ever been built for them).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '9c2f4e8a1b3d'
down_revision: Union[str, None] = '20f90186d2e9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("recording_sessions", sa.Column("playable_status", sa.String(), nullable=False, server_default="not_ready"))
    op.add_column("recording_sessions", sa.Column("playable_storage_key", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("recording_sessions", "playable_storage_key")
    op.drop_column("recording_sessions", "playable_status")
