"""add camera_lens_direction to recording_sessions + gps/recorded_at to video_chunks

Revision ID: 3d5e8f1a9c72
Revises: 7a1b9c4e2f60
Create Date: 2026-09-16 00:00:00.000000

Body-camera GPS/timestamp watermark feature. recording_sessions gains
camera_lens_direction ("front"/"back", plain string like playable_status --
set once at /recordings/start, never changed mid-session). video_chunks
gains latitude/longitude/recorded_at, supplied per-chunk by the mobile app
from its existing cached LocationService fix (never a new GPS polling
loop) -- nullable, since GPS can be genuinely unavailable at capture time
and this must never be a fabricated value.

All four columns are nullable/defaulted; safe for existing rows (they
simply have no watermark metadata, matching their real historical state --
no chunk before this migration was ever burned with an overlay).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '3d5e8f1a9c72'
down_revision: Union[str, None] = '7a1b9c4e2f60'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("recording_sessions", sa.Column("camera_lens_direction", sa.String(), nullable=False, server_default="back"))
    op.add_column("video_chunks", sa.Column("latitude", sa.Float(), nullable=True))
    op.add_column("video_chunks", sa.Column("longitude", sa.Float(), nullable=True))
    op.add_column("video_chunks", sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("video_chunks", "recorded_at")
    op.drop_column("video_chunks", "longitude")
    op.drop_column("video_chunks", "latitude")
    op.drop_column("recording_sessions", "camera_lens_direction")
