"""add user station association

Revision ID: 3d6e8a2c4f19
Revises: 7a1c9e3f5b2d
Create Date: 2026-08-22 00:00:00.000000

Adds `users.station_id` (nullable FK -> police_stations.id, ON DELETE SET
NULL) so an authenticated `station`-role user can be reliably mapped to the
PoliceStation they represent, for authorization scoping (see
routers/incidents.py, routers/constables.py, routers/media.py).

This resolves the schema gap flagged repeatedly in the Phase 2/3 reports:
"station"-role users could authenticate but the backend had no way to know
which station they belonged to, so every station-scoped view fell back to
an empty result (safe but useless) rather than the correct subset.

`Incident.station_id` already existed from the initial migration and is
reused as-is for "responsible station" -- no new incident-side column is
introduced here (see models.py comment on Incident.station_id).

Purely additive/nullable; no data migration needed since there is no
reliable prior source to backfill an existing station user's station_id
from (this must be set explicitly, e.g. by an admin, going forward).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '3d6e8a2c4f19'
down_revision: Union[str, None] = '7a1c9e3f5b2d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("station_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_users_station_id", "users", ["station_id"], unique=False)
    op.create_foreign_key(
        "fk_users_station_id_police_stations",
        "users", "police_stations",
        ["station_id"], ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_users_station_id_police_stations", "users", type_="foreignkey")
    op.drop_index("ix_users_station_id", table_name="users")
    op.drop_column("users", "station_id")
