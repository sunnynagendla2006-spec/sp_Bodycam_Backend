"""enforce single active assignment per incident

Revision ID: 2b7f4e9a1d63
Revises: 9f4b7d2a6c81
Create Date: 2026-08-22 00:00:00.000000

Adds a PARTIAL UNIQUE INDEX on incident_assignments(incident_id), scoped to
rows whose status is one of ('pending', 'accepted', 'en_route', 'arrived')
-- i.e. an "active" assignment. This is a genuine database-level
constraint, not just the application-level `if existing_active_assignment:`
pre-check already present in incidents.py::dispatch_incident. That
pre-check remains as a fast-path (avoids a wasted round trip in the common
case), but only a real constraint closes the race window where two
concurrent transactions could both pass that check before either commits.

`rejected` and `completed` are deliberately EXCLUDED from the predicate, so
an incident can still accumulate multiple historical (non-active)
assignment rows over time (e.g. one rejection followed by a later
successful reassignment) -- the constraint only ever blocks a SECOND
concurrently-active assignment on the same incident.

This is safe to apply to an existing database: if (and only if) a bug
already produced two simultaneously-active assignments for the same
incident before this migration, the CREATE UNIQUE INDEX statement itself
would fail on that pre-existing data. No such repair migration is included
here since there is no live database in this environment to inspect for
that condition -- see the phase report for how to check before running
this in a real deployment (`SELECT incident_id, count(*) FROM
incident_assignments WHERE status IN ('pending','accepted','en_route','arrived')
GROUP BY incident_id HAVING count(*) > 1;` should return zero rows first).
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '2b7f4e9a1d63'
down_revision: Union[str, None] = '9f4b7d2a6c81'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ACTIVE_STATUS_PREDICATE = "status IN ('pending', 'accepted', 'en_route', 'arrived')"


def upgrade() -> None:
    op.create_index(
        "uq_active_assignment_per_incident",
        "incident_assignments",
        ["incident_id"],
        unique=True,
        postgresql_where=_ACTIVE_STATUS_PREDICATE,
        sqlite_where=_ACTIVE_STATUS_PREDICATE,
    )


def downgrade() -> None:
    op.drop_index("uq_active_assignment_per_incident", table_name="incident_assignments")
