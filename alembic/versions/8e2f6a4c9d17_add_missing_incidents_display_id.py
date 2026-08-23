"""add missing incidents display_id column

Revision ID: 8e2f6a4c9d17
Revises: 6c1a9f3e7b52
Create Date: 2026-08-22 00:00:00.000000

Discovered via this phase's mandatory "fresh database upgrade + compare
against Base.metadata" verification (see the migration-history repair phase
report): `Incident.display_id` has existed in `app/models.py` since the
initial schema (used throughout `app/routers/incidents.py` to generate and
store human-readable incident codes like "INC-20260822-153000-20-78"), but
no migration ever actually added this column to the database. Every prior
phase's testing used `Base.metadata.create_all()` (which reads the CURRENT
model definitions directly) rather than the real Alembic chain, which
masked this gap until `alembic upgrade head` was actually run against a
genuinely fresh database and `create_incident` failed with
`UndefinedColumn: column "display_id" of relation "incidents" does not exist`.

This is a straightforward additive column -- nullable, so safe for any
existing rows (which would simply have `display_id IS NULL` until the
application sets it going forward), matching the column's declared
nullability in `models.py`.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '8e2f6a4c9d17'
down_revision: Union[str, None] = '6c1a9f3e7b52'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("display_id", sa.String(), nullable=True))
    op.create_index(op.f("ix_incidents_display_id"), "incidents", ["display_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_incidents_display_id"), table_name="incidents")
    op.drop_column("incidents", "display_id")
