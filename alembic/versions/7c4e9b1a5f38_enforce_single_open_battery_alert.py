"""enforce single open battery alert per device

Revision ID: 7c4e9b1a5f38
Revises: 1f6a3d8c2e94
Create Date: 2026-08-22 00:00:01.000000

Adds a PARTIAL UNIQUE INDEX on alerts(device_id), scoped to rows where
status='open' AND type IN ('low_battery', 'critical_battery').

WHY: discovered during Phase 1 real-PostgreSQL concurrency testing (see
phase report) that `_process_battery_thresholds()` in
app/routers/devices.py performs a check-then-insert (SELECT for an
existing open alert, then conditionally INSERT a new one) with NO
database-level constraint behind it. Two concurrent battery/heartbeat
requests for the same device, both crossing a threshold at the same
instant, could both see "no existing open alert" and both insert one --
producing two duplicate open alerts for the same device, which the spec
explicitly requires never happens.

This mirrors the exact same pattern already proven safe for
`uq_active_assignment_per_incident` (see migration 2b7f4e9a1d63): the
application-level check remains as a fast-path, but this index is the
genuine safety net that closes the race between two concurrent
transactions. The router now retries via a SAVEPOINT (db.begin_nested())
on a constraint violation and re-reads the winning row instead of
surfacing a 500 to the caller.

Scoped to only the two battery alert types (not device_id alone) so a
future, unrelated alert type introduced in a later phase (e.g.
device_offline) is never blocked by this constraint from also being open
at the same time for the same device.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '7c4e9b1a5f38'
down_revision: Union[str, None] = '1f6a3d8c2e94'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "status = 'open' AND type IN ('low_battery', 'critical_battery')"


def upgrade() -> None:
    op.create_index(
        "uq_open_battery_alert_per_device",
        "alerts",
        ["device_id"],
        unique=True,
        postgresql_where=_PREDICATE,
        sqlite_where=_PREDICATE,
    )


def downgrade() -> None:
    op.drop_index("uq_open_battery_alert_per_device", table_name="alerts")
