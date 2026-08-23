"""add device battery alert tables

Revision ID: 1f6a3d8c2e94
Revises: 5d8b2f0a3c47
Create Date: 2026-08-22 00:00:00.000000

Phase 1 of the body-camera system: Device registration/heartbeat, battery
history, and the minimal Alert table needed for battery-threshold
notifications.

Combined into a single migration (rather than three separate ones)
because all three tables are one coherent, atomically-deployed feature --
`battery_readings` and `alerts` both depend on `devices` existing, and
there is no meaningful intermediate state where you'd want `devices`
deployed without the other two (unlike, say, the evidence-verification
fields, which were genuinely separable additions). This mirrors how
`7a1c9e3f5b2d_harden_evidence_and_assignments.py` bundled multiple related
additions for one phase.

Purely additive: no existing table/column is touched. `Constable.battery_level`
and `Constable.last_login` are untouched and remain for backward
compatibility -- nothing in this migration requires them to be removed or
migrated.

Downgrade drops the three new enum types (devicestatus, alerttype,
alertseverity, alertstatus) explicitly, AFTER dropping the tables that use
them -- see 2f44e1be4993's own downgrade() for why this matters (a table
DROP does not automatically drop the ENUM TYPE that was implicitly created
alongside it; omitting this caused a real, previously-discovered bug where
downgrade-then-reupgrade failed with "type already exists").
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '1f6a3d8c2e94'
down_revision: Union[str, None] = '5d8b2f0a3c47'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'devices',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('constable_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('device_identifier', sa.String(), nullable=False),
        sa.Column('platform', sa.String(), nullable=True),
        sa.Column('app_version', sa.String(), nullable=True),
        sa.Column('device_model', sa.String(), nullable=True),
        sa.Column(
            'status',
            postgresql.ENUM('online', 'offline', 'stale', 'recording', name='devicestatus'),
            nullable=False,
            server_default='offline',
        ),
        sa.Column('last_heartbeat_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['constable_id'], ['constables.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('device_identifier'),
    )
    op.create_index('ix_devices_constable_id', 'devices', ['constable_id'], unique=False)
    op.create_index('ix_devices_device_identifier', 'devices', ['device_identifier'], unique=True)

    op.create_table(
        'battery_readings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('battery_percent', sa.Integer(), nullable=False),
        sa.Column('is_charging', sa.Boolean(), nullable=True),
        sa.Column('recorded_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint('battery_percent >= 0 AND battery_percent <= 100', name='ck_battery_percent_range'),
    )
    op.create_index('ix_battery_readings_device_id', 'battery_readings', ['device_id'], unique=False)
    op.create_index('ix_battery_readings_recorded_at', 'battery_readings', ['recorded_at'], unique=False)
    op.create_index('idx_battery_readings_device_recorded', 'battery_readings', ['device_id', 'recorded_at'], unique=False)

    op.create_table(
        'alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('type', postgresql.ENUM('low_battery', 'critical_battery', name='alerttype'), nullable=False),
        sa.Column('severity', postgresql.ENUM('warning', 'critical', name='alertseverity'), nullable=False),
        sa.Column('constable_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('message', sa.String(), nullable=True),
        sa.Column(
            'status',
            postgresql.ENUM('open', 'acknowledged', 'resolved', name='alertstatus'),
            nullable=False,
            server_default='open',
        ),
        sa.Column('acknowledged_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['constable_id'], ['constables.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['acknowledged_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_alerts_device_id', 'alerts', ['device_id'], unique=False)
    op.create_index('ix_alerts_status', 'alerts', ['status'], unique=False)
    op.create_index('ix_alerts_created_at', 'alerts', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_alerts_created_at', table_name='alerts')
    op.drop_index('ix_alerts_status', table_name='alerts')
    op.drop_index('ix_alerts_device_id', table_name='alerts')
    op.drop_table('alerts')

    op.drop_index('idx_battery_readings_device_recorded', table_name='battery_readings')
    op.drop_index('ix_battery_readings_recorded_at', table_name='battery_readings')
    op.drop_index('ix_battery_readings_device_id', table_name='battery_readings')
    op.drop_table('battery_readings')

    op.drop_index('ix_devices_device_identifier', table_name='devices')
    op.drop_index('ix_devices_constable_id', table_name='devices')
    op.drop_table('devices')

    bind = op.get_bind()
    postgresql.ENUM(name='alertstatus').drop(bind, checkfirst=True)
    postgresql.ENUM(name='alertseverity').drop(bind, checkfirst=True)
    postgresql.ENUM(name='alerttype').drop(bind, checkfirst=True)
    postgresql.ENUM(name='devicestatus').drop(bind, checkfirst=True)
