"""add remote commands and phase 3 alert types

Revision ID: 6b1f4a9d3e72
Revises: 3e8d6f2a1c95
Create Date: 2026-08-22 00:00:00.000000

Phase 3 of the body-camera system: RemoteCommand + extended Alert types
(device_offline, device_stale, recording_device_offline, command_failed,
command_timeout).

Uses `ALTER TYPE ... ADD VALUE IF NOT EXISTS` to extend the existing
`alerttype` enum rather than recreating it -- this is safe to run inside
Alembic's transactional DDL on PostgreSQL 12+ (the restriction against
using a freshly-added enum value in the SAME transaction that added it
does not apply here, since nothing in this migration queries using the
new values).

Adds a SECOND partial unique index (uq_open_alert_per_device_and_type),
scoped per (device_id, type) for the five new alert types specifically --
deliberately NOT touching or reusing uq_open_battery_alert_per_device
(Phase 1's battery pair intentionally shares one escalating row; the new
types are independent conditions that can coexist for the same device).

remote_commands.issued_by uses ON DELETE RESTRICT (matching the pattern
already used for Evidence.uploader_id) -- an issued command is an audit-
relevant record of who did what, so deleting that user should not be
allowed to silently orphan/destroy that attribution.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '6b1f4a9d3e72'
down_revision: Union[str, None] = '3e8d6f2a1c95'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_ALERT_VALUES = ["device_offline", "device_stale", "recording_device_offline", "command_failed", "command_timeout"]
_NEW_ALERT_PREDICATE = (
    "status = 'open' AND type IN ('device_offline', 'device_stale', 'recording_device_offline', 'command_failed', 'command_timeout')"
)


def upgrade() -> None:
    # PostgreSQL disallows using a freshly-added enum value within the
    # same transaction that added it (confirmed directly: without this,
    # `alembic upgrade head` failed with
    # `UnsafeNewEnumValueUsage: unsafe use of new value "device_offline"`
    # the moment the partial index below tried to reference these values).
    # autocommit_block() runs the ALTER TYPE statements in their own,
    # immediately-committed transaction, exactly as Alembic's own
    # documentation recommends for this scenario.
    with op.get_context().autocommit_block():
        for value in _NEW_ALERT_VALUES:
            op.execute(f"ALTER TYPE alerttype ADD VALUE IF NOT EXISTS '{value}'")

    op.create_index(
        "uq_open_alert_per_device_and_type",
        "alerts",
        ["device_id", "type"],
        unique=True,
        postgresql_where=_NEW_ALERT_PREDICATE,
        sqlite_where=_NEW_ALERT_PREDICATE,
    )

    op.create_table(
        'remote_commands',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('issued_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('command_type', postgresql.ENUM('start_recording', 'stop_recording', name='remotecommandtype'), nullable=False),
        sa.Column(
            'status',
            postgresql.ENUM('pending', 'sent', 'acknowledged', 'executed', 'failed', 'timeout', 'cancelled', name='remotecommandstatus'),
            nullable=False,
            server_default='pending',
        ),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failure_reason', sa.String(), nullable=True),
        sa.Column('result_payload', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['issued_by'], ['users.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_remote_commands_device_id', 'remote_commands', ['device_id'], unique=False)
    op.create_index('ix_remote_commands_status', 'remote_commands', ['status'], unique=False)
    op.create_index('ix_remote_commands_created_at', 'remote_commands', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_remote_commands_created_at', table_name='remote_commands')
    op.drop_index('ix_remote_commands_status', table_name='remote_commands')
    op.drop_index('ix_remote_commands_device_id', table_name='remote_commands')
    op.drop_table('remote_commands')

    bind = op.get_bind()
    postgresql.ENUM(name='remotecommandstatus').drop(bind, checkfirst=True)
    postgresql.ENUM(name='remotecommandtype').drop(bind, checkfirst=True)

    op.drop_index('uq_open_alert_per_device_and_type', table_name='alerts')

    # NOTE: PostgreSQL does not support removing a value from an existing
    # ENUM type (no `ALTER TYPE ... DROP VALUE`). The 5 alert type values
    # added in upgrade() are NOT removed here -- this is a genuine,
    # documented limitation of Postgres enums, not an oversight. Any
    # `alerts` rows already using these values would need to be migrated
    # to a different type first if a true rollback of the enum itself were
    # ever required (out of scope for a normal downgrade).
