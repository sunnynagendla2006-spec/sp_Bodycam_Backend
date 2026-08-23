"""harden audit log

Revision ID: 9f4b7d2a6c81
Revises: 3d6e8a2c4f19
Create Date: 2026-08-22 00:00:00.000000

Extends the existing `audit_logs` table (unchanged since the initial
migration) with:
  - incident_id  (nullable FK -> incidents.id, ON DELETE SET NULL)
  - evidence_id  (nullable FK -> evidence.id, ON DELETE SET NULL)
  - ip_address   (nullable String)
plus indexes on user_id, action, incident_id, evidence_id, and timestamp,
to support the new GET /audit-logs filters (?incident_id=, ?user_id=,
?action=, pagination ordered by timestamp).

`details` is intentionally left as-is (String) -- structured audit details
are JSON-serialized into that existing column by app/services/audit.py
rather than requiring a column type change.

Purely additive/nullable; no data migration needed (there is no existing
audit data to backfill incident_id/evidence_id/ip_address for -- those
simply start NULL on any pre-existing rows).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '9f4b7d2a6c81'
down_revision: Union[str, None] = '3d6e8a2c4f19'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("audit_logs", sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("audit_logs", sa.Column("ip_address", sa.String(), nullable=True))

    op.create_foreign_key(
        "fk_audit_logs_incident_id_incidents",
        "audit_logs", "incidents",
        ["incident_id"], ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_audit_logs_evidence_id_evidence",
        "audit_logs", "evidence",
        ["evidence_id"], ["id"],
        ondelete="SET NULL",
    )

    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"], unique=False)
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"], unique=False)
    op.create_index("ix_audit_logs_incident_id", "audit_logs", ["incident_id"], unique=False)
    op.create_index("ix_audit_logs_evidence_id", "audit_logs", ["evidence_id"], unique=False)
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_index("ix_audit_logs_evidence_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_incident_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")

    op.drop_constraint("fk_audit_logs_evidence_id_evidence", "audit_logs", type_="foreignkey")
    op.drop_constraint("fk_audit_logs_incident_id_incidents", "audit_logs", type_="foreignkey")

    op.drop_column("audit_logs", "ip_address")
    op.drop_column("audit_logs", "evidence_id")
    op.drop_column("audit_logs", "incident_id")
