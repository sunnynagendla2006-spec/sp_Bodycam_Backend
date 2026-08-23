"""add evidence verification fields

Revision ID: 6c1a9f3e7b52
Revises: 2b7f4e9a1d63
Create Date: 2026-08-22 00:00:00.000000

Adds verification-lifecycle attribution fields to `evidence`:
  - verified_by, verified_at
  - rejected_by, rejected_at, rejection_reason
  - archived_by, archived_at

All nullable FKs to users.id with ON DELETE SET NULL (not RESTRICT, unlike
uploader_id/constable_id which protect the actual evidentiary chain of
custody) -- these are attribution/audit details, so deleting a user who
once verified/rejected/archived some evidence should not be blocked by it.

Purely additive; no data migration needed since no evidence row has ever
been transitioned out of `uploaded` before this phase (no such endpoint
existed until now).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '6c1a9f3e7b52'
down_revision: Union[str, None] = '2b7f4e9a1d63'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("evidence", sa.Column("verified_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("evidence", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("evidence", sa.Column("rejected_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("evidence", sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("evidence", sa.Column("rejection_reason", sa.String(), nullable=True))
    op.add_column("evidence", sa.Column("archived_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("evidence", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))

    op.create_foreign_key(
        "fk_evidence_verified_by_users", "evidence", "users", ["verified_by"], ["id"], ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_evidence_rejected_by_users", "evidence", "users", ["rejected_by"], ["id"], ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_evidence_archived_by_users", "evidence", "users", ["archived_by"], ["id"], ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_evidence_archived_by_users", "evidence", type_="foreignkey")
    op.drop_constraint("fk_evidence_rejected_by_users", "evidence", type_="foreignkey")
    op.drop_constraint("fk_evidence_verified_by_users", "evidence", type_="foreignkey")

    op.drop_column("evidence", "archived_at")
    op.drop_column("evidence", "archived_by")
    op.drop_column("evidence", "rejection_reason")
    op.drop_column("evidence", "rejected_at")
    op.drop_column("evidence", "rejected_by")
    op.drop_column("evidence", "verified_at")
    op.drop_column("evidence", "verified_by")
