"""harden evidence and assignments

Revision ID: 7a1c9e3f5b2d
Revises: 2f44e1be4993
Create Date: 2026-08-21 00:00:00.000000

Adds, without touching any existing column or destroying data:
  - evidence: uploader_id, uploader_role, mime_type, file_size,
    original_filename, storage_key, upload_status, metadata (JSON),
    plus supporting indexes.
  - incident_assignments: status, responded_at, closed_at.
  - constable_locations: accuracy.

Two new Postgres enum types are created (uploadstatus, assignmentstatus).
The existing `userrole` enum type is reused (create_type=False) for
evidence.uploader_role -- it is NOT recreated or altered.

This migration is purely additive/nullable-safe for existing rows:
  - `evidence.upload_status` gets a server_default of 'uploaded' so
    existing evidence rows (if any) are backfilled automatically and the
    column can be NOT NULL from the start.
  - `incident_assignments.status` gets a server_default of 'pending' for
    the same reason.
  - All other new columns are nullable, since there is no reliable way to
    backfill (e.g.) a SHA-256-verified file_size or a sanitized
    original_filename for evidence that predates this migration without
    re-reading the original upload -- they simply start NULL for old rows
    and are populated by the app for every new upload from this point on.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '7a1c9e3f5b2d'
down_revision: Union[str, None] = '2f44e1be4993'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Enum types newly introduced by this migration (do NOT include `userrole`
# here -- that type already exists from the initial migration and must be
# referenced with create_type=False, never recreated).
_upload_status_enum = postgresql.ENUM(
    "uploading", "uploaded", "verified", "rejected", "archived",
    name="uploadstatus",
)
_assignment_status_enum = postgresql.ENUM(
    "pending", "accepted", "rejected", "en_route", "arrived", "completed",
    name="assignmentstatus",
)


def upgrade() -> None:
    bind = op.get_bind()

    # Create the two new enum types explicitly so both add_column calls
    # below can reference them with create_type=False (avoids Alembic
    # trying to auto-create the type twice under Postgres).
    _upload_status_enum.create(bind, checkfirst=True)
    _assignment_status_enum.create(bind, checkfirst=True)

    # --- constable_locations: add accuracy --------------------------------
    op.add_column(
        "constable_locations",
        sa.Column("accuracy", sa.Float(), nullable=True),
    )

    # --- incident_assignments: add lifecycle fields -----------------------
    op.add_column(
        "incident_assignments",
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending", "accepted", "rejected", "en_route", "arrived", "completed",
                name="assignmentstatus", create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "incident_assignments",
        sa.Column("responded_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "incident_assignments",
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- evidence: uploader identity, file metadata, storage key, status --
    op.add_column(
        "evidence",
        sa.Column("uploader_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "evidence",
        sa.Column(
            "uploader_role",
            postgresql.ENUM(
                "admin", "control_room", "station", "constable", "citizen",
                name="userrole", create_type=False,
            ),
            nullable=True,
        ),
    )
    op.add_column("evidence", sa.Column("mime_type", sa.String(), nullable=True))
    op.add_column("evidence", sa.Column("file_size", sa.BigInteger(), nullable=True))
    op.add_column("evidence", sa.Column("original_filename", sa.String(), nullable=True))
    op.add_column("evidence", sa.Column("storage_key", sa.String(), nullable=True))
    op.add_column(
        "evidence",
        sa.Column(
            "upload_status",
            postgresql.ENUM(
                "uploading", "uploaded", "verified", "rejected", "archived",
                name="uploadstatus", create_type=False,
            ),
            nullable=False,
            server_default="uploaded",
        ),
    )
    op.add_column("evidence", sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True))

    op.create_foreign_key(
        "fk_evidence_uploader_id_users",
        "evidence", "users",
        ["uploader_id"], ["id"],
        ondelete="RESTRICT",
    )

    # NOTE: evidence.incident_id and evidence.constable_id are intentionally
    # NOT altered here. Their existing foreign keys (created in the initial
    # migration with no explicit ON DELETE clause) already default to
    # Postgres's NO ACTION behavior, which blocks deleting an incident/
    # constable while evidence rows still reference it -- functionally the
    # same protection RESTRICT would add. Renaming/recreating those
    # constraints would require knowing their exact auto-generated
    # constraint names on the live database, which cannot be verified from
    # this sandbox without a running Postgres instance; changing them
    # blind risks a migration that fails against the real dev DB. Left
    # alone per "do not redesign unrelated relationships unless necessary."

    # --- indexes -----------------------------------------------------------
    op.create_index("ix_evidence_incident_id", "evidence", ["incident_id"], unique=False)
    op.create_index("ix_evidence_uploader_id", "evidence", ["uploader_id"], unique=False)
    op.create_index("ix_evidence_timestamp", "evidence", ["timestamp"], unique=False)
    op.create_index("ix_evidence_upload_status", "evidence", ["upload_status"], unique=False)
    op.create_index(
        "idx_evidence_incident_timestamp", "evidence", ["incident_id", "timestamp"], unique=False
    )


def downgrade() -> None:
    bind = op.get_bind()

    op.drop_index("idx_evidence_incident_timestamp", table_name="evidence")
    op.drop_index("ix_evidence_upload_status", table_name="evidence")
    op.drop_index("ix_evidence_timestamp", table_name="evidence")
    op.drop_index("ix_evidence_uploader_id", table_name="evidence")
    op.drop_index("ix_evidence_incident_id", table_name="evidence")

    op.drop_constraint("fk_evidence_uploader_id_users", "evidence", type_="foreignkey")

    op.drop_column("evidence", "metadata")
    op.drop_column("evidence", "upload_status")
    op.drop_column("evidence", "storage_key")
    op.drop_column("evidence", "original_filename")
    op.drop_column("evidence", "file_size")
    op.drop_column("evidence", "mime_type")
    op.drop_column("evidence", "uploader_role")
    op.drop_column("evidence", "uploader_id")

    op.drop_column("incident_assignments", "closed_at")
    op.drop_column("incident_assignments", "responded_at")
    op.drop_column("incident_assignments", "status")

    op.drop_column("constable_locations", "accuracy")

    # Drop only the enum types THIS migration created. `userrole` is reused
    # from the initial migration and must never be dropped here.
    _assignment_status_enum.drop(bind, checkfirst=True)
    _upload_status_enum.drop(bind, checkfirst=True)
