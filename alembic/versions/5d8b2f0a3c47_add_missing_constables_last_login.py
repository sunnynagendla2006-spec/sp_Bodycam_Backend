"""add missing constables last_login column

Revision ID: 5d8b2f0a3c47
Revises: 3a9c5e1f8b06
Create Date: 2026-08-22 00:00:02.000000

A third schema-drift gap discovered during the production-hardening audit
phase, this time via a comprehensive column-by-column comparison of every
table's real (migration-built) schema against `Base.metadata` rather than
waiting for another runtime error -- this is the same category of bug as
`incidents.display_id` (migration 8e2f6a4c9d17) and `evidence.comment`
(migration 3a9c5e1f8b06): `Constable.last_login` has existed in
`app/models.py` and been read by `app/routers/constables.py::list_constables`
(`GET /constables/`) since early on, but was never actually added by any
migration -- meaning that endpoint would have thrown an UndefinedColumn
error against any database that went through the real Alembic chain
rather than `Base.metadata.create_all()`.

Nullable, purely additive; safe for any existing constable rows.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '5d8b2f0a3c47'
down_revision: Union[str, None] = '3a9c5e1f8b06'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("constables", sa.Column("last_login", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("constables", "last_login")
