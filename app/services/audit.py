"""
Reusable audit-logging helper.

Transaction-safety design (see Phase 5 report Part 5 for the full
rationale): `log_action()` only ADDS the AuditLog row to the given
SQLAlchemy session -- it deliberately does NOT call `db.commit()` itself.
Every call site adds the audit entry BEFORE the business operation's own
`db.commit()`, so the audit row and the business change it describes are
part of the exact same database transaction: either both persist together,
or (if something fails first) neither does. This avoids two failure modes
we explicitly want to avoid:
  - wrapping the audit write in its own blanket try/except that silently
    swallows a failed audit insert (Part 5 says not to do this for
    security-sensitive actions)
  - a separate, later commit for the audit row that could succeed even
    though the business operation it describes was rolled back, producing
    a misleading "this happened" record for something that didn't.

The one exception is standalone actions with no other business-state
change to piggyback on (e.g. a FAILED login attempt) -- those call
`log_action(...)` followed by their own dedicated `db.commit()`.
"""
import json
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from .. import models


def log_action(
    db: Session,
    user_id: Optional[uuid.UUID],
    action: str,
    details: Optional[dict] = None,
    incident_id: Optional[uuid.UUID] = None,
    evidence_id: Optional[uuid.UUID] = None,
    ip_address: Optional[str] = None,
) -> models.AuditLog:
    """
    Stage an AuditLog row for insertion (added to the session, not committed).

    `user_id`, `action`, `incident_id`, `evidence_id`, `ip_address` must
    always be values the SERVER derived (from the authenticated user, from
    a loaded DB row, from the request's actual connecting IP) -- never
    values blindly copied from client-supplied request fields.

    `details` is a plain dict of already-safe, already-vetted values (e.g.
    old_status/new_status/reason/badge numbers) -- NEVER put a password,
    JWT, raw file bytes, or other secret in here. Serialized to JSON text
    into the existing `details` String column.
    """
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        details=json.dumps(details, default=str) if details else None,
        incident_id=incident_id,
        evidence_id=evidence_id,
        ip_address=ip_address,
    )
    db.add(entry)
    return entry
