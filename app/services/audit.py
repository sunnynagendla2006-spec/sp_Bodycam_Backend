"""
Reusable audit-logging helper.

Transaction-safety design: for call sites where the audit row must persist
atomically together with the business-state change it describes, the
caller opens `database.transaction()` and passes the resulting session
through to both writes (see that helper's docstring). Call sites with no
other business-state change to piggyback on (e.g. a failed login attempt)
just call `await log_action(...)` on its own -- a single document insert
is already atomic by itself.
"""
import uuid
from typing import Optional

from .. import models


async def log_action(
    *,
    user_id: Optional[uuid.UUID],
    action: str,
    details: Optional[dict] = None,
    incident_id: Optional[uuid.UUID] = None,
    evidence_id: Optional[uuid.UUID] = None,
    ip_address: Optional[str] = None,
    session=None,
) -> models.AuditLog:
    """
    Insert an AuditLog document, optionally as part of an in-flight Motor
    transaction `session` (see database.transaction()).

    `user_id`, `action`, `incident_id`, `evidence_id`, `ip_address` must
    always be values the SERVER derived (from the authenticated user, from
    a loaded DB row, from the request's actual connecting IP) -- never
    values blindly copied from client-supplied request fields.

    `details` is a plain dict of already-safe, already-vetted values (e.g.
    old_status/new_status/reason/badge numbers) -- NEVER put a password,
    JWT, raw file bytes, or other secret in here. Stored as a native
    embedded document (no more manual JSON serialization).
    """
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        incident_id=incident_id,
        evidence_id=evidence_id,
        ip_address=ip_address,
    )
    await entry.insert(session=session)
    return entry
