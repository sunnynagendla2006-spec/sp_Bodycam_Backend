from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional
import uuid

from .. import database, models, schemas
from ..auth.deps import require_role

router = APIRouter(prefix="/audit-logs", tags=["Audit"])

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


@router.get("/", response_model=list[schemas.AuditLogResponse])
def list_audit_logs(
    incident_id: Optional[uuid.UUID] = None,
    user_id: Optional[uuid.UUID] = None,
    action: Optional[str] = None,
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """
    admin/control_room: full audit trail, unchanged from Phase 5.

    station (Phase 6): only records that can be SAFELY associated with
    their own station, via either:
      - AuditLog.incident_id -> Incident.station_id == their station, or
      - AuditLog.evidence_id -> Evidence.incident_id -> Incident.station_id == their station

    Records with NEITHER incident_id NOR evidence_id set (logins, settings
    changes, police-station CRUD, etc.) have no safe way to associate them
    with a station and are EXCLUDED entirely for station callers -- never
    guessed-included. A station user with no station_id set gets an empty
    list. This is deliberately conservative: a partial-but-plausible-looking
    audit trail would be worse than an honestly incomplete one.

    `limit` is capped at 200 to prevent an unbounded dump of the entire
    audit history in one call.
    """
    query = db.query(models.AuditLog)

    if current_user.role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_incident_ids = db.query(models.Incident.id).filter(models.Incident.station_id == current_user.station_id)
        station_evidence_ids = (
            db.query(models.Evidence.id)
            .join(models.Incident, models.Evidence.incident_id == models.Incident.id)
            .filter(models.Incident.station_id == current_user.station_id)
        )
        query = query.filter(
            models.AuditLog.incident_id.in_(station_incident_ids)
            | models.AuditLog.evidence_id.in_(station_evidence_ids)
        )

    if incident_id is not None:
        query = query.filter(models.AuditLog.incident_id == incident_id)
    if user_id is not None:
        query = query.filter(models.AuditLog.user_id == user_id)
    if action is not None:
        query = query.filter(models.AuditLog.action == action)

    entries = (
        query.order_by(models.AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [schemas.AuditLogResponse.from_audit_log(e) for e in entries]
