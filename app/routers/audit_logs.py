from fastapi import APIRouter, Depends, Query
from typing import Optional
import uuid

from beanie.operators import In, Or

from .. import models, schemas
from ..auth.deps import require_role

router = APIRouter(prefix="/audit-logs", tags=["Audit"])

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


@router.get("/", response_model=list[schemas.AuditLogResponse])
async def list_audit_logs(
    incident_id: Optional[uuid.UUID] = None,
    user_id: Optional[uuid.UUID] = None,
    action: Optional[str] = None,
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """
    admin/control_room: full audit trail.

    station: only records that can be SAFELY associated with their own
    station, via either:
      - AuditLog.incident_id -> Incident.station_id == their station, or
      - AuditLog.evidence_id -> Evidence.incident_id -> Incident.station_id == their station

    Records with NEITHER incident_id NOR evidence_id set (logins, settings
    changes, police-station CRUD, etc.) have no safe way to associate them
    with a station and are EXCLUDED entirely for station callers -- never
    guessed-included. A station user with no station_id set gets an empty
    list.

    `limit` is capped at 200 to prevent an unbounded dump of the entire
    audit history in one call.
    """
    query = models.AuditLog.find()

    if current_user.role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_incident_ids = [
            inc.id for inc in await models.Incident.find(models.Incident.station_id == current_user.station_id).to_list()
        ]
        station_evidence_ids = [
            e.id for e in await models.Evidence.find(In(models.Evidence.incident_id, station_incident_ids)).to_list()
        ]
        query = query.find(
            Or(
                In(models.AuditLog.incident_id, station_incident_ids),
                In(models.AuditLog.evidence_id, station_evidence_ids),
            )
        )

    if incident_id is not None:
        query = query.find(models.AuditLog.incident_id == incident_id)
    if user_id is not None:
        query = query.find(models.AuditLog.user_id == user_id)
    if action is not None:
        query = query.find(models.AuditLog.action == action)

    entries = await query.sort(-models.AuditLog.timestamp).skip(offset).limit(limit).to_list()
    return [schemas.AuditLogResponse.from_audit_log(e) for e in entries]
