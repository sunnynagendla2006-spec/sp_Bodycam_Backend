"""
Minimal, read-only GET /alerts/ endpoint. Adds NO new alert-generation
logic, no side effects, purely a list/filter view over the existing
`alerts` collection.
"""
from typing import Optional
import uuid

from beanie.operators import In
from fastapi import APIRouter, Depends, Query

from .. import models, schemas
from ..auth.deps import require_role
from .constables import get_own_constable

router = APIRouter(prefix="/alerts", tags=["Alerts"])

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


@router.get("/", response_model=list[schemas.AlertResponse])
async def list_alerts(
    status: Optional[models.AlertStatus] = None,
    severity: Optional[models.AlertSeverity] = None,
    type: Optional[models.AlertType] = None,
    device_id: Optional[uuid.UUID] = None,
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(require_role("admin", "control_room", "station", "constable")),
):
    """
    Read-only. Never creates, updates, or resolves an alert -- all alert
    state changes remain exclusively in app/services/alerts.py and
    app/routers/devices.py, unchanged by this endpoint.

    admin/control_room: all alerts.
    station: only alerts whose Alert.constable_id belongs to a constable
      in their own station.
    constable: only alerts for their own device.
    citizen: denied -- no existing requirement in this project grants
      citizens alert visibility, so none is invented here.
    """
    query = models.Alert.find()

    if current_user.role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = [
            c.id for c in await models.Constable.find(models.Constable.station_id == current_user.station_id).to_list()
        ]
        query = query.find(In(models.Alert.constable_id, station_constable_ids))
    elif current_user.role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            return []
        query = query.find(models.Alert.constable_id == own_constable.id)

    if status is not None:
        query = query.find(models.Alert.status == status)
    if severity is not None:
        query = query.find(models.Alert.severity == severity)
    if type is not None:
        query = query.find(models.Alert.type == type)
    if device_id is not None:
        query = query.find(models.Alert.device_id == device_id)

    return await query.sort(-models.Alert.created_at).skip(offset).limit(limit).to_list()
