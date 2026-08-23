"""
Phase 4A: minimal, read-only GET /alerts/ endpoint.

Alerts have been generated since Phase 1 (battery thresholds) and Phase 3
(device offline/stale, recording-device-offline, command failures) via
app/services/alerts.py and app/routers/devices.py -- this endpoint adds
NO new alert-generation logic, no side effects, purely a list/filter view
over the existing `alerts` table. schemas.AlertResponse already existed
(added in Phase 3) but had no endpoint returning it until now.
"""
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import database, models, schemas
from ..auth.deps import require_role
from .constables import get_own_constable

router = APIRouter(prefix="/alerts", tags=["Alerts"])

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


@router.get("/", response_model=list[schemas.AlertResponse])
def list_alerts(
    status: Optional[models.AlertStatus] = None,
    severity: Optional[models.AlertSeverity] = None,
    type: Optional[models.AlertType] = None,
    device_id: Optional[uuid.UUID] = None,
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station", "constable")),
):
    """
    Read-only. Never creates, updates, or resolves an alert -- all alert
    state changes remain exclusively in app/services/alerts.py and
    app/routers/devices.py, unchanged by this endpoint.

    admin/control_room: all alerts.
    station: only alerts whose Alert.constable_id belongs to a constable
      in their own station (Alert.constable_id is populated at creation
      time from the owning device's constable -- see
      app/routers/devices.py::_observe_and_alert_device_status and
      app/services/alerts.py::upsert_open_alert).
    constable: only alerts for their own device (Alert.constable_id ==
      their own Constable.id).
    citizen: denied -- no existing requirement in this project grants
      citizens alert visibility, so none is invented here.

    `limit` capped at 200, same convention as GET /audit-logs/.
    """
    query = db.query(models.Alert)

    if current_user.role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = db.query(models.Constable.id).filter(models.Constable.station_id == current_user.station_id)
        query = query.filter(models.Alert.constable_id.in_(station_constable_ids))
    elif current_user.role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable:
            return []
        query = query.filter(models.Alert.constable_id == own_constable.id)

    if status is not None:
        query = query.filter(models.Alert.status == status)
    if severity is not None:
        query = query.filter(models.Alert.severity == severity)
    if type is not None:
        query = query.filter(models.Alert.type == type)
    if device_id is not None:
        query = query.filter(models.Alert.device_id == device_id)

    alerts = (
        query.order_by(models.Alert.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return alerts
