"""
Officer tracking read model + zone assignment + location-history access.

Authorisation (enforced here, never only in the UI):
  admin / control_room : every officer
  station              : officers of their own station only
  constable / citizen  : no access to this router at all

What a snapshot row guarantees:
  * `position` is the last SERVER-CONFIRMED fix, with its own recorded_at,
    accuracy and age. It is omitted entirely while the officer is off duty.
  * `tracking_state` is live/delayed/stale/unavailable, computed from the
    fix's recorded_at (services/tracking.py) -- a buffered old fix is never live.
  * `assigned_zone_*` (administrative) and `detected_zone_*` (from
    coordinates + boundaries) are separate fields and may differ.
  * `network` appears only when a real source reported the AP association
    (authenticated edge controller, or the device itself); simulator presence
    is never surfaced here.
"""
import datetime
import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import models, schemas
from ..auth.deps import require_role
from ..services import events, tracking
from ..services.audit import log_action

router = APIRouter(prefix="/tracking", tags=["Tracking"])

_VIEW_ROLES = ("admin", "control_room", "station")
HISTORY_MAX_POINTS = 2000


def _scope_query(user: models.User) -> Optional[dict]:
    """None means 'nothing visible'."""
    if user.role == models.UserRole.station:
        if not user.station_id:
            return None
        return {"station_id": user.station_id}
    return {}


def _require_can_view(user: models.User, constable: models.Constable) -> None:
    if user.role == models.UserRole.station and (not user.station_id or constable.station_id != user.station_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this officer")


async def _build_officers(constables: List[models.Constable], now: datetime.datetime) -> List[schemas.TrackedOfficer]:
    if not constables:
        return []
    ids = [c.id for c in constables]

    sessions: Dict[uuid.UUID, models.DutySession] = {}
    async for sess in models.DutySession.find({"constable_id": {"$in": ids}, "status": "active"}):
        sessions[sess.constable_id] = sess

    zone_codes = {c.assigned_zone_code for c in constables if c.assigned_zone_code} | {
        c.current_geographic_zone for c in constables if c.current_geographic_zone
    }
    zone_names: Dict[str, str] = {}
    if zone_codes:
        async for z in models.EventZone.find({"code": {"$in": list(zone_codes)}}):
            zone_names[z.code] = z.name

    station_ids = {c.station_id for c in constables if c.station_id}
    station_names: Dict[uuid.UUID, Optional[str]] = {}
    if station_ids:
        async for st in models.PoliceStation.find({"_id": {"$in": list(station_ids)}}):
            station_names[st.id] = st.name

    presence_by_constable: Dict[uuid.UUID, models.PolicePresence] = {}
    async for pr in models.PolicePresence.find({"constable_id": {"$in": ids}}):
        prev = presence_by_constable.get(pr.constable_id)
        if prev is None or (pr.last_seen_at and (prev.last_seen_at is None or pr.last_seen_at > prev.last_seen_at)):
            presence_by_constable[pr.constable_id] = pr
    ap_ids = {p.current_access_point_id for p in presence_by_constable.values() if p.current_access_point_id}
    aps: Dict[uuid.UUID, models.AccessPoint] = {}
    if ap_ids:
        async for ap in models.AccessPoint.find({"_id": {"$in": list(ap_ids)}}):
            aps[ap.id] = ap

    out: List[schemas.TrackedOfficer] = []
    for c in constables:
        sess = sessions.get(c.id)
        on_duty = sess is not None
        point = c.last_location_point if on_duty else None
        ts = tracking.compute_tracking_state(
            on_duty=on_duty,
            recorded_at=c.last_location_recorded_at if point else None,
            server_received_at=c.last_location_at,
            now=now,
        )
        position = None
        if point is not None and c.last_location_recorded_at is not None:
            lon, lat = point.coordinates
            position = schemas.TrackedPosition(
                latitude=lat, longitude=lon, accuracy=c.last_location_accuracy,
                recorded_at=c.last_location_recorded_at, server_received_at=c.last_location_at,
                sequence_number=c.last_location_sequence, source="GNSS", age_seconds=ts.age_seconds, buffered=ts.buffered,
            )

        network = None
        pr = presence_by_constable.get(c.id)
        if on_duty and pr is not None and pr.source in (models.PresenceEventSource.controller, models.PresenceEventSource.real) \
                and pr.status != models.PresenceConnectionStatus.disconnected:
            ap = aps.get(pr.current_access_point_id) if pr.current_access_point_id else None
            network = schemas.TrackedNetwork(
                access_point_code=ap.code if ap else None, access_point_name=ap.name if ap else None,
                bssid=ap.bssid if ap else None, ssid=ap.ssid if ap else None, ap_zone=pr.current_zone,
                source=pr.source.value, verified_by_controller=pr.source == models.PresenceEventSource.controller,
                ap_verification_status=ap.verification_status.value if ap else None,
                last_seen_at=pr.last_seen_at, connection_status=pr.status.value,
            )

        detected = c.current_geographic_zone if on_duty else None
        in_assigned: Optional[bool] = None
        if on_duty and c.assigned_zone_code and c.zone_status in ("CONFIRMED", "OUTSIDE"):
            in_assigned = detected == c.assigned_zone_code

        out.append(schemas.TrackedOfficer(
            constable_id=c.id, badge_number=c.badge_number, station_id=c.station_id,
            station_name=station_names.get(c.station_id), battery_level=c.battery_level,
            on_duty=on_duty, duty_session_id=sess.id if sess else None, duty_started_at=sess.started_at if sess else None,
            device_identifier=sess.device_identifier if sess else None,
            tracking_state=ts.state, unavailable_reason=ts.reason,
            assigned_zone_code=c.assigned_zone_code, assigned_zone_name=zone_names.get(c.assigned_zone_code),
            detected_zone_code=detected, detected_zone_name=zone_names.get(detected) if detected else None,
            zone_status=c.zone_status if on_duty else None, zone_changed_at=c.zone_changed_at if on_duty else None,
            in_assigned_zone=in_assigned, position=position, network=network,
        ))
    return out


@router.get("/officers", response_model=schemas.TrackingSnapshotResponse)
async def tracking_snapshot(current_user: models.User = Depends(require_role(*_VIEW_ROLES))):
    """Authoritative snapshot for the live map (also used to resync after a WebSocket reconnect)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    scope = _scope_query(current_user)
    constables = [] if scope is None else await models.Constable.find(scope).to_list()
    officers = await _build_officers(constables, now)
    officers.sort(key=lambda o: (not o.on_duty, o.badge_number or ""))
    return schemas.TrackingSnapshotResponse(server_time=now, thresholds=tracking.thresholds(), officers=officers)


@router.get("/officers/{constable_id}", response_model=schemas.TrackedOfficer)
async def tracking_officer(constable_id: uuid.UUID, current_user: models.User = Depends(require_role(*_VIEW_ROLES))):
    constable = await models.Constable.get(constable_id)
    if constable is None:
        raise HTTPException(status_code=404, detail="Constable not found")
    _require_can_view(current_user, constable)
    return (await _build_officers([constable], datetime.datetime.now(datetime.timezone.utc)))[0]


@router.put("/officers/{constable_id}/assigned-zone", response_model=schemas.TrackedOfficer)
async def set_assigned_zone(
    constable_id: uuid.UUID,
    payload: schemas.AssignedZoneRequest,
    current_user: models.User = Depends(require_role("admin")),
):
    """Assigns (or clears, with null) an officer's DUTY zone. Independent of where the officer is currently detected."""
    constable = await models.Constable.get(constable_id)
    if constable is None:
        raise HTTPException(status_code=404, detail="Constable not found")
    code = payload.zone_code.strip() if payload.zone_code else None
    if code:
        zone = await models.EventZone.find_one(models.EventZone.code == code)
        if zone is None:
            raise HTTPException(status_code=422, detail=f"Unknown event zone '{code}'")
        if not zone.enabled:
            raise HTTPException(status_code=409, detail=f"Event zone '{code}' is disabled")
    previous = constable.assigned_zone_code
    constable.assigned_zone_code = code
    constable.assigned_zone_updated_at = datetime.datetime.now(datetime.timezone.utc)
    constable.assigned_zone_updated_by = current_user.id
    await constable.save()
    await log_action(
        user_id=current_user.id, action="constable.assigned_zone_changed",
        details={"constable_id": str(constable.id), "previous": previous, "current": code},
    )
    await events.publish_constable_assignment_changed(constable.id, constable.station_id, code)
    return (await _build_officers([constable], datetime.datetime.now(datetime.timezone.utc)))[0]


@router.get("/officers/{constable_id}/history", response_model=schemas.LocationHistoryResponse)
async def location_history(
    constable_id: uuid.UUID,
    start: Optional[datetime.datetime] = Query(default=None, alias="from"),
    end: Optional[datetime.datetime] = Query(default=None, alias="to"),
    limit: int = Query(default=500, ge=1, le=HISTORY_MAX_POINTS),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """
    Stored location history (retention-limited, see LOCATION_RETENTION_DAYS).
    Every call is written to the audit log with who looked, at whom and over
    what range -- including calls that return nothing.
    """
    constable = await models.Constable.get(constable_id)
    if constable is None:
        raise HTTPException(status_code=404, detail="Constable not found")
    _require_can_view(current_user, constable)

    query: dict = {"constable_id": constable_id}
    window: dict = {}
    if start is not None:
        window["$gte"] = start
    if end is not None:
        window["$lte"] = end
    if window:
        query["timestamp"] = window
    rows = await models.ConstableLocation.find(query).sort(-models.ConstableLocation.timestamp).limit(limit + 1).to_list()
    truncated = len(rows) > limit
    rows = rows[:limit]

    await log_action(
        user_id=current_user.id, action="location_history_viewed",
        details={
            "constable_id": str(constable_id), "from": start.isoformat() if start else None,
            "to": end.isoformat() if end else None, "returned": len(rows), "role": current_user.role.value,
        },
    )
    points = [
        schemas.LocationHistoryPoint(
            latitude=r.location.coordinates[1], longitude=r.location.coordinates[0], accuracy=r.accuracy,
            recorded_at=r.recorded_at, server_received_at=r.server_received_at, sequence_number=r.sequence_number,
            geographic_zone=r.geographic_zone, zone_status=r.zone_status, buffered=r.buffered,
            advanced_projection=r.advanced_projection, duty_session_id=r.duty_session_id,
        )
        for r in rows
    ]
    return schemas.LocationHistoryResponse(constable_id=constable_id, count=len(points), truncated=truncated, points=points)
