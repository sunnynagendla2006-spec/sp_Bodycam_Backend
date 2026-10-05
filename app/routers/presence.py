"""
AP-based police presence: the association-reporting + current-state +
movement-history endpoints. See app/models.py's module docstring above
AccessPoint and app/services/presence.py's module docstring for the
overall design.

Every mutation in this router goes through
services/presence.py::process_association -- this router never writes
PolicePresence/PresenceHandoff directly. That is what keeps this the
single business-logic path a future edge-server or dev-only simulator
endpoint would also call, rather than a second, divergent one.
"""
import os
import uuid
from typing import List, Optional

from beanie.operators import In
from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import models, schemas
from ..auth.deps import get_current_user
from ..services.audit import log_action
from ..services import events
from ..services import presence as presence_service
from ..services import ap_association
from ..services import movement_state
from .constables import get_own_constable
from .devices import _require_own_device_for_constable, _device_station_id
from .settings import load_settings

router = APIRouter(prefix="/presence", tags=["Presence"])

# Production safety gate for the whole virtual-AP simulator surface (see
# routers/presence.py's virtual endpoints below) -- same pattern as
# app/services/cctv_security.py::CCTV_ENABLED. Defaults to enabled so the
# demo works out of the box in development; set to "false" in any
# environment where frontend-driven movement simulation of a real
# officer's presence must not be possible.
VIRTUAL_AP_MODE_ENABLED = os.getenv("VIRTUAL_AP_MODE_ENABLED", "true").strip().lower() in ("1", "true", "yes")


def _require_virtual_ap_mode_enabled():
    if not VIRTUAL_AP_MODE_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Virtual AP mode is disabled in this environment (VIRTUAL_AP_MODE_ENABLED=false)",
        )


async def _ap_codes_by_id(ap_ids) -> dict:
    ap_ids = {i for i in ap_ids if i}
    if not ap_ids:
        return {}
    aps = await models.AccessPoint.find(In(models.AccessPoint.id, list(ap_ids))).to_list()
    return {a.id: a.code for a in aps}


def _to_presence_response(
    presence: models.PolicePresence,
    access_point_code: Optional[str],
    effective_status: Optional[models.PresenceConnectionStatus] = None,
) -> schemas.PresenceStateResponse:
    return schemas.PresenceStateResponse(
        device_id=presence.device_id,
        constable_id=presence.constable_id,
        current_access_point_id=presence.current_access_point_id,
        current_access_point_code=access_point_code,
        current_zone=presence.current_zone,
        status=effective_status if effective_status is not None else presence.status,
        location_source=presence.location_source,
        last_seen_at=presence.last_seen_at,
        handoff_count=presence.handoff_count,
        current_zone_since=presence.current_zone_since,
        updated_at=presence.updated_at,
    )


async def _observe_and_publish_presence_status(
    presence: models.PolicePresence, settings: dict, station_id: Optional[uuid.UUID]
) -> models.PresenceConnectionStatus:
    """
    Lazy degradation detection, called from every read path -- same
    "no background scheduler, observe on read" design as
    devices.py::_observe_and_alert_device_status. Persists and publishes
    a transition if (and only if) the effective status actually differs
    from what's stored.
    """
    effective = presence_service.compute_effective_presence_status(presence, settings)
    if presence.status == effective:
        return effective
    old_status = presence.status.value if presence.status else None
    presence.status = effective
    await presence.save()
    await events.publish_presence_status_changed(presence, old_status, effective.value, station_id)
    return effective


async def _authorize_presence_access(device: models.Device, current_user: models.User) -> bool:
    """admin/control_room: any device. station: only devices whose constable belongs to their station. constable: only their own device. citizen: never. Mirrors recordings.py::_authorize_recording_access."""
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        return True
    if role == models.UserRole.station:
        if not current_user.station_id or not device.constable_id:
            return False
        constable = await models.Constable.get(device.constable_id)
        return constable is not None and constable.station_id == current_user.station_id
    if role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        return own_constable is not None and device.constable_id == own_constable.id
    return False


# ===========================================================================
# Association reporting
# ===========================================================================

async def _submit_association(
    *,
    provider: ap_association.APAssociationProvider,
    current_user: models.User,
    device_identifier: str,
    access_point_code: str,
    event_id: Optional[str],
    occurred_at=None,
    action_prefix: str = "presence",
) -> schemas.PresenceAssociationResponse:
    """
    Shared by POST /presence/association (RealAPAssociationProvider) and
    POST /presence/association/virtual (VirtualAPAssociationProvider) --
    everything from ownership-checking through event-publishing is
    identical regardless of source; only `provider` (and therefore the
    resulting `source` tag) differs. See app/services/ap_association.py.
    """
    own_constable, device = await _require_own_device_for_constable(current_user, device_identifier)

    access_point = await models.AccessPoint.find_one(models.AccessPoint.code == access_point_code)
    if not access_point:
        raise HTTPException(status_code=404, detail=f"Access point '{access_point_code}' not found")

    event = ap_association.AssociationEvent(
        device_identifier=device_identifier, access_point_code=access_point_code,
        event_id=event_id, occurred_at=occurred_at,
    )
    try:
        result = await provider.submit(event, device=device, constable=own_constable, access_point=access_point)
    except presence_service.PresenceError as exc:
        if exc.code == "access_point_disabled":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.message)
        raise HTTPException(status_code=400, detail=exc.message)

    station_id = own_constable.station_id
    movement_state.clear_moving(str(device.id))  # arrived for real -- no longer "moving"

    if result.duplicate_event:
        status_label = "duplicate_event"
    elif not result.handoff_created:
        status_label = "duplicate_ignored"
    elif result.is_first_association:
        status_label = "connected"
        await log_action(
            user_id=current_user.id, action=f"{action_prefix}.connected",
            details={"device_id": str(device.id), "access_point_code": access_point.code, "source": provider.source.value},
        )
        await events.publish_presence_connected(result.presence, access_point, station_id)
    else:
        status_label = "handoff"
        from_ap = None
        if result.handoff and result.handoff.previous_access_point_id:
            from_ap = await models.AccessPoint.get(result.handoff.previous_access_point_id)
        await log_action(
            user_id=current_user.id, action=f"{action_prefix}.handoff",
            details={
                "device_id": str(device.id),
                "from_access_point_code": from_ap.code if from_ap else None,
                "to_access_point_code": access_point.code,
                "event_id": event_id,
                "source": provider.source.value,
            },
        )
        await events.publish_presence_handoff(result.presence, result.handoff, from_ap, access_point, station_id)

    return schemas.PresenceAssociationResponse(
        status=status_label,
        handoff_created=result.handoff_created,
        presence=_to_presence_response(result.presence, access_point.code),
        handoff=schemas.PresenceHandoffResponse.model_validate(result.handoff, from_attributes=True) if result.handoff else None,
    )


_REAL_PROVIDER = ap_association.RealAPAssociationProvider()
_VIRTUAL_PROVIDER = ap_association.VirtualAPAssociationProvider()


@router.post("/association", response_model=schemas.PresenceAssociationResponse)
async def associate(
    payload: schemas.PresenceAssociationRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Constable-owned device only -- reuses devices.py's exact ownership
    check (`_require_own_device_for_constable`), the same way
    recordings.py/live_stream.py already do. `source` on the resulting
    PresenceHandoff/PolicePresence is always REAL: this endpoint has no
    field for the caller to claim otherwise (see
    models.PresenceEventSource's docstring).

    - Unknown device / not this constable's own -> 404/403 (from the
      reused ownership check).
    - Unknown access_point_code -> 404.
    - Disabled access point -> 409.
    - Same-AP repeat heartbeat -> 200, handoff_created=false, no audit
      entry, no WebSocket event (idempotent no-op).
    - Different AP -> 200, a PresenceHandoff row is created, audited, and
      published as either `presence.connected` (first-ever association)
      or `presence.handoff`.
    """
    return await _submit_association(
        provider=_REAL_PROVIDER, current_user=current_user,
        device_identifier=payload.device_identifier, access_point_code=payload.access_point_code,
        event_id=payload.event_id, occurred_at=payload.occurred_at,
    )


@router.post("/association/virtual", response_model=schemas.PresenceAssociationResponse)
async def associate_virtual(
    payload: schemas.PresenceAssociationVirtualRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    VIRTUAL AP / DEMO MODE ONLY -- see docs/VIRTUAL_AP_POLICE_PRESENCE.md.
    Identical authorization and identical PresenceService path as
    POST /presence/association (same ownership check, same duplicate/
    disabled-AP/unknown-AP handling) -- the only difference is `source`
    is always SIMULATOR, never REAL, and this entire endpoint 403s when
    VIRTUAL_AP_MODE_ENABLED=false. This never pretends a real Wi-Fi
    association occurred; it simulates AP association for development
    and demonstration only.
    """
    _require_virtual_ap_mode_enabled()
    return await _submit_association(
        provider=_VIRTUAL_PROVIDER, current_user=current_user,
        device_identifier=payload.device_identifier, access_point_code=payload.access_point_code,
        event_id=payload.event_id, action_prefix="presence_virtual",
    )


# ===========================================================================
# Current state
# ===========================================================================

@router.get("/me", response_model=List[schemas.PresenceStateResponse])
async def my_presence(current_user: models.User = Depends(get_current_user)):
    """Constable-only: the authenticated constable's own device(s). Never another constable's."""
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Constable role required")
    own_constable = await get_own_constable(current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")

    settings = load_settings()
    presences = await models.PolicePresence.find(models.PolicePresence.constable_id == own_constable.id).to_list()
    ap_codes = await _ap_codes_by_id(p.current_access_point_id for p in presences)

    results = []
    for p in presences:
        effective = await _observe_and_publish_presence_status(p, settings, own_constable.station_id)
        results.append(_to_presence_response(p, ap_codes.get(p.current_access_point_id), effective))
    return results


@router.get("/", response_model=List[schemas.PresenceStateResponse])
async def list_presence(current_user: models.User = Depends(get_current_user)):
    """admin/control_room: every device's presence. station: only constables at their own station. constable: only their own. citizen: denied."""
    role = current_user.role
    settings = load_settings()

    if role in (models.UserRole.admin, models.UserRole.control_room):
        presences = await models.PolicePresence.find_all().to_list()
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = [
            c.id for c in await models.Constable.find(models.Constable.station_id == current_user.station_id).to_list()
        ]
        presences = await models.PolicePresence.find(In(models.PolicePresence.constable_id, station_constable_ids)).to_list()
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            return []
        presences = await models.PolicePresence.find(models.PolicePresence.constable_id == own_constable.id).to_list()
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view presence data")

    ap_codes = await _ap_codes_by_id(p.current_access_point_id for p in presences)

    # Station id per presence row -- batch-resolved via each row's own
    # constable_id rather than one query per row (same discipline as
    # constables.py::list_constables).
    constable_ids = {p.constable_id for p in presences}
    station_by_constable = {}
    if constable_ids:
        for c in await models.Constable.find(In(models.Constable.id, list(constable_ids))).to_list():
            station_by_constable[c.id] = c.station_id

    results = []
    for p in presences:
        effective = await _observe_and_publish_presence_status(p, settings, station_by_constable.get(p.constable_id))
        results.append(_to_presence_response(p, ap_codes.get(p.current_access_point_id), effective))
    return results


@router.get("/devices/{device_id}", response_model=schemas.PresenceStateResponse)
async def get_device_presence(
    device_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    device = await models.Device.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not await _authorize_presence_access(device, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this device's presence")

    presence = await models.PolicePresence.find_one(models.PolicePresence.device_id == device_id)
    if not presence:
        raise HTTPException(status_code=404, detail="No presence record for this device yet")

    settings = load_settings()
    station_id = await _device_station_id(device)
    effective = await _observe_and_publish_presence_status(presence, settings, station_id)
    ap_codes = await _ap_codes_by_id([presence.current_access_point_id])

    return _to_presence_response(presence, ap_codes.get(presence.current_access_point_id), effective)


@router.get("/devices/{device_id}/history", response_model=List[schemas.PresenceHandoffResponse])
async def get_device_presence_history(
    device_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(get_current_user),
):
    """Ordered movement history (most recent first) -- same authorization as GET /presence/devices/{id}."""
    device = await models.Device.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not await _authorize_presence_access(device, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this device's presence history")

    handoffs = await models.PresenceHandoff.find(
        models.PresenceHandoff.device_id == device_id
    ).sort(-models.PresenceHandoff.occurred_at).skip(offset).limit(limit).to_list()

    return [schemas.PresenceHandoffResponse.model_validate(h, from_attributes=True) for h in handoffs]


# ===========================================================================
# Virtual AP mode -- see docs/VIRTUAL_AP_POLICE_PRESENCE.md and
# app/services/ap_association.py. Everything below is either read-only,
# a pure WebSocket passthrough with no persistence, or routes through
# _submit_association above (same PresenceService path as the real
# endpoint) -- nothing here duplicates presence/handoff logic.
# ===========================================================================

@router.get("/virtual/map", response_model=List[schemas.AccessPointResponse])
async def virtual_map(
    deployment: Optional[str] = None,
    current_user: models.User = Depends(get_current_user),
):
    """
    A deliberately narrow, constable-safe view of enabled access points
    (for the police app's own "select a destination" map) -- NOT the
    same endpoint as GET /access-points/ (admin/control_room/station
    only, full management view). A constable sees only what they need to
    pick a destination in demo mode; they still cannot create, update, or
    delete an AP through this or any endpoint.
    """
    if current_user.role == models.UserRole.citizen:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    query = models.AccessPoint.find(models.AccessPoint.enabled == True)  # noqa: E712
    if deployment is not None:
        query = query.find(models.AccessPoint.deployment == deployment)
    aps = await query.sort(models.AccessPoint.code).to_list()

    from .. import geo
    results = []
    for ap in aps:
        lon, lat = geo.lon_lat(ap.location)
        results.append(schemas.AccessPointResponse(
            id=ap.id, code=ap.code, name=ap.name, zone=ap.zone, deployment=ap.deployment,
            station_id=None, latitude=lat, longitude=lon, enabled=ap.enabled, status=ap.status,
            is_demo=ap.is_demo, created_at=ap.created_at, updated_at=ap.updated_at,
        ))
    return results


@router.get("/virtual/nearest-ap", response_model=schemas.NearestAccessPointResponse)
async def virtual_nearest_ap(
    latitude: float = Query(..., ge=-90.0, le=90.0),
    longitude: float = Query(..., ge=-180.0, le=180.0),
    deployment: Optional[str] = None,
    current_user: models.User = Depends(get_current_user),
):
    """
    Real geographic nearest-AP lookup (see ap_association.find_nearest_access_point)
    for the simulator's "connect to nearest AP" capability -- never a
    pixel/UI distance, and never a claim of actual Wi-Fi radio association.
    """
    if current_user.role == models.UserRole.citizen:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    found = await ap_association.find_nearest_access_point(longitude=longitude, latitude=latitude, deployment=deployment)
    if not found:
        raise HTTPException(status_code=404, detail="No enabled access point with a location is registered")
    ap, distance = found
    return schemas.NearestAccessPointResponse(id=ap.id, code=ap.code, name=ap.name, zone=ap.zone, distance_meters=distance)


@router.post("/virtual/moving-ping")
async def moving_ping(
    payload: schemas.PresenceMovingPingRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Pure WebSocket passthrough -- see schemas.PresenceMovingPingRequest's
    docstring. NEVER writes to MongoDB; only updates the in-memory
    movement_state tracker (TTL-bound, see that module) and publishes
    `presence.moving` to control_room + the constable's own station. The
    backend remains authoritative regardless: this never changes
    PolicePresence.current_access_point_id -- only a real
    POST /presence/association/virtual call does that.
    """
    _require_virtual_ap_mode_enabled()
    own_constable, device = await _require_own_device_for_constable(current_user, payload.device_identifier)

    target_ap = await models.AccessPoint.find_one(models.AccessPoint.code == payload.target_access_point_code)
    if not target_ap:
        raise HTTPException(status_code=404, detail=f"Access point '{payload.target_access_point_code}' not found")

    presence = await models.PolicePresence.find_one(models.PolicePresence.device_id == device.id)
    from_ap = None
    if presence and presence.current_access_point_id:
        from_ap = await models.AccessPoint.get(presence.current_access_point_id)

    movement_state.record_moving_ping(str(device.id), target_ap.code, target_ap.zone, payload.progress)

    await events.publish_presence_moving(
        device_id=device.id, constable_id=own_constable.id,
        from_access_point_code=from_ap.code if from_ap else None,
        target_access_point_code=target_ap.code,
        from_zone=from_ap.zone if from_ap else None, target_zone=target_ap.zone,
        progress=payload.progress, station_id=own_constable.station_id,
    )
    return {"status": "ok"}


@router.post("/zones/{zone}/alert", response_model=schemas.ZoneAlertResponse)
async def alert_zone(
    zone: str,
    payload: schemas.ZoneAlertRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    admin/control_room only. Targets exactly the constables CURRENTLY
    connected to an access point in this zone (status=connected) --
    reuses the existing WebSocket transport (manager.send_to_constable,
    via events.publish_zone_emergency_alert) rather than inventing a
    second notification channel. Never targets a constable not presently
    in this zone, and never a citizen/station/other role.
    """
    if current_user.role not in (models.UserRole.admin, models.UserRole.control_room):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to send zone alerts")

    aps_in_zone = await models.AccessPoint.find(models.AccessPoint.zone == zone).to_list()
    ap_ids = [a.id for a in aps_in_zone]
    if not ap_ids:
        return schemas.ZoneAlertResponse(zone=zone, message=payload.message, targeted_constable_ids=[], targeted_device_count=0)

    presences = await models.PolicePresence.find(
        In(models.PolicePresence.current_access_point_id, ap_ids),
        models.PolicePresence.status == models.PresenceConnectionStatus.connected,
    ).to_list()
    constable_ids = list({p.constable_id for p in presences})

    await log_action(
        user_id=current_user.id, action="zone_emergency_alert_sent",
        details={"zone": zone, "message": payload.message, "targeted_constable_count": len(constable_ids)},
    )
    await events.publish_zone_emergency_alert(zone=zone, message=payload.message, targeted_constable_ids=constable_ids)

    return schemas.ZoneAlertResponse(
        zone=zone, message=payload.message, targeted_constable_ids=constable_ids, targeted_device_count=len(presences),
    )
