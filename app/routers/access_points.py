"""
Access point (AP) management -- the fixed-infrastructure half of the
AP-based presence feature (see app/models.py's module docstring above
AccessPoint). Authorization mirrors app/routers/police_stations.py
exactly: admin manages, admin/control_room/station(own) view, constable
and citizen have no access to this asset list at all (a constable's own
device reports its association via app/routers/presence.py -- it never
needs to browse the AP roster itself).

State is deliberately layered, and only the last two layers may ever come
from real hardware/integrations (see services/ap_integration.py):

  1. registered inventory   -- an administrator created/edited the row
  2. configured             -- identifiers (BSSID/serial/IP) recorded, NOT checked
  3. verified               -- a real controller lookup or authorised edge
                               telemetry confirmed the device exists
  4. reachable              -- verified AND recent real telemetry

Creating, editing, enabling or disabling an AP never moves it up that ladder.
"""
import datetime
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.errors import DuplicateKeyError

from .. import geo, models, schemas
from ..auth.deps import require_role
from ..services.audit import log_action
from ..services import movement_state
from ..services import ap_integration

router = APIRouter(prefix="/access-points", tags=["Access Points"])

_IDENTIFIER_FIELDS = ("bssid", "serial_number", "manufacturer", "management_ip")
_TRACKED_FIELDS = (
    "name", "description", "zone", "deployment", "station_id", "coverage_radius_m", "edge_node_id", "is_demo",
    "manufacturer", "model", "serial_number", "bssid", "ssid", "management_ip", "controller_source",
    "building", "floor", "event_zone_codes",
)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _to_response(
    ap: models.AccessPoint,
    associated_device_count: Optional[int] = None,
    include_history: bool = False,
) -> schemas.AccessPointResponse:
    lon, lat = geo.lon_lat(ap.location)
    reachability = ap_integration.derive_reachability(ap)
    data = dict(
        id=ap.id, code=ap.code, name=ap.name, description=ap.description, zone=ap.zone, deployment=ap.deployment,
        station_id=ap.station_id, latitude=lat, longitude=lon, coverage_radius_m=ap.coverage_radius_m,
        edge_node_id=ap.edge_node_id, manufacturer=ap.manufacturer, model=ap.model, serial_number=ap.serial_number,
        bssid=ap.bssid, ssid=ap.ssid, management_ip=ap.management_ip, controller_source=ap.controller_source,
        building=ap.building, floor=ap.floor, event_zone_codes=list(ap.event_zone_codes or []),
        enabled=ap.enabled, lifecycle_status=ap.lifecycle_status, verification_status=ap.verification_status,
        verification_source=ap.verification_source, verified_at=ap.verified_at,
        last_verification_attempt_at=ap.last_verification_attempt_at, last_verification_error=ap.last_verification_error,
        last_seen_at=ap.last_seen_at, integration_health=ap.integration_health, reachability=reachability,
        status=ap_integration.legacy_status(reachability), retired_at=ap.retired_at, retire_reason=ap.retire_reason,
        is_demo=ap.is_demo, created_at=ap.created_at, updated_at=ap.updated_at,
        associated_device_count=associated_device_count,
    )
    if include_history:
        data["config_history"] = [schemas.APConfigChangeResponse(**h.model_dump()) for h in reversed(ap.config_history)]
    return schemas.AccessPointResponse(**data)


async def _get_ap_or_404(access_point_id: uuid.UUID) -> models.AccessPoint:
    ap = await models.AccessPoint.get(access_point_id)
    if not ap:
        raise HTTPException(status_code=404, detail="Access point not found")
    return ap


def _conflict_message(exc: DuplicateKeyError, payload_code: Optional[str] = None) -> str:
    text = str(exc)
    if "bssid" in text:
        return "Another access point already uses this BSSID"
    if "serial_number" in text:
        return "An access point with this manufacturer and serial number is already registered"
    return f"An access point with code '{payload_code}' already exists" if payload_code else "Duplicate access point"


async def _validate_event_zone_codes(codes: Optional[List[str]]) -> List[str]:
    cleaned = sorted({c.strip() for c in (codes or []) if c and c.strip()})
    if not cleaned:
        return []
    known = {z.code async for z in models.EventZone.find({"code": {"$in": cleaned}})}
    unknown = [c for c in cleaned if c not in known]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown event zone code(s): {', '.join(unknown)}")
    return cleaned


def _initial_verification_status(ap: models.AccessPoint) -> models.APVerificationStatus:
    configured = bool(ap.bssid or ap.serial_number or ap.management_ip)
    return models.APVerificationStatus.configured if configured else models.APVerificationStatus.registered


@router.post("/", response_model=schemas.AccessPointResponse)
async def create_access_point(
    payload: schemas.AccessPointCreateRequest,
    current_user: models.User = Depends(require_role("admin")),
):
    """
    admin only. The new AP is an INVENTORY record: verification `registered`
    /`configured`, reachability `unknown`, until a controller/telemetry says otherwise.
    """
    if (payload.latitude is None) != (payload.longitude is None):
        raise HTTPException(status_code=422, detail="Provide both latitude and longitude, or neither")
    if payload.serial_number and not payload.manufacturer:
        raise HTTPException(status_code=422, detail="A serial number requires the manufacturer (serials are only unique per manufacturer)")
    location = geo.point(payload.longitude, payload.latitude) if payload.latitude is not None else None
    event_zone_codes = await _validate_event_zone_codes(payload.event_zone_codes)
    ap = models.AccessPoint(
        code=payload.code, name=payload.name, description=payload.description, zone=payload.zone, deployment=payload.deployment,
        station_id=payload.station_id, location=location, coverage_radius_m=payload.coverage_radius_m,
        edge_node_id=payload.edge_node_id, is_demo=payload.is_demo,
        manufacturer=payload.manufacturer, model=payload.model, serial_number=payload.serial_number, bssid=payload.bssid,
        ssid=payload.ssid, management_ip=payload.management_ip, controller_source=payload.controller_source,
        building=payload.building, floor=payload.floor, event_zone_codes=event_zone_codes,
        created_by=current_user.id, updated_by=current_user.id,
    )
    ap.verification_status = _initial_verification_status(ap)
    ap_integration.add_history(ap, by=current_user.id, action="created", changes={"code": ap.code, "verification_status": ap.verification_status.value})
    try:
        await ap.insert()
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_conflict_message(exc, payload.code))

    await log_action(user_id=current_user.id, action="access_point_created", details={"access_point_id": str(ap.id), "code": ap.code})
    return _to_response(ap)


@router.get("/", response_model=List[schemas.AccessPointResponse])
async def list_access_points(
    deployment: Optional[str] = None,
    zone: Optional[str] = None,
    enabled: Optional[bool] = None,
    lifecycle_status: Optional[models.APLifecycleStatus] = None,
    verification_status: Optional[models.APVerificationStatus] = None,
    station_id: Optional[uuid.UUID] = None,
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """admin/control_room: every AP. station: only their own station's APs (same pattern as police_stations.py::list_police_stations)."""
    if current_user.role == models.UserRole.station:
        if not current_user.station_id:
            return []
        query = models.AccessPoint.find(models.AccessPoint.station_id == current_user.station_id)
    else:
        query = models.AccessPoint.find()

    if deployment is not None:
        query = query.find(models.AccessPoint.deployment == deployment)
    if zone is not None:
        query = query.find(models.AccessPoint.zone == zone)
    if enabled is not None:
        query = query.find(models.AccessPoint.enabled == enabled)
    if lifecycle_status is not None:
        query = query.find(models.AccessPoint.lifecycle_status == lifecycle_status)
    if verification_status is not None:
        query = query.find(models.AccessPoint.verification_status == verification_status)
    if station_id is not None:
        query = query.find(models.AccessPoint.station_id == station_id)

    aps = await query.sort(models.AccessPoint.code).to_list()

    # "How many devices are currently associated" -- one aggregation for
    # the whole page rather than one query per AP (same O(1)-queries
    # discipline as constables.py::list_constables).
    counts: dict = {}
    if aps:
        pipeline = [
            {"$match": {"current_access_point_id": {"$in": [a.id for a in aps]}}},
            {"$group": {"_id": "$current_access_point_id", "n": {"$sum": 1}}},
        ]
        async for doc in models.PolicePresence.get_motor_collection().aggregate(pipeline):
            counts[doc["_id"]] = doc["n"]

    return [_to_response(a, associated_device_count=counts.get(a.id, 0)) for a in aps]


@router.get("/integration", response_model=schemas.APIntegrationStatusResponse)
async def get_integration_status(
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """Whether a controller integration exists at all -- the UI uses this to say 'cannot verify' honestly instead of offering a button that cannot work."""
    return schemas.APIntegrationStatusResponse(**ap_integration.integration_status())


# IMPORTANT ROUTING NOTE: "/zones" and "/zones/{zone}/..." must be
# registered BEFORE "/{access_point_id}" below -- same reasoning as
# cctv.py's "/nearby" / presence.py's "/me" ordering notes.
@router.get("/zones", response_model=List[schemas.ZoneSummaryResponse])
async def list_zones(
    deployment: Optional[str] = None,
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """
    A zone is a DERIVED grouping of AccessPoint.zone -- never a stored
    row (see models.py::Deployment's docstring). Computed fresh on every
    call from AccessPoint + PolicePresence (+ the in-memory moving-state
    tracker for `moving_count`) -- there is nothing to keep in sync.
    """
    if current_user.role == models.UserRole.station:
        if not current_user.station_id:
            return []
        query = models.AccessPoint.find(models.AccessPoint.station_id == current_user.station_id)
    else:
        query = models.AccessPoint.find()
    if deployment is not None:
        query = query.find(models.AccessPoint.deployment == deployment)
    aps = await query.to_list()

    zones: dict = {}
    for ap in aps:
        if not ap.zone:
            continue
        z = zones.setdefault(ap.zone, {"codes": [], "enabled": False, "deployment": ap.deployment})
        z["codes"].append(ap.code)
        z["enabled"] = z["enabled"] or ap.enabled

    police_counts: dict = {}
    if aps:
        pipeline = [
            {"$match": {"current_access_point_id": {"$in": [a.id for a in aps]}, "status": models.PresenceConnectionStatus.connected.value}},
            {"$group": {"_id": "$current_access_point_id", "n": {"$sum": 1}}},
        ]
        ap_by_id = {a.id: a for a in aps}
        async for doc in models.PolicePresence.get_motor_collection().aggregate(pipeline):
            ap = ap_by_id.get(doc["_id"])
            if ap and ap.zone:
                police_counts[ap.zone] = police_counts.get(ap.zone, 0) + doc["n"]

    moving_counts = movement_state.moving_zone_counts()

    return [
        schemas.ZoneSummaryResponse(
            zone=zone, deployment=info["deployment"], access_point_codes=sorted(info["codes"]),
            enabled=info["enabled"], police_count=police_counts.get(zone, 0), moving_count=moving_counts.get(zone, 0),
        )
        for zone, info in sorted(zones.items())
    ]


@router.post("/zones/{zone}/enable")
async def enable_zone(
    zone: str,
    deployment: Optional[str] = None,
    current_user: models.User = Depends(require_role("admin")),
):
    """Bulk-enables every AccessPoint in this zone (optionally scoped to one deployment) -- see models.py::Deployment's docstring for why a zone is enable/disable-by-proxy over its APs, not a separate stored toggle."""
    query = models.AccessPoint.find(models.AccessPoint.zone == zone)
    if deployment is not None:
        query = query.find(models.AccessPoint.deployment == deployment)
    aps = await query.to_list()
    aps = [a for a in aps if a.lifecycle_status != models.APLifecycleStatus.retired]
    for ap in aps:
        ap.enabled = True
        ap.lifecycle_status = models.APLifecycleStatus.active
        ap_integration.add_history(ap, by=current_user.id, action="enabled", changes={"via": "zone"})
        await ap.save()
    await log_action(user_id=current_user.id, action="zone_enabled", details={"zone": zone, "access_point_count": len(aps)})
    return {"status": "enabled", "zone": zone, "access_point_count": len(aps)}


@router.post("/zones/{zone}/disable")
async def disable_zone(
    zone: str,
    deployment: Optional[str] = None,
    current_user: models.User = Depends(require_role("admin")),
):
    query = models.AccessPoint.find(models.AccessPoint.zone == zone)
    if deployment is not None:
        query = query.find(models.AccessPoint.deployment == deployment)
    aps = await query.to_list()
    aps = [a for a in aps if a.lifecycle_status != models.APLifecycleStatus.retired]
    for ap in aps:
        ap.enabled = False
        ap.lifecycle_status = models.APLifecycleStatus.disabled
        ap_integration.add_history(ap, by=current_user.id, action="disabled", changes={"via": "zone"})
        await ap.save()
    await log_action(user_id=current_user.id, action="zone_disabled", details={"zone": zone, "access_point_count": len(aps)})
    return {"status": "disabled", "zone": zone, "access_point_count": len(aps)}


@router.get("/{access_point_id}", response_model=schemas.AccessPointResponse)
async def get_access_point(
    access_point_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    ap = await _get_ap_or_404(access_point_id)
    if current_user.role == models.UserRole.station and current_user.station_id != ap.station_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this access point")

    count = await models.PolicePresence.find(models.PolicePresence.current_access_point_id == ap.id).count()
    # The configuration history is an administrative record: admin and control room only.
    return _to_response(ap, associated_device_count=count, include_history=current_user.role != models.UserRole.station)


def _require_not_retired(ap: models.AccessPoint) -> None:
    if ap.lifecycle_status == models.APLifecycleStatus.retired:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This access point is retired and can no longer be changed")


@router.patch("/{access_point_id}", response_model=schemas.AccessPointResponse)
async def update_access_point(
    access_point_id: uuid.UUID,
    payload: schemas.AccessPointUpdateRequest,
    current_user: models.User = Depends(require_role("admin")),
):
    """
    admin only. Only fields explicitly provided are changed, and every change
    is recorded in the AP's configuration history. Changing a hardware
    identifier (BSSID/serial/manufacturer/management IP) of a verified AP
    withdraws its verification: the proof was about the OLD identifiers.
    """
    ap = await _get_ap_or_404(access_point_id)
    _require_not_retired(ap)
    provided = payload.model_dump(exclude_unset=True)

    if "event_zone_codes" in provided:
        provided["event_zone_codes"] = await _validate_event_zone_codes(provided["event_zone_codes"])

    changes: dict = {}
    for field in _TRACKED_FIELDS:
        if field in provided and provided[field] != getattr(ap, field):
            changes[field] = {"from": _loggable(getattr(ap, field)), "to": _loggable(provided[field])}
            setattr(ap, field, provided[field])

    if "latitude" in provided or "longitude" in provided:
        existing_lon, existing_lat = geo.lon_lat(ap.location)
        new_lat = provided["latitude"] if provided.get("latitude") is not None else existing_lat
        new_lon = provided["longitude"] if provided.get("longitude") is not None else existing_lon
        if new_lat is None or new_lon is None:
            raise HTTPException(status_code=422, detail="Both latitude and longitude are required to set an access point's location")
        if (new_lon, new_lat) != (existing_lon, existing_lat):
            changes["location"] = {"from": [existing_lon, existing_lat], "to": [new_lon, new_lat]}
            ap.location = geo.point(new_lon, new_lat)

    if ap.serial_number and not ap.manufacturer:
        raise HTTPException(status_code=422, detail="A serial number requires the manufacturer (serials are only unique per manufacturer)")

    if any(f in changes for f in _IDENTIFIER_FIELDS):
        if ap.verification_status == models.APVerificationStatus.verified:
            changes["verification_status"] = {"from": "verified", "to": "configured"}
            ap.verified_at = None
            ap.verification_source = None
            ap.last_seen_at = None
            ap.status = models.AccessPointStatus.unknown
        ap.verification_status = _initial_verification_status(ap)
        ap.last_verification_error = None

    if not changes:
        return _to_response(ap)

    ap.updated_by = current_user.id
    ap.updated_at = _utcnow()
    ap_integration.add_history(ap, by=current_user.id, action="updated", changes=changes)
    try:
        await ap.save()
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_conflict_message(exc))

    await log_action(user_id=current_user.id, action="access_point_updated", details={"access_point_id": str(access_point_id), "fields": sorted(changes)})
    return _to_response(ap)


def _loggable(value):
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


@router.post("/{access_point_id}/enable", response_model=schemas.AccessPointResponse)
async def enable_access_point(
    access_point_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin")),
):
    """Re-enables an administratively disabled AP. This is an administrative flag only: it never marks the AP online/reachable."""
    ap = await _get_ap_or_404(access_point_id)
    _require_not_retired(ap)
    ap.enabled = True
    ap.lifecycle_status = models.APLifecycleStatus.active
    ap.updated_by = current_user.id
    ap.updated_at = _utcnow()
    ap_integration.add_history(ap, by=current_user.id, action="enabled")
    await ap.save()

    await log_action(user_id=current_user.id, action="access_point_enabled", details={"access_point_id": str(access_point_id)})
    return _to_response(ap)


@router.post("/{access_point_id}/disable", response_model=schemas.AccessPointResponse)
async def disable_access_point(
    access_point_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin")),
):
    """A disabled AP can never be the target of a new association -- see routers/presence.py::associate (raises 409 via PresenceError('access_point_disabled', ...)). Does not claim the hardware is offline."""
    ap = await _get_ap_or_404(access_point_id)
    _require_not_retired(ap)
    ap.enabled = False
    ap.lifecycle_status = models.APLifecycleStatus.disabled
    ap.updated_by = current_user.id
    ap.updated_at = _utcnow()
    ap_integration.add_history(ap, by=current_user.id, action="disabled")
    await ap.save()

    await log_action(user_id=current_user.id, action="access_point_disabled", details={"access_point_id": str(access_point_id)})
    return _to_response(ap)


@router.post("/{access_point_id}/retire", response_model=schemas.AccessPointResponse)
async def retire_access_point(
    access_point_id: uuid.UUID,
    payload: schemas.AccessPointRetireRequest,
    force: bool = False,
    current_user: models.User = Depends(require_role("admin")),
):
    """
    Decommissions an AP (terminal; the record and its history are retained).
    Refused with 409 while officers are still associated, unless force=true.
    """
    ap = await _get_ap_or_404(access_point_id)
    if ap.lifecycle_status == models.APLifecycleStatus.retired:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This access point is already retired")
    active_count = await models.PolicePresence.find(models.PolicePresence.current_access_point_id == ap.id).count()
    if active_count > 0 and not force:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{active_count} police device(s) are currently associated with this access point. Pass force=true to retire it anyway.",
        )
    now = _utcnow()
    ap.lifecycle_status = models.APLifecycleStatus.retired
    ap.enabled = False
    ap.retired_at = now
    ap.retire_reason = payload.reason
    ap.status = models.AccessPointStatus.unknown
    ap.updated_by = current_user.id
    ap.updated_at = now
    ap_integration.add_history(ap, by=current_user.id, action="retired", changes={"reason": payload.reason})
    await ap.save()

    await log_action(user_id=current_user.id, action="access_point_retired", details={"access_point_id": str(access_point_id), "code": ap.code, "forced": force})
    return _to_response(ap)


@router.post("/{access_point_id}/verify", response_model=schemas.AccessPointResponse)
async def verify_access_point(
    access_point_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin")),
):
    """
    Asks the configured controller/NMS integration whether this AP exists.
    - integration not configured -> 503 `integration_unconfigured`, nothing is claimed
    - controller unreachable/misconfigured -> 502 `integration_error`
    - otherwise 200 with the honest outcome (`verified` or `verification_failed`)
    """
    ap = await _get_ap_or_404(access_point_id)
    _require_not_retired(ap)
    if not (ap.bssid or ap.serial_number or ap.management_ip):
        raise HTTPException(status_code=422, detail="Register at least a BSSID, serial number or management IP before verifying")
    try:
        await ap_integration.verify_via_integration(ap, current_user.id)
    except ap_integration.IntegrationUnconfigured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "integration_unconfigured", "message": "No AP controller integration is configured, so this access point cannot be verified. Nothing has been marked verified."},
        )
    except ap_integration.IntegrationError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail={"code": "integration_error", "message": exc.message})

    await log_action(
        user_id=current_user.id, action="access_point_verification",
        details={"access_point_id": str(access_point_id), "result": ap.verification_status.value},
    )
    return _to_response(ap)


@router.delete("/{access_point_id}")
async def delete_access_point(
    access_point_id: uuid.UUID,
    force: bool = False,
    current_user: models.User = Depends(require_role("admin")),
):
    """
    admin only, hard delete -- for mistaken/never-deployed inventory rows.
    A verified, still-active AP must be retired first (retire keeps the
    record); deleting it would erase evidence that real hardware existed.
    Historical PresenceHandoff rows referencing this access_point_id are left
    in place -- same precedent as CCTV camera deletion (app/routers/cctv.py).

    Refuses (409) when police devices are currently associated, unless
    `force=true` is explicitly passed -- deleting an AP out from under
    devices that currently report it as their current_access_point_id
    would silently orphan those presence rows (dangling foreign key) the
    next time anything tries to resolve the AP's code/name/zone for them.
    """
    ap = await _get_ap_or_404(access_point_id)

    if ap.verification_status == models.APVerificationStatus.verified and ap.lifecycle_status != models.APLifecycleStatus.retired:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This access point is verified. Retire it instead of deleting it so the record is kept.",
        )

    active_count = await models.PolicePresence.find(models.PolicePresence.current_access_point_id == ap.id).count()
    if active_count > 0 and not force:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{active_count} police device(s) are currently associated with this access point. Disable it instead, or pass force=true to delete anyway.",
        )

    await ap.delete()

    await log_action(
        user_id=current_user.id, action="access_point_deleted",
        details={"access_point_id": str(access_point_id), "code": ap.code, "forced": force, "active_devices_at_deletion": active_count},
    )
    return {"status": "deleted"}
