"""
Access point (AP) management -- the fixed-infrastructure half of the
AP-based presence feature (see app/models.py's module docstring above
AccessPoint). Authorization mirrors app/routers/police_stations.py
exactly: admin manages, admin/control_room/station(own) view, constable
and citizen have no access to this asset list at all (a constable's own
device reports its association via app/routers/presence.py -- it never
needs to browse the AP roster itself).
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

router = APIRouter(prefix="/access-points", tags=["Access Points"])


def _to_response(ap: models.AccessPoint, associated_device_count: Optional[int] = None) -> schemas.AccessPointResponse:
    lon, lat = geo.lon_lat(ap.location)
    return schemas.AccessPointResponse(
        id=ap.id, code=ap.code, name=ap.name, description=ap.description, zone=ap.zone, deployment=ap.deployment,
        station_id=ap.station_id, latitude=lat, longitude=lon, coverage_radius_m=ap.coverage_radius_m,
        edge_node_id=ap.edge_node_id, enabled=ap.enabled,
        status=ap.status, is_demo=ap.is_demo, created_at=ap.created_at, updated_at=ap.updated_at,
        associated_device_count=associated_device_count,
    )


async def _get_ap_or_404(access_point_id: uuid.UUID) -> models.AccessPoint:
    ap = await models.AccessPoint.get(access_point_id)
    if not ap:
        raise HTTPException(status_code=404, detail="Access point not found")
    return ap


@router.post("/", response_model=schemas.AccessPointResponse)
async def create_access_point(
    payload: schemas.AccessPointCreateRequest,
    current_user: models.User = Depends(require_role("admin")),
):
    """admin only -- same role restriction as POST /police-stations/."""
    location = geo.point(payload.longitude, payload.latitude) if (payload.latitude is not None and payload.longitude is not None) else None
    ap = models.AccessPoint(
        code=payload.code, name=payload.name, description=payload.description, zone=payload.zone, deployment=payload.deployment,
        station_id=payload.station_id, location=location, coverage_radius_m=payload.coverage_radius_m,
        edge_node_id=payload.edge_node_id, is_demo=payload.is_demo,
        created_by=current_user.id, updated_by=current_user.id,
    )
    try:
        await ap.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"An access point with code '{payload.code}' already exists")

    await log_action(user_id=current_user.id, action="access_point_created", details={"access_point_id": str(ap.id), "code": ap.code})
    return _to_response(ap)


@router.get("/", response_model=List[schemas.AccessPointResponse])
async def list_access_points(
    deployment: Optional[str] = None,
    zone: Optional[str] = None,
    enabled: Optional[bool] = None,
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
    for ap in aps:
        ap.enabled = True
        ap.status = models.AccessPointStatus.online
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
    for ap in aps:
        ap.enabled = False
        ap.status = models.AccessPointStatus.offline
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
    return _to_response(ap, associated_device_count=count)


@router.patch("/{access_point_id}", response_model=schemas.AccessPointResponse)
async def update_access_point(
    access_point_id: uuid.UUID,
    payload: schemas.AccessPointUpdateRequest,
    current_user: models.User = Depends(require_role("admin")),
):
    """admin only. Only fields explicitly provided are changed."""
    ap = await _get_ap_or_404(access_point_id)

    if payload.name is not None:
        ap.name = payload.name
    if payload.description is not None:
        ap.description = payload.description
    if payload.zone is not None:
        ap.zone = payload.zone
    if payload.deployment is not None:
        ap.deployment = payload.deployment
    if payload.station_id is not None:
        ap.station_id = payload.station_id
    if payload.latitude is not None or payload.longitude is not None:
        existing_lon, existing_lat = geo.lon_lat(ap.location)
        new_lat = payload.latitude if payload.latitude is not None else existing_lat
        new_lon = payload.longitude if payload.longitude is not None else existing_lon
        if new_lat is None or new_lon is None:
            raise HTTPException(status_code=422, detail="Both latitude and longitude are required to set an access point's location")
        ap.location = geo.point(new_lon, new_lat)
    if payload.coverage_radius_m is not None:
        ap.coverage_radius_m = payload.coverage_radius_m
    if payload.edge_node_id is not None:
        ap.edge_node_id = payload.edge_node_id
    if payload.is_demo is not None:
        ap.is_demo = payload.is_demo

    ap.updated_by = current_user.id
    ap.updated_at = datetime.datetime.now(datetime.timezone.utc)
    await ap.save()

    await log_action(user_id=current_user.id, action="access_point_updated", details={"access_point_id": str(access_point_id)})
    return _to_response(ap)


@router.post("/{access_point_id}/enable", response_model=schemas.AccessPointResponse)
async def enable_access_point(
    access_point_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin")),
):
    ap = await _get_ap_or_404(access_point_id)
    ap.enabled = True
    ap.status = models.AccessPointStatus.online
    ap.updated_by = current_user.id
    await ap.save()

    await log_action(user_id=current_user.id, action="access_point_enabled", details={"access_point_id": str(access_point_id)})
    return _to_response(ap)


@router.post("/{access_point_id}/disable", response_model=schemas.AccessPointResponse)
async def disable_access_point(
    access_point_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin")),
):
    """A disabled AP can never be the target of a new association -- see routers/presence.py::associate (raises 409 via PresenceError('access_point_disabled', ...))."""
    ap = await _get_ap_or_404(access_point_id)
    ap.enabled = False
    ap.status = models.AccessPointStatus.offline
    ap.updated_by = current_user.id
    await ap.save()

    await log_action(user_id=current_user.id, action="access_point_disabled", details={"access_point_id": str(access_point_id)})
    return _to_response(ap)


@router.delete("/{access_point_id}")
async def delete_access_point(
    access_point_id: uuid.UUID,
    force: bool = False,
    current_user: models.User = Depends(require_role("admin")),
):
    """
    admin only, hard delete. Historical PresenceHandoff rows referencing
    this access_point_id are left in place -- same precedent as CCTV
    camera deletion (app/routers/cctv.py).

    Refuses (409) when police devices are currently associated, unless
    `force=true` is explicitly passed -- deleting an AP out from under
    devices that currently report it as their current_access_point_id
    would silently orphan those presence rows (dangling foreign key) the
    next time anything tries to resolve the AP's code/name/zone for them.
    Disabling is the recommended non-destructive alternative (see
    disable_access_point above); force=true is for a deliberate admin
    cleanup action, confirmed client-side before being sent.
    """
    ap = await _get_ap_or_404(access_point_id)

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
