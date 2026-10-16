"""
Generic monitored sites: sites, optional buildings and floors, zones, floor plans.

A site is ANY monitored area (campus, mall, hospital, station, stadium, festival
ground, outdoor square, ...). Buildings and floors are optional; zones may be
geographic (boundary), indoor (a polygon on a floor plan), both, or neither.

AUTHORIZATION: admin manages everything. control_room may read the sites it is
allowed to see (services/site_access.py: restricted sites are visible only to
listed users). All other roles get 403. A site the caller may not see answers 404,
so its existence is not disclosed.
"""
import datetime
import os
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from pymongo.errors import DuplicateKeyError, OperationFailure

from .. import geo, models, schemas_network as sn
from ..auth.deps import require_role
from ..services import adapter_catalog, site_access, site_privacy
from ..services.audit import log_action
from . import media as media_module

router = APIRouter(prefix="/sites", tags=["Sites"])

require_site_viewer = require_role("admin", "control_room")
require_site_admin = require_role("admin")

_PLAN_MIMES = {"image/png": ".png", "image/jpeg": ".jpg"}


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def is_admin(user: models.User) -> bool:
    return user.role == models.UserRole.admin


async def get_site_or_404(site_id: uuid.UUID, user: models.User) -> models.MonitoredSite:
    site = await models.MonitoredSite.get(site_id)
    if site is None or not site_access.can_view_user(site, user):
        raise HTTPException(status_code=404, detail="Site not found")
    return site


# ---------------------------------------------------------------------------
# Representations
# ---------------------------------------------------------------------------

def site_out(site: models.MonitoredSite, admin: bool) -> sn.SiteResponse:
    lon, lat = geo.lon_lat(site.location)
    return sn.SiteResponse(
        id=site.id, code=site.code, name=site.name, site_type=site.site_type, custom_type_label=site.custom_type_label,
        organization=site.organization, description=site.description, address=site.address, latitude=lat, longitude=lon,
        boundary=site.boundary.coordinates if site.boundary else None, timezone=site.timezone, active=site.active,
        access_mode=site.access_mode, viewer_user_ids=list(site.viewer_user_ids) if admin else [],
        policy=sn.SitePolicyOut(
            scope_mode=site.policy.scope_mode, authorization_reference=site.policy.authorization_reference if admin else None,
            retention_days=site.policy.retention_days, store_raw_identifiers=site.policy.store_raw_identifiers,
            allowlist_size=len(site.policy.allowlist or []),
        ),
        ap_warning_clients=site.ap_warning_clients, ap_critical_clients=site.ap_critical_clients, metadata=site.metadata,
        created_at=site.created_at, updated_at=site.updated_at,
    )


def zone_out(z: models.SiteZone) -> sn.ZoneOut:
    return sn.ZoneOut(
        id=z.id, site_id=z.site_id, code=z.code, name=z.name, zone_type=z.zone_type, description=z.description,
        building_id=z.building_id, floor_id=z.floor_id, boundary=z.boundary.coordinates if z.boundary else None,
        plan_polygon=z.plan_polygon, capacity=z.capacity, warning_threshold=z.warning_threshold,
        critical_threshold=z.critical_threshold, active=z.active, display_order=z.display_order, metadata=z.metadata,
    )


def building_out(b: models.SiteBuilding) -> sn.BuildingOut:
    lon, lat = geo.lon_lat(b.location)
    return sn.BuildingOut(
        id=b.id, site_id=b.site_id, code=b.code, name=b.name, description=b.description,
        cctv_building_id=b.cctv_building_id, latitude=lat, longitude=lon, metadata=b.metadata,
    )


def floor_out(f: models.SiteFloor) -> sn.FloorOut:
    return sn.FloorOut(
        id=f.id, site_id=f.site_id, building_id=f.building_id, code=f.code, name=f.name, level=f.level, height_m=f.height_m,
        has_plan=bool(f.plan_storage_key), plan_width_px=f.plan_width_px, plan_height_px=f.plan_height_px,
        plan_meters_per_pixel=f.plan_meters_per_pixel, display_order=f.display_order, metadata=f.metadata,
    )


def _validate_policy(policy: models.SitePolicy) -> None:
    if policy.scope_mode == models.SiteMonitoringScope.all_clients and not (policy.authorization_reference or "").strip():
        raise HTTPException(status_code=422, detail="Monitoring all clients requires an authorization_reference recording who authorized it")
    if policy.store_raw_identifiers and not site_privacy.raw_storage_available():
        raise HTTPException(status_code=422, detail="Storing raw identifiers is unavailable: CLIENT_RAW_ID_KEY is not configured on the server")


async def _check_parents(site_id: uuid.UUID, building_id: Optional[uuid.UUID], floor_id: Optional[uuid.UUID]) -> None:
    if building_id is not None:
        b = await models.SiteBuilding.get(building_id)
        if not b or b.site_id != site_id:
            raise HTTPException(status_code=422, detail="building_id does not belong to this site")
    if floor_id is not None:
        f = await models.SiteFloor.get(floor_id)
        if not f or f.site_id != site_id:
            raise HTTPException(status_code=422, detail="floor_id does not belong to this site")
        if building_id is not None and f.building_id not in (None, building_id):
            raise HTTPException(status_code=422, detail="floor_id belongs to a different building")


# ===========================================================================
# Catalogue
# ===========================================================================

@router.get("/adapters", response_model=List[sn.AdapterInfo])
async def list_adapters(current_user: models.User = Depends(require_site_admin)):
    """Telemetry adapter kinds a collector can run, and honestly whether each is simulated or production-ready."""
    return adapter_catalog.ADAPTERS


@router.get("/site-types", response_model=List[str])
async def list_site_types(current_user: models.User = Depends(require_site_viewer)):
    return [t.value for t in models.SiteType]


# ===========================================================================
# Sites
# ===========================================================================

@router.post("", response_model=sn.SiteResponse, status_code=status.HTTP_201_CREATED)
async def create_site(payload: sn.SiteCreate, current_user: models.User = Depends(require_site_admin)):
    policy = models.SitePolicy()
    if payload.policy:
        data = payload.policy.model_dump(exclude_none=True)
        policy = models.SitePolicy(**data)
    _validate_policy(policy)
    now = _utcnow()
    site = models.MonitoredSite(
        code=payload.code, name=payload.name, site_type=payload.site_type, custom_type_label=payload.custom_type_label,
        organization=payload.organization, description=payload.description, address=payload.address,
        location=geo.point(payload.longitude, payload.latitude) if payload.latitude is not None else None,
        boundary=geo.polygon(payload.boundary) if payload.boundary else None, timezone=payload.timezone,
        access_mode=payload.access_mode, viewer_user_ids=payload.viewer_user_ids, policy=policy,
        ap_warning_clients=payload.ap_warning_clients, ap_critical_clients=payload.ap_critical_clients, metadata=payload.metadata,
        created_at=now, updated_at=now, created_by=current_user.id, updated_by=current_user.id,
    )
    try:
        await site.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail=f"A site with code '{payload.code}' already exists")
    except OperationFailure:
        raise HTTPException(status_code=422, detail="The boundary is not a valid polygon (for example it crosses itself)")
    await log_action(user_id=current_user.id, action="site_created", details={"site_id": str(site.id), "code": site.code, "scope_mode": policy.scope_mode.value})
    return site_out(site, True)


@router.get("", response_model=List[sn.SiteResponse])
async def list_sites(
    active: Optional[bool] = None,
    site_type: Optional[models.SiteType] = None,
    q: Optional[str] = Query(default=None, max_length=100),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(require_site_viewer),
):
    query: dict = {}
    if active is not None:
        query["active"] = active
    if site_type is not None:
        query["site_type"] = site_type.value
    if q:
        import re

        pattern = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [{"name": pattern}, {"code": pattern}]
    sites = await models.MonitoredSite.find(query).sort("name").skip(offset).limit(limit).to_list()
    return [site_out(s, is_admin(current_user)) for s in sites if site_access.can_view_user(s, current_user)]


@router.get("/{site_id}", response_model=sn.SiteResponse)
async def get_site(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    return site_out(await get_site_or_404(site_id, current_user), is_admin(current_user))


@router.patch("/{site_id}", response_model=sn.SiteResponse)
async def update_site(site_id: uuid.UUID, payload: sn.SiteUpdate, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    for field in ("name", "site_type", "custom_type_label", "organization", "description", "address", "timezone", "active",
                  "access_mode", "ap_warning_clients", "ap_critical_clients", "metadata"):
        value = getattr(payload, field)
        if value is not None:
            setattr(site, field, value)
    if payload.viewer_user_ids is not None:
        site.viewer_user_ids = payload.viewer_user_ids
    if payload.latitude is not None and payload.longitude is not None:
        site.location = geo.point(payload.longitude, payload.latitude)
    elif (payload.latitude is None) != (payload.longitude is None):
        raise HTTPException(status_code=422, detail="latitude and longitude must be given together")
    if payload.clear_boundary:
        site.boundary = None
    elif payload.boundary:
        site.boundary = geo.polygon(payload.boundary)
    if payload.policy:
        data = payload.policy.model_dump(exclude_none=True)
        merged = site.policy.model_copy(update=data)
        _validate_policy(merged)
        site.policy = merged
    if site.ap_warning_clients and site.ap_critical_clients and site.ap_warning_clients > site.ap_critical_clients:
        raise HTTPException(status_code=422, detail="ap_warning_clients cannot exceed ap_critical_clients")
    site.updated_at = _utcnow()
    site.updated_by = current_user.id
    try:
        await site.save()
    except OperationFailure:
        raise HTTPException(status_code=422, detail="The boundary is not a valid polygon (for example it crosses itself)")
    await log_action(
        user_id=current_user.id, action="site_updated",
        details={"site_id": str(site.id), "fields": sorted(payload.model_fields_set), "policy_changed": payload.policy is not None},
    )
    return site_out(site, True)


@router.post("/{site_id}/allowlist", response_model=sn.AllowlistResponse)
async def add_to_allowlist(site_id: uuid.UUID, payload: sn.AllowlistRequest, current_user: models.User = Depends(require_site_admin)):
    """Authorizes specific devices for an `allowlist` site. Raw identifiers are hashed on arrival and never stored."""
    site = await get_site_or_404(site_id, current_user)
    if not site_privacy.is_configured():
        raise HTTPException(status_code=503, detail="CLIENT_ID_HMAC_KEY is not configured")
    existing = set(site.policy.allowlist or [])
    try:
        new = {site_privacy.pseudonymize(site.id, raw) for raw in payload.identifiers if raw.strip()}
    except ValueError:
        raise HTTPException(status_code=422, detail="identifiers must not be empty")
    added = len(new - existing)
    site.policy.allowlist = sorted(existing | new)
    site.updated_at = _utcnow()
    site.updated_by = current_user.id
    await site.save()
    await log_action(user_id=current_user.id, action="site_allowlist_added", details={"site_id": str(site.id), "added": added})
    return sn.AllowlistResponse(added=added, allowlist_size=len(site.policy.allowlist))


@router.delete("/{site_id}/allowlist/{pseudonym}")
async def remove_from_allowlist(site_id: uuid.UUID, pseudonym: str, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    if pseudonym not in (site.policy.allowlist or []):
        raise HTTPException(status_code=404, detail="Not on the allowlist")
    site.policy.allowlist = [p for p in site.policy.allowlist if p != pseudonym]
    site.updated_at = _utcnow()
    await site.save()
    await log_action(user_id=current_user.id, action="site_allowlist_removed", details={"site_id": str(site.id)})
    return {"status": "removed", "allowlist_size": len(site.policy.allowlist)}


@router.delete("/{site_id}")
async def delete_site(
    site_id: uuid.UUID,
    force: bool = Query(default=False, description="Also delete the site's zones, buildings, floors, switches, controllers, collectors and ALL monitoring data."),
    current_user: models.User = Depends(require_site_admin),
):
    """Refuses while the site still has configuration unless `force=true`. APs are never deleted: they are detached from the site."""
    site = await get_site_or_404(site_id, current_user)
    counts = {
        "zones": await models.SiteZone.find({"site_id": site.id}).count(),
        "collectors": await models.Collector.find({"site_id": site.id}).count(),
        "access_points": await models.AccessPoint.find({"site_id": site.id}).count(),
    }
    if any(counts.values()) and not force:
        raise HTTPException(status_code=409, detail=f"Site still has {counts}; deactivate it instead or pass force=true")
    if force:
        for model in (models.SiteZone, models.SiteBuilding, models.NetworkSwitch, models.NetworkController, models.Collector,
                      models.ClientAssociation, models.NetworkEvent, models.OccupancySample, models.ThresholdBreach, models.AvailabilityEvent):
            await model.get_motor_collection().delete_many({"site_id": site.id})
        for floor in await models.SiteFloor.find({"site_id": site.id}).to_list():
            if floor.plan_storage_key:
                media_module._get_storage_backend().delete(floor.plan_storage_key)
            await floor.delete()
        await models.AccessPoint.get_motor_collection().update_many(
            {"site_id": site.id},
            {"$set": {"site_id": None, "site_zone_id": None, "site_building_id": None, "site_floor_id": None, "controller_id": None, "switch_id": None, "switch_port": None}},
        )
    await site.delete()
    await log_action(user_id=current_user.id, action="site_deleted", details={"site_id": str(site_id), "code": site.code, "forced": force, **counts})
    return {"status": "deleted", **counts}


# ===========================================================================
# Buildings (optional)
# ===========================================================================

@router.post("/{site_id}/buildings", response_model=sn.BuildingOut, status_code=201)
async def create_building(site_id: uuid.UUID, payload: sn.BuildingIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    b = models.SiteBuilding(
        site_id=site.id, code=payload.code, name=payload.name, description=payload.description, cctv_building_id=payload.cctv_building_id,
        location=geo.point(payload.longitude, payload.latitude) if payload.latitude is not None and payload.longitude is not None else None,
        metadata=payload.metadata,
    )
    try:
        await b.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail=f"Building code '{payload.code}' already exists in this site")
    await log_action(user_id=current_user.id, action="site_building_created", details={"site_id": str(site.id), "building_id": str(b.id)})
    return building_out(b)


@router.get("/{site_id}/buildings", response_model=List[sn.BuildingOut])
async def list_buildings(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    return [building_out(b) for b in await models.SiteBuilding.find({"site_id": site.id}).sort("code").to_list()]


@router.patch("/{site_id}/buildings/{building_id}", response_model=sn.BuildingOut)
async def update_building(site_id: uuid.UUID, building_id: uuid.UUID, payload: sn.BuildingPatch, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    b = await models.SiteBuilding.get(building_id)
    if not b or b.site_id != site.id:
        raise HTTPException(status_code=404, detail="Building not found")
    for field in ("name", "description", "cctv_building_id", "metadata"):
        value = getattr(payload, field)
        if value is not None:
            setattr(b, field, value)
    if payload.latitude is not None and payload.longitude is not None:
        b.location = geo.point(payload.longitude, payload.latitude)
    b.updated_at = _utcnow()
    await b.save()
    await log_action(user_id=current_user.id, action="site_building_updated", details={"site_id": str(site.id), "building_id": str(b.id)})
    return building_out(b)


@router.delete("/{site_id}/buildings/{building_id}")
async def delete_building(site_id: uuid.UUID, building_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    b = await models.SiteBuilding.get(building_id)
    if not b or b.site_id != site.id:
        raise HTTPException(status_code=404, detail="Building not found")
    if await models.SiteFloor.find({"site_id": site.id, "building_id": b.id}).count():
        raise HTTPException(status_code=409, detail="Building still has floors; delete or move them first")
    await models.SiteZone.get_motor_collection().update_many({"site_id": site.id, "building_id": b.id}, {"$set": {"building_id": None}})
    await models.AccessPoint.get_motor_collection().update_many({"site_id": site.id, "site_building_id": b.id}, {"$set": {"site_building_id": None}})
    await b.delete()
    await log_action(user_id=current_user.id, action="site_building_deleted", details={"site_id": str(site.id), "building_id": str(building_id)})
    return {"status": "deleted"}


# ===========================================================================
# Floors (optional) and floor plans
# ===========================================================================

@router.post("/{site_id}/floors", response_model=sn.FloorOut, status_code=201)
async def create_floor(site_id: uuid.UUID, payload: sn.FloorIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    await _check_parents(site.id, payload.building_id, None)
    f = models.SiteFloor(
        site_id=site.id, building_id=payload.building_id, code=payload.code, name=payload.name, level=payload.level,
        height_m=payload.height_m, plan_meters_per_pixel=payload.plan_meters_per_pixel, display_order=payload.display_order, metadata=payload.metadata,
    )
    try:
        await f.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail=f"Floor code '{payload.code}' already exists in this site")
    await log_action(user_id=current_user.id, action="site_floor_created", details={"site_id": str(site.id), "floor_id": str(f.id)})
    return floor_out(f)


@router.get("/{site_id}/floors", response_model=List[sn.FloorOut])
async def list_floors(site_id: uuid.UUID, building_id: Optional[uuid.UUID] = None, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    query = {"site_id": site.id}
    if building_id:
        query["building_id"] = building_id
    return [floor_out(f) for f in await models.SiteFloor.find(query).sort("display_order", "code").to_list()]


@router.patch("/{site_id}/floors/{floor_id}", response_model=sn.FloorOut)
async def update_floor(site_id: uuid.UUID, floor_id: uuid.UUID, payload: sn.FloorPatch, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    f = await models.SiteFloor.get(floor_id)
    if not f or f.site_id != site.id:
        raise HTTPException(status_code=404, detail="Floor not found")
    if payload.building_id is not None:
        await _check_parents(site.id, payload.building_id, None)
        f.building_id = payload.building_id
    for field in ("name", "level", "height_m", "plan_meters_per_pixel", "display_order", "metadata"):
        value = getattr(payload, field)
        if value is not None:
            setattr(f, field, value)
    f.updated_at = _utcnow()
    await f.save()
    await log_action(user_id=current_user.id, action="site_floor_updated", details={"site_id": str(site.id), "floor_id": str(f.id)})
    return floor_out(f)


@router.delete("/{site_id}/floors/{floor_id}")
async def delete_floor(site_id: uuid.UUID, floor_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    f = await models.SiteFloor.get(floor_id)
    if not f or f.site_id != site.id:
        raise HTTPException(status_code=404, detail="Floor not found")
    await models.SiteZone.get_motor_collection().update_many({"site_id": site.id, "floor_id": f.id}, {"$set": {"floor_id": None, "plan_polygon": None}})
    await models.AccessPoint.get_motor_collection().update_many(
        {"site_id": site.id, "site_floor_id": f.id}, {"$set": {"site_floor_id": None, "plan_x": None, "plan_y": None}}
    )
    if f.plan_storage_key:
        media_module._get_storage_backend().delete(f.plan_storage_key)
    await f.delete()
    await log_action(user_id=current_user.id, action="site_floor_deleted", details={"site_id": str(site.id), "floor_id": str(floor_id)})
    return {"status": "deleted"}


@router.post("/{site_id}/floors/{floor_id}/plan", response_model=sn.FloorOut)
async def upload_floor_plan(
    site_id: uuid.UUID, floor_id: uuid.UUID,
    width_px: Optional[int] = Query(default=None, ge=1, le=20000), height_px: Optional[int] = Query(default=None, ge=1, le=20000),
    file: UploadFile = File(...), current_user: models.User = Depends(require_site_admin),
):
    """Stores a PNG/JPEG floor plan using the same storage backend as evidence (local disk or S3). The type is decided from the file's bytes, not its name."""
    site = await get_site_or_404(site_id, current_user)
    f = await models.SiteFloor.get(floor_id)
    if not f or f.site_id != site.id:
        raise HTTPException(status_code=404, detail="Floor not found")
    max_bytes = int(os.getenv("FLOOR_PLAN_MAX_MB", "10")) * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail="Floor plan is too large")
    mime = media_module._sniff_mime_type(data[:64])
    if mime not in _PLAN_MIMES:
        raise HTTPException(status_code=400, detail="Floor plans must be PNG or JPEG images")
    storage = media_module._get_storage_backend()
    key = f"site-plans/{site.id}/{f.id}/{uuid.uuid4().hex}{_PLAN_MIMES[mime]}"
    with storage.open_write(key) as out:
        out.write(data)
    old_key = f.plan_storage_key
    f.plan_storage_key, f.plan_mime = key, mime
    f.plan_width_px, f.plan_height_px = width_px or f.plan_width_px, height_px or f.plan_height_px
    f.updated_at = _utcnow()
    await f.save()
    if old_key:
        storage.delete(old_key)
    await log_action(user_id=current_user.id, action="site_floor_plan_uploaded", details={"site_id": str(site.id), "floor_id": str(f.id), "bytes": len(data)})
    return floor_out(f)


@router.get("/{site_id}/floors/{floor_id}/plan")
async def get_floor_plan(site_id: uuid.UUID, floor_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    f = await models.SiteFloor.get(floor_id)
    if not f or f.site_id != site.id or not f.plan_storage_key:
        raise HTTPException(status_code=404, detail="No floor plan")
    storage = media_module._get_storage_backend()
    size = storage.get_size(f.plan_storage_key)
    if not size:
        raise HTTPException(status_code=404, detail="Floor plan file is missing")
    return StreamingResponse(
        storage.read_range(f.plan_storage_key, 0, size - 1), media_type=f.plan_mime or "image/png",
        headers={"Content-Length": str(size), "Cache-Control": "private, max-age=300"},
    )


# ===========================================================================
# Zones
# ===========================================================================

@router.post("/{site_id}/zones", response_model=sn.ZoneOut, status_code=201)
async def create_zone(site_id: uuid.UUID, payload: sn.ZoneIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    await _check_parents(site.id, payload.building_id, payload.floor_id)
    if payload.plan_polygon and not payload.floor_id:
        raise HTTPException(status_code=422, detail="plan_polygon needs a floor_id (it is drawn on that floor's plan)")
    z = models.SiteZone(
        site_id=site.id, code=payload.code, name=payload.name, zone_type=payload.zone_type, description=payload.description,
        building_id=payload.building_id, floor_id=payload.floor_id, boundary=geo.polygon(payload.boundary) if payload.boundary else None,
        plan_polygon=payload.plan_polygon, capacity=payload.capacity, warning_threshold=payload.warning_threshold,
        critical_threshold=payload.critical_threshold, display_order=payload.display_order, metadata=payload.metadata,
    )
    try:
        await z.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail=f"Zone code '{payload.code}' already exists in this site")
    except OperationFailure:
        raise HTTPException(status_code=422, detail="The zone boundary is not a valid polygon (for example it crosses itself)")
    await log_action(user_id=current_user.id, action="site_zone_created", details={"site_id": str(site.id), "zone_id": str(z.id)})
    return zone_out(z)


@router.get("/{site_id}/zones", response_model=List[sn.ZoneOut])
async def list_zones(site_id: uuid.UUID, floor_id: Optional[uuid.UUID] = None, active: Optional[bool] = None, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    query: dict = {"site_id": site.id}
    if floor_id:
        query["floor_id"] = floor_id
    if active is not None:
        query["active"] = active
    return [zone_out(z) for z in await models.SiteZone.find(query).sort("display_order", "code").to_list()]


@router.patch("/{site_id}/zones/{zone_id}", response_model=sn.ZoneOut)
async def update_zone(site_id: uuid.UUID, zone_id: uuid.UUID, payload: sn.ZonePatch, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    z = await models.SiteZone.get(zone_id)
    if not z or z.site_id != site.id:
        raise HTTPException(status_code=404, detail="Zone not found")
    await _check_parents(site.id, payload.building_id, payload.floor_id)
    for field in ("name", "zone_type", "description", "building_id", "floor_id", "capacity", "active", "display_order", "metadata"):
        value = getattr(payload, field)
        if value is not None:
            setattr(z, field, value)
    if payload.clear_boundary:
        z.boundary = None
    elif payload.boundary:
        z.boundary = geo.polygon(payload.boundary)
    if payload.clear_plan_polygon:
        z.plan_polygon = None
    elif payload.plan_polygon:
        if not z.floor_id:
            raise HTTPException(status_code=422, detail="plan_polygon needs a floor_id")
        z.plan_polygon = payload.plan_polygon
    if payload.clear_thresholds:
        z.warning_threshold = z.critical_threshold = None
    else:
        if payload.warning_threshold is not None:
            z.warning_threshold = payload.warning_threshold
        if payload.critical_threshold is not None:
            z.critical_threshold = payload.critical_threshold
    if z.warning_threshold and z.critical_threshold and z.warning_threshold > z.critical_threshold:
        raise HTTPException(status_code=422, detail="warning_threshold cannot exceed critical_threshold")
    z.updated_at = _utcnow()
    try:
        await z.save()
    except OperationFailure:
        raise HTTPException(status_code=422, detail="The zone boundary is not a valid polygon (for example it crosses itself)")
    # Denormalized placement used for counting follows the zone.
    if payload.floor_id is not None or payload.building_id is not None:
        await models.AccessPoint.get_motor_collection().update_many(
            {"site_id": site.id, "site_zone_id": z.id}, {"$set": {"site_floor_id": z.floor_id, "site_building_id": z.building_id}}
        )
        await models.ClientAssociation.get_motor_collection().update_many(
            {"site_id": site.id, "zone_id": z.id}, {"$set": {"floor_id": z.floor_id, "building_id": z.building_id}}
        )
    await log_action(user_id=current_user.id, action="site_zone_updated", details={"site_id": str(site.id), "zone_id": str(z.id)})
    return zone_out(z)


@router.delete("/{site_id}/zones/{zone_id}")
async def delete_zone(site_id: uuid.UUID, zone_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    z = await models.SiteZone.get(zone_id)
    if not z or z.site_id != site.id:
        raise HTTPException(status_code=404, detail="Zone not found")
    await models.AccessPoint.get_motor_collection().update_many({"site_id": site.id, "site_zone_id": z.id}, {"$set": {"site_zone_id": None}})
    await models.ClientAssociation.get_motor_collection().update_many({"site_id": site.id, "zone_id": z.id}, {"$set": {"zone_id": None}})
    await z.delete()
    await log_action(user_id=current_user.id, action="site_zone_deleted", details={"site_id": str(site.id), "zone_id": str(zone_id)})
    return {"status": "deleted"}
