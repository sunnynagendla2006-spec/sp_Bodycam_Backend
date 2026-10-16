"""
Building management for CCTV: one Building = one control-room slot, many
cameras. Built on the existing CCTV domain (models.CCTVCamera) rather than
beside it: a building simply groups cameras, and cameras registered before
buildings existed keep working as standalone (building_id=None) cameras that
an admin can later assign with PUT /cctv/cameras/{id}/building.

AUTHORIZATION (same split as app/routers/cctv.py, reusing its dependencies):
  * admin           -- create/update/enable/disable/delete buildings and
                       their cameras; sees infrastructure details
                       (IPs, authorized networks, recorder endpoint).
  * control_room    -- read-only: list/get buildings and watch feeds. The
                       owner contact, IPs and recorder endpoint are withheld.
  * everyone else   -- 403, enforced here, never left to the frontend.

CREDENTIALS: recorder/camera secrets are accepted as input only, Fernet
encrypted immediately (services/cctv_security.py) and never returned; only
`recorder_credentials_configured` is exposed.

SSRF: every recorder/camera destination is validated against the global
allowlist PLUS the building's admin-authorized networks (never widening the
policy for any other building) before it is stored.
"""
import datetime
import re
import uuid
from types import SimpleNamespace
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pymongo.errors import DuplicateKeyError

from .. import geo, models, schemas
from ..services import cctv_buildings, cctv_health, cctv_playback, cctv_security, cctv_sources, events
from ..services.audit import log_action
from .cctv import _get_camera_or_404, _to_camera_response, require_cctv_admin, require_cctv_viewer

router = APIRouter(prefix="/cctv/buildings", tags=["CCTV Buildings"])
camera_router = APIRouter(prefix="/cctv/cameras", tags=["CCTV Buildings"])


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _is_admin(user: models.User) -> bool:
    return user.role == models.UserRole.admin


async def _get_building_or_404(building_id: uuid.UUID) -> models.Building:
    building = await models.Building.get(building_id)
    if not building:
        raise HTTPException(status_code=404, detail="Building not found")
    return building


async def _cameras_of(building_id: uuid.UUID) -> List[models.CCTVCamera]:
    return await models.CCTVCamera.find(models.CCTVCamera.building_id == building_id).to_list()


async def _detail(building: models.Building, user: models.User) -> schemas.BuildingDetailResponse:
    return cctv_buildings.to_response(building, await _cameras_of(building.id), _is_admin(user))


def _validate_target_or_400(building: models.Building, host: str, port: int) -> None:
    try:
        with cctv_security.extra_networks(cctv_sources.networks_for_building(building)):
            cctv_security.validate_stream_target(host, port)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Camera network target rejected: {exc}")


def _make_camera(
    building: models.Building, inp: schemas.BuildingCameraInput, index: int, user_id: uuid.UUID, now: datetime.datetime, is_demo: bool = False
) -> models.CCTVCamera:
    nvr = building.connection_mode == models.CCTVConnectionMode.nvr
    if nvr:
        channel = inp.channel if inp.channel is not None else index + 1
        host, port, protocol, path = building.recorder_host, building.recorder_port, building.recorder_protocol, None
        default_code = f"{building.code}-CH{channel:02d}"
    else:
        if not inp.stream_host:
            raise HTTPException(status_code=422, detail=f"Camera '{inp.name}' needs a stream_host in direct-IP mode")
        channel = inp.channel
        host, port, protocol = inp.stream_host, inp.stream_port, inp.stream_protocol
        try:
            path = cctv_sources.validate_path(inp.stream_path) if inp.stream_path else None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Camera '{inp.name}': {exc}")
        default_code = f"{building.code}-CAM{index + 1:02d}"

    lon, lat = geo.lon_lat(building.location)
    if inp.latitude is not None and inp.longitude is not None:
        lon, lat = inp.longitude, inp.latitude
    return models.CCTVCamera(
        name=inp.name,
        camera_code=(inp.camera_code or default_code)[:64],
        description=inp.description,
        zone=building.zone,
        address=building.address,
        location=geo.point(lon, lat) if lon is not None and lat is not None else None,
        provider_type=models.CCTVProviderType(inp.provider_type),
        stream_protocol=protocol,
        stream_host=host,
        stream_port=port,
        stream_path=path,
        management_url=inp.management_url,
        username=inp.username,
        encrypted_secret=cctv_security.encrypt_secret(inp.secret) if inp.secret else None,
        enabled=inp.enabled,
        status=models.CCTVCameraStatus.unknown if inp.enabled else models.CCTVCameraStatus.disabled,
        is_demo=is_demo,
        building_id=building.id,
        channel=channel,
        sort_order=inp.sort_order if inp.sort_order is not None else index,
        created_at=now, updated_at=now, created_by=user_id, updated_by=user_id,
    )


# ===========================================================================
# Static paths first (before /{building_id}).
# ===========================================================================

@router.get("/zones", response_model=List[str])
async def list_zones(current_user: models.User = Depends(require_cctv_viewer)):
    """Distinct zone names of registered buildings, for the dashboard's zone filter."""
    zones = await models.Building.get_motor_collection().distinct("zone")
    return sorted(z for z in zones if z)


@router.get("/unassigned-cameras", response_model=List[schemas.CCTVCameraResponse])
async def list_unassigned_cameras(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(require_cctv_admin),
):
    """admin-only. Cameras registered before buildings existed (or detached from one) -- candidates for PUT /cctv/cameras/{id}/building."""
    cameras = await (
        models.CCTVCamera.find({"building_id": None}).sort(models.CCTVCamera.camera_code).skip(offset).limit(limit).to_list()
    )
    return [_to_camera_response(c) for c in cameras]


@router.post("/health/run", response_model=schemas.CCTVHealthRunResponse)
async def run_health_cycle(current_user: models.User = Depends(require_cctv_admin)):
    """admin-only. Runs one bounded health-check cycle now, ignoring each camera's back-off schedule. Lets an external scheduler (cron/Kubernetes CronJob) drive monitoring instead of the in-process loop (CCTV_HEALTH_ENABLED)."""
    summary = await cctv_health.run_cycle(force=True)
    await log_action(user_id=current_user.id, action="cctv_health_cycle_run", details=summary.as_dict())
    return schemas.CCTVHealthRunResponse(**summary.as_dict())


# ===========================================================================
# Building CRUD
# ===========================================================================

@router.post("", response_model=schemas.BuildingDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_building(payload: schemas.BuildingCreateRequest, current_user: models.User = Depends(require_cctv_admin)):
    """admin-only. Creates the building and (optionally) its initial camera rows in one call. NVR mode: one row per channel (channel defaults to the row position). Camera count is not stored; it is derived."""
    now = _utcnow()
    building = models.Building(
        name=payload.name, code=payload.code, owner_name=payload.owner_name, owner_contact=payload.owner_contact,
        zone=payload.zone, address=payload.address, location=geo.point(payload.longitude, payload.latitude),
        public_ip=payload.public_ip, connection_mode=payload.connection_mode, network_access=payload.network_access,
        authorized_networks=payload.authorized_networks, recorder_vendor=payload.recorder_vendor,
        recorder_protocol=payload.recorder_protocol, recorder_host=payload.recorder_host, recorder_port=payload.recorder_port,
        stream_path_template=payload.stream_path_template, recorder_username=payload.recorder_username,
        recorder_encrypted_secret=cctv_security.encrypt_secret(payload.recorder_secret) if payload.recorder_secret else None,
        enabled=True, created_at=now, updated_at=now, created_by=current_user.id, updated_by=current_user.id,
    )
    if building.connection_mode == models.CCTVConnectionMode.nvr:
        _validate_target_or_400(building, building.recorder_host, building.recorder_port)

    channels = [c.channel for c in payload.cameras if c.channel is not None]
    if len(channels) != len(set(channels)):
        raise HTTPException(status_code=422, detail="Two cameras use the same NVR channel number")

    cameras = [_make_camera(building, inp, i, current_user.id, now, payload.is_demo) for i, inp in enumerate(payload.cameras)]
    if building.connection_mode == models.CCTVConnectionMode.direct_ip:
        for cam in cameras:
            _validate_target_or_400(building, cam.stream_host, cam.stream_port)

    try:
        await building.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"A building with code '{payload.code}' already exists")

    inserted: List[models.CCTVCamera] = []
    try:
        for cam in cameras:
            await cam.insert()
            inserted.append(cam)
    except DuplicateKeyError:
        # Compensate (no multi-document transaction assumed): leave nothing half-created.
        for cam in inserted:
            await cam.delete()
        await building.delete()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A camera_code in this request already exists")

    await log_action(
        user_id=current_user.id, action="building_created",
        details={"building_id": str(building.id), "code": building.code, "mode": building.connection_mode.value, "cameras": len(inserted)},
    )
    await events.publish_cctv_building_changed(building, "created")
    return cctv_buildings.to_response(building, inserted, True)


@router.get("", response_model=schemas.BuildingListResponse)
async def list_buildings(
    zone: Optional[str] = None,
    enabled: Optional[bool] = None,
    q: Optional[str] = Query(default=None, max_length=100, description="name/code substring"),
    limit: int = Query(default=24, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(require_cctv_viewer),
):
    """admin/control_room. Paginated, with each building's cameras embedded so a dashboard page needs a single request."""
    query = {}
    if zone:
        query["zone"] = zone
    if enabled is not None:
        query["enabled"] = enabled
    if q:
        pattern = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [{"name": pattern}, {"code": pattern}]

    total = await models.Building.find(query).count()
    buildings = await models.Building.find(query).sort([("zone", 1), ("name", 1)]).skip(offset).limit(limit).to_list()
    grouped = await cctv_buildings.cameras_by_building(b.id for b in buildings)
    admin = _is_admin(current_user)
    return schemas.BuildingListResponse(
        items=[cctv_buildings.to_response(b, grouped.get(b.id, []), admin) for b in buildings],
        total=total, limit=limit, offset=offset,
    )


@router.get("/{building_id}", response_model=schemas.BuildingDetailResponse)
async def get_building(building_id: uuid.UUID, current_user: models.User = Depends(require_cctv_viewer)):
    return await _detail(await _get_building_or_404(building_id), current_user)


@router.patch("/{building_id}", response_model=schemas.BuildingDetailResponse)
async def update_building(
    building_id: uuid.UUID, payload: schemas.BuildingUpdateRequest, current_user: models.User = Depends(require_cctv_admin)
):
    """admin-only. Only provided fields change; the merged result is re-validated. Changing the recorder endpoint re-validates it against the SSRF policy and updates the building's NVR cameras. The connection mode itself cannot be switched while the building has cameras."""
    building = await _get_building_or_404(building_id)
    cameras = await _cameras_of(building.id)
    provided = payload.model_fields_set

    if payload.connection_mode is not None and payload.connection_mode != building.connection_mode and cameras:
        raise HTTPException(status_code=409, detail="Remove or re-create the building's cameras before switching its connection mode")

    simple = ("name", "owner_name", "owner_contact", "zone", "address", "network_access", "authorized_networks",
              "recorder_vendor", "recorder_protocol", "recorder_host", "recorder_port", "stream_path_template",
              "recorder_username", "connection_mode")
    merged = SimpleNamespace(**{f: getattr(building, f) for f in simple}, public_ip=building.public_ip)
    for field in simple:
        value = getattr(payload, field)
        if value is not None:
            setattr(merged, field, value)
    if payload.clear_public_ip:
        merged.public_ip = None
    elif payload.public_ip is not None:
        merged.public_ip = payload.public_ip
    try:
        schemas.check_building_consistency(merged)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    for field in simple:
        setattr(building, field, getattr(merged, field))
    building.public_ip = merged.public_ip
    if payload.latitude is not None or payload.longitude is not None:
        old_lon, old_lat = geo.lon_lat(building.location)
        new_lat = payload.latitude if payload.latitude is not None else old_lat
        new_lon = payload.longitude if payload.longitude is not None else old_lon
        if new_lat is None or new_lon is None:
            raise HTTPException(status_code=422, detail="Both latitude and longitude are required")
        building.location = geo.point(new_lon, new_lat)
    if payload.recorder_secret:
        building.recorder_encrypted_secret = cctv_security.encrypt_secret(payload.recorder_secret)
    elif payload.clear_recorder_secret:
        building.recorder_encrypted_secret = None

    connection_touched = bool(provided & {
        "recorder_host", "recorder_port", "recorder_protocol", "recorder_vendor", "stream_path_template", "recorder_username",
        "recorder_secret", "clear_recorder_secret", "authorized_networks", "public_ip", "clear_public_ip",
    })
    if connection_touched and building.connection_mode == models.CCTVConnectionMode.nvr:
        _validate_target_or_400(building, building.recorder_host, building.recorder_port)

    building.updated_at = _utcnow()
    building.updated_by = current_user.id
    await building.save()

    if building.connection_mode == models.CCTVConnectionMode.nvr and bool(provided & {"recorder_host", "recorder_port", "recorder_protocol"}):
        await models.CCTVCamera.get_motor_collection().update_many(
            {"building_id": building.id},
            {"$set": {"stream_host": building.recorder_host, "stream_port": building.recorder_port,
                      "stream_protocol": building.recorder_protocol.value, "updated_at": building.updated_at}},
        )
    if "zone" in provided or "address" in provided:
        await models.CCTVCamera.get_motor_collection().update_many(
            {"building_id": building.id}, {"$set": {"zone": building.zone, "address": building.address}},
        )
    if connection_touched:
        for cam in cameras:
            await cctv_playback.release_path(cam.id)

    await log_action(
        user_id=current_user.id, action="building_updated",
        details={"building_id": str(building.id), "fields": sorted(provided - {"recorder_secret"})},  # never the secret's value
    )
    await events.publish_cctv_building_changed(building, "updated")
    return await _detail(building, current_user)


async def _set_enabled(building_id: uuid.UUID, enabled: bool, user: models.User) -> schemas.BuildingDetailResponse:
    building = await _get_building_or_404(building_id)
    building.enabled = enabled
    building.updated_at = _utcnow()
    building.updated_by = user.id
    await building.save()
    if not enabled:
        for cam in await _cameras_of(building.id):
            await cctv_playback.release_path(cam.id)
    await log_action(user_id=user.id, action="building_enabled" if enabled else "building_disabled", details={"building_id": str(building.id)})
    await events.publish_cctv_building_changed(building, "enabled" if enabled else "disabled")
    return await _detail(building, user)


@router.post("/{building_id}/enable", response_model=schemas.BuildingDetailResponse)
async def enable_building(building_id: uuid.UUID, current_user: models.User = Depends(require_cctv_admin)):
    return await _set_enabled(building_id, True, current_user)


@router.post("/{building_id}/disable", response_model=schemas.BuildingDetailResponse)
async def disable_building(building_id: uuid.UUID, current_user: models.User = Depends(require_cctv_admin)):
    """Disabled buildings drop out of the dashboard and their gateway paths are closed."""
    return await _set_enabled(building_id, False, current_user)


@router.delete("/{building_id}")
async def delete_building(
    building_id: uuid.UUID,
    cameras: Literal["reject", "detach", "delete"] = Query(
        default="reject", description="What to do with the building's cameras: reject (409 if any exist), detach (keep them as unassigned cameras) or delete them."),
    current_user: models.User = Depends(require_cctv_admin),
):
    """admin-only. Never silently orphans or destroys cameras: the caller must choose."""
    building = await _get_building_or_404(building_id)
    building_cameras = await _cameras_of(building.id)
    if building_cameras and cameras == "reject":
        raise HTTPException(status_code=409, detail=f"Building has {len(building_cameras)} camera(s); pass cameras=detach or cameras=delete")

    for cam in building_cameras:
        await cctv_playback.release_path(cam.id)
        if cameras == "delete":
            await cam.delete()
            await events.publish_cctv_deleted(cam.id)
    if cameras == "detach":
        await models.CCTVCamera.get_motor_collection().update_many(
            {"building_id": building.id},
            {"$set": {"building_id": None, "channel": None, "updated_at": _utcnow()}},
        )
    await building.delete()
    await log_action(
        user_id=current_user.id, action="building_deleted",
        details={"building_id": str(building_id), "code": building.code, "cameras": cameras, "camera_count": len(building_cameras)},
    )
    await events.publish_cctv_building_changed(building, "deleted")
    return {"status": "deleted", "cameras": cameras, "camera_count": len(building_cameras)}


# ===========================================================================
# Cameras inside a building
# ===========================================================================

@router.get("/{building_id}/cameras", response_model=List[schemas.CCTVCameraResponse])
async def list_building_cameras(building_id: uuid.UUID, current_user: models.User = Depends(require_cctv_viewer)):
    await _get_building_or_404(building_id)
    return [_to_camera_response(c) for c in cctv_buildings.sort_cameras(await _cameras_of(building_id))]


@router.post("/{building_id}/cameras", response_model=schemas.CCTVCameraResponse, status_code=status.HTTP_201_CREATED)
async def add_building_camera(
    building_id: uuid.UUID, payload: schemas.BuildingCameraInput, current_user: models.User = Depends(require_cctv_admin)
):
    building = await _get_building_or_404(building_id)
    existing = await _cameras_of(building.id)
    if building.connection_mode == models.CCTVConnectionMode.nvr:
        used = {c.channel for c in existing}
        if payload.channel is None:
            payload.channel = next(n for n in range(1, cctv_sources.MAX_CHANNEL + 2) if n not in used)
        if payload.channel in used:
            raise HTTPException(status_code=409, detail=f"Channel {payload.channel} is already used in this building")
    camera = _make_camera(building, payload, len(existing), current_user.id, _utcnow())
    if camera.sort_order == len(existing) and existing:
        camera.sort_order = max(c.sort_order for c in existing) + 1
    if building.connection_mode == models.CCTVConnectionMode.direct_ip:
        _validate_target_or_400(building, camera.stream_host, camera.stream_port)
    try:
        await camera.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"A camera with camera_code '{camera.camera_code}' already exists")
    await log_action(user_id=current_user.id, action="camera_created", details={"camera_id": str(camera.id), "camera_code": camera.camera_code, "building_id": str(building.id)})
    await events.publish_cctv_registered(camera)
    return _to_camera_response(camera)


@router.patch("/{building_id}/cameras/{camera_id}", response_model=schemas.CCTVCameraResponse)
async def update_building_camera(
    building_id: uuid.UUID, camera_id: uuid.UUID, payload: schemas.BuildingCameraUpdate,
    current_user: models.User = Depends(require_cctv_admin),
):
    building = await _get_building_or_404(building_id)
    camera = await _get_camera_or_404(camera_id)
    if camera.building_id != building.id:
        raise HTTPException(status_code=404, detail="Camera does not belong to this building")
    nvr = building.connection_mode == models.CCTVConnectionMode.nvr
    connection_changed = False

    if payload.name is not None:
        camera.name = payload.name
    if payload.description is not None:
        camera.description = payload.description
    if payload.sort_order is not None:
        camera.sort_order = payload.sort_order
    if payload.provider_type is not None:
        camera.provider_type = models.CCTVProviderType(payload.provider_type)
        connection_changed = True
    if payload.channel is not None:
        if nvr and await models.CCTVCamera.find_one({"building_id": building.id, "channel": payload.channel, "_id": {"$ne": camera.id}}):
            raise HTTPException(status_code=409, detail=f"Channel {payload.channel} is already used in this building")
        camera.channel = payload.channel
        connection_changed = True
    if payload.latitude is not None and payload.longitude is not None:
        camera.location = geo.point(payload.longitude, payload.latitude)
    if payload.management_url is not None:
        camera.management_url = payload.management_url
    if payload.username is not None:
        camera.username = payload.username
        connection_changed = True
    if payload.secret:
        camera.encrypted_secret = cctv_security.encrypt_secret(payload.secret)
        connection_changed = True
    elif payload.clear_secret:
        camera.encrypted_secret = None
        connection_changed = True
    if not nvr:  # direct-IP cameras own their endpoint
        if payload.stream_protocol is not None:
            camera.stream_protocol = payload.stream_protocol
        if payload.stream_host is not None or payload.stream_port is not None:
            host = payload.stream_host if payload.stream_host is not None else camera.stream_host
            port = payload.stream_port if payload.stream_port is not None else camera.stream_port
            _validate_target_or_400(building, host, port)
            camera.stream_host, camera.stream_port = host, port
        if payload.stream_path is not None:
            try:
                camera.stream_path = cctv_sources.validate_path(payload.stream_path) if payload.stream_path else None
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        connection_changed = connection_changed or any(
            v is not None for v in (payload.stream_protocol, payload.stream_host, payload.stream_port, payload.stream_path)
        )
    if payload.enabled is not None and payload.enabled != camera.enabled:
        camera.enabled = payload.enabled
        camera.status = models.CCTVCameraStatus.unknown if payload.enabled else models.CCTVCameraStatus.disabled
        connection_changed = connection_changed or not payload.enabled

    camera.updated_at = _utcnow()
    camera.updated_by = current_user.id
    await camera.save()
    if connection_changed:
        await cctv_playback.release_path(camera.id)
    await log_action(user_id=current_user.id, action="camera_updated", details={"camera_id": str(camera.id), "building_id": str(building.id)})
    await events.publish_cctv_updated(camera)
    return _to_camera_response(camera)


@router.post("/{building_id}/cameras/reorder", response_model=List[schemas.CCTVCameraResponse])
async def reorder_building_cameras(
    building_id: uuid.UUID, payload: schemas.CameraReorderRequest, current_user: models.User = Depends(require_cctv_admin)
):
    """admin-only. Sets rotation order to the position in `camera_ids`. Every id must belong to this building; cameras not listed keep their relative order after the listed ones."""
    building = await _get_building_or_404(building_id)
    cameras = {c.id: c for c in await _cameras_of(building.id)}
    if len(set(payload.camera_ids)) != len(payload.camera_ids) or any(i not in cameras for i in payload.camera_ids):
        raise HTTPException(status_code=422, detail="camera_ids must be distinct cameras of this building")
    rest = [c for c in cctv_buildings.sort_cameras(cameras.values()) if c.id not in set(payload.camera_ids)]
    ordered = [cameras[i] for i in payload.camera_ids] + rest
    now = _utcnow()
    for position, cam in enumerate(ordered):
        if cam.sort_order != position:
            cam.sort_order = position
            cam.updated_at = now
            cam.updated_by = current_user.id
            await cam.save()
    await log_action(user_id=current_user.id, action="building_cameras_reordered", details={"building_id": str(building.id)})
    await events.publish_cctv_building_changed(building, "updated")
    return [_to_camera_response(c) for c in ordered]


@router.post("/{building_id}/test", response_model=schemas.BuildingTestResponse)
async def test_building(building_id: uuid.UUID, current_user: models.User = Depends(require_cctv_viewer)):
    """admin/control_room. Real connectivity probe of the building's recorder (NVR mode) or of each distinct camera endpoint (direct-IP), updating camera statuses. A recorder being reachable does NOT prove an individual channel has video; that is only established on first playback."""
    building = await _get_building_or_404(building_id)
    results = await cctv_health.probe_building(building, force=True)
    await log_action(user_id=current_user.id, action="building_tested", details={"building_id": str(building.id), "targets": len(results)})
    return schemas.BuildingTestResponse(building_id=building.id, results=results)


# ===========================================================================
# Assign an existing / legacy camera to a building
# ===========================================================================

@camera_router.put("/{camera_id}/building", response_model=schemas.CCTVCameraResponse)
async def assign_camera_to_building(
    camera_id: uuid.UUID, payload: schemas.CameraAssignRequest, current_user: models.User = Depends(require_cctv_admin)
):
    """admin-only. Moves a camera into a building (building_id=<id>) or detaches it (building_id=null). Assigning to an NVR building requires a free channel: the camera is then addressed through the building's recorder."""
    camera = await _get_camera_or_404(camera_id)
    if payload.building_id is None:
        camera.building_id = None
        camera.channel = None
    else:
        building = await _get_building_or_404(payload.building_id)
        siblings = await _cameras_of(building.id)
        if building.connection_mode == models.CCTVConnectionMode.nvr:
            used = {c.channel for c in siblings if c.id != camera.id}
            channel = payload.channel if payload.channel is not None else camera.channel
            if channel is None:
                raise HTTPException(status_code=422, detail="An NVR channel number is required to assign a camera to this building")
            if channel in used:
                raise HTTPException(status_code=409, detail=f"Channel {channel} is already used in this building")
            camera.channel = channel
            camera.stream_host, camera.stream_port = building.recorder_host, building.recorder_port
            camera.stream_protocol = building.recorder_protocol
            camera.stream_path = None
        else:
            _validate_target_or_400(building, camera.stream_host, camera.stream_port)
            camera.channel = payload.channel if payload.channel is not None else camera.channel
        camera.building_id = building.id
        camera.zone = building.zone or camera.zone
        camera.sort_order = payload.sort_order if payload.sort_order is not None else (max((c.sort_order for c in siblings), default=-1) + 1)
    camera.updated_at = _utcnow()
    camera.updated_by = current_user.id
    await camera.save()
    await cctv_playback.release_path(camera.id)
    await log_action(
        user_id=current_user.id, action="camera_assigned",
        details={"camera_id": str(camera.id), "building_id": str(camera.building_id) if camera.building_id else None},
    )
    await events.publish_cctv_updated(camera)
    return _to_camera_response(camera)
