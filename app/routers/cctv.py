"""
Authorized CCTV monitoring -- a separate domain from the Body Camera
`Device`/`RecordingSession` subsystem (see app/models.py::CCTVCamera's
docstring for why it is not built on top of either).

AUTHORIZATION: every endpoint in this router is restricted to `admin`
and/or `control_room` only -- never `station`, `constable`, or `citizen`,
regardless of any ownership/scoping relationship those roles might have
elsewhere in this backend. This is enforced here, at the dependency
level, not left to the frontend to hide buttons for. See the module-level
`require_cctv_viewer`/`require_cctv_admin` dependencies below and the
CCTV access matrix in the implementation report for the exact per-action
breakdown.

AUTHORIZED-CAMERA POLICY: this subsystem only ever OPERATES on cameras
that an admin has explicitly registered via POST /cctv/cameras. There is
no "find nearby public cameras" capability of any kind -- `GET
/cctv/cameras/nearby` only ever searches among cameras already
registered in this database. This backend never claims or provides
access to a city's CCTV network; see cctv_providers.py and
cctv_security.py for the connectivity/streaming logic, which only ever
talks to a camera's own configured, SSRF-validated host:port.

LOCAL NETWORK DISCOVERY (`POST /cctv/discover`, admin-only): a real
WS-Discovery scan for ONVIF devices (see cctv_discovery.py), inherently
limited to the link-local multicast domain -- it cannot reach the
internet or any address outside CCTV_ALLOWED_NETWORKS regardless of what
responds. It only SURFACES candidates; it never auto-registers a camera
-- the admin still explicitly reviews and calls POST /cctv/cameras for
any device they choose to add.

CREDENTIAL SAFETY: `CCTVCamera.encrypted_secret` is never read back out
to plaintext anywhere in this router -- only `credentials_configured`
(a bool) is ever exposed. See services/cctv_security.py.
"""
import datetime
import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from .. import geo, models, schemas
from ..auth.deps import require_role
from ..services.audit import log_action
from ..services import events
from ..services import cctv_providers
from ..services import cctv_security
from ..services import cctv_discovery

router = APIRouter(prefix="/cctv", tags=["CCTV"])

# CCTV-specific authorization, built from the existing generic
# require_role() factory (app/auth/deps.py) -- exactly the same pattern
# every other router already uses inline (e.g. police_stations.py,
# audit_logs.py), just named once here since every CCTV endpoint needs
# one of these two exact sets and the distinction between them matters a
# lot for this subsystem (see the access matrix above).
require_cctv_viewer = require_role("admin", "control_room")
require_cctv_admin = require_role("admin")

_NON_TERMINAL_STREAM_STATUSES = [
    models.CCTVStreamSessionStatus.requested,
    models.CCTVStreamSessionStatus.starting,
    models.CCTVStreamSessionStatus.active,
]


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _to_camera_response(camera: models.CCTVCamera) -> schemas.CCTVCameraResponse:
    lon, lat = geo.lon_lat(camera.location)
    return schemas.CCTVCameraResponse(
        id=camera.id,
        name=camera.name,
        camera_code=camera.camera_code,
        description=camera.description,
        manufacturer=camera.manufacturer,
        model=camera.model,
        capabilities=camera.capabilities,
        station_id=camera.station_id,
        zone=camera.zone,
        address=camera.address,
        latitude=lat,
        longitude=lon,
        provider_type=camera.provider_type,
        stream_protocol=camera.stream_protocol,
        stream_host=camera.stream_host,
        stream_port=camera.stream_port,
        stream_path=camera.stream_path,
        management_url=camera.management_url,
        username=camera.username,
        credentials_configured=bool(camera.encrypted_secret),
        enabled=camera.enabled,
        status=camera.status,
        last_seen_at=camera.last_seen_at,
        last_status_check_at=camera.last_status_check_at,
        last_error=camera.last_error,
        is_demo=camera.is_demo,
        created_at=camera.created_at,
        updated_at=camera.updated_at,
        created_by=camera.created_by,
        updated_by=camera.updated_by,
        metadata=camera.metadata,
    )


def _validate_target_or_400(host: str, port: int) -> None:
    try:
        cctv_security.validate_stream_target(host, port)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Camera network target rejected: {exc}")


async def _get_camera_or_404(camera_id: uuid.UUID) -> models.CCTVCamera:
    camera = await models.CCTVCamera.get(camera_id)
    if not camera:
        raise HTTPException(status_code=404, detail="CCTV camera not found")
    return camera


async def _apply_status_change(camera: models.CCTVCamera, new_status: models.CCTVCameraStatus, current_user: models.User) -> str:
    """Persists `new_status` on `camera` (caller must still .save()) and returns the previous status value for callers that need to audit/publish a transition."""
    old_status = camera.status.value if camera.status else None
    camera.status = new_status
    if old_status != new_status.value:
        await log_action(
            user_id=current_user.id,
            action="camera_status_changed",
            details={"camera_id": str(camera.id), "old_status": old_status, "new_status": new_status.value},
        )
    return old_status


# ===========================================================================
# Camera management
# ===========================================================================

@router.post("/cameras", response_model=schemas.CCTVCameraResponse)
async def create_camera(
    payload: schemas.CCTVCameraCreateRequest,
    current_user: models.User = Depends(require_cctv_admin),
):
    """admin-only. Rejects a stream target outside CCTV_ALLOWED_NETWORKS/the permanently-blocked ranges BEFORE the camera is ever stored (see cctv_security.validate_stream_target) -- registering an unauthorized/unreachable-by-policy target is refused, not just flagged later at test time."""
    _validate_target_or_400(payload.stream_host, payload.stream_port)

    now = _utcnow()
    camera = models.CCTVCamera(
        name=payload.name,
        camera_code=payload.camera_code,
        description=payload.description,
        manufacturer=payload.manufacturer,
        model=payload.model,
        station_id=payload.station_id,
        zone=payload.zone,
        address=payload.address,
        location=geo.point(payload.longitude, payload.latitude),
        provider_type=payload.provider_type,
        stream_protocol=payload.stream_protocol,
        stream_host=payload.stream_host,
        stream_port=payload.stream_port,
        stream_path=payload.stream_path,
        management_url=payload.management_url,
        username=payload.username,
        encrypted_secret=cctv_security.encrypt_secret(payload.secret) if payload.secret else None,
        enabled=True,
        status=models.CCTVCameraStatus.unknown,
        is_demo=payload.is_demo,
        created_at=now,
        updated_at=now,
        created_by=current_user.id,
        updated_by=current_user.id,
        metadata=payload.metadata,
    )
    try:
        await camera.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"A camera with camera_code '{payload.camera_code}' already exists")

    await log_action(
        user_id=current_user.id,
        action="camera_created",
        details={"camera_id": str(camera.id), "camera_code": camera.camera_code, "is_demo": camera.is_demo},
    )
    await events.publish_cctv_registered(camera)

    return _to_camera_response(camera)


@router.get("/cameras", response_model=List[schemas.CCTVCameraResponse])
async def list_cameras(
    station_id: Optional[uuid.UUID] = None,
    zone: Optional[str] = None,
    enabled: Optional[bool] = None,
    status_: Optional[models.CCTVCameraStatus] = Query(default=None, alias="status"),
    provider_type: Optional[models.CCTVProviderType] = None,
    camera_code: Optional[str] = None,
    name: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(require_cctv_viewer),
):
    """admin/control_room only -- station/constable/citizen get a 403 from the dependency itself, never an empty/scoped list (there is no partial CCTV visibility for any other role)."""
    query = models.CCTVCamera.find()

    if station_id is not None:
        query = query.find(models.CCTVCamera.station_id == station_id)
    if zone is not None:
        query = query.find(models.CCTVCamera.zone == zone)
    if enabled is not None:
        query = query.find(models.CCTVCamera.enabled == enabled)
    if status_ is not None:
        query = query.find(models.CCTVCamera.status == status_)
    if provider_type is not None:
        query = query.find(models.CCTVCamera.provider_type == provider_type)
    if camera_code is not None:
        query = query.find(models.CCTVCamera.camera_code == camera_code)
    if name is not None:
        query = query.find({"name": {"$regex": re.escape(name), "$options": "i"}})

    cameras = await query.sort(-models.CCTVCamera.created_at).skip(offset).limit(limit).to_list()
    return [_to_camera_response(c) for c in cameras]


@router.post("/discover", response_model=List[schemas.CCTVDiscoveredDeviceResponse])
async def discover_cameras(
    timeout_seconds: float = Query(default=3.0, gt=0, le=15),
    current_user: models.User = Depends(require_cctv_admin),
):
    """
    admin-only. Real WS-Discovery scan for ONVIF devices on the local
    multicast domain (see cctv_discovery.py) -- never a public/internet
    scan, and results are filtered to CCTV_ALLOWED_NETWORKS before ever
    reaching this response. Returns candidates only; nothing here
    registers a camera. An empty list is the honest, expected result in
    an environment with no physical ONVIF device reachable.
    """
    try:
        devices = await cctv_discovery.discover(timeout_seconds=timeout_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    await log_action(
        user_id=current_user.id, action="cctv_discovery_scan",
        details={"timeout_seconds": timeout_seconds, "devices_found": len(devices)},
    )
    return [
        schemas.CCTVDiscoveredDeviceResponse(address=d.address, xaddrs=d.xaddrs, scopes=d.scopes, types=d.types)
        for d in devices
    ]


# IMPORTANT ROUTING NOTE: "/nearby" must be registered BEFORE
# "/{camera_id}" below -- same reasoning as constables.py's documented
# "/me must come before /{constable_id}" ordering: a literal path segment
# has to be matched before a UUID-typed path parameter would otherwise
# swallow it and fail UUID validation.
@router.get("/cameras/nearby", response_model=List[schemas.CCTVNearbyCameraResponse])
async def nearby_cameras(
    latitude: float = Query(..., ge=-90.0, le=90.0),
    longitude: float = Query(..., ge=-180.0, le=180.0),
    radius_m: float = Query(default=500.0, gt=0, le=50000),
    enabled_only: bool = Query(default=True),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: models.User = Depends(require_cctv_viewer),
):
    """
    Nearby AUTHORIZED cameras only -- this queries exclusively against
    cameras already registered in this database via $geoNear (needs the
    2dsphere index declared on CCTVCamera.location), the same mechanism
    already used by police_stations.py::find_nearest_stations and
    Incident.location. There is no public/internet camera discovery of
    any kind here -- see this module's docstring.
    """
    return await _geonear_cameras(longitude=longitude, latitude=latitude, radius_m=radius_m, enabled_only=enabled_only, limit=limit)


async def _geonear_cameras(*, longitude: float, latitude: float, radius_m: float, enabled_only: bool, limit: int) -> List[schemas.CCTVNearbyCameraResponse]:
    """Shared by GET /cctv/cameras/nearby and GET /cctv/incidents/{id}/nearby-cameras -- one $geoNear implementation, two entry points."""
    geo_query: dict = {"location": {"$ne": None}}
    if enabled_only:
        geo_query["enabled"] = True

    pipeline = [
        {
            "$geoNear": {
                "near": {"type": "Point", "coordinates": [longitude, latitude]},
                "distanceField": "distance_meters",
                "spherical": True,
                "maxDistance": radius_m,
                "query": geo_query,
            }
        },
        {"$limit": limit},
    ]

    results: List[schemas.CCTVNearbyCameraResponse] = []
    async for doc in models.CCTVCamera.get_motor_collection().aggregate(pipeline):
        lon, lat = doc["location"]["coordinates"]
        results.append(schemas.CCTVNearbyCameraResponse(
            id=doc["_id"],
            name=doc.get("name"),
            camera_code=doc.get("camera_code"),
            station_id=doc.get("station_id"),
            latitude=lat,
            longitude=lon,
            distance_meters=doc["distance_meters"],
            status=doc.get("status", models.CCTVCameraStatus.unknown.value),
            enabled=doc.get("enabled", False),
        ))
    return results


@router.get("/incidents/{incident_id}/nearby-cameras", response_model=List[schemas.CCTVNearbyCameraResponse])
async def nearby_cameras_for_incident(
    incident_id: uuid.UUID,
    radius_m: float = Query(default=500.0, gt=0, le=50000),
    enabled_only: bool = Query(default=True),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: models.User = Depends(require_cctv_viewer),
):
    """
    admin/control_room only -- same authorized-camera-only policy as
    GET /cctv/cameras/nearby, just anchored at an Incident's own location
    instead of an arbitrary lat/lon. This is the "Incident -> nearby
    authorized CCTV" integration: it identifies which already-registered
    cameras are near a given incident and returns them (id, distance,
    status) for Control Room to act on -- it does NOT itself start a
    stream, create an audit entry, or touch the incident in any way
    (read-only, same as GET /incidents/{id}/responsible-stations).
    """
    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if not incident.location:
        raise HTTPException(status_code=422, detail="Incident has no location to search from")

    lon, lat = geo.lon_lat(incident.location)
    return await _geonear_cameras(longitude=lon, latitude=lat, radius_m=radius_m, enabled_only=enabled_only, limit=limit)


@router.get("/cameras/{camera_id}", response_model=schemas.CCTVCameraResponse)
async def get_camera(
    camera_id: uuid.UUID,
    current_user: models.User = Depends(require_cctv_viewer),
):
    camera = await _get_camera_or_404(camera_id)
    return _to_camera_response(camera)


@router.patch("/cameras/{camera_id}", response_model=schemas.CCTVCameraResponse)
async def update_camera(
    camera_id: uuid.UUID,
    payload: schemas.CCTVCameraUpdateRequest,
    current_user: models.User = Depends(require_cctv_admin),
):
    """admin-only. Only fields explicitly provided are changed. A changed stream_host/stream_port is re-validated against the SSRF policy before being persisted."""
    camera = await _get_camera_or_404(camera_id)

    if payload.name is not None:
        camera.name = payload.name
    if payload.description is not None:
        camera.description = payload.description
    if payload.manufacturer is not None:
        camera.manufacturer = payload.manufacturer
    if payload.model is not None:
        camera.model = payload.model
    if payload.station_id is not None:
        camera.station_id = payload.station_id
    if payload.zone is not None:
        camera.zone = payload.zone
    if payload.address is not None:
        camera.address = payload.address

    if payload.latitude is not None or payload.longitude is not None:
        existing_lon, existing_lat = geo.lon_lat(camera.location)
        new_lat = payload.latitude if payload.latitude is not None else existing_lat
        new_lon = payload.longitude if payload.longitude is not None else existing_lon
        if new_lat is None or new_lon is None:
            raise HTTPException(status_code=422, detail="Both latitude and longitude are required to set a camera's location")
        camera.location = geo.point(new_lon, new_lat)

    if payload.provider_type is not None:
        camera.provider_type = payload.provider_type
    if payload.stream_protocol is not None:
        camera.stream_protocol = payload.stream_protocol

    new_host = payload.stream_host if payload.stream_host is not None else camera.stream_host
    new_port = payload.stream_port if payload.stream_port is not None else camera.stream_port
    if payload.stream_host is not None or payload.stream_port is not None:
        _validate_target_or_400(new_host, new_port)
    camera.stream_host = new_host
    camera.stream_port = new_port

    if payload.stream_path is not None:
        camera.stream_path = payload.stream_path
    if payload.management_url is not None:
        camera.management_url = payload.management_url
    if payload.username is not None:
        camera.username = payload.username
    if payload.secret:
        camera.encrypted_secret = cctv_security.encrypt_secret(payload.secret)
    elif payload.clear_secret:
        camera.encrypted_secret = None
    if payload.is_demo is not None:
        camera.is_demo = payload.is_demo
    if payload.metadata is not None:
        camera.metadata = payload.metadata

    camera.updated_at = _utcnow()
    camera.updated_by = current_user.id
    await camera.save()

    await log_action(user_id=current_user.id, action="camera_updated", details={"camera_id": str(camera_id)})
    await events.publish_cctv_updated(camera)

    return _to_camera_response(camera)


@router.delete("/cameras/{camera_id}")
async def delete_camera(
    camera_id: uuid.UUID,
    current_user: models.User = Depends(require_cctv_admin),
):
    """admin-only, hard delete. Does not touch any CCTVStreamSession history for this camera -- those rows remain for audit purposes, orphaned by camera_id the same way AuditLog rows survive other deletions elsewhere in this codebase."""
    camera = await _get_camera_or_404(camera_id)
    await camera.delete()

    await log_action(user_id=current_user.id, action="camera_deleted", details={"camera_id": str(camera_id), "camera_code": camera.camera_code})
    await events.publish_cctv_deleted(camera_id)

    return {"status": "deleted"}


@router.post("/cameras/{camera_id}/enable", response_model=schemas.CCTVCameraResponse)
async def enable_camera(
    camera_id: uuid.UUID,
    current_user: models.User = Depends(require_cctv_admin),
):
    """admin-only. Resets status to `unknown` (not `online`) -- enabling a camera does not itself prove it's reachable; call /test or wait for the next status check."""
    camera = await _get_camera_or_404(camera_id)
    camera.enabled = True
    await _apply_status_change(camera, models.CCTVCameraStatus.unknown, current_user)
    camera.updated_at = _utcnow()
    camera.updated_by = current_user.id
    await camera.save()

    await log_action(user_id=current_user.id, action="camera_enabled", details={"camera_id": str(camera_id)})
    await events.publish_cctv_enabled(camera)

    return _to_camera_response(camera)


@router.post("/cameras/{camera_id}/disable", response_model=schemas.CCTVCameraResponse)
async def disable_camera(
    camera_id: uuid.UUID,
    current_user: models.User = Depends(require_cctv_admin),
):
    """admin-only. `enabled=False` is administrative; `status` is set to the explicit `disabled` value (not `offline` -- see models.CCTVCameraStatus's docstring: these are different concepts)."""
    camera = await _get_camera_or_404(camera_id)
    camera.enabled = False
    await _apply_status_change(camera, models.CCTVCameraStatus.disabled, current_user)
    camera.updated_at = _utcnow()
    camera.updated_by = current_user.id
    await camera.save()

    await log_action(user_id=current_user.id, action="camera_disabled", details={"camera_id": str(camera_id)})
    await events.publish_cctv_disabled(camera)

    return _to_camera_response(camera)


@router.post("/cameras/{camera_id}/test", response_model=schemas.CCTVCameraTestResponse)
async def test_camera(
    camera_id: uuid.UUID,
    current_user: models.User = Depends(require_cctv_viewer),
):
    """
    admin/control_room. Performs a REAL connectivity probe (see
    cctv_providers.py) -- never fakes an "online" result. The response
    always reflects the live probe outcome, even for a disabled camera
    (useful to check reachability before re-enabling it); the PERSISTED
    `camera.status` field, however, is only updated from this probe while
    the camera is enabled -- a disabled camera's persisted status stays
    `disabled` regardless of what a manual test observes (see
    GET /cctv/cameras/{id}/status for the persisted view).
    """
    camera = await _get_camera_or_404(camera_id)
    provider = cctv_providers.get_provider(camera.provider_type)

    try:
        result = await provider.validate_connection(camera)
    except NotImplementedError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc))

    now = _utcnow()
    camera.last_status_check_at = now
    camera.last_error = result.error
    if result.status == models.CCTVCameraStatus.online:
        camera.last_seen_at = now
        # Only the flag matching the protocol actually just proven to work
        # is ever set here -- a real, this-probe-confirmed fact, never a
        # guess from provider_type/manufacturer. Every other capability
        # (ptz/audio/snapshot/multiple_streams) stays exactly as it was:
        # this simple GetSystemDateAndTime/RTSP-OPTIONS probe cannot
        # honestly determine any of those.
        if camera.provider_type == models.CCTVProviderType.onvif:
            camera.capabilities.onvif = True
        elif camera.provider_type == models.CCTVProviderType.rtsp:
            camera.capabilities.rtsp = True

    old_status = None
    if camera.enabled:
        old_status = await _apply_status_change(camera, result.status, current_user)
    await camera.save()

    await log_action(
        user_id=current_user.id,
        action="camera_tested",
        details={"camera_id": str(camera_id), "result_status": result.status.value, "latency_ms": result.latency_ms, "error": result.error},
    )
    if camera.enabled and old_status is not None and old_status != result.status.value:
        await events.publish_cctv_status_changed(camera, old_status, result.status.value)

    return schemas.CCTVCameraTestResponse(
        camera_id=camera_id, status=result.status, checked_at=now, latency_ms=result.latency_ms, error=result.error,
        capabilities=camera.capabilities,
    )


@router.get("/cameras/{camera_id}/status", response_model=schemas.CCTVCameraTestResponse)
async def get_camera_status(
    camera_id: uuid.UUID,
    current_user: models.User = Depends(require_cctv_viewer),
):
    """Read-only: the last PERSISTED status (from registration, the last /test call, or any prior check) -- never triggers a new connectivity attempt itself. Not audited, same convention as other routine reads in this codebase (e.g. GET /auth/me)."""
    camera = await _get_camera_or_404(camera_id)
    return schemas.CCTVCameraTestResponse(
        camera_id=camera.id,
        status=camera.status,
        checked_at=camera.last_status_check_at or camera.updated_at,
        latency_ms=None,
        error=camera.last_error,
    )


# ===========================================================================
# Streaming (see cctv_providers.py's module docstring for exactly what is
# and is not implemented here).
# ===========================================================================

async def _active_session_for_camera(camera_id: uuid.UUID) -> Optional[models.CCTVStreamSession]:
    return await models.CCTVStreamSession.find_one(
        models.CCTVStreamSession.camera_id == camera_id,
        {"status": {"$in": [s.value for s in _NON_TERMINAL_STREAM_STATUSES]}},
    )


@router.post("/cameras/{camera_id}/stream", response_model=schemas.CCTVStreamStartResponse)
async def request_stream(
    camera_id: uuid.UUID,
    current_user: models.User = Depends(require_cctv_viewer),
):
    """
    admin/control_room. Creates a CCTVStreamSession and asks the camera's
    provider to bridge it into something a browser can play. See
    cctv_providers.py: today this always ends in `status=failed` with a
    clear error -- the session lifecycle, RBAC, audit trail, and
    WebSocket events are fully real; the actual media bridge is a
    documented, unimplemented extension point, not a fabricated success.
    """
    camera = await _get_camera_or_404(camera_id)
    if not camera.enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Camera is disabled -- enable it before requesting a stream")

    session = models.CCTVStreamSession(
        camera_id=camera.id,
        requested_by=current_user.id,
        provider=camera.provider_type,
        protocol=camera.stream_protocol,
        status=models.CCTVStreamSessionStatus.requested,
    )
    try:
        await session.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This camera already has an active or pending stream session")

    await log_action(
        user_id=current_user.id, action="camera_stream_requested",
        details={"camera_id": str(camera_id), "session_id": str(session.id)},
    )
    await events.publish_cctv_stream_requested(session, camera)

    provider = cctv_providers.get_provider(camera.provider_type)
    try:
        result = await provider.start_stream(camera, session)
    except NotImplementedError as exc:
        result = cctv_providers.CCTVStreamStartResult(ok=False, error=str(exc))

    now = _utcnow()
    if result.ok:
        session.status = models.CCTVStreamSessionStatus.active
        session.gateway = result.gateway
        session.stream_reference = result.stream_reference
        session.started_at = now
    else:
        session.status = models.CCTVStreamSessionStatus.failed
        session.error = result.error
        session.ended_at = now
    session.updated_at = now
    await session.save()

    if result.ok:
        await log_action(user_id=current_user.id, action="camera_stream_started", details={"camera_id": str(camera_id), "session_id": str(session.id), "gateway": result.gateway})
        await events.publish_cctv_stream_started(session, camera)
    else:
        await log_action(user_id=current_user.id, action="camera_stream_failed", details={"camera_id": str(camera_id), "session_id": str(session.id), "error": result.error})
        await events.publish_cctv_stream_failed(session, camera, result.error)

    return schemas.CCTVStreamStartResponse(
        session=schemas.CCTVStreamSessionResponse.model_validate(session, from_attributes=True),
        livekit_url=result.livekit_url,
        token=result.token,
        identity=result.identity,
        can_publish=False,
    )


@router.post("/cameras/{camera_id}/stream/stop", response_model=schemas.CCTVStreamSessionResponse)
async def stop_stream(
    camera_id: uuid.UUID,
    current_user: models.User = Depends(require_cctv_viewer),
):
    """admin/control_room. Stops THIS CAMERA's current non-terminal session, whoever originally requested it -- same "any authorized operator may act" model as live_stream.py's force-stop for admin/control_room (there is no separate device-owner concept for CCTV)."""
    camera = await _get_camera_or_404(camera_id)
    session = await _active_session_for_camera(camera_id)
    if not session:
        raise HTTPException(status_code=404, detail="No active or pending stream session for this camera")

    provider = cctv_providers.get_provider(camera.provider_type)
    try:
        await provider.stop_stream(camera, session)
    except Exception:
        pass  # best-effort -- never blocks marking the session stopped in our own records

    now = _utcnow()
    updated = await models.CCTVStreamSession.get_motor_collection().find_one_and_update(
        {"_id": session.id, "status": {"$in": [s.value for s in _NON_TERMINAL_STREAM_STATUSES]}},
        {"$set": {"status": models.CCTVStreamSessionStatus.stopped.value, "ended_at": now, "updated_at": now}},
        return_document=ReturnDocument.AFTER,
    )
    if updated is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Stream session was already stopped")

    await log_action(user_id=current_user.id, action="camera_stream_stopped", details={"camera_id": str(camera_id), "session_id": str(session.id)})
    await events.publish_cctv_stream_ended(session, camera)

    return schemas.CCTVStreamSessionResponse(
        id=updated["_id"], camera_id=updated["camera_id"], requested_by=updated["requested_by"],
        provider=updated["provider"], protocol=updated["protocol"], gateway=updated.get("gateway"),
        stream_reference=updated.get("stream_reference"), status=updated["status"],
        started_at=updated.get("started_at"), ended_at=updated.get("ended_at"),
        viewer_count=updated.get("viewer_count", 0), error=updated.get("error"),
        created_at=updated["created_at"], updated_at=updated["updated_at"],
    )
