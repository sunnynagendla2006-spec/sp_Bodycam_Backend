"""
Building read-model helpers: derived camera counts, health roll-up and the
safe API representations (see schemas.BuildingResponse).

Camera counts are ALWAYS derived from CCTVCamera rows here; nothing stores
a count that could drift from the real camera list.
"""
import uuid
from typing import Dict, Iterable, List

from .. import geo, models, schemas

_ONLINE = models.CCTVCameraStatus.online.value
_OFFLINE = models.CCTVCameraStatus.offline.value
_DEGRADED = models.CCTVCameraStatus.degraded.value


def rollup_health(building_enabled: bool, enabled_cameras: int, online: int, offline: int, degraded: int) -> str:
    """disabled | empty | online (all enabled cameras online) | offline (all offline) | degraded (some trouble but something works) | unknown."""
    if not building_enabled:
        return "disabled"
    if enabled_cameras == 0:
        return "empty"
    if online == enabled_cameras:
        return "online"
    if offline == enabled_cameras:
        return "offline"
    if online or degraded or offline:
        return "degraded" if (online or degraded) else "unknown"
    return "unknown"


def stats_from_cameras(building: models.Building, cameras: Iterable[models.CCTVCamera]) -> dict:
    cams = list(cameras)
    enabled = [c for c in cams if c.enabled]
    online = sum(1 for c in enabled if c.status.value == _ONLINE)
    offline = sum(1 for c in enabled if c.status.value == _OFFLINE)
    degraded = sum(1 for c in enabled if c.status.value == _DEGRADED)
    return {
        "camera_count": len(cams),
        "enabled_camera_count": len(enabled),
        "online_count": online,
        "offline_count": offline,
        "health": rollup_health(building.enabled, len(enabled), online, offline, degraded),
    }


def to_brief(camera: models.CCTVCamera) -> schemas.BuildingCameraBrief:
    return schemas.BuildingCameraBrief(
        id=camera.id, name=camera.name, camera_code=camera.camera_code, channel=camera.channel,
        sort_order=camera.sort_order, enabled=camera.enabled, status=camera.status,
        last_seen_at=camera.last_seen_at, last_error=camera.last_error,
    )


def sort_cameras(cameras: Iterable[models.CCTVCamera]) -> List[models.CCTVCamera]:
    return sorted(cameras, key=lambda c: (c.sort_order, c.name.lower(), c.camera_code))


def to_response(building: models.Building, cameras: Iterable[models.CCTVCamera], include_infrastructure: bool) -> schemas.BuildingDetailResponse:
    """`include_infrastructure` is True only for admins: owner contact, IPs, authorized networks and the recorder endpoint are withheld from control-room operators, who only need to watch."""
    cams = sort_cameras(cameras)
    lon, lat = geo.lon_lat(building.location)
    data = dict(
        id=building.id, name=building.name, code=building.code, owner_name=building.owner_name,
        zone=building.zone, address=building.address, latitude=lat, longitude=lon,
        connection_mode=building.connection_mode, network_access=building.network_access,
        recorder_vendor=building.recorder_vendor, recorder_protocol=building.recorder_protocol,
        recorder_credentials_configured=bool(building.recorder_encrypted_secret),
        enabled=building.enabled, created_at=building.created_at, updated_at=building.updated_at,
        cameras=[to_brief(c) for c in cams], **stats_from_cameras(building, cams),
    )
    if include_infrastructure:
        data.update(
            owner_contact=building.owner_contact, public_ip=building.public_ip,
            authorized_networks=list(building.authorized_networks or []),
            recorder_host=building.recorder_host, recorder_port=building.recorder_port,
            stream_path_template=building.stream_path_template, recorder_username=building.recorder_username,
        )
    return schemas.BuildingDetailResponse(**data)


async def cameras_by_building(building_ids: Iterable[uuid.UUID]) -> Dict[uuid.UUID, List[models.CCTVCamera]]:
    ids = list(building_ids)
    grouped: Dict[uuid.UUID, List[models.CCTVCamera]] = {i: [] for i in ids}
    if not ids:
        return grouped
    for camera in await models.CCTVCamera.find({"building_id": {"$in": ids}}).to_list():
        grouped.setdefault(camera.building_id, []).append(camera)
    return grouped
