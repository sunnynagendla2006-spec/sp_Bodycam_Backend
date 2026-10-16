"""
Playback preparation shared by the stream-session endpoint
(routers/cctv.py) and the lightweight playback endpoint used by the
control-room rotation (routers/cctv_streaming.py).

prepare_path() turns "camera X" into "a MediaMTX path that is ready to be
watched": it resolves the camera's real source (NVR channel or direct IP),
re-validates the destination against the SSRF policy including the
building's own authorized networks, and registers the on-demand path with
the gateway. It never returns or logs the credential-bearing source URL.
"""
import asyncio
import logging
from typing import Optional

from .. import models
from . import cctv_gateway, cctv_security, cctv_sources

logger = logging.getLogger("cctv_playback")


class PlaybackError(Exception):
    """An expected, operator-facing failure. `code` is stable for UI logic; `status_code` is the HTTP status the router should use."""

    def __init__(self, code: str, message: str, status_code: int = 409):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


async def load_building(camera: models.CCTVCamera) -> Optional[models.Building]:
    if camera.building_id is None:
        return None
    return await models.Building.get(camera.building_id)


async def camera_networks(camera: models.CCTVCamera) -> list:
    """The camera's building-authorized networks (empty for an unassigned camera). Usage: `with cctv_security.extra_networks(await camera_networks(camera)): ...`."""
    return cctv_sources.networks_for_building(await load_building(camera))


async def prepare_path(camera: models.CCTVCamera) -> str:
    """Returns the gateway path name, ready for playback. Raises PlaybackError."""
    if not cctv_gateway.is_configured():
        raise PlaybackError(
            "gateway_not_configured",
            "No media gateway is configured (CCTV_GATEWAY_API_URL, CCTV_GATEWAY_PUBLIC_URL, CCTV_GATEWAY_AUTH_KEY). "
            "Camera management and connectivity testing work without it.",
            503,
        )
    if not camera.enabled:
        raise PlaybackError("camera_disabled", "Camera is disabled -- enable it before requesting a stream")
    building = await load_building(camera)
    if camera.building_id is not None and building is None:
        raise PlaybackError("building_missing", "The camera's building no longer exists", 409)
    if building is not None and not building.enabled:
        raise PlaybackError("building_disabled", "The camera's building is disabled")

    try:
        source = cctv_sources.resolve_source(camera, building)
    except cctv_sources.SourceError as exc:
        raise PlaybackError(exc.code, exc.message, 422)

    try:
        with cctv_security.extra_networks(cctv_sources.networks_for_building(building)):
            resolved = await asyncio.to_thread(cctv_security.resolve_and_validate, source.host, source.port)
    except ValueError as exc:
        raise PlaybackError("target_not_authorized", f"Camera network target rejected: {exc}", 403)

    # Connect to the address we just validated, not the name (DNS-rebinding
    # defence). rtsps needs the hostname for TLS certificate verification, so
    # it keeps the name; its destination was still validated above.
    pinned = resolved[0] if source.protocol == "rtsp" else None
    name = cctv_gateway.path_name(camera.id)
    try:
        await cctv_gateway.ensure_path(name, cctv_sources.gateway_source_url(source, pinned))
    except cctv_gateway.GatewayError as exc:
        raise PlaybackError(exc.code, exc.message, 502 if exc.code != "gateway_not_configured" else 503)
    return name


async def check_capacity(path_name: str) -> None:
    """Soft server-side cap on simultaneously watched cameras (CCTV_MAX_CONCURRENT_STREAMS). Fails open if the gateway cannot report viewers."""
    active = await cctv_gateway.active_viewer_paths()
    if active is None or path_name in active:
        return
    if len(active) >= cctv_gateway.max_concurrent_streams():
        raise PlaybackError("stream_capacity", "The maximum number of simultaneous CCTV streams is already in use", 429)


async def release_path(camera_id) -> None:
    await cctv_gateway.delete_path(cctv_gateway.path_name(camera_id))
