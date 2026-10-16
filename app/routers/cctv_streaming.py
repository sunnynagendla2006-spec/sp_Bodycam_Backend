"""
Browser playback for fixed CCTV cameras (MediaMTX gateway, WebRTC/WHEP).

  POST /cctv/cameras/{id}/playback         -> short-lived token + WHEP URL for ONE camera
  POST /cctv/cameras/{id}/playback/report  -> a viewer reports a playback failure/recovery
  GET  /cctv/streaming/config              -> dashboard tunables (rotation, stream cap, ...)
  POST /cctv/gateway/auth                  -> MediaMTX's external-auth callback (NOT a user endpoint)

`playback` is deliberately lighter than the session-based POST
/cctv/cameras/{id}/stream: the control-room wall asks for a new camera every
few seconds, so it creates no per-view database row and no audit entry
(a stream-view audit trail is kept by /stream, used from the camera detail
view). Authorization is the same: admin/control_room only.

The gateway auth callback authenticates MediaMTX with a shared key in the
callback URL (CCTV_GATEWAY_AUTH_KEY) and then admits exactly one thing: a READ
of the path named in a valid, unexpired playback token. Publishing, API
access and everything else is refused here.
"""
import hmac
import urllib.parse
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict

from .. import models, schemas
from ..auth import request_limiter
from ..services import cctv_gateway, cctv_health, cctv_playback, events
from .cctv import _get_camera_or_404, require_cctv_viewer

router = APIRouter(prefix="/cctv", tags=["CCTV Streaming"])


def _playback_http_error(exc: cctv_playback.PlaybackError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.message, headers={"X-CCTV-Error": exc.code})


@router.get("/streaming/config", response_model=schemas.CCTVStreamingConfigResponse)
async def streaming_config(current_user: models.User = Depends(require_cctv_viewer)):
    return schemas.CCTVStreamingConfigResponse(
        gateway_configured=cctv_gateway.is_configured(),
        rotation_seconds=cctv_gateway.rotation_seconds(),
        max_concurrent_streams=cctv_gateway.max_concurrent_streams(),
        prefetch_next=cctv_gateway.prefetch_next_enabled(),
        playback_ttl_seconds=cctv_gateway.playback_ttl_seconds(),
    )


@router.post("/cameras/{camera_id}/playback", response_model=schemas.CCTVPlaybackResponse)
async def request_playback(camera_id: uuid.UUID, current_user: models.User = Depends(require_cctv_viewer)):
    """
    admin/control_room. Makes sure the gateway has an on-demand path for this
    camera and returns a playback token scoped to exactly that path. Error
    responses carry a stable code in the `X-CCTV-Error` header
    (gateway_not_configured, camera_disabled, building_disabled,
    target_not_authorized, stream_capacity, gateway_unreachable, ...).
    """
    if not request_limiter.allow(f"cctvplay:{current_user.id}", 240):
        raise HTTPException(status_code=429, detail="Too many playback requests", headers={"X-CCTV-Error": "rate_limited"})
    camera = await _get_camera_or_404(camera_id)
    try:
        name = await cctv_playback.prepare_path(camera)
        await cctv_playback.check_capacity(name)
    except cctv_playback.PlaybackError as exc:
        raise _playback_http_error(exc)

    token, expires_at = cctv_gateway.mint_playback_token(current_user.id, camera.id)
    return schemas.CCTVPlaybackResponse(
        camera_id=camera.id, path=name, whep_url=cctv_gateway.whep_url(name), token=token,
        expires_at=expires_at, ttl_seconds=cctv_gateway.playback_ttl_seconds(),
    )


@router.post("/cameras/{camera_id}/playback/report")
async def report_playback(
    camera_id: uuid.UUID, report: schemas.CCTVPlaybackReport, current_user: models.User = Depends(require_cctv_viewer)
):
    """
    A dashboard tells the backend that playback of this camera failed or
    recovered, so channel-level problems (which a recorder-level probe cannot
    see) show up in camera/building health. The reason is length-bounded,
    stripped of addresses and never trusted for anything but display.
    """
    if not request_limiter.allow(f"cctvrep:{current_user.id}", 120):
        raise HTTPException(status_code=429, detail="Too many reports", headers={"X-CCTV-Error": "rate_limited"})
    camera = await _get_camera_or_404(camera_id)
    if not camera.enabled:
        return {"status": "ignored"}

    old = camera.status
    if report.state == "error":
        # `degraded`, not `offline`: the recorder may be fine and only this stream failed.
        if camera.status in (models.CCTVCameraStatus.online, models.CCTVCameraStatus.unknown):
            camera.status = models.CCTVCameraStatus.degraded
        camera.last_error = cctv_health.sanitize_error(report.reason) or "playback failed"
    elif camera.status in (models.CCTVCameraStatus.degraded, models.CCTVCameraStatus.unknown):
        camera.status = models.CCTVCameraStatus.online
        camera.last_error = None
    await camera.save()
    if old != camera.status:
        await events.publish_cctv_status_changed(camera, old.value, camera.status.value)
    return {"status": "recorded"}


class GatewayAuthRequest(BaseModel):
    """The JSON body MediaMTX posts to its external-auth URL (unknown fields ignored)."""
    model_config = ConfigDict(extra="ignore")
    user: Optional[str] = None
    password: Optional[str] = None
    ip: Optional[str] = None
    action: Optional[str] = None
    path: Optional[str] = None
    protocol: Optional[str] = None
    id: Optional[str] = None
    query: Optional[str] = None


@router.post("/gateway/auth", include_in_schema=False)
async def gateway_auth(body: GatewayAuthRequest, key: str = Query(default="")):
    """200 = allow, 401 = deny. Not callable by users: requires the shared gateway key."""
    expected = cctv_gateway.auth_key()
    if not expected or not hmac.compare_digest(key.encode(), expected.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
    if body.action != "read":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")

    path = (body.path or "").lstrip("/")
    if not path.startswith(cctv_gateway.PATH_PREFIX):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
    token = (urllib.parse.parse_qs(body.query or "").get("token") or [""])[0]
    if not token or cctv_gateway.verify_playback_token(token, expected_path=path) is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
    return {"status": "ok"}
