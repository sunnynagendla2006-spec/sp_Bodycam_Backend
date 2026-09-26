"""
Live camera streaming (ephemeral only -- never recorded/stored). See
app/models.py::LiveStreamSession module docstring for the full picture:
this backend never touches video bytes, it only issues short-lived signed
LiveKit join tokens -- the actual media fan-out happens entirely inside
the external LiveKit SFU.

Authorization mirrors app/routers/commands.py exactly:
  - issuing/force-stopping/viewing a stream: admin/control_room (any
    device) or station (only devices belonging to constables in their own
    station).
  - starting/stopping AS the device: only the constable who owns that
    device.
"""
import datetime
import logging
import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from livekit import api as lk_api
from pymongo import ReturnDocument

from beanie.operators import In

from .. import models, schemas
from ..auth.deps import get_current_user
from ..services.audit import log_action
from ..services import events
from ..services import storage as storage_service
from . import media as media_module
from .commands import _authorize_command_issue, _get_device_or_404
from .constables import get_own_constable
from .devices import _device_station_id

router = APIRouter(tags=["Live Stream"])
logger = logging.getLogger(__name__)

LIVEKIT_URL = os.getenv("LIVEKIT_URL", "ws://localhost:7880")
LIVEKIT_API_KEY = os.getenv("LIVEKIT_API_KEY", "devkey")
LIVEKIT_API_SECRET = os.getenv("LIVEKIT_API_SECRET", "secret")

LIVEKIT_INTERNAL_URL = os.getenv("LIVEKIT_INTERNAL_URL", "ws://livekit:7880")
BACKEND_INTERNAL_URL = os.getenv("BACKEND_INTERNAL_URL", "http://backend:8000")

_EGRESS_CONTAINER_OUTPUT_ROOT = "/egress_out"

_TOKEN_TTL_SECONDS = 6 * 60 * 60


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _room_name(device_id: uuid.UUID) -> str:
    return f"device-{device_id}"


def _mint_token(*, room: str, identity: str, name: str, can_publish: bool) -> str:
    grants = lk_api.VideoGrants(
        room_join=True,
        room=room,
        can_publish=can_publish,
        can_subscribe=True,
        can_publish_data=False,
    )
    token = (
        lk_api.AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET)
        .with_identity(identity)
        .with_name(name)
        .with_grants(grants)
        .with_ttl(datetime.timedelta(seconds=_TOKEN_TTL_SECONDS))
    )
    return token.to_jwt()


async def _require_own_device_constable(current_user: models.User, device_id: uuid.UUID):
    """Only the constable who owns this device may start/stop a stream AS the device."""
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the device's own constable may perform this action")
    own_constable = await get_own_constable(current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")
    device = await _get_device_or_404(device_id)
    if device.constable_id != own_constable.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to act on this device")
    return own_constable, device


def _pending_egress_rel_path(session_id: uuid.UUID) -> str:
    return f"_egress_pending/{session_id}.mp4"


def _s3_egress_rel_path(session_id: uuid.UUID) -> str:
    return f"recordings/{session_id}/playable.mp4"


def _s3_upload_output_or_none() -> "lk_api.S3Upload | None":
    """
    Built only when EVIDENCE_STORAGE_BACKEND=s3 (see storage.py) -- lets a
    managed/cloud LiveKit (whose egress workers have no access to this
    backend's local disk) upload the room-composite recording directly to
    the same S3-compatible bucket evidence already lives in, instead of
    the docker-compose self-hosted setup's shared /egress_out volume.
    """
    bucket = os.getenv("EVIDENCE_S3_BUCKET")
    if not bucket:
        return None
    return lk_api.S3Upload(
        access_key=os.getenv("AWS_ACCESS_KEY_ID", ""),
        secret=os.getenv("AWS_SECRET_ACCESS_KEY", ""),
        bucket=bucket,
        endpoint=os.getenv("EVIDENCE_S3_ENDPOINT_URL", ""),
        region=os.getenv("EVIDENCE_S3_REGION", "auto"),
        force_path_style=os.getenv("EVIDENCE_S3_FORCE_PATH_STYLE", "false").lower() == "true",
    )


async def _start_egress_best_effort(session: models.LiveStreamSession) -> None:
    """
    Best-effort: a room-composite (camera + mic, real audio+video) egress
    recording of this live session's room. Must NEVER block or break
    starting the live stream itself.
    """
    storage = media_module._get_storage_backend()
    is_local = isinstance(storage, storage_service.LocalFilesystemStorage)
    s3_output = None if is_local else _s3_upload_output_or_none()
    if not is_local and s3_output is None:
        logger.warning(f"live stream {session.id}: egress recording skipped -- not on LocalFilesystemStorage or S3")
        return

    if is_local:
        egress_filepath = f"{_EGRESS_CONTAINER_OUTPUT_ROOT}/{_pending_egress_rel_path(session.id)}"
        file_output = lk_api.EncodedFileOutput(file_type=lk_api.EncodedFileType.MP4, filepath=egress_filepath)
    else:
        file_output = lk_api.EncodedFileOutput(
            file_type=lk_api.EncodedFileType.MP4,
            filepath=_s3_egress_rel_path(session.id),
            s3=s3_output,
        )

    try:
        async with lk_api.LiveKitAPI(LIVEKIT_INTERNAL_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET) as lkapi:
            info = await lkapi.egress.start_room_composite_egress(
                lk_api.RoomCompositeEgressRequest(
                    room_name=session.room_name,
                    audio_only=False,
                    file_outputs=[file_output],
                    webhooks=[lk_api.WebhookConfig(url=f"{BACKEND_INTERNAL_URL}/live-stream/egress-webhook")],
                )
            )
        session.egress_id = info.egress_id
        await session.save()
    except Exception as exc:
        logger.warning(f"live stream {session.id}: failed to start egress recording: {exc}")


async def _stop_egress_best_effort(session: models.LiveStreamSession) -> None:
    if not session.egress_id:
        return
    try:
        async with lk_api.LiveKitAPI(LIVEKIT_INTERNAL_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET) as lkapi:
            await lkapi.egress.stop_egress(lk_api.StopEgressRequest(egress_id=session.egress_id))
    except Exception as exc:
        logger.warning(f"live stream {session.id}: failed to stop egress recording {session.egress_id}: {exc}")


def _webhook_receiver() -> lk_api.WebhookReceiver:
    return lk_api.WebhookReceiver(lk_api.TokenVerifier(LIVEKIT_API_KEY, LIVEKIT_API_SECRET))


async def _handle_egress_ended(egress_info) -> None:
    """
    Turns a completed egress recording into a real RecordingSession
    document (trigger_type='live_stream') -- reusing recordings.py's exact
    playable pipeline rather than a second video collection/player. Never
    fabricates a recording: only EGRESS_COMPLETE with a real, non-empty
    output file on disk results in a document being created.
    """
    session = await models.LiveStreamSession.find_one(models.LiveStreamSession.egress_id == egress_info.egress_id)
    if not session:
        return  # some other egress job, or one from a previous deployment
    if session.recording_session_id is not None:
        return  # webhook redelivery -- never create a duplicate recording

    if egress_info.status != lk_api.EgressStatus.EGRESS_COMPLETE:
        logger.warning(f"live stream {session.id}: egress {egress_info.egress_id} ended with status {egress_info.status} -- no recording created")
        return

    storage = media_module._get_storage_backend()
    is_local = isinstance(storage, storage_service.LocalFilesystemStorage)
    if not is_local and not isinstance(storage, storage_service.S3StorageBackend):
        return

    new_id = uuid.uuid4()
    if is_local:
        pending_abs_path = storage._abs_path(_pending_egress_rel_path(session.id))
        if not os.path.exists(pending_abs_path) or os.path.getsize(pending_abs_path) == 0:
            logger.warning(f"live stream {session.id}: egress reported complete but output file missing/empty at {pending_abs_path}")
            return
        final_rel_path = f"recordings/{new_id}/playable.mp4"
        final_abs_path = storage._abs_path(final_rel_path)
        os.makedirs(os.path.dirname(final_abs_path), exist_ok=True)
        os.rename(pending_abs_path, final_abs_path)  # same volume -- a rename, never a copy
    else:
        # Egress (running on managed/cloud LiveKit) already uploaded the
        # file straight to this key -- see _s3_upload_output_or_none --
        # so there's no local move to do, just confirm it's really there.
        final_rel_path = _s3_egress_rel_path(session.id)
        size = storage.get_size(final_rel_path)
        if not size:
            logger.warning(f"live stream {session.id}: egress reported complete but output object missing/empty at {final_rel_path}")
            return

    now = _utcnow()
    recording = models.RecordingSession(
        id=new_id,
        constable_id=session.constable_id,
        device_id=session.device_id,
        trigger_type=models.RecordingTriggerType.live_stream,
        status=models.RecordingStatus.completed,
        started_at=session.started_at,
        ended_at=session.ended_at or now,
        playable_status="ready",
        playable_storage_key=final_rel_path,
    )
    await recording.insert()
    session.recording_session_id = new_id
    await session.save()

    await log_action(
        user_id=None, action="live_stream.recorded",
        details={"live_stream_session_id": str(session.id), "recording_session_id": str(new_id), "egress_id": egress_info.egress_id},
    )


async def _cas_session_status(session_id: uuid.UUID, expected: models.LiveStreamStatus, update_fields: dict):
    return await models.LiveStreamSession.get_motor_collection().find_one_and_update(
        {"_id": session_id, "status": expected.value},
        {"$set": update_fields},
        return_document=ReturnDocument.BEFORE,
    )


@router.post("/devices/{device_id}/live-stream/start", response_model=schemas.LiveStreamTokenResponse)
async def start_live_stream(
    device_id: uuid.UUID,
    payload: schemas.LiveStreamStartRequest,
    current_user: models.User = Depends(get_current_user),
):
    own_constable, device = await _require_own_device_constable(current_user, device_id)

    started_by = (
        models.LiveStreamStartedBy.remote_command
        if payload.triggering_command_id is not None
        else models.LiveStreamStartedBy.self
    )
    room = _room_name(device_id)
    session = models.LiveStreamSession(
        device_id=device_id,
        constable_id=own_constable.id,
        room_name=room,
        status=models.LiveStreamStatus.live,
        started_by=started_by,
        triggering_command_id=payload.triggering_command_id,
    )
    await session.insert()
    await log_action(
        user_id=current_user.id, action="live_stream.started",
        details={"device_id": str(device_id), "room_name": room, "started_by": started_by.value},
    )

    station_id = own_constable.station_id
    await events.publish_live_stream_started(session, station_id)

    # Best-effort -- never raises, never delays/blocks issuing the join
    # token below even if it's slow or fails outright.
    await _start_egress_best_effort(session)

    identity = f"device-{device_id}"
    token = _mint_token(room=room, identity=identity, name=identity, can_publish=True)
    return schemas.LiveStreamTokenResponse(
        session=session, livekit_url=LIVEKIT_URL, token=token, identity=identity, can_publish=True,
    )


@router.post("/live-stream/{session_id}/stop", response_model=schemas.LiveStreamSessionResponse)
async def stop_live_stream(
    session_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    session = await models.LiveStreamSession.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Live stream session not found")
    if session.status != models.LiveStreamStatus.live:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot stop a session in status {session.status.value}")

    device = await _get_device_or_404(session.device_id)

    # Either the device's own constable, or an admin/control_room/station
    # (own station) force-stopping it -- same rule as issuing a command.
    if current_user.role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable or session.constable_id != own_constable.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to stop this session")
    else:
        await _authorize_command_issue(device, current_user)

    now = _utcnow()
    before = await _cas_session_status(
        session_id, models.LiveStreamStatus.live,
        {"status": models.LiveStreamStatus.ended.value, "ended_at": now},
    )
    if before is None:
        current = await models.LiveStreamSession.get(session_id)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot stop a session in status {current.status.value}")

    await log_action(user_id=current_user.id, action="live_stream.ended", details={"session_id": str(session_id), "device_id": str(session.device_id)})

    session = await models.LiveStreamSession.get(session_id)
    station_id = await _device_station_id(device)
    await events.publish_live_stream_ended(session, station_id)

    # Best-effort -- tells egress to finalize the file now rather than
    # waiting for the room to empty on its own; never raises.
    await _stop_egress_best_effort(session)

    return session


@router.post("/live-stream/egress-webhook", include_in_schema=False)
async def egress_webhook(request: Request):
    """
    Called by LiveKit Egress itself -- never a browser or mobile client.
    Authenticated by LiveKit's own signed-JWT webhook scheme -- NOT a user
    Bearer token, so this route is deliberately outside get_current_user.
    """
    body = await request.body()
    auth_header = request.headers.get("Authorization", "")
    try:
        event = _webhook_receiver().receive(body.decode(), auth_header)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if event.event == "egress_ended" and event.egress_info is not None:
        await _handle_egress_ended(event.egress_info)

    return {"received": True}


@router.get("/live-stream/active", response_model=list[schemas.LiveStreamSessionResponse])
async def list_active_live_streams(
    current_user: models.User = Depends(get_current_user),
):
    role = current_user.role
    query = models.LiveStreamSession.find(models.LiveStreamSession.status == models.LiveStreamStatus.live)

    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = [
            c.id for c in await models.Constable.find(models.Constable.station_id == current_user.station_id).to_list()
        ]
        query = query.find(In(models.LiveStreamSession.constable_id, station_constable_ids))
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            return []
        query = query.find(models.LiveStreamSession.constable_id == own_constable.id)
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view live streams")

    return await query.sort(-models.LiveStreamSession.started_at).to_list()


@router.post("/live-stream/{session_id}/viewer-token", response_model=schemas.LiveStreamTokenResponse)
async def get_viewer_token(
    session_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """Subscribe-only token -- never can_publish. Any number of authorized viewers may call this concurrently for the same live session; LiveKit's SFU fans the stream out to all of them."""
    session = await models.LiveStreamSession.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Live stream session not found")
    if session.status != models.LiveStreamStatus.live:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This session is not currently live")

    device = await _get_device_or_404(session.device_id)
    await _authorize_command_issue(device, current_user)

    identity = f"viewer-{current_user.id}"
    token = _mint_token(room=session.room_name, identity=identity, name=identity, can_publish=False)
    return schemas.LiveStreamTokenResponse(
        session=session, livekit_url=LIVEKIT_URL, token=token, identity=identity, can_publish=False,
    )
