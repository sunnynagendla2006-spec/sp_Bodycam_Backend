"""
Live camera streaming (ephemeral only -- never recorded/stored). See
app/models.py::LiveStreamSession module docstring for the full picture:
this backend never touches video bytes, it only issues short-lived signed
LiveKit join tokens (publisher for the streaming device, subscriber-only
for every viewing admin) -- the actual media fan-out happens entirely
inside the external LiveKit SFU.

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
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from livekit import api as lk_api
from sqlalchemy.orm import Session

from .. import database, models, schemas
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

# Internal, container-to-container addresses -- distinct from LIVEKIT_URL
# above, which is handed to clients (phones/browsers) and must be the
# host's real LAN-reachable address. Requests this backend process itself
# makes to LiveKit's RPC API (egress start/stop) and requests LiveKit
# Egress itself makes back to this backend (the webhook below) both stay
# entirely inside the Docker Compose network, so the service names already
# defined there (see docker-compose.yml) are always correct and never
# subject to the LAN-IP-changes-on-every-reboot problem LIVEKIT_URL has.
LIVEKIT_INTERNAL_URL = os.getenv("LIVEKIT_INTERNAL_URL", "ws://livekit:7880")
BACKEND_INTERNAL_URL = os.getenv("BACKEND_INTERNAL_URL", "http://backend:8000")

# The egress container's own view of the shared uploads volume (see
# docker-compose.yml's livekit-egress service -- `./backend/uploads:/egress_out`
# is the SAME host directory the backend's LocalFilesystemStorage root
# already serves recordings from). A relative path under here always
# resolves to the identical file from either container.
_EGRESS_CONTAINER_OUTPUT_ROOT = "/egress_out"

# How long a minted join token remains valid for. Generous enough to cover
# a real patrol shift's live-view session without needing re-minting, but
# still bounded -- these are join credentials, not permanent access.
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


def _require_own_device_constable(db: Session, current_user: models.User, device_id: uuid.UUID):
    """Only the constable who owns this device may start/stop a stream AS the device."""
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the device's own constable may perform this action")
    own_constable = get_own_constable(db, current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")
    device = _get_device_or_404(db, device_id)
    if device.constable_id != own_constable.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to act on this device")
    return own_constable, device


def _pending_egress_rel_path(session_id: uuid.UUID) -> str:
    return f"_egress_pending/{session_id}.mp4"


async def _start_egress_best_effort(db: Session, session: models.LiveStreamSession) -> None:
    """
    Best-effort: a room-composite (camera + mic, real audio+video) egress
    recording of this live session's room, to a file on the shared uploads
    volume (see docker-compose.yml/livekit-egress). This must NEVER block
    or break starting the live stream itself -- any failure here (egress
    infra unreachable, Redis down, etc.) just means this particular session
    goes unrecorded, exactly like a missing chunk never blocks a mobile
    recording's own completion elsewhere in this codebase.

    Only supported against LocalFilesystemStorage (same constraint as
    _try_build_playable_recording in recordings.py) -- an S3-backed
    deployment would need egress uploading directly to S3 instead, a
    separate, larger piece of work.
    """
    storage = media_module._get_storage_backend()
    if not isinstance(storage, storage_service.LocalFilesystemStorage):
        logger.warning(f"live stream {session.id}: egress recording skipped -- not on LocalFilesystemStorage")
        return

    egress_filepath = f"{_EGRESS_CONTAINER_OUTPUT_ROOT}/{_pending_egress_rel_path(session.id)}"
    try:
        async with lk_api.LiveKitAPI(LIVEKIT_INTERNAL_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET) as lkapi:
            info = await lkapi.egress.start_room_composite_egress(
                lk_api.RoomCompositeEgressRequest(
                    room_name=session.room_name,
                    audio_only=False,
                    file_outputs=[lk_api.EncodedFileOutput(file_type=lk_api.EncodedFileType.MP4, filepath=egress_filepath)],
                    webhooks=[lk_api.WebhookConfig(url=f"{BACKEND_INTERNAL_URL}/live-stream/egress-webhook")],
                )
            )
        session.egress_id = info.egress_id
        db.commit()
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


async def _handle_egress_ended(db: Session, egress_info) -> None:
    """
    Turns a completed egress recording into a real recording_sessions row
    (trigger_type='live_stream') -- reusing Requirement 1's exact playable
    pipeline (playable_status/playable_storage_key + GET
    /recordings/{id}/play) rather than a second video table/player. Never
    fabricates a recording: only EGRESS_COMPLETE with a real, non-empty
    output file on disk results in a row being created; anything else is
    logged and left alone (the live stream itself already ended fine
    regardless).
    """
    session = db.query(models.LiveStreamSession).filter(models.LiveStreamSession.egress_id == egress_info.egress_id).first()
    if not session:
        return  # some other egress job, or one from a previous deployment
    if session.recording_session_id is not None:
        return  # webhook redelivery -- never create a duplicate recording

    if egress_info.status != lk_api.EgressStatus.EGRESS_COMPLETE:
        logger.warning(f"live stream {session.id}: egress {egress_info.egress_id} ended with status {egress_info.status} -- no recording created")
        return

    storage = media_module._get_storage_backend()
    if not isinstance(storage, storage_service.LocalFilesystemStorage):
        return

    pending_abs_path = storage._abs_path(_pending_egress_rel_path(session.id))
    if not os.path.exists(pending_abs_path) or os.path.getsize(pending_abs_path) == 0:
        logger.warning(f"live stream {session.id}: egress reported complete but output file missing/empty at {pending_abs_path}")
        return

    new_id = uuid.uuid4()
    final_rel_path = f"recordings/{new_id}/playable.mp4"
    final_abs_path = storage._abs_path(final_rel_path)
    os.makedirs(os.path.dirname(final_abs_path), exist_ok=True)
    os.rename(pending_abs_path, final_abs_path)  # same volume -- a rename, never a copy

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
    db.add(recording)
    session.recording_session_id = new_id
    log_action(
        db, user_id=None, action="live_stream.recorded",
        details={"live_stream_session_id": str(session.id), "recording_session_id": str(new_id), "egress_id": egress_info.egress_id},
    )
    db.commit()


def _locked_session_or_404(db: Session, session_id: uuid.UUID) -> models.LiveStreamSession:
    session = (
        db.query(models.LiveStreamSession)
        .filter(models.LiveStreamSession.id == session_id)
        .with_for_update()
        .first()
    )
    if not session:
        raise HTTPException(status_code=404, detail="Live stream session not found")
    return session


@router.post("/devices/{device_id}/live-stream/start", response_model=schemas.LiveStreamTokenResponse)
async def start_live_stream(
    device_id: uuid.UUID,
    payload: schemas.LiveStreamStartRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    own_constable, device = _require_own_device_constable(db, current_user, device_id)

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
    db.add(session)
    log_action(
        db, user_id=current_user.id, action="live_stream.started",
        details={"device_id": str(device_id), "room_name": room, "started_by": started_by.value},
    )
    db.commit()
    db.refresh(session)

    station_id = own_constable.station_id
    await events.publish_live_stream_started(session, station_id)

    # Best-effort -- never raises, never delays/blocks issuing the join
    # token below even if it's slow or fails outright.
    await _start_egress_best_effort(db, session)

    identity = f"device-{device_id}"
    token = _mint_token(room=room, identity=identity, name=identity, can_publish=True)
    return schemas.LiveStreamTokenResponse(
        session=session, livekit_url=LIVEKIT_URL, token=token, identity=identity, can_publish=True,
    )


@router.post("/live-stream/{session_id}/stop", response_model=schemas.LiveStreamSessionResponse)
async def stop_live_stream(
    session_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    session = _locked_session_or_404(db, session_id)
    if session.status != models.LiveStreamStatus.live:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot stop a session in status {session.status.value}")

    device = _get_device_or_404(db, session.device_id)

    # Either the device's own constable, or an admin/control_room/station
    # (own station) force-stopping it -- same rule as issuing a command.
    if current_user.role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable or session.constable_id != own_constable.id:
            db.rollback()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to stop this session")
    else:
        try:
            _authorize_command_issue(db, device, current_user)
        except HTTPException:
            db.rollback()
            raise

    session.status = models.LiveStreamStatus.ended
    session.ended_at = _utcnow()
    log_action(db, user_id=current_user.id, action="live_stream.ended", details={"session_id": str(session_id), "device_id": str(session.device_id)})
    db.commit()
    db.refresh(session)

    station_id = _device_station_id(db, device)
    await events.publish_live_stream_ended(session, station_id)

    # Best-effort -- tells egress to finalize the file now rather than
    # waiting for the room to empty on its own; never raises.
    await _stop_egress_best_effort(session)

    return session


@router.post("/live-stream/egress-webhook", include_in_schema=False)
async def egress_webhook(request: Request, db: Session = Depends(database.get_db)):
    """
    Called by LiveKit Egress itself (see the webhooks= field passed in
    _start_egress_best_effort above) -- never a browser or mobile client.
    Authenticated by LiveKit's own signed-JWT webhook scheme, verified
    against the same devkey/secret every other LiveKit call in this file
    already uses -- NOT a user Bearer token, so this route is deliberately
    outside get_current_user.
    """
    body = await request.body()
    auth_header = request.headers.get("Authorization", "")
    try:
        event = _webhook_receiver().receive(body.decode(), auth_header)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if event.event == "egress_ended" and event.egress_info is not None:
        await _handle_egress_ended(db, event.egress_info)

    return {"received": True}


@router.get("/live-stream/active", response_model=list[schemas.LiveStreamSessionResponse])
def list_active_live_streams(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    role = current_user.role
    query = db.query(models.LiveStreamSession).filter(models.LiveStreamSession.status == models.LiveStreamStatus.live)

    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = db.query(models.Constable.id).filter(models.Constable.station_id == current_user.station_id)
        query = query.filter(models.LiveStreamSession.constable_id.in_(station_constable_ids))
    elif role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable:
            return []
        query = query.filter(models.LiveStreamSession.constable_id == own_constable.id)
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view live streams")

    return query.order_by(models.LiveStreamSession.started_at.desc()).all()


@router.post("/live-stream/{session_id}/viewer-token", response_model=schemas.LiveStreamTokenResponse)
def get_viewer_token(
    session_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Subscribe-only token -- never can_publish. Any number of authorized viewers may call this concurrently for the same live session; LiveKit's SFU fans the stream out to all of them."""
    session = db.query(models.LiveStreamSession).filter(models.LiveStreamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Live stream session not found")
    if session.status != models.LiveStreamStatus.live:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This session is not currently live")

    device = _get_device_or_404(db, session.device_id)
    _authorize_command_issue(db, device, current_user)

    identity = f"viewer-{current_user.id}"
    token = _mint_token(room=session.room_name, identity=identity, name=identity, can_publish=False)
    return schemas.LiveStreamTokenResponse(
        session=session, livekit_url=LIVEKIT_URL, token=token, identity=identity, can_publish=False,
    )
