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
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from livekit import api as lk_api
from sqlalchemy.orm import Session

from .. import database, models, schemas
from ..auth.deps import get_current_user
from ..services.audit import log_action
from ..services import events
from .commands import _authorize_command_issue, _get_device_or_404
from .constables import get_own_constable
from .devices import _device_station_id

router = APIRouter(tags=["Live Stream"])

LIVEKIT_URL = os.getenv("LIVEKIT_URL", "ws://localhost:7880")
LIVEKIT_API_KEY = os.getenv("LIVEKIT_API_KEY", "devkey")
LIVEKIT_API_SECRET = os.getenv("LIVEKIT_API_SECRET", "secret")

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

    return session


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
