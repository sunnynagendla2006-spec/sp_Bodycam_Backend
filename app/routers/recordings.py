"""
RecordingSession + embedded VideoChunk (see models.Chunk's docstring for
why chunks are embedded rather than a separate collection).

Reuses the existing evidence storage/validation pipeline from
app/routers/media.py (ALLOWED_MIME_TO_EXT, MIME sniffing, storage backend
abstraction) rather than duplicating it.

RecordingSession deliberately never requires an Incident (incident_id is
optional) -- a constable must be able to start an emergency recording
without any Incident existing first.
"""
import asyncio
import datetime
import hashlib
import logging
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Query, UploadFile, File, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials
from jose import JWTError
from pymongo import ReturnDocument

from beanie.operators import In

from .. import models, schemas
from ..auth.deps import bearer_scheme, get_current_user, require_role
from ..auth.security import decode_access_token
from ..services.audit import log_action
from ..services import events
from ..services import chunk_manifest as chunk_manifest_service
from ..services import storage as storage_service
from . import media as media_module
from .constables import get_own_constable
from .devices import _require_own_device_for_constable

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recordings", tags=["Recordings"])


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _build_chunk_storage_key(recording_session_id: uuid.UUID, chunk_number: int, mime_type: str) -> str:
    ext = media_module.ALLOWED_MIME_TO_EXT.get(mime_type, "")
    return f"recordings/{recording_session_id}/chunk_{chunk_number:06d}{ext}"


_WATERMARK_FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


def _format_watermark_text(
    session: models.RecordingSession,
    latitude: Optional[float],
    longitude: Optional[float],
    recorded_at: Optional[datetime.datetime],
) -> tuple[str, str]:
    """Returns (top_status_text, bottom_info_block_text) for _burn_watermark_best_effort."""
    status_text = "EMERGENCY RECORDING" if session.trigger_type == models.RecordingTriggerType.emergency_button else "RECORDING"
    gps_text = f"GPS: {latitude:.6f}, {longitude:.6f}" if latitude is not None and longitude is not None else "GPS: SIGNAL UNAVAILABLE"
    when = recorded_at or _utcnow()
    time_text = f"TIME: {when.strftime('%Y-%m-%d %H:%M:%S')}"
    camera_text = f"CAMERA: {(session.camera_lens_direction or 'back').upper()}"
    return status_text, f"{gps_text}\n{time_text}\n{camera_text}"


def _escape_drawtext(text: str) -> str:
    return text.replace("\\", "\\\\").replace(":", "\\:").replace("'", "\\'")


async def _burn_watermark_best_effort(
    *,
    storage: storage_service.EvidenceStorageBackend,
    storage_key: str,
    session: models.RecordingSession,
    latitude: Optional[float],
    longitude: Optional[float],
    recorded_at: Optional[datetime.datetime],
) -> Optional[tuple[int, str]]:
    """
    Re-encodes the chunk at storage_key IN PLACE, burning a status/GPS/
    timestamp/camera overlay directly into the video frames. Never raises
    and never corrupts/loses the chunk: on ANY failure the ORIGINAL file at
    storage_key is left completely untouched. Returns (new_size,
    new_sha256_hex) on success, None on skip/failure.
    """
    if not isinstance(storage, storage_service.LocalFilesystemStorage):
        logger.warning(f"chunk {storage_key}: watermark burn skipped -- not on LocalFilesystemStorage")
        return None

    original_abs_path = storage._abs_path(storage_key)
    burned_abs_path = original_abs_path + ".watermarked.tmp.mp4"
    info_text_path = original_abs_path + ".overlay.txt"

    status_text, info_text = _format_watermark_text(session, latitude, longitude, recorded_at)

    returncode = -1
    stderr = b""
    try:
        with open(info_text_path, "w") as f:
            f.write(info_text)

        vf = (
            "drawbox=x=10:y=10:w=22:h=22:color=red@0.9:t=fill,"
            f"drawtext=text='{_escape_drawtext(status_text)}':fontfile={_WATERMARK_FONT_PATH}:"
            "fontcolor=white:fontsize=22:x=42:y=12:box=1:boxcolor=black@0.45:boxborderw=6,"
            f"drawtext=textfile={info_text_path}:fontfile={_WATERMARK_FONT_PATH}:"
            "fontcolor=white:fontsize=18:x=10:y=h-th-14:line_spacing=6:box=1:boxcolor=black@0.5:boxborderw=8"
        )

        proc = await asyncio.create_subprocess_exec(
            "ffmpeg", "-y", "-i", original_abs_path,
            "-vf", vf,
            "-c:v", "libx264", "-preset", "ultrafast", "-crf", "23",
            "-c:a", "copy",
            "-movflags", "+faststart",
            burned_abs_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        returncode = proc.returncode
    except FileNotFoundError:
        stderr = b"ffmpeg is not installed in this environment"
    except Exception as exc:  # never let a watermark failure break chunk upload
        stderr = str(exc).encode()
    finally:
        try:
            os.remove(info_text_path)
        except OSError:
            pass

    if returncode != 0 or not os.path.exists(burned_abs_path) or os.path.getsize(burned_abs_path) == 0:
        logger.warning(f"chunk {storage_key}: watermark burn failed (code={returncode}): {stderr.decode(errors='replace')[-2000:]}")
        try:
            if os.path.exists(burned_abs_path):
                os.remove(burned_abs_path)
        except OSError:
            pass
        return None

    hasher = hashlib.sha256()
    with open(burned_abs_path, "rb") as f:
        while True:
            piece = f.read(media_module._READ_CHUNK_SIZE)
            if not piece:
                break
            hasher.update(piece)
    new_size = os.path.getsize(burned_abs_path)
    new_hash = hasher.hexdigest()

    os.replace(burned_abs_path, original_abs_path)  # same filesystem -- atomic
    return new_size, new_hash


def _to_recording_response(session: models.RecordingSession) -> schemas.RecordingSessionResponse:
    summary = chunk_manifest_service.summarize_chunks([c.chunk_number for c in session.chunks])
    return schemas.RecordingSessionResponse(
        id=session.id,
        constable_id=session.constable_id,
        device_id=session.device_id,
        trigger_type=session.trigger_type,
        status=session.status,
        started_at=session.started_at,
        ended_at=session.ended_at,
        incident_id=session.incident_id,
        created_at=session.created_at,
        chunk_count=len(summary.received_chunk_numbers),
        highest_chunk_number=summary.highest_received,
        missing_chunk_numbers=summary.missing_chunk_numbers,
        playable_status=session.playable_status,
        camera_lens_direction=session.camera_lens_direction,
    )


async def _authorize_recording_access(session: models.RecordingSession, current_user: models.User) -> bool:
    """
    admin/control_room: any recording.
    station: only recordings belonging to constables assigned to that station.
    constable: only their own recordings.
    citizen: never.
    """
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        return True
    if role == models.UserRole.station:
        if not current_user.station_id:
            return False
        constable = await models.Constable.get(session.constable_id)
        return constable is not None and constable.station_id == current_user.station_id
    if role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        return own_constable is not None and session.constable_id == own_constable.id
    return False


async def _require_own_recording(current_user: models.User, recording_id: uuid.UUID):
    """Used by the mutating endpoints (chunks/complete/cancel) -- ownership only."""
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the recording constable may perform this action")
    own_constable = await get_own_constable(current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")

    session = await models.RecordingSession.get(recording_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if session.constable_id != own_constable.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to modify this recording")

    return own_constable, session


@router.post("/start", response_model=schemas.RecordingSessionResponse)
async def start_recording(
    payload: schemas.RecordingStartRequest,
    current_user: models.User = Depends(get_current_user),
):
    """Constable-only, for their own already-registered device (reuses the exact ownership check from devices.py's heartbeat/battery endpoints)."""
    own_constable, device = await _require_own_device_for_constable(current_user, payload.device_identifier)

    if payload.incident_id is not None:
        incident = await models.Incident.get(payload.incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Referenced incident not found")

    camera_lens_direction = payload.camera_lens_direction or "back"
    if camera_lens_direction not in ("front", "back"):
        raise HTTPException(status_code=422, detail="camera_lens_direction must be 'front' or 'back'")

    session = models.RecordingSession(
        constable_id=own_constable.id,
        device_id=device.id,
        trigger_type=payload.trigger_type,
        status=models.RecordingStatus.recording,
        incident_id=payload.incident_id,
        camera_lens_direction=camera_lens_direction,
    )
    await session.insert()
    device.status = models.DeviceStatus.recording  # see devices.py::compute_effective_status for how this is surfaced
    await device.save()

    await log_action(
        user_id=current_user.id,
        action="recording.started",
        incident_id=payload.incident_id,
        details={"recording_session_id": str(session.id), "trigger_type": payload.trigger_type.value, "device_id": str(device.id)},
    )

    await events.publish_recording_started(session, own_constable.station_id)

    return _to_recording_response(session)


@router.post("/{recording_id}/chunks", response_model=schemas.VideoChunkResponse)
async def upload_chunk(
    recording_id: uuid.UUID,
    chunk_number: int = Form(...),
    duration_seconds: Optional[float] = Form(None),
    is_last_chunk: bool = Form(False),
    latitude: Optional[float] = Form(None),
    longitude: Optional[float] = Form(None),
    recorded_at: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user),
):
    """
    Out-of-order arrival is fully supported -- chunk_number is preserved
    exactly as supplied, never physically reordered or renamed on disk.
    Duplicate chunk_number is rejected with 409, protected by BOTH an
    application-level fast-path check AND an atomic `find_one_and_update`
    array-push (the direct Mongo equivalent of the old
    uq_chunk_number_per_recording database constraint) -- the fast-path
    check alone cannot close a race between two concurrent uploads of the
    same chunk_number, but the atomic push (which only matches when no
    existing array element already has this chunk_number) can.
    """
    own_constable, session = await _require_own_recording(current_user, recording_id)

    if session.status != models.RecordingStatus.recording:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot upload chunks to a recording in status {session.status.value}",
            headers={"X-Conflict-Reason": "recording_not_active"},
        )
    if chunk_number < 1:
        raise HTTPException(status_code=422, detail="chunk_number must be >= 1")

    # Fast-path duplicate check (not the genuine safety net -- see below).
    if any(c.chunk_number == chunk_number for c in session.chunks):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Chunk {chunk_number} was already uploaded for this recording",
            headers={"X-Conflict-Reason": "duplicate_chunk"},
        )

    # --- Validated read/store pipeline, reusing media.py's exact logic ---
    first_chunk = await file.read(media_module._READ_CHUNK_SIZE)
    declared_mime = (file.content_type or "").lower()
    sniffed_mime = media_module._sniff_mime_type(first_chunk)

    if sniffed_mime and declared_mime and media_module._mime_category(sniffed_mime) != media_module._mime_category(declared_mime):
        raise HTTPException(status_code=400, detail="Chunk content does not match the declared file type")

    resolved_mime = sniffed_mime or declared_mime
    if resolved_mime not in media_module.ALLOWED_MIME_TO_EXT:
        raise HTTPException(status_code=400, detail=f"Unsupported chunk file type: {resolved_mime or 'unknown'}")

    storage_key = _build_chunk_storage_key(recording_id, chunk_number, resolved_mime)
    storage = media_module._get_storage_backend()

    hasher = hashlib.sha256()
    bytes_written = 0
    try:
        with storage.open_write(storage_key) as buffer:
            for piece in (first_chunk,):
                hasher.update(piece)
                buffer.write(piece)
                bytes_written += len(piece)
            while True:
                if bytes_written > media_module.MAX_EVIDENCE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Chunk exceeds the {media_module.MAX_EVIDENCE_SIZE_MB}MB limit",
                    )
                piece = await file.read(media_module._READ_CHUNK_SIZE)
                if not piece:
                    break
                hasher.update(piece)
                buffer.write(piece)
                bytes_written += len(piece)
        if bytes_written > media_module.MAX_EVIDENCE_SIZE_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Chunk exceeds the {media_module.MAX_EVIDENCE_SIZE_MB}MB limit")
    except HTTPException:
        storage.delete(storage_key)
        raise
    except Exception:
        storage.delete(storage_key)
        raise

    file_hash = hasher.hexdigest()

    parsed_recorded_at: Optional[datetime.datetime] = None
    if recorded_at:
        try:
            parsed_recorded_at = datetime.datetime.fromisoformat(recorded_at.replace("Z", "+00:00"))
        except ValueError:
            parsed_recorded_at = None  # malformed value from an old/buggy client -- never fatal, just omitted

    burn_result = await _burn_watermark_best_effort(
        storage=storage,
        storage_key=storage_key,
        session=session,
        latitude=latitude,
        longitude=longitude,
        recorded_at=parsed_recorded_at,
    )
    if burn_result is not None:
        bytes_written, file_hash = burn_result

    chunk = models.Chunk(
        chunk_number=chunk_number,
        storage_key=storage_key,
        file_size=bytes_written,
        duration_seconds=duration_seconds,
        file_hash=file_hash,
        mime_type=resolved_mime,
        is_last_chunk=is_last_chunk,
        upload_status=models.ChunkUploadStatus.uploaded,
        latitude=latitude,
        longitude=longitude,
        recorded_at=parsed_recorded_at,
    )

    updated = await models.RecordingSession.get_motor_collection().find_one_and_update(
        {"_id": recording_id, "chunks.chunk_number": {"$ne": chunk_number}},
        {"$push": {"chunks": chunk.model_dump()}},
        return_document=ReturnDocument.AFTER,
    )
    if updated is None:
        # Lost the race -- a concurrent request already pushed this exact
        # chunk_number in between our fast-path check and this atomic push.
        storage.delete(storage_key)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Chunk {chunk_number} was already uploaded for this recording",
            headers={"X-Conflict-Reason": "duplicate_chunk"},
        )
    session.chunks.append(chunk)

    await log_action(
        user_id=current_user.id,
        action="recording.chunk_uploaded",
        incident_id=session.incident_id,
        details={"recording_session_id": str(recording_id), "chunk_number": chunk_number, "file_hash": file_hash, "file_size": bytes_written},
    )

    await events.publish_recording_chunk_uploaded(session, own_constable.station_id, chunk_number, is_last_chunk)

    return schemas.VideoChunkResponse(
        id=chunk.id,
        recording_session_id=recording_id,
        chunk_number=chunk.chunk_number,
        file_size=chunk.file_size,
        duration_seconds=chunk.duration_seconds,
        file_hash=chunk.file_hash,
        mime_type=chunk.mime_type,
        is_last_chunk=chunk.is_last_chunk,
        upload_status=chunk.upload_status.value,
        created_at=chunk.created_at,
        latitude=chunk.latitude,
        longitude=chunk.longitude,
        recorded_at=chunk.recorded_at,
    )


async def _try_build_playable_recording(session: models.RecordingSession) -> None:
    """
    Best-effort: concatenates this recording's chunks (in chunk_number
    order) into one playable file via ffmpeg's concat demuxer with stream
    copy. Never raises. Only runs against the LocalFilesystemStorage
    backend.
    """
    storage = media_module._get_storage_backend()
    if not isinstance(storage, storage_service.LocalFilesystemStorage):
        session.playable_status = "failed"
        await session.save()
        logger.warning(f"recording {session.id}: playable build skipped -- not on LocalFilesystemStorage")
        return

    chunks = sorted(session.chunks, key=lambda c: c.chunk_number)
    if not chunks:
        session.playable_status = "failed"
        await session.save()
        return

    session.playable_status = "building"
    await session.save()

    playable_key = f"recordings/{session.id}/playable.mp4"
    playable_abs_path = storage._abs_path(playable_key)
    concat_list_path = storage._abs_path(f"recordings/{session.id}/_concat_list.txt")
    os.makedirs(os.path.dirname(playable_abs_path), exist_ok=True)

    with open(concat_list_path, "w") as f:
        for chunk in chunks:
            abs_chunk_path = storage._abs_path(chunk.storage_key)
            escaped = abs_chunk_path.replace("'", "'\\''")
            f.write(f"file '{escaped}'\n")

    try:
        proc = await asyncio.create_subprocess_exec(
            "ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", concat_list_path, "-c", "copy", playable_abs_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        returncode = proc.returncode
    except FileNotFoundError:
        returncode = -1
        stderr = b"ffmpeg is not installed in this environment"
    finally:
        try:
            os.remove(concat_list_path)
        except OSError:
            pass

    if returncode == 0 and os.path.exists(playable_abs_path) and os.path.getsize(playable_abs_path) > 0:
        session.playable_status = "ready"
        session.playable_storage_key = playable_key
    else:
        session.playable_status = "failed"
        logger.warning(f"recording {session.id}: ffmpeg concat failed (code={returncode}): {stderr.decode(errors='replace')[-2000:]}")
        try:
            if os.path.exists(playable_abs_path):
                os.remove(playable_abs_path)
        except OSError:
            pass
    await session.save()


@router.post("/{recording_id}/complete", response_model=schemas.RecordingSessionResponse)
async def complete_recording(
    recording_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """
    RECORDING -> COMPLETED only; any other current status is a 409.
    Completion is ALLOWED even with missing chunks.
    """
    own_constable, session = await _require_own_recording(current_user, recording_id)
    if session.status != models.RecordingStatus.recording:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot complete a recording in status {session.status.value}")

    summary = chunk_manifest_service.summarize_chunks([c.chunk_number for c in session.chunks])

    session.status = models.RecordingStatus.completed
    session.ended_at = _utcnow()
    await session.save()

    device = await models.Device.get(session.device_id)
    if device and device.status == models.DeviceStatus.recording:
        device.status = models.DeviceStatus.online
        await device.save()

    await log_action(
        user_id=current_user.id,
        action="recording.completed",
        incident_id=session.incident_id,
        details={"recording_session_id": str(recording_id), "missing_chunk_numbers": summary.missing_chunk_numbers, "chunk_count": len(summary.received_chunk_numbers)},
    )

    await events.publish_recording_completed(session, own_constable.station_id, summary.missing_chunk_numbers)

    if summary.is_contiguous:
        await _try_build_playable_recording(session)

    return _to_recording_response(session)


@router.post("/{recording_id}/cancel", response_model=schemas.RecordingSessionResponse)
async def cancel_recording(
    recording_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """RECORDING -> CANCELLED only; any other current status is a 409."""
    own_constable, session = await _require_own_recording(current_user, recording_id)
    if session.status != models.RecordingStatus.recording:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot cancel a recording in status {session.status.value}")

    session.status = models.RecordingStatus.cancelled
    session.ended_at = _utcnow()
    await session.save()

    device = await models.Device.get(session.device_id)
    if device and device.status == models.DeviceStatus.recording:
        device.status = models.DeviceStatus.online
        await device.save()

    await log_action(
        user_id=current_user.id,
        action="recording.cancelled",
        incident_id=session.incident_id,
        details={"recording_session_id": str(recording_id)},
    )

    await events.publish_recording_cancelled(session, own_constable.station_id)

    return _to_recording_response(session)


@router.get("/", response_model=list[schemas.RecordingSessionResponse])
async def list_recordings(
    device_id: Optional[uuid.UUID] = None,
    status: Optional[models.RecordingStatus] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(require_role("admin", "control_room", "station", "constable")),
):
    """
    Read-only listing so Control Room can discover recordings without
    already knowing a recording_id. Same authorization matrix as GET
    /recordings/{id} (see _authorize_recording_access).
    """
    role = current_user.role
    query = models.RecordingSession.find()

    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = [
            c.id for c in await models.Constable.find(models.Constable.station_id == current_user.station_id).to_list()
        ]
        query = query.find(In(models.RecordingSession.constable_id, station_constable_ids))
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            return []
        query = query.find(models.RecordingSession.constable_id == own_constable.id)

    if device_id is not None:
        query = query.find(models.RecordingSession.device_id == device_id)
    if status is not None:
        query = query.find(models.RecordingSession.status == status)

    sessions = await query.sort(-models.RecordingSession.created_at).skip(offset).limit(limit).to_list()
    return [_to_recording_response(s) for s in sessions]


@router.get("/{recording_id}", response_model=schemas.RecordingSessionResponse)
async def get_recording(
    recording_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    session = await models.RecordingSession.get(recording_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if not await _authorize_recording_access(session, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this recording")

    return _to_recording_response(session)


@router.get("/{recording_id}/chunks", response_model=schemas.RecordingManifestResponse)
async def get_recording_manifest(
    recording_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """
    Ordered chunk manifest -- NOT a live stream. Never exposes
    storage_key/filesystem paths (see schemas.VideoChunkResponse).
    """
    session = await models.RecordingSession.get(recording_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if not await _authorize_recording_access(session, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this recording")

    chunks = sorted(session.chunks, key=lambda c: c.chunk_number)
    summary = chunk_manifest_service.summarize_chunks([c.chunk_number for c in chunks])

    return schemas.RecordingManifestResponse(
        recording_session_id=recording_id,
        status=session.status,
        chunks=[
            schemas.VideoChunkResponse(
                id=c.id,
                recording_session_id=recording_id,
                chunk_number=c.chunk_number,
                file_size=c.file_size,
                duration_seconds=c.duration_seconds,
                file_hash=c.file_hash,
                mime_type=c.mime_type,
                is_last_chunk=c.is_last_chunk,
                upload_status=c.upload_status.value,
                created_at=c.created_at,
                latitude=c.latitude,
                longitude=c.longitude,
                recorded_at=c.recorded_at,
            )
            for c in chunks
        ],
        highest_chunk_number=summary.highest_received,
        missing_chunk_numbers=summary.missing_chunk_numbers,
        is_complete=(session.status == models.RecordingStatus.completed and summary.is_contiguous),
    )


async def _authenticate_stream_request(
    credentials: Optional[HTTPAuthorizationCredentials],
    token_qs: Optional[str],
) -> models.User:
    """
    A browser <video> element never sends a custom Authorization header on
    its own GET/Range requests, so this endpoint must also accept the JWT
    as a `?token=` query parameter -- mirrors websocket.py's
    _authenticate_websocket.
    """
    raw_token = credentials.credentials if credentials and credentials.credentials else token_qs
    if not raw_token:
        raise HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = decode_access_token(raw_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        user_id = uuid.UUID(payload.sub) if isinstance(payload.sub, str) else payload.sub
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    user = await models.User.get(user_id)
    if not user or user.status != models.UserStatus.active:
        raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    return user


@router.get("/{recording_id}/chunks/{chunk_number}/stream")
async def stream_chunk(
    recording_id: uuid.UUID,
    chunk_number: int,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    token: Optional[str] = Query(default=None),
    range: Optional[str] = Header(default=None),
):
    """
    Range-aware playback for a single stored chunk file. Same authorization
    matrix as GET /{recording_id} and .../chunks (via
    _authorize_recording_access) -- never the narrower _require_own_recording
    used by the mutating endpoints.
    """
    current_user = await _authenticate_stream_request(credentials, token)

    session = await models.RecordingSession.get(recording_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if not await _authorize_recording_access(session, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this recording")

    chunk = next((c for c in session.chunks if c.chunk_number == chunk_number), None)
    if not chunk:
        raise HTTPException(status_code=404, detail="Chunk not found")

    storage = media_module._get_storage_backend()
    if not storage.exists(chunk.storage_key):
        raise HTTPException(status_code=404, detail="Chunk file not found")
    size = storage.get_size(chunk.storage_key)
    if size is None:
        raise HTTPException(status_code=404, detail="Chunk file not found")

    media_type = chunk.mime_type or "application/octet-stream"

    async def _audit(extra: dict):
        await log_action(
            user_id=current_user.id,
            action="recording.chunk_streamed",
            details={"recording_id": str(recording_id), "chunk_number": chunk_number, **extra},
        )

    if not range:
        await _audit({"access_method": "stream"})
        headers = {
            "Content-Length": str(size),
            "Accept-Ranges": "bytes",
        }
        return StreamingResponse(
            storage.read_range(chunk.storage_key, 0, size - 1),
            media_type=media_type,
            headers=headers,
            status_code=200,
        )

    start, end, error = media_module._parse_range_header(range, size)
    if error:
        raise HTTPException(status_code=416, detail=error, headers={"Content-Range": f"bytes */{size}"})

    await _audit({"access_method": "stream", "range": f"{start}-{end}"})
    headers = {
        "Content-Range": f"bytes {start}-{end}/{size}",
        "Content-Length": str(end - start + 1),
        "Accept-Ranges": "bytes",
    }
    return StreamingResponse(
        storage.read_range(chunk.storage_key, start, end),
        media_type=media_type,
        headers=headers,
        status_code=206,
    )


@router.get("/{recording_id}/play")
async def play_recording(
    recording_id: uuid.UUID,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    token: Optional[str] = Query(default=None),
    range: Optional[str] = Header(default=None),
):
    """
    Range-aware playback of the single concatenated recording (see
    _try_build_playable_recording).
    """
    current_user = await _authenticate_stream_request(credentials, token)

    session = await models.RecordingSession.get(recording_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if not await _authorize_recording_access(session, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this recording")

    if session.playable_status != "ready" or not session.playable_storage_key:
        detail = "Recording is still being processed" if session.playable_status in ("not_ready", "building") else "Playable recording could not be generated -- see individual chunks instead"
        raise HTTPException(status_code=404, detail=detail)

    storage = media_module._get_storage_backend()
    if not storage.exists(session.playable_storage_key):
        raise HTTPException(status_code=404, detail="Playable recording file not found")
    size = storage.get_size(session.playable_storage_key)
    if size is None:
        raise HTTPException(status_code=404, detail="Playable recording file not found")

    media_type = "video/mp4"

    async def _audit(extra: dict):
        await log_action(
            user_id=current_user.id,
            action="recording.played",
            details={"recording_id": str(recording_id), **extra},
        )

    if not range:
        await _audit({"access_method": "play"})
        headers = {"Content-Length": str(size), "Accept-Ranges": "bytes"}
        return StreamingResponse(
            storage.read_range(session.playable_storage_key, 0, size - 1),
            media_type=media_type,
            headers=headers,
            status_code=200,
        )

    start, end, error = media_module._parse_range_header(range, size)
    if error:
        raise HTTPException(status_code=416, detail=error, headers={"Content-Range": f"bytes */{size}"})

    await _audit({"access_method": "play", "range": f"{start}-{end}"})
    headers = {
        "Content-Range": f"bytes {start}-{end}/{size}",
        "Content-Length": str(end - start + 1),
        "Accept-Ranges": "bytes",
    }
    return StreamingResponse(
        storage.read_range(session.playable_storage_key, start, end),
        media_type=media_type,
        headers=headers,
        status_code=206,
    )
