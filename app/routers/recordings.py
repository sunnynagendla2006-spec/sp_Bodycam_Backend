"""
Phase 2 (body-camera system): RecordingSession + VideoChunk.

Reuses the existing evidence storage/validation pipeline from
app/routers/media.py (ALLOWED_MIME_TO_EXT, MIME sniffing, storage backend
abstraction) rather than duplicating it -- a second, unsafe storage
implementation is exactly what the approved spec forbids.

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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import database, models, schemas
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
    """
    Both path components are server-controlled: recording_session_id is a
    UUID (never client-suppliable as a path -- it's the resource being
    addressed, validated by FastAPI's uuid.UUID path-param typing before
    this ever runs), and chunk_number is formatted as a zero-padded
    integer, never inserted as a raw string. No client-supplied filename
    is ever used to build a path (mirrors media.py::_build_storage_key).
    """
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
    """Escapes characters ffmpeg's drawtext `text=` filter parameter treats
    specially. Only ever applied to server-generated strings (status labels)
    -- never raw client input reaches a filtergraph string anywhere here."""
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
    timestamp/camera overlay directly into the video frames. This is a
    genuine pixel-level change -- never a Flutter UI overlay (which would
    only exist on-screen, not in the encoded file) and never a raw byte
    edit (drawtext/drawbox require an actual decode+re-encode of the video
    stream, via ffmpeg, the same tool/pattern _try_build_playable_recording
    already uses for the separate concat step below). The audio stream is
    stream-copied (-c:a copy) since drawtext never touches audio.

    Never raises and never corrupts/loses the chunk: on ANY failure (ffmpeg
    missing, decode error, an S3-backed deployment, etc.) the ORIGINAL file
    at storage_key is left completely untouched -- still fully valid,
    individually playable evidence, just without the burned overlay this
    one time. Returns (new_size, new_sha256_hex) on success so the caller
    can update the VideoChunk row to describe the bytes actually now on
    disk; returns None on skip/failure, meaning the caller's original
    file_size/file_hash (from the as-uploaded bytes) remain correct as-is.
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

        # Small red square + status label top-left; semi-transparent info
        # block bottom-left (GPS/time/camera) -- positioned so neither
        # covers the center of the frame, per the design brief. h-th-14
        # positions the (possibly multi-line) info block a fixed 14px above
        # the bottom edge regardless of how tall the rendered text block is.
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


def _chunk_numbers_for(db: Session, recording_session_id: uuid.UUID) -> list[int]:
    rows = db.query(models.VideoChunk.chunk_number).filter(models.VideoChunk.recording_session_id == recording_session_id).all()
    return [r[0] for r in rows]


def _to_recording_response(db: Session, session: models.RecordingSession) -> schemas.RecordingSessionResponse:
    summary = chunk_manifest_service.summarize_chunks(_chunk_numbers_for(db, session.id))
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


def _authorize_recording_access(db: Session, session: models.RecordingSession, current_user: models.User) -> bool:
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
        constable = db.query(models.Constable).filter(models.Constable.id == session.constable_id).first()
        return constable is not None and constable.station_id == current_user.station_id
    if role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        return own_constable is not None and session.constable_id == own_constable.id
    return False


def _require_own_recording(db: Session, current_user: models.User, recording_id: uuid.UUID):
    """Used by the mutating endpoints (chunks/complete/cancel) -- ownership only, not the broader read-authorization matrix above (a station/control_room user may VIEW a recording but must never be able to mutate a constable's own in-progress recording)."""
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the recording constable may perform this action")
    own_constable = get_own_constable(db, current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")

    session = db.query(models.RecordingSession).filter(models.RecordingSession.id == recording_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if session.constable_id != own_constable.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to modify this recording")

    return own_constable, session


@router.post("/start", response_model=schemas.RecordingSessionResponse)
async def start_recording(
    payload: schemas.RecordingStartRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Constable-only, for their own already-registered device (reuses the exact ownership check from Phase 1's heartbeat/battery endpoints)."""
    own_constable, device = _require_own_device_for_constable(db, current_user, payload.device_identifier)

    if payload.incident_id is not None:
        incident = db.query(models.Incident).filter(models.Incident.id == payload.incident_id).first()
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
    db.add(session)
    device.status = models.DeviceStatus.recording  # see devices.py::compute_effective_status for how this is surfaced

    db.flush()
    log_action(
        db,
        user_id=current_user.id,
        action="recording.started",
        incident_id=payload.incident_id,
        details={"recording_session_id": str(session.id), "trigger_type": payload.trigger_type.value, "device_id": str(device.id)},
    )

    db.commit()
    db.refresh(session)

    await events.publish_recording_started(session, own_constable.station_id)

    return _to_recording_response(db, session)


@router.post("/{recording_id}/chunks", response_model=schemas.VideoChunkResponse)
async def upload_chunk(
    recording_id: uuid.UUID,
    chunk_number: int = Form(...),
    duration_seconds: Optional[float] = Form(None),
    is_last_chunk: bool = Form(False),
    # Real GPS fix (from the mobile app's existing cached LocationService --
    # see recording_service.dart) and device-local capture time as of THIS
    # segment. All optional: an older client, or a device with no GPS fix
    # yet, simply omits them -- the watermark burn below then shows "GPS:
    # SIGNAL UNAVAILABLE" rather than treating it as an error.
    latitude: Optional[float] = Form(None),
    longitude: Optional[float] = Form(None),
    recorded_at: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Out-of-order arrival is fully supported -- chunk_number is preserved
    exactly as supplied, never physically reordered or renamed on disk.
    Duplicate chunk_number is rejected with 409, protected by BOTH an
    application-level fast-path check AND the genuine
    uq_chunk_number_per_recording database constraint (see Task 5) --
    the fast-path check alone cannot close a race between two concurrent
    uploads of the same chunk_number.
    """
    own_constable, session = _require_own_recording(db, current_user, recording_id)

    if session.status != models.RecordingStatus.recording:
        # Distinct from the "duplicate chunk" 409 below via the
        # X-Conflict-Reason header -- see chunk_uploader.dart's matching
        # handling for why these two, despite sharing an HTTP status code,
        # must never be treated the same by the client: this one means the
        # chunk was NEVER accepted and its local copy must be preserved,
        # not deleted.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot upload chunks to a recording in status {session.status.value}",
            headers={"X-Conflict-Reason": "recording_not_active"},
        )
    if chunk_number < 1:
        raise HTTPException(status_code=422, detail="chunk_number must be >= 1")

    # Fast-path duplicate check (not the genuine safety net -- see below).
    existing = (
        db.query(models.VideoChunk)
        .filter(models.VideoChunk.recording_session_id == recording_id, models.VideoChunk.chunk_number == chunk_number)
        .first()
    )
    if existing:
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

    # Best-effort: burns STATUS/GPS/TIME/CAMERA into this chunk's actual
    # video frames, re-encoding the file in place at storage_key. Never
    # raises -- on any failure the original, un-watermarked-but-perfectly-
    # valid chunk is left exactly as uploaded (see the function's own
    # docstring). Only on success are file_hash/bytes_written updated below
    # to reflect the real, now-watermarked bytes actually stored.
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

    chunk = models.VideoChunk(
        recording_session_id=recording_id,
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

    try:
        with db.begin_nested():
            db.add(chunk)
            db.flush()
    except IntegrityError:
        # Lost the race against uq_chunk_number_per_recording -- a
        # concurrent request already committed this exact chunk_number.
        # The SAVEPOINT rollback (handled automatically by the `with`
        # block above on exception) leaves the outer session/transaction
        # perfectly usable -- nothing here poisons it.
        storage.delete(storage_key)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Chunk {chunk_number} was already uploaded for this recording",
            headers={"X-Conflict-Reason": "duplicate_chunk"},
        )

    log_action(
        db,
        user_id=current_user.id,
        action="recording.chunk_uploaded",
        incident_id=session.incident_id,
        details={"recording_session_id": str(recording_id), "chunk_number": chunk_number, "file_hash": file_hash, "file_size": bytes_written},
    )

    try:
        db.commit()
    except Exception:
        db.rollback()
        storage.delete(storage_key)
        raise
    db.refresh(chunk)

    await events.publish_recording_chunk_uploaded(session, own_constable.station_id, chunk_number, is_last_chunk)

    return chunk


async def _try_build_playable_recording(db: Session, session: models.RecordingSession) -> None:
    """
    Best-effort: concatenates this recording's chunks (in chunk_number
    order) into one playable file via ffmpeg's concat demuxer with stream
    copy (`-c copy` -- no re-encoding, so this is a real remux, never a
    raw byte-slice/concatenation of MP4 files, which would corrupt the
    container). Never raises: any failure here must never fail the
    /complete request itself, and never touches the individual chunk
    files/rows, which remain the authoritative evidence either way.

    Only runs against the LocalFilesystemStorage backend (the one actually
    deployed here -- see storage.py's get_storage_backend default). Against
    an S3-backed deployment this cleanly records "failed" with a clear
    reason rather than downloading every chunk into this process first,
    which would be a much larger, separate piece of work.
    """
    storage = media_module._get_storage_backend()
    if not isinstance(storage, storage_service.LocalFilesystemStorage):
        session.playable_status = "failed"
        db.commit()
        logger.warning(f"recording {session.id}: playable build skipped -- not on LocalFilesystemStorage")
        return

    chunks = (
        db.query(models.VideoChunk)
        .filter(models.VideoChunk.recording_session_id == session.id)
        .order_by(models.VideoChunk.chunk_number.asc())
        .all()
    )
    if not chunks:
        session.playable_status = "failed"
        db.commit()
        return

    session.playable_status = "building"
    db.commit()

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
    db.commit()


@router.post("/{recording_id}/complete", response_model=schemas.RecordingSessionResponse)
async def complete_recording(
    recording_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    RECORDING -> COMPLETED only; any other current status is a 409.

    Completion is ALLOWED even with missing chunks (network conditions can
    legitimately and permanently prevent a chunk from ever arriving --
    blocking completion forever would trap the recording in limbo). The
    gap is never hidden: missing_chunk_numbers is included in the
    response, the audit record, and the recording.completed WebSocket
    event.
    """
    own_constable, session = _require_own_recording(db, current_user, recording_id)
    if session.status != models.RecordingStatus.recording:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot complete a recording in status {session.status.value}")

    summary = chunk_manifest_service.summarize_chunks(_chunk_numbers_for(db, recording_id))

    session.status = models.RecordingStatus.completed
    session.ended_at = _utcnow()

    device = db.query(models.Device).filter(models.Device.id == session.device_id).first()
    if device and device.status == models.DeviceStatus.recording:
        device.status = models.DeviceStatus.online

    log_action(
        db,
        user_id=current_user.id,
        action="recording.completed",
        incident_id=session.incident_id,
        details={"recording_session_id": str(recording_id), "missing_chunk_numbers": summary.missing_chunk_numbers, "chunk_count": len(summary.received_chunk_numbers)},
    )

    db.commit()
    db.refresh(session)

    await events.publish_recording_completed(session, own_constable.station_id, summary.missing_chunk_numbers)

    # Best-effort, additive only -- see _try_build_playable_recording's
    # docstring. Only attempted when every chunk actually arrived; a gap
    # means ffmpeg concat would either fail outright or silently produce a
    # playable file with a real missing segment, neither of which is
    # acceptable for evidence. The chunks/manifest remain the authoritative
    # record regardless of whether this succeeds.
    if summary.is_contiguous:
        await _try_build_playable_recording(db, session)

    return _to_recording_response(db, session)


@router.post("/{recording_id}/cancel", response_model=schemas.RecordingSessionResponse)
async def cancel_recording(
    recording_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """RECORDING -> CANCELLED only; any other current status is a 409."""
    own_constable, session = _require_own_recording(db, current_user, recording_id)
    if session.status != models.RecordingStatus.recording:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot cancel a recording in status {session.status.value}")

    session.status = models.RecordingStatus.cancelled
    session.ended_at = _utcnow()

    device = db.query(models.Device).filter(models.Device.id == session.device_id).first()
    if device and device.status == models.DeviceStatus.recording:
        device.status = models.DeviceStatus.online

    log_action(
        db,
        user_id=current_user.id,
        action="recording.cancelled",
        incident_id=session.incident_id,
        details={"recording_session_id": str(recording_id)},
    )

    db.commit()
    db.refresh(session)

    await events.publish_recording_cancelled(session, own_constable.station_id)

    return _to_recording_response(db, session)


@router.get("/", response_model=list[schemas.RecordingSessionResponse])
def list_recordings(
    device_id: Optional[uuid.UUID] = None,
    status: Optional[models.RecordingStatus] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station", "constable")),
):
    """
    Phase 4A: read-only listing so Control Room can discover recordings
    without already knowing a recording_id (previously the ONLY way to
    reach a recording was already having its ID, e.g. from a live
    `recording.started` WebSocket event). Never starts/stops/mutates a
    recording -- purely a query over existing RecordingSession rows.

    Same authorization matrix as GET /recordings/{id} (see
    _authorize_recording_access): admin/control_room see everything;
    station sees only recordings whose constable belongs to their
    station; constable sees only their own; citizen is denied entirely
    (matching every other device/recording endpoint in this project).

    Reuses _to_recording_response for each row so the computed fields
    (chunk_count, highest_chunk_number, missing_chunk_numbers) are
    identical to what GET /recordings/{id} already returns -- no
    duplicated/divergent logic.
    """
    role = current_user.role
    query = db.query(models.RecordingSession)

    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = db.query(models.Constable.id).filter(models.Constable.station_id == current_user.station_id)
        query = query.filter(models.RecordingSession.constable_id.in_(station_constable_ids))
    elif role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable:
            return []
        query = query.filter(models.RecordingSession.constable_id == own_constable.id)

    if device_id is not None:
        query = query.filter(models.RecordingSession.device_id == device_id)
    if status is not None:
        query = query.filter(models.RecordingSession.status == status)

    sessions = (
        query.order_by(models.RecordingSession.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_to_recording_response(db, s) for s in sessions]


@router.get("/{recording_id}", response_model=schemas.RecordingSessionResponse)
def get_recording(
    recording_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    session = db.query(models.RecordingSession).filter(models.RecordingSession.id == recording_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if not _authorize_recording_access(db, session, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this recording")

    return _to_recording_response(db, session)


@router.get("/{recording_id}/chunks", response_model=schemas.RecordingManifestResponse)
def get_recording_manifest(
    recording_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Ordered chunk manifest -- NOT a live stream. Chunks are always
    returned ordered by chunk_number regardless of upload arrival order.
    Never exposes storage_key/filesystem paths (see schemas.VideoChunkResponse).
    """
    session = db.query(models.RecordingSession).filter(models.RecordingSession.id == recording_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if not _authorize_recording_access(db, session, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this recording")

    chunks = (
        db.query(models.VideoChunk)
        .filter(models.VideoChunk.recording_session_id == recording_id)
        .order_by(models.VideoChunk.chunk_number.asc())
        .all()
    )
    summary = chunk_manifest_service.summarize_chunks([c.chunk_number for c in chunks])

    return schemas.RecordingManifestResponse(
        recording_session_id=recording_id,
        status=session.status,
        chunks=chunks,
        highest_chunk_number=summary.highest_received,
        missing_chunk_numbers=summary.missing_chunk_numbers,
        is_complete=(session.status == models.RecordingStatus.completed and summary.is_contiguous),
    )


def _authenticate_stream_request(
    db: Session,
    credentials: Optional[HTTPAuthorizationCredentials],
    token_qs: Optional[str],
) -> models.User:
    """
    A browser <video> element never sends a custom Authorization header on
    its own GET/Range requests, so this endpoint must also accept the JWT
    as a `?token=` query parameter -- mirrors websocket.py's
    _authenticate_websocket exactly (same reason: WebSocket connections
    from browser JS can't set custom headers either), rather than
    reusing get_current_user's Bearer-only dependency, which cannot see a
    query-string token. Prefers a real Authorization header when present
    (e.g. non-browser callers, tests) and falls back to the query token.
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
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or user.status != models.UserStatus.active:
        raise HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    return user


@router.get("/{recording_id}/chunks/{chunk_number}/stream")
def stream_chunk(
    recording_id: uuid.UUID,
    chunk_number: int,
    db: Session = Depends(database.get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    token: Optional[str] = Query(default=None),
    range: Optional[str] = Header(default=None),
):
    """
    Range-aware playback for a single stored chunk file, so RecordingDetails
    can actually play back what was recorded instead of only listing chunk
    metadata. Each chunk is an independent, fully valid segment file (real
    device validation confirmed each one decodes correctly on its own via
    ffprobe/VLC). Kept as its own endpoint even now that a concatenated
    file also exists (see /play below) -- it needs no playable_status
    check and works even when concatenation failed/hasn't run, and the web
    dashboard's chunk-by-chunk player still uses it unchanged.

    Same authorization matrix as GET /{recording_id} and .../chunks (via
    _authorize_recording_access) -- never the narrower _require_own_recording
    used by the mutating endpoints, since viewing a recording someone else
    made is exactly what admin/control_room/station need to be able to do.
    Mirrors app/routers/media.py's stream_media Range handling exactly
    (same 200-vs-206 behavior, same 416 contract) rather than reinventing
    it, reusing the same storage backend VideoChunk already writes through.
    """
    current_user = _authenticate_stream_request(db, credentials, token)

    session = db.query(models.RecordingSession).filter(models.RecordingSession.id == recording_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if not _authorize_recording_access(db, session, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this recording")

    chunk = (
        db.query(models.VideoChunk)
        .filter(models.VideoChunk.recording_session_id == recording_id, models.VideoChunk.chunk_number == chunk_number)
        .first()
    )
    if not chunk:
        raise HTTPException(status_code=404, detail="Chunk not found")

    storage = media_module._get_storage_backend()
    if not storage.exists(chunk.storage_key):
        raise HTTPException(status_code=404, detail="Chunk file not found")
    size = storage.get_size(chunk.storage_key)
    if size is None:
        raise HTTPException(status_code=404, detail="Chunk file not found")

    media_type = chunk.mime_type or "application/octet-stream"

    def _audit(extra: dict):
        log_action(
            db,
            user_id=current_user.id,
            action="recording.chunk_streamed",
            details={"recording_id": str(recording_id), "chunk_number": chunk_number, **extra},
        )
        db.commit()

    if not range:
        _audit({"access_method": "stream"})
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

    _audit({"access_method": "stream", "range": f"{start}-{end}"})
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
def play_recording(
    recording_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    token: Optional[str] = Query(default=None),
    range: Optional[str] = Header(default=None),
):
    """
    Range-aware playback of the single concatenated recording (see
    _try_build_playable_recording) -- what the mobile video player and any
    future single-file web player actually load, as opposed to
    .../chunks/{n}/stream's per-chunk playback. Same
    _authenticate_stream_request (header or query token -- a mobile
    video_player/exoplayer sends a real Authorization header; a browser
    <video> element cannot) and the same _authorize_recording_access
    matrix as every other read on this recording -- a constable can never
    reach another constable's recording here by editing the ID in the
    request, same as .../chunks/{n}/stream and GET /{recording_id} already
    guarantee (see test_unrelated_constable_cannot_view_another_constables_recording).

    404 when no playable file exists yet -- distinguished in `detail`
    between "still building/never attempted" and "failed" so the client
    can decide whether to retry later or fall back to per-chunk playback,
    without guessing from a bare 404.
    """
    current_user = _authenticate_stream_request(db, credentials, token)

    session = db.query(models.RecordingSession).filter(models.RecordingSession.id == recording_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Recording not found")
    if not _authorize_recording_access(db, session, current_user):
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

    def _audit(extra: dict):
        log_action(
            db,
            user_id=current_user.id,
            action="recording.played",
            details={"recording_id": str(recording_id), **extra},
        )
        db.commit()

    if not range:
        _audit({"access_method": "play"})
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

    _audit({"access_method": "play", "range": f"{start}-{end}"})
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
