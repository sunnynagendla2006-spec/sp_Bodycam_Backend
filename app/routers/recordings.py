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
import datetime
import hashlib
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, UploadFile, File, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import database, models, schemas
from ..auth.deps import get_current_user, require_role
from ..services.audit import log_action
from ..services import events
from ..services import chunk_manifest as chunk_manifest_service
from . import media as media_module
from .constables import get_own_constable
from .devices import _require_own_device_for_constable

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

    session = models.RecordingSession(
        constable_id=own_constable.id,
        device_id=device.id,
        trigger_type=payload.trigger_type,
        status=models.RecordingStatus.recording,
        incident_id=payload.incident_id,
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
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot upload chunks to a recording in status {session.status.value}",
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
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Chunk {chunk_number} was already uploaded for this recording")

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
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Chunk {chunk_number} was already uploaded for this recording")

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
