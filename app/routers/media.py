from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Header, status
from fastapi.responses import StreamingResponse
from pymongo import ReturnDocument

from beanie.operators import In, Or

from .. import database, geo, models, schemas
from ..auth.deps import get_current_user
from .constables import get_own_constable
from ..services.audit import log_action
from ..services import events
from ..services import storage as storage_service
import uuid
import os
import hashlib
import datetime

router = APIRouter(prefix="/media", tags=["Media Upload"])

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
UPLOAD_DIR = os.getenv("EVIDENCE_UPLOAD_ROOT", "/app/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_EVIDENCE_SIZE_MB = int(os.getenv("MAX_EVIDENCE_SIZE_MB", "500"))
MAX_EVIDENCE_SIZE_BYTES = MAX_EVIDENCE_SIZE_MB * 1024 * 1024

_READ_CHUNK_SIZE = 1024 * 1024  # 1 MiB per read -- never buffers the whole file in memory


def _get_storage_backend() -> storage_service.EvidenceStorageBackend:
    backend_name = os.getenv("EVIDENCE_STORAGE_BACKEND", "local").lower()
    if backend_name == "s3":
        return storage_service.get_storage_backend()
    return storage_service.LocalFilesystemStorage(root=UPLOAD_DIR)


# ---------------------------------------------------------------------------
# Allowed evidence types (server-controlled allow-list)
# ---------------------------------------------------------------------------
ALLOWED_MIME_TO_EXT = {
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "video/quicktime": ".mov",
    "audio/mpeg": ".mp3",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "audio/mp4": ".m4a",
    "image/jpeg": ".jpg",
    "image/png": ".png",
}


def _mime_category(mime_type: str) -> str:
    return mime_type.split("/", 1)[0] if mime_type else ""


def _sniff_mime_type(header: bytes) -> str | None:
    if not header:
        return None
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if len(header) >= 12 and header[4:8] == b"ftyp":
        return "video/mp4"  # covers the mp4/mov/m4a "ftyp box" family broadly
    if header.startswith(b"\x1a\x45\xdf\xa3"):
        return "video/webm"
    if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WAVE":
        return "audio/wav"
    if header.startswith(b"ID3") or header[:2] == b"\xff\xfb":
        return "audio/mpeg"
    return None


def _sanitize_original_filename(filename: str | None) -> str | None:
    if not filename:
        return None
    base = os.path.basename(filename.replace("\\", "/"))
    safe = "".join(c for c in base if c.isalnum() or c in ("-", "_", ".", " "))
    return safe[:255] or None


def _content_disposition_filename(media_item: models.Evidence) -> str:
    fallback = f"evidence{ALLOWED_MIME_TO_EXT.get(media_item.mime_type, '')}"
    name = media_item.original_filename or fallback
    return _sanitize_original_filename(name) or "evidence"


def _build_storage_key(incident_id: uuid.UUID, evidence_id: uuid.UUID, mime_type: str) -> str:
    ext = ALLOWED_MIME_TO_EXT.get(mime_type, "")
    return f"evidence/{incident_id}/{evidence_id}{ext}"


def _scan_for_malware(storage_key: str) -> None:
    return None


def _resolve_evidence_read_target(media_item: models.Evidence):
    if media_item.storage_key:
        return "backend", media_item.storage_key
    return "legacy_path", media_item.file_path


def _evidence_object_exists(kind: str, ref: str | None) -> bool:
    if kind == "backend":
        return _get_storage_backend().exists(ref)
    return bool(ref) and os.path.exists(ref)


def _evidence_object_size(kind: str, ref: str | None) -> Optional[int]:
    if kind == "backend":
        return _get_storage_backend().get_size(ref)
    if not ref or not os.path.exists(ref):
        return None
    return os.path.getsize(ref)


def _evidence_object_range(kind: str, ref: str, start: int, end: int):
    if kind == "backend":
        yield from _get_storage_backend().read_range(ref, start, end)
    else:
        yield from storage_service._read_range_from_local_path(ref, start, end)


async def _load_and_authorize_evidence(media_id: uuid.UUID, current_user: models.User):
    """
    Shared by both /download and /stream. Role/ownership authorization:
      - admin / control_room: always authorized
      - constable: authorized if they uploaded it themselves, OR if it
        belongs to an incident they are currently assigned to
      - citizen: authorized only if the evidence's incident belongs to them
      - station: authorized only if the evidence's incident belongs to
        their own station
    """
    media_item = await models.Evidence.get(media_id)
    if not media_item:
        raise HTTPException(status_code=404, detail="File not found")

    kind, ref = _resolve_evidence_read_target(media_item)
    if not _evidence_object_exists(kind, ref):
        raise HTTPException(status_code=404, detail="File not found")

    role = current_user.role
    authorized = False

    if role in (models.UserRole.admin, models.UserRole.control_room):
        authorized = True
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if own_constable:
            if media_item.constable_id == own_constable.id:
                authorized = True
            else:
                incident = await models.Incident.find_one(
                    models.Incident.id == media_item.incident_id,
                    {"assignments.constable_id": own_constable.id},
                )
                authorized = incident is not None
    elif role == models.UserRole.citizen:
        incident = await models.Incident.get(media_item.incident_id)
        authorized = incident is not None and incident.citizen_id == current_user.id
    elif role == models.UserRole.station:
        if current_user.station_id:
            incident = await models.Incident.get(media_item.incident_id)
            authorized = incident is not None and incident.station_id == current_user.station_id

    if not authorized:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this evidence")

    return media_item, kind, ref


async def _audit_evidence_access(current_user: models.User, media_item: models.Evidence, method: str, extra: dict | None = None):
    details = {"access_method": method}
    if extra:
        details.update(extra)
    await log_action(
        user_id=current_user.id,
        action="evidence.downloaded",
        incident_id=media_item.incident_id,
        evidence_id=media_item.id,
        details=details,
    )


def _parse_range_header(range_header: str, size: int):
    if "," in range_header:
        return None, None, "Multiple ranges are not supported in a single request"
    if not range_header.startswith("bytes="):
        return None, None, "Only 'bytes' ranges are supported"

    spec = range_header[len("bytes="):].strip()
    if "-" not in spec:
        return None, None, "Malformed range"

    start_str, _, end_str = spec.partition("-")
    try:
        if start_str == "":
            if end_str == "":
                return None, None, "Malformed range"
            suffix_len = int(end_str)
            if suffix_len <= 0:
                return None, None, "Malformed range"
            start = max(0, size - suffix_len)
            end = size - 1
        else:
            start = int(start_str)
            end = int(end_str) if end_str != "" else size - 1
    except ValueError:
        return None, None, "Malformed range"

    if size <= 0 or start < 0 or end < start or start >= size:
        return None, None, "Range not satisfiable"

    end = min(end, size - 1)
    return start, end, None


@router.post("/upload", response_model=schemas.EvidenceUploadResponse)
async def upload_evidence(
    incident_id: uuid.UUID = Form(...),
    constable_id: uuid.UUID = Form(None),
    type: models.MediaType = Form(...),
    comment: str = Form(None),
    latitude: float = Form(None),
    longitude: float = Form(None),
    accuracy: float = Form(None),
    device_timestamp: str = Form(None),
    duration_seconds: float = Form(None),
    camera: str = Form(None),
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user),
):
    """
    Uploader identity (`uploader_id`, `uploader_role`) is ALWAYS derived from
    the authenticated user for every role -- never accepted from the
    request body.
    """
    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    role = current_user.role
    resolved_constable_id = None

    if role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to upload evidence")
        assigned = any(a.constable_id == own_constable.id for a in incident.assignments)
        if not assigned:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to upload evidence for this incident")
        resolved_constable_id = own_constable.id  # never trust the client-supplied constable_id
    elif role == models.UserRole.citizen:
        if incident.citizen_id != current_user.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to upload evidence for this incident")
    elif role in (models.UserRole.admin, models.UserRole.control_room):
        resolved_constable_id = constable_id  # trusted administrative attribution, optional
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to upload evidence")

    first_chunk = await file.read(_READ_CHUNK_SIZE)

    declared_mime = (file.content_type or "").lower()
    sniffed_mime = _sniff_mime_type(first_chunk)

    if sniffed_mime and declared_mime and _mime_category(sniffed_mime) != _mime_category(declared_mime):
        raise HTTPException(status_code=400, detail="File content does not match the declared file type")

    resolved_mime = sniffed_mime or declared_mime
    if resolved_mime not in ALLOWED_MIME_TO_EXT:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {resolved_mime or 'unknown'}")

    evidence_id = uuid.uuid4()
    storage_key = _build_storage_key(incident_id, evidence_id, resolved_mime)
    storage = _get_storage_backend()

    hasher = hashlib.sha256()
    bytes_written = 0

    try:
        with storage.open_write(storage_key) as buffer:
            for chunk in (first_chunk,):
                hasher.update(chunk)
                buffer.write(chunk)
                bytes_written += len(chunk)

            while True:
                if bytes_written > MAX_EVIDENCE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Evidence file exceeds the {MAX_EVIDENCE_SIZE_MB}MB limit",
                    )
                chunk = await file.read(_READ_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                buffer.write(chunk)
                bytes_written += len(chunk)

        if bytes_written > MAX_EVIDENCE_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Evidence file exceeds the {MAX_EVIDENCE_SIZE_MB}MB limit",
            )
    except HTTPException:
        storage.delete(storage_key)
        raise
    except Exception:
        storage.delete(storage_key)
        raise

    file_hash = hasher.hexdigest()

    _scan_for_malware(storage_key)  # no-op placeholder; see function docstring

    client_metadata = {}
    if latitude is not None:
        client_metadata["latitude"] = latitude
    if longitude is not None:
        client_metadata["longitude"] = longitude
    if accuracy is not None:
        client_metadata["accuracy"] = accuracy
    if device_timestamp is not None:
        client_metadata["device_timestamp"] = device_timestamp
    if duration_seconds is not None:
        client_metadata["duration_seconds"] = duration_seconds
    if camera is not None:
        client_metadata["camera"] = camera

    location = None
    if latitude is not None and longitude is not None:
        location = geo.point(longitude, latitude)

    legacy_file_path = None
    if isinstance(storage, storage_service.LocalFilesystemStorage):
        legacy_file_path = storage._abs_path(storage_key)

    evidence = models.Evidence(
        id=evidence_id,
        incident_id=incident_id,
        constable_id=resolved_constable_id,
        type=type,
        comment=comment,
        location=location,
        uploader_id=current_user.id,           # server-derived, always
        uploader_role=current_user.role,       # server-derived, always
        file_hash=file_hash,                   # server-computed from actual bytes
        file_size=bytes_written,               # server-computed
        mime_type=resolved_mime,                # server-validated
        upload_status=models.UploadStatus.uploaded,
        storage_key=storage_key,
        file_path=legacy_file_path,  # local-backend-only compatibility value, never exposed via API
        original_filename=_sanitize_original_filename(file.filename),
        evidence_metadata=client_metadata or None,
    )

    try:
        await evidence.insert()
    except Exception:
        # The DB row failed to persist -- the object we already wrote must
        # not be left orphaned on disk/in the bucket pointing nowhere.
        storage.delete(storage_key)
        raise

    await log_action(
        user_id=current_user.id,
        action="evidence.uploaded",
        incident_id=incident_id,
        evidence_id=evidence_id,
        details={
            "mime_type": resolved_mime,
            "file_size": bytes_written,
            "type": type.value if hasattr(type, "value") else str(type),
        },
    )

    await events.publish_evidence_uploaded(evidence, incident.station_id)

    return schemas.EvidenceUploadResponse(
        status="uploaded",
        evidence_id=evidence.id,
        hash=file_hash,
        upload_status=evidence.upload_status,
    )


@router.get("/", response_model=list[schemas.EvidenceResponse])
async def list_media(
    current_user: models.User = Depends(get_current_user),
):
    """
    Role-scoped evidence listing:
      - admin / control_room: all evidence
      - constable: evidence they personally uploaded, plus evidence tied to
        incidents currently assigned to them
      - citizen: evidence belonging to incidents they created
      - station: evidence belonging to incidents whose station_id matches
        the authenticated user's station_id. A station user with no
        station_id set gets an empty list rather than an error.
    """
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        media_items = await models.Evidence.find_all().sort(-models.Evidence.timestamp).to_list()
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            return []
        assigned_incident_ids = [
            inc.id for inc in await models.Incident.find({"assignments.constable_id": own_constable.id}).to_list()
        ]
        media_items = await models.Evidence.find(
            Or(models.Evidence.constable_id == own_constable.id, In(models.Evidence.incident_id, assigned_incident_ids))
        ).sort(-models.Evidence.timestamp).to_list()
    elif role == models.UserRole.citizen:
        own_incident_ids = [inc.id for inc in await models.Incident.find(models.Incident.citizen_id == current_user.id).to_list()]
        media_items = await models.Evidence.find(In(models.Evidence.incident_id, own_incident_ids)).sort(-models.Evidence.timestamp).to_list()
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_incident_ids = [inc.id for inc in await models.Incident.find(models.Incident.station_id == current_user.station_id).to_list()]
        media_items = await models.Evidence.find(In(models.Evidence.incident_id, station_incident_ids)).sort(-models.Evidence.timestamp).to_list()
    else:
        return []

    return [schemas.EvidenceResponse.from_evidence(m) for m in media_items]


@router.get("/{media_id}/download")
async def download_media(
    media_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """
    Full-file download. Authorization and existence handling are shared
    with /stream via _load_and_authorize_evidence.
    """
    media_item, kind, ref = await _load_and_authorize_evidence(media_id, current_user)

    size = _evidence_object_size(kind, ref)
    if size is None:
        raise HTTPException(status_code=404, detail="File not found")

    await _audit_evidence_access(current_user, media_item, method="download")

    headers = {
        "Content-Length": str(size),
        "Accept-Ranges": "bytes",
        "Content-Disposition": f'attachment; filename="{_content_disposition_filename(media_item)}"',
    }
    return StreamingResponse(
        _evidence_object_range(kind, ref, 0, size - 1),
        media_type=media_item.mime_type or "application/octet-stream",
        headers=headers,
        status_code=200,
    )


@router.get("/{media_id}/stream")
async def stream_media(
    media_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
    range: Optional[str] = Header(default=None),
):
    """
    Authenticated, Range-aware evidence playback endpoint for large
    video/audio evidence.
    """
    media_item, kind, ref = await _load_and_authorize_evidence(media_id, current_user)

    size = _evidence_object_size(kind, ref)
    if size is None:
        raise HTTPException(status_code=404, detail="File not found")

    media_type = media_item.mime_type or "application/octet-stream"
    disposition = f'inline; filename="{_content_disposition_filename(media_item)}"'

    if not range:
        await _audit_evidence_access(current_user, media_item, method="stream")
        headers = {
            "Content-Length": str(size),
            "Accept-Ranges": "bytes",
            "Content-Disposition": disposition,
        }
        return StreamingResponse(
            _evidence_object_range(kind, ref, 0, size - 1),
            media_type=media_type,
            headers=headers,
            status_code=200,
        )

    start, end, error = _parse_range_header(range, size)
    if error:
        raise HTTPException(
            status_code=416,
            detail=error,
            headers={"Content-Range": f"bytes */{size}"},
        )

    await _audit_evidence_access(current_user, media_item, method="stream", extra={"range": f"{start}-{end}"})

    headers = {
        "Content-Range": f"bytes {start}-{end}/{size}",
        "Content-Length": str(end - start + 1),
        "Accept-Ranges": "bytes",
        "Content-Disposition": disposition,
    }
    return StreamingResponse(
        _evidence_object_range(kind, ref, start, end),
        media_type=media_type,
        headers=headers,
        status_code=206,
    )


# ===========================================================================
# Evidence Verification workflow.
# ===========================================================================

_EVIDENCE_ALLOWED_TRANSITIONS: dict[models.UploadStatus, set[models.UploadStatus]] = {
    models.UploadStatus.uploaded: {models.UploadStatus.verified, models.UploadStatus.rejected},
    models.UploadStatus.verified: {models.UploadStatus.archived},
}


async def _check_evidence_verification_authority(media_item: models.Evidence, current_user: models.User):
    """
    admin/control_room: always allowed.
    station: allowed ONLY if the evidence's incident belongs to their own
      station.
    constable/citizen: never allowed, regardless of upload/assignment
      ownership.
    """
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        return
    if role == models.UserRole.station:
        if current_user.station_id:
            incident = await models.Incident.get(media_item.incident_id)
            if incident is not None and incident.station_id == current_user.station_id:
                return
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to verify this evidence")
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to verify this evidence")


async def _get_evidence_or_404(evidence_id: uuid.UUID) -> models.Evidence:
    media_item = await models.Evidence.get(evidence_id)
    if not media_item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return media_item


async def _transition_evidence_status(
    evidence_id: uuid.UUID,
    new_status: models.UploadStatus,
    current_user: models.User,
    action: str,
    reason: Optional[str] = None,
) -> models.Evidence:
    """
    Atomic compare-and-swap via `find_one_and_update`, conditioned on the
    document's CURRENT upload_status being one of the legal predecessors of
    `new_status` -- the direct Mongo equivalent of the old
    `SELECT ... FOR UPDATE` + re-validate pattern: two concurrent
    transition attempts can never both succeed, because the update only
    matches (and only one concurrent request can ever see) the
    not-yet-transitioned document.

    The state change and its audit row are written inside one
    `database.transaction()` (see that helper's docstring) so they succeed
    or fail together -- the direct Mongo equivalent of the old SQLAlchemy
    session sharing one not-yet-committed transaction across both writes.
    """
    allowed_predecessors = [s.value for s, nexts in _EVIDENCE_ALLOWED_TRANSITIONS.items() if new_status in nexts]

    now = datetime.datetime.now(datetime.timezone.utc)
    update_fields = {"upload_status": new_status.value}
    details = {"new_status": new_status.value}
    if new_status == models.UploadStatus.verified:
        update_fields.update(verified_by=current_user.id, verified_at=now)
    elif new_status == models.UploadStatus.rejected:
        update_fields.update(rejected_by=current_user.id, rejected_at=now, rejection_reason=reason)
        if reason:
            details["reason"] = reason
    elif new_status == models.UploadStatus.archived:
        update_fields.update(archived_by=current_user.id, archived_at=now)

    async with database.transaction() as session:
        before = await models.Evidence.get_motor_collection().find_one_and_update(
            {"_id": evidence_id, "upload_status": {"$in": allowed_predecessors}},
            {"$set": update_fields},
            return_document=ReturnDocument.BEFORE,
            session=session,
        )

        if before is None:
            existing = await models.Evidence.get(evidence_id)
            if existing is None:
                raise HTTPException(status_code=404, detail="Evidence not found")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot transition evidence from {existing.upload_status.value} to {new_status.value}",
            )

        details["old_status"] = before["upload_status"]
        media_item = await models.Evidence.get(evidence_id, session=session)

        await log_action(
            user_id=current_user.id,
            action=action,
            incident_id=media_item.incident_id,
            evidence_id=media_item.id,
            details=details,
            session=session,
        )
    return media_item


@router.post("/{evidence_id}/verify", response_model=schemas.EvidenceResponse)
async def verify_evidence(
    evidence_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """
    uploaded -> verified. admin/control_room: any evidence. station: only
    evidence belonging to an incident in their own station's jurisdiction.
    constable/citizen: 403. Re-verifying already-verified/rejected/archived
    evidence is rejected with 409.
    """
    media_item = await _get_evidence_or_404(evidence_id)
    await _check_evidence_verification_authority(media_item, current_user)
    media_item = await _transition_evidence_status(evidence_id, models.UploadStatus.verified, current_user, "evidence.verified")

    incident = await models.Incident.get(media_item.incident_id)
    await events.publish_evidence_verified(media_item, incident.station_id if incident else None)

    return schemas.EvidenceResponse.from_evidence(media_item)


@router.post("/{evidence_id}/reject", response_model=schemas.EvidenceResponse)
async def reject_evidence(
    evidence_id: uuid.UUID,
    payload: schemas.EvidenceRejectRequest = schemas.EvidenceRejectRequest(),
    current_user: models.User = Depends(get_current_user),
):
    """uploaded -> rejected, with an optional reason. Same authorization as /verify. A rejected evidence item is terminal."""
    media_item = await _get_evidence_or_404(evidence_id)
    await _check_evidence_verification_authority(media_item, current_user)
    media_item = await _transition_evidence_status(
        evidence_id, models.UploadStatus.rejected, current_user, "evidence.rejected", reason=payload.reason
    )

    incident = await models.Incident.get(media_item.incident_id)
    await events.publish_evidence_rejected(media_item, incident.station_id if incident else None)

    return schemas.EvidenceResponse.from_evidence(media_item)


@router.post("/{evidence_id}/archive", response_model=schemas.EvidenceResponse)
async def archive_evidence(
    evidence_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """verified -> archived ONLY. Same authorization as /verify."""
    media_item = await _get_evidence_or_404(evidence_id)
    await _check_evidence_verification_authority(media_item, current_user)
    media_item = await _transition_evidence_status(evidence_id, models.UploadStatus.archived, current_user, "evidence.archived")

    incident = await models.Incident.get(media_item.incident_id)
    await events.publish_evidence_archived(media_item, incident.station_id if incident else None)

    return schemas.EvidenceResponse.from_evidence(media_item)
