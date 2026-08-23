from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Header, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from .. import database, models, schemas
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
# Local disk root for evidence storage (used by the default LocalFilesystemStorage
# backend). This module-level variable is intentionally read fresh on every
# request (see _get_storage_backend()) rather than captured once at import
# time, because the test suite monkeypatches `media_router_module.UPLOAD_DIR`
# per test run to redirect uploads into an isolated temp directory -- if the
# storage backend were constructed once at import time, that monkeypatch
# would silently stop working.
UPLOAD_DIR = os.getenv("EVIDENCE_UPLOAD_ROOT", "/app/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_EVIDENCE_SIZE_MB = int(os.getenv("MAX_EVIDENCE_SIZE_MB", "500"))
MAX_EVIDENCE_SIZE_BYTES = MAX_EVIDENCE_SIZE_MB * 1024 * 1024

_READ_CHUNK_SIZE = 1024 * 1024  # 1 MiB per read -- never buffers the whole file in memory


def _get_storage_backend() -> storage_service.EvidenceStorageBackend:
    """
    Selects the storage backend per-request. Defaults to a
    LocalFilesystemStorage rooted at the CURRENT value of the module-level
    UPLOAD_DIR (see the comment on UPLOAD_DIR above for why this must be
    read fresh, not cached). Set EVIDENCE_STORAGE_BACKEND=s3 (+
    EVIDENCE_S3_BUCKET) to use S3/MinIO instead -- see app/services/storage.py.
    """
    backend_name = os.getenv("EVIDENCE_STORAGE_BACKEND", "local").lower()
    if backend_name == "s3":
        return storage_service.get_storage_backend()
    return storage_service.LocalFilesystemStorage(root=UPLOAD_DIR)


# ---------------------------------------------------------------------------
# Allowed evidence types (server-controlled allow-list)
# ---------------------------------------------------------------------------
# Maps an accepted MIME type to the extension used for the stored file. The
# extension is ALWAYS derived from this table, never from the client's
# filename -- see _build_storage_key().
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
    """
    Lightweight magic-byte detection for the formats in ALLOWED_MIME_TO_EXT.
    This is NOT a full file-type-identification library -- it only needs to
    catch "obviously mismatched" uploads (e.g. an .exe renamed to
    evidence.mp4, or a client Content-Type that doesn't match the bytes at
    all), not identify every possible container/codec precisely. Returns
    None when the header doesn't match a recognized signature; callers
    should NOT treat that as a rejection by itself (see upload_evidence).
    """
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
    """
    The original client filename is METADATA ONLY -- it is never used to
    construct a filesystem path (see _build_storage_key), so path
    traversal via filename is structurally impossible regardless of this
    function. This still strips directory components and odd characters
    purely so a sane, safe string is stored/displayed, and is re-applied
    defensively before use in a Content-Disposition response header (see
    _content_disposition_filename) since that's a second, independent
    place a raw value could otherwise leak into an HTTP header.
    """
    if not filename:
        return None
    # Strip any directory components a client might have sent (both
    # POSIX and Windows separators), then keep only a conservative
    # character set for display purposes.
    base = os.path.basename(filename.replace("\\", "/"))
    safe = "".join(c for c in base if c.isalnum() or c in ("-", "_", ".", " "))
    return safe[:255] or None


def _content_disposition_filename(media_item: models.Evidence) -> str:
    fallback = f"evidence{ALLOWED_MIME_TO_EXT.get(media_item.mime_type, '')}"
    name = media_item.original_filename or fallback
    return _sanitize_original_filename(name) or "evidence"


def _build_storage_key(incident_id: uuid.UUID, evidence_id: uuid.UUID, mime_type: str) -> str:
    """
    Logical, object-storage-compatible key. Both path components are
    server-generated UUIDs -- never derived from client input -- so this is
    inherently safe from path traversal.
    """
    ext = ALLOWED_MIME_TO_EXT.get(mime_type, "")
    return f"evidence/{incident_id}/{evidence_id}{ext}"


def _scan_for_malware(storage_key: str) -> None:
    """
    Extension point for a future antivirus/malware scan (e.g. ClamAV)
    integration. Intentionally a no-op in this phase -- per scope, a full
    scanning system is NOT implemented here. The call site below is wired
    in so a real scanner can be dropped in later without changing the
    upload flow.
    """
    return None


# ---------------------------------------------------------------------------
# Evidence read-target resolution: EVERY evidence row is resolved to either
#   ("backend", storage_key)   -- the normal case, any storage backend
#   ("legacy_path", file_path) -- rows created before storage_key existed
# None of the functions below ever return or leak a raw filesystem path to
# a caller outside this module; `ref` for the "backend" case is just the
# logical storage_key, and "legacy_path" is only ever read locally on the
# server, never serialized into a response.
# ---------------------------------------------------------------------------

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


def _load_and_authorize_evidence(media_id: uuid.UUID, db: Session, current_user: models.User):
    """
    Shared by both /download and /stream. Role/ownership authorization is
    UNCHANGED from the existing, already-tested contract:
      - admin / control_room: always authorized
      - constable: authorized if they uploaded it themselves, OR if it
        belongs to an incident they are currently assigned to
      - citizen: authorized only if the evidence's incident belongs to them
      - station: authorized only if the evidence's incident belongs to
        their own station

    NOTE on existence-leakage (see phase report): a genuinely unknown
    evidence UUID (or one whose physical object is missing) returns 404; a
    real evidence row the caller isn't authorized for returns 403 -- this
    does confirm the ID exists, but that is the PRE-EXISTING, already-
    tested contract from Phase 2 onward (test_authorization.py asserts 403
    for exactly this case), not something introduced or changed here.
    Switching to a uniform 404 would be a real anti-enumeration
    improvement, but it would also break that established, currently-
    passing test contract -- flagged rather than silently changed.
    """
    media_item = db.query(models.Evidence).filter(models.Evidence.id == media_id).first()
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
        own_constable = get_own_constable(db, current_user)
        if own_constable:
            if media_item.constable_id == own_constable.id:
                authorized = True
            else:
                assigned = db.query(models.IncidentAssignment).filter(
                    models.IncidentAssignment.incident_id == media_item.incident_id,
                    models.IncidentAssignment.constable_id == own_constable.id,
                ).first()
                authorized = assigned is not None
    elif role == models.UserRole.citizen:
        incident = db.query(models.Incident).filter(models.Incident.id == media_item.incident_id).first()
        authorized = incident is not None and incident.citizen_id == current_user.id
    elif role == models.UserRole.station:
        if current_user.station_id:
            incident = db.query(models.Incident).filter(models.Incident.id == media_item.incident_id).first()
            authorized = incident is not None and incident.station_id == current_user.station_id

    if not authorized:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this evidence")

    return media_item, kind, ref


def _audit_evidence_access(db: Session, current_user: models.User, media_item: models.Evidence, method: str, extra: dict | None = None):
    """
    Both /download and /stream write the SAME existing `evidence.downloaded`
    audit action (per this phase's instructions) -- `access_method`
    ("download" | "stream") in `details` is what distinguishes them. Only
    called on a genuinely successful response (200/206); a 416 or an
    authorization failure never reaches this.
    """
    details = {"access_method": method}
    if extra:
        details.update(extra)
    log_action(
        db,
        user_id=current_user.id,
        action="evidence.downloaded",
        incident_id=media_item.incident_id,
        evidence_id=media_item.id,
        details=details,
    )
    db.commit()


def _parse_range_header(range_header: str, size: int):
    """
    Parses a `Range` header for a single byte range, per RFC 7233:
      bytes=start-end | bytes=start- | bytes=-suffix

    Returns (start, end, error_message). On success error_message is None
    and (start, end) is an inclusive, size-clamped, valid range. On
    failure (start, end) are None and error_message describes why --
    callers should respond 416 with `Content-Range: bytes */{size}`.

    Multiple ranges (e.g. "bytes=0-10,20-30") are explicitly NOT supported:
    this returns an error rather than attempting a multipart/byteranges
    response, which the current media pipeline (single evidence
    file/object per request) has no need for. This is a deliberate,
    documented choice, not an oversight.
    """
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
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Uploader identity (`uploader_id`, `uploader_role`) is ALWAYS derived from
    the authenticated user for every role -- never accepted from the
    request body. Additionally, for a constable caller, `constable_id` is
    ALSO always derived server-side (their own Constable row), never
    trusted from the client-supplied form field:

      - constable: must be assigned (via IncidentAssignment) to the target
        incident.
      - citizen: may only upload evidence for an incident they created
        (incident.citizen_id == current_user.id).
      - admin / control_room: may upload operational evidence for any
        incident; the client-supplied `constable_id` is honored ONLY here
        as a trusted administrative attribution, since these are
        privileged roles.
      - station / other roles: not authorized to upload.

    File handling:
      1. Read in bounded chunks (never buffers the whole upload in memory),
         enforcing MAX_EVIDENCE_SIZE_MB as it streams -> 413 if exceeded.
      2. Sniff magic bytes from the first chunk and cross-check against the
         declared MediaType/Content-Type's broad category (video/audio/
         image) -> 400 on an obvious mismatch.
      3. Compute the SHA-256 hash from the actual bytes written (never from
         filename/metadata/any client-supplied hash).
      4. Store under a server-generated `storage_key`
         ("evidence/{incident_id}/{evidence_id}.ext") via the configured
         storage backend (local disk by default; S3/MinIO if configured --
         see app/services/storage.py) -- the client's original filename is
         never used to build a path, so upload filenames such as
         "../../etc/passwd" cannot escape the storage root.
      5. `_scan_for_malware()` extension point runs (currently a no-op).
      6. If the file write succeeds but the database insert fails, the
         just-written object is deleted so no Evidence row is ever left
         pointing at a nonexistent (or, worse, orphaned-and-undeleted)
         object.
    """
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    role = current_user.role
    resolved_constable_id = None

    if role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to upload evidence")
        assigned = db.query(models.IncidentAssignment).filter(
            models.IncidentAssignment.incident_id == incident_id,
            models.IncidentAssignment.constable_id == own_constable.id,
        ).first()
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

    # --- Read the first chunk up front so we can sniff + validate BEFORE
    #     committing to writing the rest of a possibly-huge file to disk.
    first_chunk = await file.read(_READ_CHUNK_SIZE)

    declared_mime = (file.content_type or "").lower()
    sniffed_mime = _sniff_mime_type(first_chunk)

    if sniffed_mime and declared_mime and _mime_category(sniffed_mime) != _mime_category(declared_mime):
        raise HTTPException(status_code=400, detail="File content does not match the declared file type")

    # Prefer the sniffed type when we have one (harder for a client to
    # spoof than a Content-Type header); otherwise fall back to whatever
    # the client declared. Either way it must be on the allow-list.
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
            # Write the chunk we already read for sniffing, then continue
            # streaming the rest in bounded pieces.
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
        # Clean up the partial object before re-raising (oversized upload, etc.)
        storage.delete(storage_key)
        raise
    except Exception:
        # Any unexpected failure during the write itself (disk full, I/O
        # error, etc.) -- still never leave a partial object behind.
        storage.delete(storage_key)
        raise

    file_hash = hasher.hexdigest()

    _scan_for_malware(storage_key)  # no-op placeholder; see function docstring

    # Client-reported metadata: explicitly NOT authoritative. Kept separate
    # (in evidence_metadata / evidence.evidence_metadata) from the
    # server-generated fields set below (file_hash, file_size, mime_type,
    # upload_status, timestamp, uploader_id, uploader_role), none of which
    # a client can influence.
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

    location_str = None
    if latitude is not None and longitude is not None:
        # Device-reported location only -- NOT treated as verified proof of
        # physical presence; stored for reference alongside the
        # server-received `timestamp` below, which is authoritative for
        # "when the backend received this."
        location_str = f"POINT({longitude} {latitude})"

    # storage_key is now the sole canonical reference; file_path is kept
    # populated (matching the historical local-path shape) ONLY when the
    # active backend is actually local disk, since it has no meaning for a
    # non-local backend and must never be treated as authoritative going
    # forward -- _resolve_evidence_read_target always prefers storage_key.
    legacy_file_path = None
    if isinstance(storage, storage_service.LocalFilesystemStorage):
        legacy_file_path = storage._abs_path(storage_key)

    evidence = models.Evidence(
        id=evidence_id,
        incident_id=incident_id,
        constable_id=resolved_constable_id,
        type=type,
        comment=comment,
        location=location_str,
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
    db.add(evidence)

    log_action(
        db,
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

    try:
        db.commit()
    except Exception:
        # The DB row failed to persist -- the object we already wrote must
        # not be left orphaned on disk/in the bucket pointing nowhere.
        db.rollback()
        storage.delete(storage_key)
        raise

    db.refresh(evidence)

    await events.publish_evidence_uploaded(evidence, incident.station_id)

    return schemas.EvidenceUploadResponse(
        status="uploaded",
        evidence_id=evidence.id,
        hash=file_hash,
        upload_status=evidence.upload_status,
    )


@router.get("/", response_model=list[schemas.EvidenceResponse])
def list_media(
    db: Session = Depends(database.get_db),
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
    query = db.query(models.Evidence)

    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable:
            return []
        assigned_incident_ids = db.query(models.IncidentAssignment.incident_id).filter(
            models.IncidentAssignment.constable_id == own_constable.id
        )
        query = query.filter(
            (models.Evidence.constable_id == own_constable.id)
            | (models.Evidence.incident_id.in_(assigned_incident_ids))
        )
    elif role == models.UserRole.citizen:
        own_incident_ids = db.query(models.Incident.id).filter(models.Incident.citizen_id == current_user.id)
        query = query.filter(models.Evidence.incident_id.in_(own_incident_ids))
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_incident_ids = db.query(models.Incident.id).filter(models.Incident.station_id == current_user.station_id)
        query = query.filter(models.Evidence.incident_id.in_(station_incident_ids))
    else:
        return []

    media_items = query.order_by(models.Evidence.timestamp.desc()).all()
    return [schemas.EvidenceResponse.from_evidence(m) for m in media_items]


@router.get("/{media_id}/download")
def download_media(
    media_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Full-file download. Authorization and existence handling are shared
    with /stream via _load_and_authorize_evidence -- see that function's
    docstring for the exact role/ownership rules (unchanged from Phase 2/6)
    and the existence-leakage note.

    Internally this now streams the object in bounded chunks (via the
    storage backend) rather than handing Starlette a raw local path
    (FileResponse) -- this both keeps memory bounded for large files and
    makes /download work identically regardless of which storage backend
    is active (local disk or S3/MinIO), where a bare filesystem path
    wouldn't exist at all. The response contract (200, correct
    Content-Type, full bytes) is unchanged; `Content-Length` and
    `Accept-Ranges: bytes` are additionally set now.
    """
    media_item, kind, ref = _load_and_authorize_evidence(media_id, db, current_user)

    size = _evidence_object_size(kind, ref)
    if size is None:
        raise HTTPException(status_code=404, detail="File not found")

    _audit_evidence_access(db, current_user, media_item, method="download")

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
def stream_media(
    media_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
    range: Optional[str] = Header(default=None),
):
    """
    Authenticated, Range-aware evidence playback endpoint for large
    video/audio evidence -- lets a Flutter/web video player seek without
    downloading the whole file first.

    Authorization/existence handling is identical to /download (shared via
    _load_and_authorize_evidence) -- station/ownership/role rules are not
    weakened or duplicated with different logic here.

    Behavior:
      - No `Range` header: behaves like a full download (200, whole
        content), but through the same chunked streaming path.
      - `Range: bytes=start-end` / `bytes=start-` / `bytes=-suffix`: 206
        Partial Content with correct Content-Range/Content-Length, serving
        only the requested slice via bounded chunked reads (never loads
        the full object into memory regardless of file size).
      - Multiple ranges (`bytes=0-10,20-30`) or any range that doesn't fit
        the object's actual size: 416, with `Content-Range: bytes */{size}`
        per RFC 7233 -- see _parse_range_header's docstring for exactly
        what is and isn't accepted.

    The server-resolved `Evidence.mime_type` is always used for
    `Content-Type` -- there is no client-supplied Content-Type input to
    this endpoint at all (it's a GET), so there is nothing to spoof.
    """
    media_item, kind, ref = _load_and_authorize_evidence(media_id, db, current_user)

    size = _evidence_object_size(kind, ref)
    if size is None:
        raise HTTPException(status_code=404, detail="File not found")

    media_type = media_item.mime_type or "application/octet-stream"
    disposition = f'inline; filename="{_content_disposition_filename(media_item)}"'

    if not range:
        _audit_evidence_access(db, current_user, media_item, method="stream")
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

    _audit_evidence_access(db, current_user, media_item, method="stream", extra={"range": f"{start}-{end}"})

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
#
# UploadStatus already had verified/rejected/archived enum values from an
# earlier phase, but NO endpoint anywhere ever transitioned an Evidence row
# into any of them -- every uploaded row stayed at `uploaded` forever. This
# section adds the actual workflow, per the explicit transition policy
# below (nothing here was inferred from existing behavior, since none
# existed to infer from).
# ===========================================================================

# Explicit, closed transition table. Only these transitions are legal;
# everything else (including rejected->verified, archived->anything,
# uploaded->archived directly, or re-verifying/re-rejecting an
# already-decided item) is rejected with 409. `uploading` has no outgoing
# transition here since nothing in the current upload flow ever leaves an
# Evidence row in that state (upload_evidence sets `uploaded` directly on
# success, or never creates the row at all on failure).
_EVIDENCE_ALLOWED_TRANSITIONS: dict[models.UploadStatus, set[models.UploadStatus]] = {
    models.UploadStatus.uploaded: {models.UploadStatus.verified, models.UploadStatus.rejected},
    models.UploadStatus.verified: {models.UploadStatus.archived},
}


def _check_evidence_verification_authority(db: Session, media_item: models.Evidence, current_user: models.User):
    """
    admin/control_room: always allowed.
    station: allowed ONLY if the evidence's incident belongs to their own
      station (Incident.station_id == current_user.station_id) -- the only
      station-ownership relationship the current data model actually
      establishes for evidence (Evidence has no station_id of its own).
    constable/citizen: never allowed, regardless of upload/assignment
      ownership -- verification is a control-room/station oversight action,
      not a participant action.
    """
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        return
    if role == models.UserRole.station:
        if current_user.station_id:
            incident = db.query(models.Incident).filter(models.Incident.id == media_item.incident_id).first()
            if incident is not None and incident.station_id == current_user.station_id:
                return
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to verify this evidence")
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to verify this evidence")


def _get_evidence_or_404(db: Session, evidence_id: uuid.UUID) -> models.Evidence:
    media_item = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not media_item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return media_item


def _transition_evidence_status(
    db: Session,
    evidence_id: uuid.UUID,
    new_status: models.UploadStatus,
    current_user: models.User,
    action: str,
    reason: Optional[str] = None,
) -> models.Evidence:
    """
    Re-reads the Evidence row -- WITH a row lock on PostgreSQL
    (`SELECT ... FOR UPDATE`) -- validates the transition against that
    freshly-locked read, mutates it, writes the audit entry, and commits,
    all before returning. The caller (verify_evidence/reject_evidence/
    archive_evidence) only publishes its WebSocket event AFTER this
    function returns successfully, so a failed/rolled-back transition can
    never result in a published event or a persisted audit row -- there is
    nothing in the session to commit if this raises before reaching
    `db.commit()`.

    CONCURRENCY MECHANISM:
      - On PostgreSQL, `.with_for_update()` compiles to a genuine
        `SELECT ... FOR UPDATE`, which blocks a second concurrent
        transaction attempting the same `SELECT ... FOR UPDATE` on the
        same row until the first transaction commits or rolls back. When
        the second transaction's lock is finally granted, its SELECT
        re-reads the row as it now stands (i.e. AFTER the first
        transaction's commit), so `old_status` reflects the first
        transaction's outcome -- the second transaction's transition
        attempt is then correctly validated against the up-to-date state
        and rejected with 409 if no longer legal.
      - On SQLite (this test environment), SQLAlchemy accepts
        `.with_for_update()` without error, but it is a NO-OP: SQLite has
        no multi-connection row-level locking model at all (it's a
        single-writer database). This was verified directly (see phase
        report) -- calling `.with_for_update()` here does NOT raise under
        SQLite, but it also does NOT provide any actual locking guarantee
        there. The SQLite test suite therefore only proves SEQUENTIAL
        conflicting requests are handled correctly (each one re-reads
        current state at the start of ITS OWN call to this function), not
        genuine concurrent-transaction safety -- that requires the
        Postgres-only integration test (see
        tests/test_evidence_verification_concurrency.py), which needs a
        real two-connection Postgres instance to mean anything and is
        explicitly skipped when one isn't configured.
    """
    # .with_for_update() compiles to a genuine `SELECT ... FOR UPDATE` on
    # PostgreSQL; confirmed harmless no-op on SQLite (see docstring above)
    # so the same code path runs under both dialects.
    query = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).with_for_update()

    media_item = query.first()
    if not media_item:
        raise HTTPException(status_code=404, detail="Evidence not found")

    old_status = media_item.upload_status  # the locked (Postgres) / freshly-queried (SQLite) current status
    allowed_next = _EVIDENCE_ALLOWED_TRANSITIONS.get(old_status, set())
    if new_status not in allowed_next:
        db.rollback()  # release the row lock immediately rather than holding it until the session closes
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot transition evidence from {old_status.value} to {new_status.value}",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    media_item.upload_status = new_status

    details = {"old_status": old_status.value, "new_status": new_status.value}
    if new_status == models.UploadStatus.verified:
        media_item.verified_by = current_user.id
        media_item.verified_at = now
    elif new_status == models.UploadStatus.rejected:
        media_item.rejected_by = current_user.id
        media_item.rejected_at = now
        media_item.rejection_reason = reason
        if reason:
            details["reason"] = reason
    elif new_status == models.UploadStatus.archived:
        media_item.archived_by = current_user.id
        media_item.archived_at = now

    log_action(
        db,
        user_id=current_user.id,
        action=action,
        incident_id=media_item.incident_id,
        evidence_id=media_item.id,
        details=details,
    )

    db.commit()
    db.refresh(media_item)
    return media_item


@router.post("/{evidence_id}/verify", response_model=schemas.EvidenceResponse)
async def verify_evidence(
    evidence_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    uploaded -> verified. admin/control_room: any evidence. station: only
    evidence belonging to an incident in their own station's jurisdiction
    (see _check_evidence_verification_authority). constable/citizen: 403.
    Re-verifying already-verified/rejected/archived evidence is rejected
    with 409 (see _EVIDENCE_ALLOWED_TRANSITIONS).
    """
    media_item = _get_evidence_or_404(db, evidence_id)
    _check_evidence_verification_authority(db, media_item, current_user)
    media_item = _transition_evidence_status(db, evidence_id, models.UploadStatus.verified, current_user, "evidence.verified")

    incident = db.query(models.Incident).filter(models.Incident.id == media_item.incident_id).first()
    await events.publish_evidence_verified(media_item, incident.station_id if incident else None)

    return schemas.EvidenceResponse.from_evidence(media_item)


@router.post("/{evidence_id}/reject", response_model=schemas.EvidenceResponse)
async def reject_evidence(
    evidence_id: uuid.UUID,
    payload: schemas.EvidenceRejectRequest = schemas.EvidenceRejectRequest(),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """uploaded -> rejected, with an optional reason. Same authorization as /verify. A rejected evidence item is terminal -- it can never be re-verified or archived (see _EVIDENCE_ALLOWED_TRANSITIONS)."""
    media_item = _get_evidence_or_404(db, evidence_id)
    _check_evidence_verification_authority(db, media_item, current_user)
    media_item = _transition_evidence_status(
        db, evidence_id, models.UploadStatus.rejected, current_user, "evidence.rejected", reason=payload.reason
    )

    incident = db.query(models.Incident).filter(models.Incident.id == media_item.incident_id).first()
    await events.publish_evidence_rejected(media_item, incident.station_id if incident else None)

    return schemas.EvidenceResponse.from_evidence(media_item)


@router.post("/{evidence_id}/archive", response_model=schemas.EvidenceResponse)
async def archive_evidence(
    evidence_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """verified -> archived ONLY -- evidence must already be verified before it can be archived (uploaded -> archived directly is rejected with 409, matching the explicit transition policy). Same authorization as /verify."""
    media_item = _get_evidence_or_404(db, evidence_id)
    _check_evidence_verification_authority(db, media_item, current_user)
    media_item = _transition_evidence_status(db, evidence_id, models.UploadStatus.archived, current_user, "evidence.archived")

    incident = db.query(models.Incident).filter(models.Incident.id == media_item.incident_id).first()
    await events.publish_evidence_archived(media_item, incident.station_id if incident else None)

    return schemas.EvidenceResponse.from_evidence(media_item)
