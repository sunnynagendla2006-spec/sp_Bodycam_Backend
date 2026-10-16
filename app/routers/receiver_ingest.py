"""
Control-room side of the SITE RECEIVER -> CONTROL ROOM protocol (prefix /receiver/v1).

Not an officer API. Every call authenticates with the receiver's OWN credential (services/receiver_auth.py),
which is bound to one site; the site is never taken from a request body, and a receiver can only touch
recordings that belong to its own site.

  POST /receiver/v1/heartbeat                              health, capacity, backlog, recent devices, failures
  GET  /receiver/v1/sync                                   revoked grant ids, queued admin commands
  PUT  /receiver/v1/recordings/{rid}                       register / reconcile a recording (idempotent)
  PUT  /receiver/v1/recordings/{rid}/chunks/{cid}          one chunk, SHA-256 verified, idempotent
  POST /receiver/v1/recordings/{rid}/complete              finalize
  GET  /receiver/v1/recordings/{rid}/manifest              what the control room already has (reconciliation)

IDEMPOTENCY / RECONCILIATION RULES
  * The recording id and chunk id are the phone's own UUIDs and are kept unchanged.
  * A chunk that already exists with the SAME original hash is acknowledged as a duplicate (never stored twice).
  * A chunk that exists with a DIFFERENT hash (same number or same id) is refused with 409 `hash_conflict`:
    existing evidence is never overwritten because an id matches. The receiver quarantines it for a human.
  * Whatever the receiver forwards is stored as ORIGINAL evidence first (services/evidence.py); the watermarked
    playback file is a separate derivative with recorded provenance.
"""
import datetime
import hashlib
import logging
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pymongo import ReturnDocument

from .. import models, schemas_bodycam as sb
from ..auth import request_limiter
from ..services import chunk_manifest as chunk_manifest_service
from ..services import evidence as evidence_service
from ..services import events, receiver_auth, site_grants
from ..services.audit import log_action
from . import media as media_module
from .recordings import _build_chunk_storage_key, _burn_watermark_best_effort, _try_build_playable_recording

logger = logging.getLogger("receiver_ingest")

router = APIRouter(prefix="/receiver/v1", tags=["Site Receiver Ingest"])

_RATE_PER_MINUTE = int(os.getenv("RECEIVER_RATE_LIMIT_PER_MINUTE", "1200"))


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt: datetime.datetime) -> datetime.datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def _limit(ctx: receiver_auth.ReceiverContext) -> None:
    if not request_limiter.allow(f"rcvingest:{ctx.receiver.id}", _RATE_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": "10"})


def _parse_dt(value: Optional[str]) -> Optional[datetime.datetime]:
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _session_for(ctx: receiver_auth.ReceiverContext, recording_id) -> models.RecordingSession:
    session = await models.RecordingSession.get(recording_id)
    # Another site's recording is reported as missing, never as forbidden: its existence is not disclosed.
    if session is None or session.site_id != ctx.site.id:
        raise HTTPException(status_code=404, detail="Recording not registered for this site")
    return session


# ---------------------------------------------------------------------------
# Heartbeat and sync
# ---------------------------------------------------------------------------

@router.post("/heartbeat")
async def heartbeat(body: sb.ReceiverHeartbeat, ctx: receiver_auth.ReceiverContext = Depends(receiver_auth.get_current_receiver)):
    if body.site_code and body.site_code != ctx.site.code:
        raise HTTPException(status_code=403, detail="This credential is not authorized for the named site")
    _limit(ctx)
    r = ctx.receiver
    now = _utcnow()
    remaining = [c for c in (r.pending_commands or []) if c.get("id") not in set(body.completed_command_ids)]
    recent = dict(r.recent_devices or {})
    recent.update(body.recent_devices)
    if len(recent) > 200:  # keep the newest 200
        recent = dict(sorted(recent.items(), key=lambda kv: kv[1], reverse=True)[:200])
    await models.SiteReceiver.get_motor_collection().update_one(
        {"_id": r.id},
        {"$set": {
            "version": body.version, "capabilities": body.capabilities, "last_seen_at": now, "updated_at": now,
            "disk_total_bytes": body.disk_total_bytes, "disk_free_bytes": body.disk_free_bytes, "min_free_bytes": body.min_free_bytes,
            "accepting_uploads": body.accepting_uploads, "pending_chunks": body.pending_chunks, "syncing_chunks": body.syncing_chunks,
            "quarantined_chunks": body.quarantined_chunks, "received_chunks_total": body.received_chunks_total,
            "last_local_upload_at": body.last_local_upload_at, "last_central_ack_at": body.last_central_ack_at,
            "central_reachable": True, "recent_devices": recent, "failures": body.failures, "pending_commands": remaining,
            "local_recordings": body.local_recordings, "local_recordings_at": now,
        }},
    )
    return {"status": "ok", "server_time": now.isoformat(), "receiver_code": r.code, "site_code": ctx.site.code, "token_version": r.token_version}


@router.get("/sync", response_model=sb.ReceiverSyncOut)
async def sync(ctx: receiver_auth.ReceiverContext = Depends(receiver_auth.get_current_receiver)):
    """What a receiver must know that only the control room can tell it: revoked grants (still unexpired) and queued admin commands."""
    _limit(ctx)
    now = _utcnow()
    revoked = await models.OfflineGrant.find({"site_id": ctx.site.id, "revoked": True, "expires_at": {"$gt": now}}).to_list()
    await models.SiteReceiver.get_motor_collection().update_one({"_id": ctx.receiver.id}, {"$set": {"last_sync_at": now, "last_seen_at": now}})
    return sb.ReceiverSyncOut(
        server_time=now, site_id=ctx.site.id, site_code=ctx.site.code, revoked_grant_ids=[g.id for g in revoked],
        commands=list(ctx.receiver.pending_commands or []), grant_issuer=site_grants.issuer(), grant_key_id=site_grants.key_id(),
    )


# ---------------------------------------------------------------------------
# Recordings
# ---------------------------------------------------------------------------

@router.put("/recordings/{recording_id}", response_model=sb.ReceiverRecordingOut)
async def upsert_recording(recording_id: uuid.UUID, body: sb.ReceiverRecordingIn, ctx: receiver_auth.ReceiverContext = Depends(receiver_auth.get_current_receiver)):
    """Registers a recording (or confirms an existing one). Never creates a duplicate and never re-assigns an existing recording to someone else."""
    _limit(ctx)
    if body.site_id and body.site_id != ctx.site.id:
        raise HTTPException(status_code=403, detail="This credential is not authorized for the named site")

    constable = await models.Constable.get(body.constable_id)
    device = await models.Device.get(body.device_id)
    if constable is None or device is None or device.constable_id != constable.id:
        raise HTTPException(status_code=422, detail="Unknown officer/device, or the device does not belong to that officer")

    existing = await models.RecordingSession.get(recording_id)
    flags = []
    if existing is not None:
        if existing.site_id != ctx.site.id or existing.constable_id != constable.id or existing.device_id != device.id:
            raise HTTPException(status_code=409, detail="That recording id already exists for a different site, officer or device", headers={"X-Conflict-Reason": "recording_id_conflict"})
        session, created = existing, False
    else:
        # Authority for this recording: a grant THIS control room issued, for this site/officer/device.
        if body.grant_id is None:
            raise HTTPException(status_code=403, detail="A grant id is required to register a new recording", headers={"X-Conflict-Reason": "grant_required"})
        grant = await models.OfflineGrant.get(body.grant_id)
        if grant is None or grant.site_id != ctx.site.id or grant.constable_id != constable.id or grant.device_id != device.id:
            raise HTTPException(status_code=403, detail="The grant does not match this site, officer and device", headers={"X-Conflict-Reason": "grant_mismatch"})
        started = _aware(body.started_at)
        if started > _aware(grant.expires_at) + datetime.timedelta(minutes=10) or started < _aware(grant.issued_at) - datetime.timedelta(minutes=10):
            raise HTTPException(status_code=403, detail="The recording started outside the grant's validity", headers={"X-Conflict-Reason": "grant_window"})
        if grant.revoked:
            if grant.revoked_at is None or _aware(grant.revoked_at) <= started:
                raise HTTPException(status_code=403, detail="The grant was revoked before this recording started", headers={"X-Conflict-Reason": "grant_revoked"})
            flags.append("grant_revoked_later")  # captured while the grant was valid; revoked afterwards: accepted, flagged
        session = models.RecordingSession(
            id=recording_id, site_id=ctx.site.id, receiver_id=ctx.receiver.id, origin="site_receiver", grant_id=grant.id,
            constable_id=constable.id, device_id=device.id, trigger_type=body.trigger_type, status=models.RecordingStatus.recording,
            started_at=started, created_at=_utcnow(), camera_lens_direction=body.camera_lens_direction, flags=flags,
        )
        await session.insert()
        created = True
        await log_action(user_id=None, action="bodycam.recording_registered", details={
            "site_id": str(ctx.site.id), "receiver_id": str(ctx.receiver.id), "recording_id": str(recording_id), "constable_id": str(constable.id),
            "device_id": str(device.id), "flags": flags,
        })
        await events.publish_recording_started(session, constable.station_id)

    if body.ended_at and session.ended_at is None:
        session.ended_at = _aware(body.ended_at)
    if body.status == "cancelled" and session.status == models.RecordingStatus.recording:
        session.status = models.RecordingStatus.cancelled
    if not created:
        await session.save()
    return sb.ReceiverRecordingOut(
        recording_id=session.id, status=session.status, created=created, chunk_numbers=sorted(c.chunk_number for c in session.chunks), flags=list(session.flags or []),
    )


@router.put("/recordings/{recording_id}/chunks/{chunk_id}", response_model=sb.ReceiverChunkAck)
async def put_chunk(
    recording_id: uuid.UUID,
    chunk_id: uuid.UUID,
    chunk_number: int = Form(..., ge=1),
    sha256: str = Form(...),
    duration_seconds: Optional[float] = Form(None),
    is_last_chunk: bool = Form(False),
    latitude: Optional[float] = Form(None),
    longitude: Optional[float] = Form(None),
    captured_start: Optional[str] = Form(None),
    captured_end: Optional[str] = Form(None),
    site_received_at: Optional[str] = Form(None),
    file: UploadFile = File(...),
    ctx: receiver_auth.ReceiverContext = Depends(receiver_auth.get_current_receiver),
):
    _limit(ctx)
    session = await _session_for(ctx, recording_id)
    if session.status == models.RecordingStatus.cancelled:
        raise HTTPException(status_code=409, detail="The recording was cancelled", headers={"X-Conflict-Reason": "recording_cancelled"})
    try:
        declared = evidence_service.normalize_sha256(sha256)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if declared is None:
        raise HTTPException(status_code=422, detail="sha256 is required")

    # ---- idempotency / reconciliation, before any bytes are stored ----
    same_number = next((c for c in session.chunks if c.chunk_number == chunk_number), None)
    same_id = next((c for c in session.chunks if c.id == chunk_id), None)
    for existing in (same_number, same_id):
        if existing is not None:
            if existing.original_hash == declared and existing.id == chunk_id and existing.chunk_number == chunk_number:
                return sb.ReceiverChunkAck(chunk_id=existing.id, recording_id=recording_id, chunk_number=existing.chunk_number,
                                           original_hash=existing.original_hash, duplicate=True, stored_at=existing.created_at)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A chunk with this id or number already exists with different content or identity; existing evidence is not overwritten",
                headers={"X-Conflict-Reason": "hash_conflict"},
            )

    first = await file.read(media_module._READ_CHUNK_SIZE)
    sniffed = media_module._sniff_mime_type(first)
    # The receiver only ever forwards files it has already recognised as MP4, so the CONTENT must identify itself as a
    # supported type here; a claimed content type alone is not enough.
    resolved_mime = sniffed
    if resolved_mime not in media_module.ALLOWED_MIME_TO_EXT:
        raise HTTPException(status_code=400, detail=f"Unsupported chunk file type: {resolved_mime or 'unknown'}", headers={"X-Conflict-Reason": "unsupported_type"})

    storage = media_module._get_storage_backend()
    ingest_token = uuid.uuid4().hex[:16]  # ownership marker: this request alone writes (and, on failure, deletes) these keys
    storage_key = _build_chunk_storage_key(recording_id, chunk_number, resolved_mime, ingest_token)
    hasher = hashlib.sha256()
    written = 0
    try:
        with storage.open_write(storage_key) as buffer:
            piece = first
            while piece:
                written += len(piece)
                if written > media_module.MAX_EVIDENCE_SIZE_BYTES:
                    raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Chunk exceeds the {media_module.MAX_EVIDENCE_SIZE_MB}MB limit")
                hasher.update(piece)
                buffer.write(piece)
                piece = await file.read(media_module._READ_CHUNK_SIZE)
    except Exception:
        storage.delete(storage_key)
        raise

    original_hash = hasher.hexdigest()
    if original_hash != declared:
        storage.delete(storage_key)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Received bytes do not match the declared SHA-256", headers={"X-Conflict-Reason": "hash_mismatch"})

    original_key = None
    if evidence_service.preserve_enabled():
        candidate = evidence_service.original_key_for(recording_id, chunk_number, os.path.splitext(storage_key)[1], ingest_token)
        if evidence_service.preserve_original(storage, storage_key, candidate):
            original_key = candidate

    started = _parse_dt(captured_start)
    # Watermark only when a pristine original exists (the burn rewrites storage_key in place).
    burn = None
    if original_key is not None:
        burn = await _burn_watermark_best_effort(storage=storage, storage_key=storage_key, session=session, latitude=latitude, longitude=longitude, recorded_at=started)
    size, served_hash, processing = written, original_hash, []
    processing.append(evidence_service.provenance("received_via_site_receiver", "site_receiver", None, original_hash, receiver_id=str(ctx.receiver.id)))
    if original_key is None:
        processing.append(evidence_service.provenance("watermark_skipped", "policy", original_hash, original_hash, reason="no preserved original"))
    if burn is not None:
        size, served_hash = burn
        processing.append(evidence_service.provenance("watermark", "ffmpeg libx264 drawtext", original_hash, served_hash, preserved_original=original_key is not None))

    now = _utcnow()
    chunk = models.Chunk(
        id=chunk_id, chunk_number=chunk_number, storage_key=storage_key, file_size=size, duration_seconds=duration_seconds, file_hash=served_hash,
        mime_type=resolved_mime, is_last_chunk=is_last_chunk, upload_status=models.ChunkUploadStatus.uploaded, latitude=latitude, longitude=longitude,
        recorded_at=started, original_storage_key=original_key, original_hash=original_hash, original_size=written,
        derived_hash=served_hash if burn is not None else None, processing=processing, received_via="site_receiver", receiver_id=ctx.receiver.id,
        captured_start=started, captured_end=_parse_dt(captured_end), site_received_at=_parse_dt(site_received_at), created_at=now,
    )
    try:
        updated = await models.RecordingSession.get_motor_collection().find_one_and_update(
            {"_id": recording_id, "chunks.chunk_number": {"$ne": chunk_number}, "chunks.id": {"$ne": chunk_id}},
            {"$push": {"chunks": chunk.model_dump()}},
            return_document=ReturnDocument.AFTER,
        )
    except Exception:
        storage.delete(storage_key)
        if original_key:
            storage.delete(original_key)
        raise
    if updated is None:
        # Lost a race with another request for the same chunk: remove only what THIS request wrote (unique keys) and
        # answer from the stored record. The winner's objects are never touched.
        storage.delete(storage_key)
        if original_key:
            storage.delete(original_key)
        fresh = await models.RecordingSession.get(recording_id)
        winner = next((c for c in (fresh.chunks if fresh else []) if c.chunk_number == chunk_number), None)
        if winner and winner.id == chunk_id and winner.original_hash == original_hash:
            return sb.ReceiverChunkAck(chunk_id=winner.id, recording_id=recording_id, chunk_number=chunk_number, original_hash=original_hash, duplicate=True, stored_at=winner.created_at)
        raise HTTPException(status_code=409, detail="Concurrent conflicting chunk", headers={"X-Conflict-Reason": "hash_conflict"})

    await log_action(user_id=None, action="bodycam.receiver_chunk_accepted", details={
        "site_id": str(ctx.site.id), "receiver_id": str(ctx.receiver.id), "recording_id": str(recording_id), "chunk_id": str(chunk_id),
        "chunk_number": chunk_number, "original_hash": original_hash,
    })
    constable = await models.Constable.get(session.constable_id)
    await events.publish_recording_chunk_uploaded(session, constable.station_id if constable else None, chunk_number, is_last_chunk)
    return sb.ReceiverChunkAck(chunk_id=chunk_id, recording_id=recording_id, chunk_number=chunk_number, original_hash=original_hash, duplicate=False, stored_at=now)


@router.post("/recordings/{recording_id}/complete", response_model=sb.ReceiverCompleteOut)
async def complete(recording_id: uuid.UUID, body: sb.ReceiverCompleteIn, ctx: receiver_auth.ReceiverContext = Depends(receiver_auth.get_current_receiver)):
    """Idempotent. Completion is accepted with missing chunks (they are reported, never invented), like the online flow."""
    _limit(ctx)
    session = await _session_for(ctx, recording_id)
    summary = chunk_manifest_service.summarize_chunks([c.chunk_number for c in session.chunks])
    if body.chunk_count is not None and body.chunk_count > len(summary.received_chunk_numbers):
        # The phone says there are more chunks than have arrived: not complete yet. The receiver retries later.
        raise HTTPException(status_code=409, detail="Not all chunks have arrived", headers={"X-Conflict-Reason": "chunks_outstanding"})
    if session.status == models.RecordingStatus.recording:
        session.status = models.RecordingStatus.completed
        session.ended_at = _aware(body.ended_at) if body.ended_at else (session.ended_at or _utcnow())
        await session.save()
        await log_action(user_id=None, action="bodycam.receiver_recording_completed", details={
            "site_id": str(ctx.site.id), "receiver_id": str(ctx.receiver.id), "recording_id": str(recording_id), "missing": summary.missing_chunk_numbers,
        })
        constable = await models.Constable.get(session.constable_id)
        await events.publish_recording_completed(session, constable.station_id if constable else None, summary.missing_chunk_numbers)
        if summary.is_contiguous:
            await _try_build_playable_recording(session)
    return sb.ReceiverCompleteOut(recording_id=recording_id, status=session.status, missing_chunk_numbers=summary.missing_chunk_numbers)


@router.get("/recordings/{recording_id}/manifest", response_model=sb.ReceiverManifestOut)
async def manifest(recording_id: uuid.UUID, ctx: receiver_auth.ReceiverContext = Depends(receiver_auth.get_current_receiver)):
    _limit(ctx)
    session = await _session_for(ctx, recording_id)
    return sb.ReceiverManifestOut(
        recording_id=recording_id, status=session.status,
        chunks=[sb.ManifestItem(chunk_id=c.id, chunk_number=c.chunk_number, original_hash=c.original_hash) for c in sorted(session.chunks, key=lambda c: c.chunk_number)],
    )
