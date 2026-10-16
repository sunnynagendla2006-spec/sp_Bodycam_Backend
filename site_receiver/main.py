"""
Site receiver HTTP API (versioned under /v1).

  GET  /v1/health                                     liveness (no auth, minimal)
  POST /v1/auth/session                               exchange an offline grant for a short-lived session token
  GET  /v1/config                                     limits and optional local live-view availability
  POST /v1/recordings                                 register / resume a recording (idempotent, client UUID)
  GET  /v1/recordings/{id}                            recording and chunk states
  PUT  /v1/recordings/{id}/chunks/{chunk_id}          upload a chunk (verified, durable, idempotent)
  POST /v1/recordings/{id}/complete                   the phone has finished (all chunks must be here)
  POST /v1/live/start                                 token for the site-local LiveKit (if configured)
  /v1/admin/*                                         operator endpoints, X-Receiver-Admin-Key

Errors always use {"error": {"code", "message"}}. A chunk is acknowledged ("locally_durable") only after its bytes were
verified against the phone's SHA-256, fsynced, renamed into place AND its metadata row was committed.

Run a SINGLE worker process (in-process locks and rate limits). Terminate TLS here (uvicorn --ssl-*) or in a reverse proxy;
do not expose this service to the public internet.
"""
import asyncio
import collections
import errno
import datetime
import hmac
import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, File, Form, Header, Query, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import __version__, auth
from .config import ConfigError, Settings, load
from .forwarder import Forwarder
from .limits import BodyLimitMiddleware
from .recovery import AlreadyRunning, InstanceLock, reconcile
from .storage import MediaStorage
from .store import ACKED, FAILED_RETRY, PENDING, PURGED, QUARANTINED, Store, now_iso

log = logging.getLogger("receiver")

READ_SIZE = 1024 * 1024
BUSY_WAIT_SECONDS = 5.0


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: Optional[Dict[str, str]] = None):
        self.status, self.code, self.message, self.headers = status, code, message, headers or {}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {"ts": now_iso(), "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        for key in ("chunk_id", "reason", "recording_id"):
            if hasattr(record, key):
                data[key] = getattr(record, key)
        return json.dumps(data)


def _setup_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=getattr(logging, level, logging.INFO), handlers=[handler], force=True)


class _RateLimiter:
    def __init__(self, per_minute: int):
        self.limit, self.hits = per_minute, collections.defaultdict(collections.deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


class SessionIn(BaseModel):
    grant: str = Field(..., min_length=20, max_length=8192)
    device_identifier: Optional[str] = Field(default=None, max_length=255)


class RecordingIn(BaseModel):
    recording_id: uuid.UUID
    started_at: datetime.datetime
    trigger_type: str = Field(default="manual", max_length=32)
    camera_lens_direction: str = Field(default="back", pattern="^(front|back)$")


class _Healed(Exception):
    pass


class CompleteIn(BaseModel):
    ended_at: Optional[datetime.datetime] = None
    chunk_count: int = Field(..., ge=0)


class RetryIn(BaseModel):
    recording_id: Optional[uuid.UUID] = None
    chunk_id: Optional[uuid.UUID] = None


def create_app() -> FastAPI:
    settings: Settings = load()
    _setup_logging(settings.log_level)
    os.makedirs(os.path.dirname(os.path.abspath(settings.db_path)), exist_ok=True)
    # One receiver per database + storage root: a second process would corrupt shared state.
    instance_lock = InstanceLock(settings.db_path + ".lock")
    try:
        instance_lock.acquire()
    except AlreadyRunning as exc:
        raise ConfigError(str(exc))
    store = Store(settings.db_path)
    media = MediaStorage(settings.storage_root, settings.site_id)
    fwd = Forwarder(settings, store, media)
    limiter = _RateLimiter(settings.rate_limit_per_minute)  # authenticated phones, per device
    # Unauthenticated traffic is counted per client address in SEPARATE buckets, so a flood from one address cannot use up
    # the capacity of authorized devices or lock the operator out. (Behind a reverse proxy every client shares the proxy's
    # address: rate-limit at the proxy as well.)
    anon_limiter = _RateLimiter(60)
    admin_fail_limiter = _RateLimiter(10)
    chunk_locks: Dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.upload_sem = asyncio.Semaphore(settings.upload_concurrency)
        recovered = store.recover_after_restart()
        removed = media.clean_stale_tmp()
        recovery = await asyncio.to_thread(reconcile, store, media)
        store.audit("receiver_started", version=__version__, recovered_syncing=recovered, stale_tmp_removed=removed, **recovery)
        if any(recovery.values()):
            log.warning("start-up recovery changed state: %s", recovery)
        log.info("receiver started (site %s)", settings.site_code)
        if not fwd.configured:
            log.warning("central forwarding is not configured (RECEIVER_CENTRAL_URL / RECEIVER_CENTRAL_TOKEN): chunks are stored but not forwarded")
        task = asyncio.create_task(fwd.run())
        try:
            yield
        finally:
            fwd.stop()
            try:
                await asyncio.wait_for(task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                task.cancel()
            await fwd.close()
            store.audit("receiver_stopped")
            store.close()
            instance_lock.release()

    app = FastAPI(title="SP Bodycam Site Receiver", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.fwd, app.state.settings, app.state.media = store, fwd, settings, media  # handles for tests and diagnostics
    # Chunk bodies are cut off before multipart parsing/spooling (limits.py); a reverse proxy should enforce the same limit.
    app.add_middleware(
        BodyLimitMiddleware, limit_bytes=settings.max_chunk_bytes + 1024 * 1024,
        matches=lambda method, path: method == "PUT" and path.startswith("/v1/recordings/") and "/chunks/" in path,
    )

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    @app.exception_handler(ApiError)
    async def _api_error(_req: Request, exc: ApiError):
        return JSONResponse(status_code=exc.status, content={"error": {"code": exc.code, "message": exc.message}}, headers=exc.headers)

    @app.exception_handler(auth.AuthError)
    async def _auth_error(_req: Request, exc: auth.AuthError):
        return JSONResponse(status_code=exc.status, content={"error": {"code": exc.code, "message": exc.message}}, headers={"WWW-Authenticate": "Bearer"} if exc.status == 401 else {})

    # ---- dependencies -------------------------------------------------------------
    async def session_claims(authorization: str = Header(default="")) -> Dict[str, Any]:
        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise auth.AuthError("session_required", "A session token is required")
        claims = await asyncio.to_thread(auth.verify_session_token, parts[1], settings, store)
        if not limiter.allow(f"dev:{claims['dev']}"):
            raise ApiError(429, "rate_limited", "Too many requests", {"Retry-After": "10"})
        return claims

    async def admin_ok(request: Request, x_receiver_admin_key: str = Header(default="")) -> None:
        if not settings.admin_key:
            raise ApiError(503, "admin_disabled", "Admin endpoints are disabled: RECEIVER_ADMIN_KEY is not set")
        if hmac.compare_digest(x_receiver_admin_key.encode(), settings.admin_key.encode()):
            return  # a correct key is never throttled by failed guesses
        if not admin_fail_limiter.allow(f"admin-fail:{client_ip(request)}"):
            raise ApiError(429, "rate_limited", "Too many failed attempts", {"Retry-After": "60"})
        raise ApiError(401, "admin_unauthorized", "Invalid admin key")

    def own_recording(claims: Dict[str, Any], recording_id: uuid.UUID) -> Dict[str, Any]:
        rec = store.one("SELECT * FROM recordings WHERE recording_id = ?", (str(recording_id),))
        # Another officer's/device's recording is "not found", never "forbidden": its existence is not disclosed.
        if rec is None or rec["constable_id"] != claims["sub"] or rec["device_id"] != claims["dev"]:
            raise ApiError(404, "recording_not_found", "Recording not registered by this device")
        return rec

    def ack_for(row: Dict[str, Any], duplicate: bool) -> Dict[str, Any]:
        return {
            # `ack` says WHAT is confirmed: local_received = durably stored at this receiver only;
            # central_received = the control room has confirmed identical content. `status` is kept for older callers.
            "ack": "central_received" if row["state"] in (ACKED, PURGED) else "local_received",
            "status": "locally_durable", "duplicate": duplicate, "chunk_id": row["chunk_id"], "recording_id": row["recording_id"], "chunk_number": row["chunk_number"],
            "sha256": row["sha256"], "size_bytes": row["size_bytes"], "received_at": row["received_at"], "sync_state": row["state"],
            "central_acknowledged": row["state"] in (ACKED, PURGED),
        }

    # ---- public -------------------------------------------------------------------
    @app.get("/v1/health")
    async def health():
        """Liveness/readiness for phones and monitors. Deliberately minimal and unauthenticated: it names the service and says
        whether uploads are accepted, nothing about the site, version or storage. It is NOT proof of identity (anyone can
        serve this body); identity comes from TLS and from the authenticated session (see docs)."""
        return {"status": "ok", "service": "sp-bodycam-receiver", "api": "v1", "ready": media.free_bytes() >= settings.min_free_bytes}

    @app.post("/v1/auth/session")
    async def create_session(body: SessionIn, request: Request):
        if not anon_limiter.allow(f"session:{client_ip(request)}"):
            raise ApiError(429, "rate_limited", "Too many session requests", {"Retry-After": "10"})
        claims = await asyncio.to_thread(auth.verify_grant, body.grant, settings, store)
        auth.require_operation(claims, "session")
        if body.device_identifier and claims.get("devid") and body.device_identifier != claims["devid"]:
            raise ApiError(403, "device_mismatch", "The grant was issued for a different device")
        token = auth.issue_session_token(claims, settings)
        await asyncio.to_thread(store.note_device, claims.get("devid"))
        await asyncio.to_thread(store.audit, "session_issued", grant_id=claims["jti"], device_id=claims["dev"], constable_id=claims["sub"])
        return {**token, "token_type": "bearer", "grant_expires_at": datetime.datetime.fromtimestamp(claims["exp"], tz=datetime.timezone.utc).isoformat(),
                "receiver": {"site_id": str(settings.site_id), "site_code": settings.site_code, "name": settings.receiver_name, "version": __version__},
                "limits": {"max_chunk_bytes": settings.max_chunk_bytes, "accepted_mime": ["video/mp4"]}}

    # ---- authenticated (phone) --------------------------------------------------------
    @app.get("/v1/config")
    async def config(claims: Dict[str, Any] = Depends(session_claims)):
        cap = fwd.capacity()
        return {"site_code": settings.site_code, "accepting_uploads": cap["accepting"], "max_chunk_bytes": settings.max_chunk_bytes,
                "central_configured": fwd.configured, "local_live_available": bool(settings.local_livekit_url and settings.local_livekit_key and settings.local_livekit_secret and "live" in claims.get("ops", []))}

    @app.post("/v1/recordings")
    async def register_recording(body: RecordingIn, claims: Dict[str, Any] = Depends(session_claims)):
        auth.require_operation(claims, "upload")
        rid = str(body.recording_id)
        existing = await asyncio.to_thread(store.one, "SELECT * FROM recordings WHERE recording_id = ?", (rid,))
        if existing is not None:
            if existing["constable_id"] != claims["sub"] or existing["device_id"] != claims["dev"]:
                raise ApiError(409, "recording_id_conflict", "That recording id belongs to another officer or device")
            return {"recording_id": rid, "status": existing["status"], "created": False}
        now = now_iso()
        await asyncio.to_thread(
            store.execute,
            "INSERT INTO recordings (recording_id, site_id, constable_id, device_id, device_identifier, grant_id, trigger_type, camera, started_at, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'recording', ?, ?)",
            (rid, str(settings.site_id), claims["sub"], claims["dev"], claims.get("devid"), claims["gid"], body.trigger_type, body.camera_lens_direction, body.started_at.isoformat(), now, now),
        )
        await asyncio.to_thread(store.audit, "recording_registered", recording_id=rid, device_id=claims["dev"], constable_id=claims["sub"])
        return {"recording_id": rid, "status": "recording", "created": True}

    @app.get("/v1/recordings/{recording_id}")
    async def recording_status(recording_id: uuid.UUID, claims: Dict[str, Any] = Depends(session_claims)):
        rec = await asyncio.to_thread(own_recording, claims, recording_id)
        chunks = await asyncio.to_thread(store.query, "SELECT chunk_id, chunk_number, sha256, size_bytes, state, central_acked_at FROM chunks WHERE recording_id = ? ORDER BY chunk_number", (rec["recording_id"],))
        return {"recording_id": rec["recording_id"], "status": rec["status"], "central_registered": bool(rec["central_registered"]), "central_completed": bool(rec["central_completed"]),
                "chunks": [{**c, "central_acknowledged": c["state"] in (ACKED, PURGED)} for c in chunks]}

    @app.put("/v1/recordings/{recording_id}/chunks/{chunk_id}")
    async def put_chunk(
        recording_id: uuid.UUID, chunk_id: uuid.UUID,
        chunk_number: int = Form(..., ge=1), sha256: str = Form(...), size_bytes: Optional[int] = Form(None, ge=0),
        duration_seconds: Optional[float] = Form(None), is_last_chunk: bool = Form(False),
        latitude: Optional[float] = Form(None), longitude: Optional[float] = Form(None),
        captured_start: Optional[str] = Form(None), captured_end: Optional[str] = Form(None),
        file: UploadFile = File(...), claims: Dict[str, Any] = Depends(session_claims),
    ):
        auth.require_operation(claims, "upload")
        rid, cid = str(recording_id), str(chunk_id)
        declared = sha256.strip().lower()
        if len(declared) != 64 or any(c not in "0123456789abcdef" for c in declared):
            raise ApiError(422, "invalid_sha256", "sha256 must be 64 hexadecimal characters")
        await asyncio.to_thread(own_recording, claims, recording_id)  # 404 unless this device registered the recording
        if size_bytes is not None and size_bytes > settings.max_chunk_bytes:
            raise ApiError(413, "chunk_too_large", f"Chunks may be at most {settings.max_chunk_bytes} bytes")

        lock = chunk_locks.setdefault(cid, asyncio.Lock())
        try:
            async with lock:
                # ---- idempotency before storing anything ----
                existing = await asyncio.to_thread(store.one, "SELECT * FROM chunks WHERE chunk_id = ? OR (recording_id = ? AND chunk_number = ?)", (cid, rid, chunk_number))
                if existing is not None:
                    if existing["sha256"] != declared:
                        await asyncio.to_thread(store.audit, "chunk_conflict", chunk_id=cid, recording_id=rid)
                        raise ApiError(409, "hash_conflict", "A chunk with this id or number already exists with different content; existing evidence is never overwritten")
                    if existing["chunk_id"] != cid or existing["recording_id"] != rid or existing["chunk_number"] != chunk_number:
                        await asyncio.to_thread(store.audit, "chunk_identity_conflict", chunk_id=cid, existing_chunk_id=existing["chunk_id"], recording_id=rid)
                        raise ApiError(409, "identity_conflict", "That chunk number is already used by a different chunk id")
                    state, path = existing["state"], existing["storage_path"]
                    file_ok = media.exists(path)
                    # A quarantined chunk with a file on disk is only repairable if the FILE is what is wrong (size or hash differ
                    # from what was recorded). If the file is intact, the quarantine has another cause (e.g. the control room
                    # refused it) and an upload cannot fix that.
                    damaged = (not file_ok) or (state == QUARANTINED and (media.size(path) != existing["size_bytes"] or await asyncio.to_thread(media.sha256_of, path) != existing["sha256"]))
                    heal = state not in (ACKED, PURGED) and damaged
                    if state == QUARANTINED and not heal:
                        await asyncio.to_thread(store.audit, "chunk_quarantined_reupload_refused", chunk_id=cid, recording_id=rid, reason=existing["last_error"])
                        raise ApiError(409, "chunk_quarantined", "This chunk is quarantined at the receiver and needs operator attention; keep the original on the phone")
                    if not heal:
                        await asyncio.to_thread(store.audit, "chunk_duplicate", chunk_id=existing["chunk_id"], recording_id=rid)
                        return ack_for(existing, duplicate=True)
                    # The row says the chunk is held but its file is gone (disk fault, manual deletion). The phone still has
                    # the identical bytes: accept them again and restore the file instead of acknowledging a copy that is not there.

                free = media.free_bytes()
                if free - (size_bytes or 0) < settings.min_free_bytes:
                    await asyncio.to_thread(store.audit, "upload_refused_storage", free=free)
                    raise ApiError(507, "storage_full", "The receiver is low on disk space and cannot accept more video right now", {"Retry-After": "120"})

                try:
                    await asyncio.wait_for(app.state.upload_sem.acquire(), timeout=BUSY_WAIT_SECONDS)
                except asyncio.TimeoutError:
                    raise ApiError(503, "busy", "The receiver is busy; retry shortly", {"Retry-After": "5"})
                staged = None
                try:
                    first = await file.read(READ_SIZE)
                    if len(first) < 12 or first[4:8] != b"ftyp":
                        raise ApiError(400, "unsupported_type", "Only MP4 video chunks are accepted")
                    staged = media.stage()
                    piece = first
                    while piece:
                        staged.write(piece)
                        if staged.size > settings.max_chunk_bytes:
                            raise ApiError(413, "chunk_too_large", f"Chunks may be at most {settings.max_chunk_bytes} bytes")
                        if staged.size % (16 * READ_SIZE) < READ_SIZE and media.free_bytes() < settings.min_free_bytes // 2:
                            raise ApiError(507, "storage_full", "Disk space ran out during the upload", {"Retry-After": "120"})
                        piece = await file.read(READ_SIZE)
                    if size_bytes is not None and staged.size != size_bytes:
                        raise ApiError(422, "size_mismatch", "The received size does not match the declared size")
                    if staged.sha256 != declared:
                        await asyncio.to_thread(store.audit, "chunk_rejected_hash", chunk_id=cid, recording_id=rid)
                        raise ApiError(422, "hash_mismatch", "The received bytes do not match the declared SHA-256; upload the chunk again")
                    final = media.chunk_path(recording_id, chunk_id)
                    size_final, hash_final = staged.size, staged.sha256
                    if existing is not None and media.exists(final):
                        await asyncio.to_thread(media.quarantine_file, final)  # keep the damaged bytes for diagnosis; never silently overwrite
                    await asyncio.to_thread(staged.finalize, final)  # fsync + atomic rename
                    staged = None
                    received = now_iso()
                    try:
                        if existing is not None:  # healing a row whose file was lost
                            await asyncio.to_thread(
                                store.execute, "UPDATE chunks SET state = ?, size_bytes = ?, storage_path = ?, hard_errors = 0, next_attempt_at = 0, last_error = NULL WHERE chunk_id = ?",
                                (PENDING, size_final, final, cid))
                            await asyncio.to_thread(store.audit, "chunk_healed", chunk_id=cid, recording_id=rid)
                            raise _Healed()
                        await asyncio.to_thread(
                            store.execute,
                            "INSERT INTO chunks (chunk_id, recording_id, chunk_number, sha256, size_bytes, mime, duration_seconds, is_last, latitude, longitude, captured_start, captured_end, storage_path, received_at, state) "
                            "VALUES (?, ?, ?, ?, ?, 'video/mp4', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (cid, rid, chunk_number, hash_final, size_final, duration_seconds, 1 if is_last_chunk else 0, latitude, longitude, captured_start, captured_end, final, received, PENDING),
                        )
                    except _Healed:
                        pass
                    except sqlite3.IntegrityError:
                        # Lost a race: another chunk id took this chunk number between our check and our insert. Our own file
                        # (named after OUR chunk id) is removed; the winner's file is untouched.
                        media.delete(final)
                        raise ApiError(409, "identity_conflict", "That chunk number was taken by a different chunk id")
                    except sqlite3.Error:
                        if existing is None:
                            media.delete(final)  # metadata not committed: the file must not exist unacknowledged
                        raise ApiError(503, "storage_error", "The chunk could not be recorded; retry", {"Retry-After": "10"})
                except OSError as exc:
                    # Disk full / permission / I-O error while writing: nothing was acknowledged, so the phone keeps the chunk.
                    if exc.errno == errno.ENOSPC:
                        raise ApiError(507, "storage_full", "The receiver ran out of disk space; retry later", {"Retry-After": "120"})
                    log.error("storage error during upload: %s", exc.__class__.__name__)
                    raise ApiError(503, "storage_error", "The receiver could not write the chunk; retry", {"Retry-After": "30"})
                finally:
                    if staged is not None:
                        staged.abort()
                    app.state.upload_sem.release()
        finally:
            if not lock.locked():
                chunk_locks.pop(cid, None)

        fwd.last_local_upload_at = received
        await asyncio.to_thread(store.note_device, claims.get("devid"))
        await asyncio.to_thread(store.audit, "chunk_received", chunk_id=cid, recording_id=rid, chunk_number=chunk_number, size=size_final, sha256=hash_final, device_id=claims["dev"])
        row = await asyncio.to_thread(store.one, "SELECT * FROM chunks WHERE chunk_id = ?", (cid,))
        return ack_for(row, duplicate=False)

    @app.post("/v1/recordings/{recording_id}/complete")
    async def complete_recording(recording_id: uuid.UUID, body: CompleteIn, claims: Dict[str, Any] = Depends(session_claims)):
        auth.require_operation(claims, "upload")
        rec = await asyncio.to_thread(own_recording, claims, recording_id)
        have = (await asyncio.to_thread(store.one, "SELECT COUNT(*) AS n FROM chunks WHERE recording_id = ?", (rec["recording_id"],)))["n"]
        if have < body.chunk_count:
            raise ApiError(409, "chunks_outstanding", f"{body.chunk_count - have} chunk(s) have not been received yet")
        await asyncio.to_thread(
            store.execute, "UPDATE recordings SET status = 'completed', complete_requested = 1, expected_chunks = ?, ended_at = COALESCE(ended_at, ?), updated_at = ? WHERE recording_id = ?",
            (body.chunk_count, (body.ended_at or datetime.datetime.now(datetime.timezone.utc)).isoformat(), now_iso(), rec["recording_id"]),
        )
        numbers = [r["chunk_number"] for r in await asyncio.to_thread(store.query, "SELECT chunk_number FROM chunks WHERE recording_id = ? ORDER BY chunk_number", (rec["recording_id"],))]
        missing = sorted(set(range(1, (numbers[-1] if numbers else 0) + 1)) - set(numbers))
        await asyncio.to_thread(store.audit, "recording_completed_local", recording_id=rec["recording_id"], chunks=have, missing=missing)
        # `completed` means the PHONE finished sending. It does not mean the control room has the evidence, and missing
        # chunks are reported, never invented.
        return {"recording_id": rec["recording_id"], "status": "completed", "chunks_received": have, "missing_chunk_numbers": missing, "central_received": False}

    @app.post("/v1/live/start")
    async def live_start(claims: Dict[str, Any] = Depends(session_claims)):
        auth.require_operation(claims, "live")
        if not (settings.local_livekit_url and settings.local_livekit_key and settings.local_livekit_secret):
            raise ApiError(404, "local_live_not_configured", "No site-local live service is configured; recording and chunk upload continue unaffected")
        from livekit import api as lk_api  # optional dependency, imported only when the feature is used

        room = f"site-{settings.site_code}-{claims['dev']}"
        identity = f"device-{claims['dev']}"
        token = (lk_api.AccessToken(settings.local_livekit_key, settings.local_livekit_secret).with_identity(identity).with_name(identity)
                 .with_grants(lk_api.VideoGrants(room_join=True, room=room, can_publish=True, can_subscribe=False)).with_ttl(datetime.timedelta(minutes=10)).to_jwt())
        await asyncio.to_thread(store.audit, "live_token_issued", device_id=claims["dev"], room=room)
        return {"livekit_url": settings.local_livekit_url, "token": token, "room": room, "identity": identity, "scope": "site_local"}

    # ---- admin (operators on the LAN) ----------------------------------------------------
    @app.get("/v1/admin/status", dependencies=[Depends(admin_ok)])
    async def admin_status():
        snap = await asyncio.to_thread(fwd.snapshot)
        return {**snap, "site_code": settings.site_code, "central_configured": fwd.configured, "central_reachable": fwd.central_reachable,
                "counts": await asyncio.to_thread(store.counts), "forwarding_paused_for_seconds": max(0, int(fwd._paused_until - time.time()))}

    @app.get("/v1/admin/recordings", dependencies=[Depends(admin_ok)])
    async def admin_recordings(limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
        rows = await asyncio.to_thread(
            store.query,
            "SELECT r.*, (SELECT COUNT(*) FROM chunks c WHERE c.recording_id = r.recording_id) AS chunks_total, "
            "(SELECT COUNT(*) FROM chunks c WHERE c.recording_id = r.recording_id AND c.state IN ('central_acknowledged','purged')) AS chunks_synced "
            "FROM recordings r ORDER BY r.created_at DESC LIMIT ? OFFSET ?", (limit, offset))
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/admin/recordings/{recording_id}", dependencies=[Depends(admin_ok)])
    async def admin_recording(recording_id: uuid.UUID):
        rec = await asyncio.to_thread(store.one, "SELECT * FROM recordings WHERE recording_id = ?", (str(recording_id),))
        if rec is None:
            raise ApiError(404, "recording_not_found", "Unknown recording")
        chunks = await asyncio.to_thread(store.query, "SELECT chunk_id, chunk_number, sha256, size_bytes, state, attempts, hard_errors, last_error, received_at, central_acked_at FROM chunks WHERE recording_id = ? ORDER BY chunk_number", (str(recording_id),))
        return {"recording": rec, "chunks": chunks}

    @app.post("/v1/admin/retry", dependencies=[Depends(admin_ok)])
    async def admin_retry(body: RetryIn):
        """Returns quarantined/failed chunks to the queue (all, one recording, or one chunk). Safe to repeat."""
        where, params = "state IN (?, ?)", [QUARANTINED, FAILED_RETRY]
        if body.chunk_id:
            where, params = where + " AND chunk_id = ?", params + [str(body.chunk_id)]
        elif body.recording_id:
            where, params = where + " AND recording_id = ?", params + [str(body.recording_id)]
        n = await asyncio.to_thread(store.execute, f"UPDATE chunks SET state = ?, hard_errors = 0, next_attempt_at = 0, last_error = NULL WHERE {where}", [PENDING] + params)
        await asyncio.to_thread(store.execute, "UPDATE recordings SET central_registered = 0, last_error = NULL, complete_next_at = 0, complete_attempts = 0 WHERE central_completed = 0")
        fwd._paused_until = 0.0
        await asyncio.to_thread(store.audit, "admin_retry", affected=n)
        return {"requeued": n}

    @app.get("/v1/admin/audit", dependencies=[Depends(admin_ok)])
    async def admin_audit(limit: int = Query(default=100, ge=1, le=1000)):
        return {"items": await asyncio.to_thread(store.recent_audit, limit)}

    @app.get("/v1/admin/recordings/{recording_id}/chunks/{chunk_id}/stream", dependencies=[Depends(admin_ok)])
    async def admin_stream_chunk(recording_id: uuid.UUID, chunk_id: uuid.UUID):
        """DELAYED playback of a completed chunk stored here. This is NOT live video; it is what makes near-live viewing on the LAN possible."""
        row = await asyncio.to_thread(store.one, "SELECT * FROM chunks WHERE chunk_id = ? AND recording_id = ?", (str(chunk_id), str(recording_id)))
        if row is None or row["state"] == PURGED or not media.exists(row["storage_path"]):
            raise ApiError(404, "chunk_not_available", "The chunk is not available locally")
        await asyncio.to_thread(store.audit, "admin_chunk_access", chunk_id=str(chunk_id), recording_id=str(recording_id))

        def gen():
            with open(row["storage_path"], "rb") as fh:
                for piece in iter(lambda: fh.read(READ_SIZE), b""):
                    yield piece

        return StreamingResponse(gen(), media_type="video/mp4", headers={"Content-Length": str(row["size_bytes"])})

    @app.post("/v1/admin/live/viewer-token", dependencies=[Depends(admin_ok)])
    async def admin_viewer_token(room: str = Query(..., min_length=3, max_length=200)):
        if not (settings.local_livekit_url and settings.local_livekit_key and settings.local_livekit_secret):
            raise ApiError(404, "local_live_not_configured", "No site-local live service is configured")
        if not room.startswith(f"site-{settings.site_code}-"):
            raise ApiError(403, "room_not_allowed", "Only this site's rooms may be viewed")
        from livekit import api as lk_api

        token = (lk_api.AccessToken(settings.local_livekit_key, settings.local_livekit_secret).with_identity("site-viewer").with_name("site-viewer")
                 .with_grants(lk_api.VideoGrants(room_join=True, room=room, can_publish=False, can_subscribe=True)).with_ttl(datetime.timedelta(minutes=30)).to_jwt())
        await asyncio.to_thread(store.audit, "live_viewer_token_issued", room=room)
        return {"livekit_url": settings.local_livekit_url, "token": token, "room": room}

    @app.get("/v1/admin/capacity-estimate", dependencies=[Depends(admin_ok)])
    async def capacity_estimate(
        bitrate_kbps: int = Query(default=4000, ge=64, le=100000), devices: int = Query(default=10, ge=1, le=10000),
        recording_hours_per_device_per_day: float = Query(default=8, gt=0, le=24), outage_days: float = Query(default=3, gt=0, le=365),
    ):
        """Planning aid: bytes needed to hold every device's video for an outage of `outage_days` (+10% overhead). Replace the defaults with your real figures."""
        per_hour = bitrate_kbps * 1000 / 8 * 3600
        total = per_hour * recording_hours_per_device_per_day * devices * outage_days * 1.10
        return {"estimated_bytes": int(total), "estimated_gib": round(total / 1024 ** 3, 1), "per_device_per_day_gib": round(per_hour * recording_hours_per_device_per_day / 1024 ** 3, 2),
                "disk_total_gib": round(media.usage()["total"] / 1024 ** 3, 1), "disk_free_gib": round(media.usage()["free"] / 1024 ** 3, 1),
                "note": "Estimate only: real bitrate varies with scene and phone model. Keep RECEIVER_MIN_FREE_MB headroom."}

    return app


try:
    app = create_app()
except ConfigError as _exc:  # fail with a readable message instead of a stack trace
    print(f"receiver configuration error: {_exc}", file=sys.stderr)
    raise
