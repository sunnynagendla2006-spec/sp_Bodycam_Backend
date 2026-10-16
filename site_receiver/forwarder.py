"""
Asynchronous, durable forwarding of stored chunks to the control room, independent of any phone connection.

    PENDING_SYNC -> SYNCING -> CENTRAL_ACKNOWLEDGED
                       |-> FAILED_RETRY (retryable, exponential back-off with jitter)
                       |-> QUARANTINED (conflict / permanent rejection / local corruption: a human decides)

FAILURE CLASSES (how a control-room answer is treated):
  * success            200 with an acknowledgement whose original_hash equals the local hash
  * retryable          network errors, 408/425/429 and EVERY 5xx (including 502/503/504 from a proxy during an outage).
                       Retried with durable exponential back-off + jitter, honouring Retry-After. Never quarantines, however long
                       the outage lasts: a chunk is evidence, and the control room being down says nothing about the chunk.
  * credential         401/403 without a policy reason: forwarding pauses, nothing is consumed (the operator must fix the credential)
  * integrity          hash_mismatch (bytes damaged in transit) is retried; a local file that no longer matches its hash is quarantined
  * policy / validation hash_conflict, grant_*, unsupported_type, other 400/413/422, 409 conflicts: quarantined for a person to decide
  Operator intervention is needed only for quarantined chunks and for a credential problem; the dashboard shows both.

Safety properties:
  * The local file is the original evidence. It is verified (size + SHA-256) before every forward attempt; a mismatch
    quarantines the chunk instead of sending damaged bytes.
  * The control room acknowledges only after it has stored identical content; the receiver marks `central_acknowledged`
    only for a 200 response whose `original_hash` equals the local hash.
  * A restart loses nothing: chunks left `syncing` return to the queue (Store.recover_after_restart).
  * A network failure never counts toward quarantine; only server-side/content problems do (RECEIVER_MAX_HARD_ERRORS).
  * 401/403 from the control room PAUSES forwarding (credential problem) without consuming retries, EXCEPT grant-related
    403s (grant_revoked, grant_window, ...) which quarantine that recording: the control room refused the evidence's authority.
  * Local files are deleted only after central acknowledgement and only under the retention policy.
"""
import asyncio
import datetime
import logging
import random
import time
from typing import Any, Dict, List, Optional

import httpx

from . import __version__
from .config import Settings
from .store import ACKED, FAILED_RETRY, PENDING, PURGED, QUARANTINED, SYNCING, Store, now_iso
from .storage import MediaStorage

log = logging.getLogger("receiver.forward")

_QUARANTINE_REASONS = {"hash_conflict", "recording_id_conflict", "recording_cancelled", "unsupported_type", "grant_required", "grant_mismatch", "grant_window", "grant_revoked"}


class Forwarder:
    def __init__(self, settings: Settings, store: Store, media: MediaStorage):
        self.s, self.store, self.media = settings, store, media
        self.stop_event = asyncio.Event()
        self.central_reachable: Optional[bool] = None
        self.last_central_ack_at: Optional[str] = None
        self._paused_until = 0.0
        self._done_commands: List[str] = []
        self._reg_locks: Dict[str, asyncio.Lock] = {}
        self._client: Optional[httpx.AsyncClient] = None
        self.last_local_upload_at: Optional[str] = None

    # ---- plumbing ----------------------------------------------------------
    @property
    def configured(self) -> bool:
        return bool(self.s.central_url and self.s.central_token)

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            verify = self.s.central_ca_file or True
            self._client = httpx.AsyncClient(base_url=self.s.central_url, verify=verify, timeout=httpx.Timeout(60.0, connect=10.0),
                                             headers={"Authorization": f"Bearer {self.s.central_token}", "User-Agent": f"sp-site-receiver/{__version__}"})
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    def _backoff(self, attempts: int) -> float:
        delay = min(self.s.backoff_max, self.s.backoff_base * (2 ** min(attempts, 12)))
        return delay * (0.8 + 0.4 * random.random())

    async def run(self) -> None:
        await asyncio.gather(self._forward_loop(), self._heartbeat_loop(), self._maintenance_loop())

    def stop(self) -> None:
        self.stop_event.set()

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    # ---- forwarding loop -----------------------------------------------------
    async def _forward_loop(self) -> None:
        sem = asyncio.Semaphore(self.s.forward_concurrency)
        while not self.stop_event.is_set():
            try:
                if not self.configured or time.time() < self._paused_until:
                    await self._sleep(5)
                    continue
                rows = await asyncio.to_thread(
                    self.store.query,
                    "SELECT * FROM chunks WHERE state IN (?, ?) AND next_attempt_at <= ? ORDER BY received_at LIMIT ?",
                    (PENDING, FAILED_RETRY, time.time(), self.s.forward_concurrency * 4),
                )
                if rows:
                    async def guarded(r):
                        async with sem:
                            await self._process_chunk(r)
                    await asyncio.gather(*(guarded(r) for r in rows))
                await self._finish_recordings()
                await self._sleep(0.5 if rows else 3)
            except Exception:
                log.exception("forwarding loop error")
                await self._sleep(5)

    async def _set_state(self, chunk_id: str, state: str, *, error: Optional[str] = None, retry_in: Optional[float] = None, hard: bool = False) -> None:
        sets, params = ["state = ?", "last_error = ?"], [state, error]
        if retry_in is not None:
            sets.append("next_attempt_at = ?")
            params.append(time.time() + retry_in)
        if hard:
            sets.append("hard_errors = hard_errors + 1")
        params.append(chunk_id)
        await asyncio.to_thread(self.store.execute, f"UPDATE chunks SET {', '.join(sets)} WHERE chunk_id = ?", params)

    async def _quarantine(self, row: Dict[str, Any], reason: str) -> None:
        await self._set_state(row["chunk_id"], QUARANTINED, error=reason[:200])
        await asyncio.to_thread(self.store.audit, "chunk_quarantined", chunk_id=row["chunk_id"], recording_id=row["recording_id"], reason=reason[:200])
        log.error("chunk quarantined", extra={"chunk_id": row["chunk_id"], "reason": reason})

    async def _soft_fail(self, row: Dict[str, Any], error: str, *, hard: bool, retry_after: Optional[float] = None) -> None:
        attempts = row["attempts"] + 1
        hard_errors = row["hard_errors"] + (1 if hard else 0)
        if hard and hard_errors >= self.s.max_hard_errors:
            await self._quarantine(row, f"gave up after {hard_errors} failed attempts: {error}")
            return
        await self._set_state(row["chunk_id"], FAILED_RETRY, error=error[:200], retry_in=retry_after or self._backoff(attempts), hard=hard)
        await asyncio.to_thread(self.store.audit, "forward_failed", chunk_id=row["chunk_id"], error=error[:200], hard=hard)

    async def _ensure_registered(self, rec: Dict[str, Any]) -> Optional[str]:
        """Returns None when the recording is registered centrally, otherwise a short reason string."""
        if rec["central_registered"]:
            return None
        lock = self._reg_locks.setdefault(rec["recording_id"], asyncio.Lock())
        async with lock:
            fresh = await asyncio.to_thread(self.store.one, "SELECT * FROM recordings WHERE recording_id = ?", (rec["recording_id"],))
            if fresh and fresh["central_registered"]:
                return None
            body = {
                "site_id": str(self.s.site_id), "constable_id": rec["constable_id"], "device_id": rec["device_id"], "grant_id": rec["grant_id"],
                "trigger_type": rec["trigger_type"] or "manual", "camera_lens_direction": rec["camera"] or "back", "started_at": rec["started_at"],
                "ended_at": rec["ended_at"], "status": "completed" if rec["status"] == "completed" else "recording",
            }
            resp = await self._http().put(f"/receiver/v1/recordings/{rec['recording_id']}", json=body)
            if resp.status_code == 200:
                await asyncio.to_thread(self.store.execute, "UPDATE recordings SET central_registered = 1, last_error = NULL WHERE recording_id = ?", (rec["recording_id"],))
                await asyncio.to_thread(self.store.audit, "recording_registered_central", recording_id=rec["recording_id"])
                return None
            reason = resp.headers.get("x-conflict-reason", "")
            if resp.status_code in (403, 409) and reason in _QUARANTINE_REASONS:
                await asyncio.to_thread(self.store.execute, "UPDATE recordings SET last_error = ? WHERE recording_id = ?", (f"central refused: {reason}", rec["recording_id"]))
                await asyncio.to_thread(self.store.execute, "UPDATE chunks SET state = ?, last_error = ? WHERE recording_id = ? AND state IN (?, ?, ?)",
                                        (QUARANTINED, f"central refused the recording: {reason}", rec["recording_id"], PENDING, FAILED_RETRY, SYNCING))
                await asyncio.to_thread(self.store.audit, "recording_refused_central", recording_id=rec["recording_id"], reason=reason)
                return f"refused:{reason}"
            if resp.status_code in (401, 403):
                self._paused_until = time.time() + 60
                return "central_auth"
            return f"http_{resp.status_code}"

    async def _process_chunk(self, row: Dict[str, Any]) -> None:
        claimed = await asyncio.to_thread(
            self.store.execute, "UPDATE chunks SET state = ?, last_attempt_at = ?, attempts = attempts + 1 WHERE chunk_id = ? AND state IN (?, ?)",
            (SYNCING, now_iso(), row["chunk_id"], PENDING, FAILED_RETRY),
        )
        if not claimed:
            return
        path = row["storage_path"]
        size = self.media.size(path)
        if size is None:
            await self._quarantine(row, "local file is missing")
            return
        if size != row["size_bytes"]:
            await self._quarantine(row, "local file size differs from the stored size")
            return
        actual = await asyncio.to_thread(self.media.sha256_of, path)
        if actual != row["sha256"]:
            await self._quarantine(row, "local file no longer matches its SHA-256 (disk corruption?)")
            return
        rec = await asyncio.to_thread(self.store.one, "SELECT * FROM recordings WHERE recording_id = ?", (row["recording_id"],))
        if rec is None:
            await self._quarantine(row, "recording record is missing")
            return
        try:
            problem = await self._ensure_registered(rec)
            if problem:
                if problem.startswith("refused:"):
                    return  # chunks already quarantined by the registration refusal
                self.central_reachable = True
                await self._soft_fail(row, f"recording not registered centrally ({problem})", hard=False)
                return
            with open(path, "rb") as fh:
                resp = await self._http().put(
                    f"/receiver/v1/recordings/{row['recording_id']}/chunks/{row['chunk_id']}",
                    data={
                        "chunk_number": str(row["chunk_number"]), "sha256": row["sha256"], "is_last_chunk": "true" if row["is_last"] else "false",
                        **({"duration_seconds": str(row["duration_seconds"])} if row["duration_seconds"] is not None else {}),
                        **({"latitude": str(row["latitude"])} if row["latitude"] is not None else {}),
                        **({"longitude": str(row["longitude"])} if row["longitude"] is not None else {}),
                        **({"captured_start": row["captured_start"]} if row["captured_start"] else {}),
                        **({"captured_end": row["captured_end"]} if row["captured_end"] else {}),
                        "site_received_at": row["received_at"],
                    },
                    files={"file": (f"{row['chunk_id']}.mp4", fh, row["mime"])},
                )
            self.central_reachable = True
        except (httpx.TransportError, httpx.TimeoutException, OSError) as exc:
            self.central_reachable = False
            await self._soft_fail(row, f"control room unreachable ({type(exc).__name__})", hard=False)
            return

        await self._handle_chunk_response(row, resp)

    async def _handle_chunk_response(self, row: Dict[str, Any], resp: httpx.Response) -> None:
        code = resp.status_code
        reason = resp.headers.get("x-conflict-reason", "")
        if code == 200:
            try:
                ack = resp.json()
            except ValueError:
                ack = {}
            if ack.get("original_hash") != row["sha256"]:
                await self._quarantine(row, "control room acknowledged different content than was sent")
                return
            now = now_iso()
            await asyncio.to_thread(self.store.execute, "UPDATE chunks SET state = ?, central_acked_at = ?, last_error = NULL WHERE chunk_id = ?", (ACKED, now, row["chunk_id"]))
            await asyncio.to_thread(self.store.audit, "chunk_central_ack", chunk_id=row["chunk_id"], recording_id=row["recording_id"], duplicate=bool(ack.get("duplicate")))
            self.last_central_ack_at = now
            return
        if code in (401, 403) and reason not in _QUARANTINE_REASONS:
            self._paused_until = time.time() + 60
            await self._set_state(row["chunk_id"], PENDING, error="control room rejected the receiver credential; forwarding paused", retry_in=60)
            await asyncio.to_thread(self.store.audit, "central_auth_failed", status=code)
            return
        if reason in _QUARANTINE_REASONS or code in (400, 413):
            await self._quarantine(row, f"control room refused the chunk (HTTP {code} {reason})")
            return
        if code == 404:
            await asyncio.to_thread(self.store.execute, "UPDATE recordings SET central_registered = 0 WHERE recording_id = ?", (row["recording_id"],))
            await self._soft_fail(row, "control room does not know the recording yet", hard=False)
            return
        if code == 422 and reason == "hash_mismatch":
            await self._soft_fail(row, "control room received damaged bytes (hash mismatch in transit); retrying", hard=False)
            return
        if code == 422:
            await self._quarantine(row, f"control room rejected the chunk as invalid (HTTP 422 {reason})".strip())
            return
        if code in (408, 425, 429) or 500 <= code <= 599:
            # Control room or proxy unavailable/overloaded: retry forever with back-off; this is NOT a problem with the chunk.
            await self._soft_fail(row, f"control room unavailable or busy (HTTP {code})", hard=False, retry_after=self._retry_after(resp))
            return
        await self._soft_fail(row, f"control room returned HTTP {code} {reason}".strip(), hard=True)

    def _retry_after(self, resp: httpx.Response) -> Optional[float]:
        try:
            return min(float(self.s.backoff_max), max(1.0, float(resp.headers.get("retry-after", ""))))
        except ValueError:
            return None

    # ---- recordings: completion -----------------------------------------------
    async def _completion_later(self, rec: Dict[str, Any], seconds: float, message: str, *, count_attempt: bool) -> None:
        """Durable schedule for the next completion attempt of a recording (survives restarts) plus a visible reason."""
        await asyncio.to_thread(
            self.store.execute, "UPDATE recordings SET complete_next_at = ?, complete_attempts = complete_attempts + ?, last_error = ? WHERE recording_id = ?",
            (time.time() + seconds, 1 if count_attempt else 0, message[:200], rec["recording_id"]))

    async def _finish_recordings(self) -> None:
        """Completes recordings centrally ONLY when every chunk is centrally confirmed. Own durable back-off, separate from chunk forwarding."""
        recs = await asyncio.to_thread(
            self.store.query, "SELECT * FROM recordings WHERE complete_requested = 1 AND central_completed = 0 AND complete_next_at <= ? LIMIT 20", (time.time(),))
        for rec in recs:
            stats = await asyncio.to_thread(
                self.store.one,
                "SELECT COUNT(*) AS total, COALESCE(SUM(state NOT IN (?, ?)), 0) AS outstanding, COALESCE(SUM(state = ?), 0) AS quarantined FROM chunks WHERE recording_id = ?",
                (ACKED, PURGED, QUARANTINED, rec["recording_id"]))
            if stats and stats["outstanding"] > 0:
                q = stats["quarantined"]
                await self._completion_later(rec, 60 if q else 15, f"completion waiting: {stats['outstanding']} chunk(s) not centrally confirmed" + (f", {q} quarantined (operator action needed)" if q else ""), count_attempt=False)
                continue
            try:
                problem = await self._ensure_registered(rec)
                if problem:
                    await self._completion_later(rec, self._backoff(rec["complete_attempts"] + 1), f"completion waiting: recording not registered centrally ({problem})", count_attempt=True)
                    continue
                total = stats["total"] if stats else 0
                resp = await self._http().post(f"/receiver/v1/recordings/{rec['recording_id']}/complete", json={"ended_at": rec["ended_at"], "chunk_count": rec["expected_chunks"] or total})
            except (httpx.TransportError, httpx.TimeoutException, OSError):
                self.central_reachable = False
                await self._completion_later(rec, self._backoff(rec["complete_attempts"] + 1), "completion waiting: control room unreachable", count_attempt=True)
                return
            if resp.status_code == 200:
                await asyncio.to_thread(self.store.execute, "UPDATE recordings SET central_completed = 1, last_error = NULL WHERE recording_id = ?", (rec["recording_id"],))
                await asyncio.to_thread(self.store.audit, "recording_completed_central", recording_id=rec["recording_id"], missing=(resp.json().get("missing_chunk_numbers") if resp.headers.get("content-type", "").startswith("application/json") else None))
            else:
                wait = self._retry_after(resp) or self._backoff(rec["complete_attempts"] + 1)
                await self._completion_later(rec, wait, f"completion refused by control room (HTTP {resp.status_code} {resp.headers.get('x-conflict-reason', '')})".strip(), count_attempt=True)

    # ---- heartbeat + sync ----------------------------------------------------------
    async def _heartbeat_loop(self) -> None:
        while not self.stop_event.is_set():
            if self.configured:
                try:
                    await self._heartbeat_and_sync()
                except (httpx.TransportError, httpx.TimeoutException, OSError):
                    self.central_reachable = False
                except Exception:
                    log.exception("heartbeat error")
            await self._sleep(self.s.heartbeat_seconds)

    def capacity(self) -> Dict[str, Any]:
        u = self.media.usage()
        return {"total": u["total"], "free": u["free"], "accepting": u["free"] >= self.s.min_free_bytes}

    def snapshot(self) -> Dict[str, Any]:
        counts = self.store.counts()
        cap = self.capacity()
        # Derived from durable state so a restart does not erase them (and nothing is invented when there is no data).
        latest = self.store.one("SELECT MAX(central_acked_at) AS ack, MAX(received_at) AS rcv FROM chunks") or {}
        self.last_central_ack_at = latest.get("ack") or self.last_central_ack_at
        self.last_local_upload_at = latest.get("rcv") or self.last_local_upload_at
        return {
            "version": __version__, "capabilities": ["chunk_ingest", "offline_grants", "forwarding"] + (["local_live"] if self.s.local_livekit_url else []),
            "disk_total_bytes": cap["total"], "disk_free_bytes": cap["free"], "min_free_bytes": self.s.min_free_bytes, "accepting_uploads": cap["accepting"],
            "pending_chunks": counts[PENDING] + counts[FAILED_RETRY], "syncing_chunks": counts[SYNCING], "quarantined_chunks": counts[QUARANTINED],
            "received_chunks_total": sum(counts.values()), "last_local_upload_at": self.last_local_upload_at, "last_central_ack_at": self.last_central_ack_at,
            "local_recordings": self.store.local_recordings_summary(),
        }

    async def _heartbeat_and_sync(self) -> None:
        snap = await asyncio.to_thread(self.snapshot)
        failures = await asyncio.to_thread(
            self.store.query, "SELECT recording_id, chunk_id, state, last_error, last_attempt_at FROM chunks WHERE state IN (?, ?) ORDER BY last_attempt_at DESC LIMIT 20", (QUARANTINED, FAILED_RETRY))
        devices = await asyncio.to_thread(self.store.recent_devices)
        done = list(self._done_commands)
        body = {**snap, "site_code": self.s.site_code, "recent_devices": devices, "failures": failures, "completed_command_ids": done}
        resp = await self._http().post("/receiver/v1/heartbeat", json={k: v for k, v in body.items() if v is not None})
        if resp.status_code in (401, 403):
            self._paused_until = time.time() + 60
            await asyncio.to_thread(self.store.audit, "central_auth_failed", status=resp.status_code, where="heartbeat")
            return
        if resp.status_code != 200:
            return
        self.central_reachable = True
        self._done_commands = [c for c in self._done_commands if c not in done]
        sync = await self._http().get("/receiver/v1/sync")
        if sync.status_code == 200:
            data = sync.json()
            await asyncio.to_thread(self.store.replace_revoked, [str(g) for g in data.get("revoked_grant_ids", [])])
            for cmd in data.get("commands", []):
                await self._apply_command(cmd)

    async def _apply_command(self, cmd: Dict[str, Any]) -> None:
        cid, ctype = str(cmd.get("id")), cmd.get("type")
        if cid in self._done_commands:
            return
        if ctype == "retry_quarantined":
            n = await asyncio.to_thread(self.store.execute, "UPDATE chunks SET state = ?, hard_errors = 0, next_attempt_at = 0, last_error = NULL WHERE state = ?", (PENDING, QUARANTINED))
            await asyncio.to_thread(self.store.execute, "UPDATE recordings SET central_registered = 0, last_error = NULL, complete_next_at = 0, complete_attempts = 0 WHERE central_completed = 0")
        elif ctype == "resync":
            n = await asyncio.to_thread(self.store.execute, "UPDATE chunks SET next_attempt_at = 0 WHERE state = ?", (FAILED_RETRY,))
            await asyncio.to_thread(self.store.execute, "UPDATE recordings SET complete_next_at = 0 WHERE central_completed = 0")
            self._paused_until = 0.0
        elif ctype == "retry_recording" and cmd.get("recording_id"):
            n = await asyncio.to_thread(self.store.execute, "UPDATE chunks SET state = ?, hard_errors = 0, next_attempt_at = 0, last_error = NULL WHERE recording_id = ? AND state IN (?, ?)",
                                        (PENDING, str(cmd["recording_id"]), QUARANTINED, FAILED_RETRY))
            await asyncio.to_thread(self.store.execute, "UPDATE recordings SET central_registered = 0, last_error = NULL WHERE recording_id = ?", (str(cmd["recording_id"]),))
        else:
            n = 0
        await asyncio.to_thread(self.store.audit, "command_applied", command=ctype, affected=n)
        self._done_commands.append(cid)

    # ---- maintenance: retention and stale files ----------------------------------------
    async def _maintenance_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                await asyncio.to_thread(self.media.clean_stale_tmp)
                await asyncio.to_thread(self.purge_synced)
            except Exception:
                log.exception("maintenance error")
            await self._sleep(300)

    def purge_synced(self) -> int:
        """Deletes local files ONLY for chunks the control room has acknowledged, by age or (if enabled) to relieve low disk space."""
        purged = 0
        days = self.s.retention_after_sync_days
        candidates: List[Dict[str, Any]] = []
        if days == 0:
            # Documented policy: 0 = remove as soon as the control room has confirmed the chunk. Only ACKED rows qualify.
            candidates += self.store.query("SELECT chunk_id, storage_path FROM chunks WHERE state = ? LIMIT 500", (ACKED,))
        elif days > 0:
            cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat()
            candidates += self.store.query("SELECT chunk_id, storage_path FROM chunks WHERE state = ? AND central_acked_at < ? LIMIT 500", (ACKED, cutoff))
        if self.s.purge_synced_on_low_space and self.media.free_bytes() < self.s.min_free_bytes * 1.5:
            candidates += self.store.query("SELECT chunk_id, storage_path FROM chunks WHERE state = ? ORDER BY central_acked_at LIMIT 200", (ACKED,))
        seen = set()
        for c in candidates:
            if c["chunk_id"] in seen:
                continue
            seen.add(c["chunk_id"])
            self.media.delete(c["storage_path"])
            self.store.execute("UPDATE chunks SET state = ?, purged_at = ? WHERE chunk_id = ? AND state = ?", (PURGED, now_iso(), c["chunk_id"], ACKED))
            purged += 1
        if purged:
            self.store.audit("retention_purge", chunks=purged)
        return purged
