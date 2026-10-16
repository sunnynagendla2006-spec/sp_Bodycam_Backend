"""
Durable metadata store (SQLite, standard library) for the site receiver.

Video bytes live in files (see storage.py); this database holds identity, integrity and synchronization state.
`synchronous=FULL` + WAL: a committed row survives power loss. A chunk row is written ONLY AFTER its file has been
fsynced and atomically renamed into place, and the acknowledgement is sent only AFTER the commit, so an
acknowledged chunk is always both on disk and recorded.

Chunk lifecycle (column `state`):
    (RECEIVING: the upload is in flight; nothing is stored or acknowledged yet)
    pending_sync        durable locally and acknowledged to the phone; waiting to be forwarded   (LOCALLY_DURABLE -> PENDING_SYNC)
    syncing             a forwarding attempt is in progress
    failed_retry        the last attempt failed in a retryable way; next attempt scheduled with back-off
    central_acknowledged the control room confirmed receipt of identical content
    quarantined         will not be retried automatically (conflict, permanent rejection, local corruption); needs a human
    purged              file deleted after central acknowledgement under the retention policy (metadata kept)
"""
import contextlib
import datetime
import json
import sqlite3
import threading
from typing import Any, Dict, Iterable, List, Optional

PENDING = "pending_sync"
SYNCING = "syncing"
FAILED_RETRY = "failed_retry"
ACKED = "central_acknowledged"
QUARANTINED = "quarantined"
PURGED = "purged"

SCHEMA = """
CREATE TABLE IF NOT EXISTS recordings (
  recording_id TEXT PRIMARY KEY, site_id TEXT NOT NULL, constable_id TEXT NOT NULL, device_id TEXT NOT NULL, device_identifier TEXT, grant_id TEXT,
  trigger_type TEXT, camera TEXT, started_at TEXT, ended_at TEXT, status TEXT NOT NULL DEFAULT 'recording',
  complete_requested INTEGER NOT NULL DEFAULT 0, expected_chunks INTEGER, central_registered INTEGER NOT NULL DEFAULT 0, central_completed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_error TEXT
);
CREATE TABLE IF NOT EXISTS chunks (
  chunk_id TEXT PRIMARY KEY, recording_id TEXT NOT NULL REFERENCES recordings(recording_id), chunk_number INTEGER NOT NULL,
  sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, mime TEXT NOT NULL, duration_seconds REAL, is_last INTEGER NOT NULL DEFAULT 0,
  latitude REAL, longitude REAL, captured_start TEXT, captured_end TEXT, storage_path TEXT NOT NULL, received_at TEXT NOT NULL,
  state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, hard_errors INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
  last_error TEXT, last_attempt_at TEXT, central_acked_at TEXT, purged_at TEXT,
  UNIQUE(recording_id, chunk_number)
);
CREATE INDEX IF NOT EXISTS idx_chunks_state ON chunks(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_chunks_recording ON chunks(recording_id);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, event TEXT NOT NULL, details TEXT);
CREATE TABLE IF NOT EXISTS revoked_grants (grant_id TEXT PRIMARY KEY, seen_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices_seen (device_identifier TEXT PRIMARY KEY, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Store:
    def __init__(self, path: str):
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Additive, idempotent column additions for databases created by an earlier version."""
        have = {r["name"] for r in self._db.execute("PRAGMA table_info(recordings)").fetchall()}
        for col, ddl in (("complete_attempts", "INTEGER NOT NULL DEFAULT 0"), ("complete_next_at", "REAL NOT NULL DEFAULT 0")):
            if col not in have:
                self._db.execute(f"ALTER TABLE recordings ADD COLUMN {col} {ddl}")

    def local_recordings_summary(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Recordings not yet fully confirmed centrally, newest first, as bounded summaries for the heartbeat."""
        return self.query(
            "SELECT r.recording_id, r.status, r.constable_id, r.device_identifier, r.started_at, r.created_at, r.expected_chunks, r.central_registered, r.central_completed, r.last_error, "
            "(SELECT COUNT(*) FROM chunks c WHERE c.recording_id = r.recording_id) AS chunks_received, "
            "(SELECT COUNT(*) FROM chunks c WHERE c.recording_id = r.recording_id AND c.state IN ('central_acknowledged', 'purged')) AS chunks_synced, "
            "(SELECT COUNT(*) FROM chunks c WHERE c.recording_id = r.recording_id AND c.state = 'quarantined') AS chunks_quarantined "
            "FROM recordings r WHERE r.central_completed = 0 OR EXISTS (SELECT 1 FROM chunks c WHERE c.recording_id = r.recording_id AND c.state NOT IN ('central_acknowledged', 'purged')) "
            "ORDER BY r.created_at DESC LIMIT ?", (limit,))

    # -- primitives ---------------------------------------------------------
    @contextlib.contextmanager
    def tx(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def query(self, sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, tuple(params)).fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self._lock:
            return self._db.execute(sql, tuple(params)).rowcount

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- audit ---------------------------------------------------------------
    def audit(self, event: str, **details: Any) -> None:
        """Structured custody/operations log. Never put tokens, grants or raw client identifiers in `details`."""
        self.execute("INSERT INTO audit (ts, event, details) VALUES (?, ?, ?)", (now_iso(), event, json.dumps(details, default=str)[:4000]))

    def recent_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.query("SELECT id, ts, event, details FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        for r in rows:
            try:
                r["details"] = json.loads(r["details"]) if r["details"] else {}
            except ValueError:
                r["details"] = {}
        return rows

    # -- kv -------------------------------------------------------------------
    def kv_get(self, key: str) -> Optional[str]:
        row = self.one("SELECT v FROM kv WHERE k = ?", (key,))
        return row["v"] if row else None

    def kv_set(self, key: str, value: str) -> None:
        self.execute("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (key, value))

    # -- grants / devices ---------------------------------------------------------
    def replace_revoked(self, grant_ids: List[str]) -> None:
        """The control room's list is authoritative for still-unexpired revoked grants; ids it no longer lists have expired."""
        with self.tx() as db:
            keep = set(grant_ids)
            db.execute("DELETE FROM revoked_grants WHERE grant_id NOT IN (%s)" % ",".join("?" * len(keep)) if keep else "DELETE FROM revoked_grants", tuple(keep))
            for gid in keep:
                db.execute("INSERT OR IGNORE INTO revoked_grants (grant_id, seen_at) VALUES (?, ?)", (gid, now_iso()))

    def is_revoked(self, grant_id: str) -> bool:
        return self.one("SELECT 1 FROM revoked_grants WHERE grant_id = ?", (grant_id,)) is not None

    def note_device(self, device_identifier: Optional[str]) -> None:
        if device_identifier:
            self.execute("INSERT INTO devices_seen (device_identifier, last_seen) VALUES (?, ?) ON CONFLICT(device_identifier) DO UPDATE SET last_seen = excluded.last_seen", (device_identifier[:128], now_iso()))

    def recent_devices(self, limit: int = 100) -> Dict[str, str]:
        return {r["device_identifier"]: r["last_seen"] for r in self.query("SELECT * FROM devices_seen ORDER BY last_seen DESC LIMIT ?", (limit,))}

    # -- stats ----------------------------------------------------------------------
    def counts(self) -> Dict[str, int]:
        out = {PENDING: 0, SYNCING: 0, FAILED_RETRY: 0, ACKED: 0, QUARANTINED: 0, PURGED: 0}
        for r in self.query("SELECT state, COUNT(*) AS n FROM chunks GROUP BY state"):
            out[r["state"]] = r["n"]
        return out

    def recover_after_restart(self) -> int:
        """Chunks left `syncing` by a crash go back to the queue. Returns how many."""
        return self.execute("UPDATE chunks SET state = ?, next_attempt_at = 0 WHERE state = ?", (PENDING, SYNCING))
