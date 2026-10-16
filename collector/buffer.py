"""
Durable local buffer (SQLite, standard library).

Everything an adapter produces is written here BEFORE any upload attempt, so a
backend or network outage, or a collector restart, loses nothing. Items are
forwarded oldest first and deleted only after the backend acknowledged them.
Replay is safe because every event carries a collector-unique event_id and the
backend treats a repeat as a duplicate.

If the buffer exceeds its cap, the OLDEST items are dropped and counted; the count
is reported to the backend in every heartbeat so the loss is visible, never silent.
Items the backend rejects as permanently invalid are moved to a bounded
quarantine table for inspection instead of blocking the queue forever.
"""
import json
import sqlite3
import threading
import time
from typing import List, Tuple


class Buffer:
    def __init__(self, path: str, max_items: int):
        self._max = max_items
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload TEXT NOT NULL, created REAL NOT NULL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, payload TEXT, reason TEXT, created REAL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)")

    def enqueue(self, kind: str, payload: dict) -> None:
        with self._lock:
            self._db.execute("INSERT INTO items (kind, payload, created) VALUES (?, ?, ?)", (kind, json.dumps(payload, separators=(",", ":")), time.time()))
            overflow = self._count_unlocked() - self._max
            if overflow > 0:
                self._db.execute("DELETE FROM items WHERE id IN (SELECT id FROM items ORDER BY id LIMIT ?)", (overflow,))
                self._db.execute("INSERT INTO meta (k, v) VALUES ('dropped', ?) ON CONFLICT(k) DO UPDATE SET v = v + ?", (overflow, overflow))

    def next_batch(self, limit: int) -> Tuple[str, List[Tuple[int, dict]]]:
        """
        The oldest items that share ONE kind (so a batch maps to one API call), in FIFO order. A run of events ends at the
        first item of a different kind, which keeps the overall order intact. Returns ("", []) when empty.
        """
        with self._lock:
            rows = self._db.execute("SELECT id, kind, payload FROM items ORDER BY id LIMIT ?", (limit,)).fetchall()
        if not rows:
            return "", []
        kind = rows[0][1]
        batch: List[Tuple[int, dict]] = []
        for item_id, row_kind, payload in rows:
            if row_kind != kind:
                break
            batch.append((item_id, json.loads(payload)))
        return kind, batch

    def delete(self, ids: List[int]) -> None:
        if not ids:
            return
        with self._lock:
            self._db.executemany("DELETE FROM items WHERE id = ?", [(i,) for i in ids])

    def quarantine(self, ids_payloads: List[Tuple[int, str, dict]], reason: str) -> None:
        with self._lock:
            for item_id, kind, payload in ids_payloads:
                self._db.execute("INSERT INTO quarantine (kind, payload, reason, created) VALUES (?, ?, ?, ?)", (kind, json.dumps(payload), reason[:200], time.time()))
                self._db.execute("DELETE FROM items WHERE id = ?", (item_id,))
            self._db.execute("DELETE FROM quarantine WHERE id IN (SELECT id FROM quarantine ORDER BY id DESC LIMIT -1 OFFSET 1000)")

    def _count_unlocked(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM items").fetchone()[0]

    def depth(self) -> int:
        with self._lock:
            return self._count_unlocked()

    def dropped(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT v FROM meta WHERE k = 'dropped'").fetchone()
            return int(row[0]) if row else 0

    def quarantined(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._db.close()
