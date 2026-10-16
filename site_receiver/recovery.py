"""
Start-up recovery and single-instance protection for the site receiver.

A receiver owns its SQLite database and media directory exclusively. Two processes on the same files would corrupt
state (in-process locks and rate limits do not span processes), so a lock file next to the database is taken first
and held for the life of the process.

`reconcile()` repairs the disagreements a crash can leave between the metadata (SQLite) and the files:
  * a row whose file is missing or has the wrong size and that the control room has NOT confirmed -> quarantined
    with a reason (the phone still holds the chunk and may re-upload it: main.py heals the row when identical bytes
    arrive). Nothing is invented and nothing is acknowledged on its behalf.
  * a row already confirmed centrally whose file is gone (crash during retention) -> marked purged.
  * a file on disk with no row (crash after rename, before the metadata commit; such a chunk was NEVER acknowledged
    to the phone) -> moved aside to `.orphans/`, never deleted and never adopted: without metadata it cannot be
    attributed, and the phone will upload it again.
"""
import os
import shutil
import sys
import time
from typing import Dict

from .storage import MediaStorage, TMP_DIRNAME
from .store import ACKED, PURGED, QUARANTINED, Store, now_iso

ORPHAN_DIRNAME = ".orphans"


class AlreadyRunning(Exception):
    pass


class InstanceLock:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._fh = None

    def acquire(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fh = open(self.path, "a+")
        try:
            if sys.platform == "win32":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            raise AlreadyRunning(f"another receiver process already uses {self.path}; run exactly one receiver per database and storage root")
        fh.seek(0)
        fh.truncate()
        fh.write(str(os.getpid()))
        fh.flush()
        self._fh = fh

    def release(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None


def reconcile(store: Store, media: MediaStorage) -> Dict[str, int]:
    report = {"missing_quarantined": 0, "size_quarantined": 0, "marked_purged": 0, "orphans_moved": 0}
    rows = store.query("SELECT chunk_id, recording_id, storage_path, size_bytes, state FROM chunks WHERE state != ?", (PURGED,))
    known = set()
    for r in rows:
        known.add(os.path.abspath(r["storage_path"]))
        size = media.size(r["storage_path"])
        if r["state"] == ACKED:
            if size is None:
                store.execute("UPDATE chunks SET state = ?, purged_at = ? WHERE chunk_id = ? AND state = ?", (PURGED, now_iso(), r["chunk_id"], ACKED))
                report["marked_purged"] += 1
            continue
        if r["state"] == QUARANTINED:
            continue
        if size is None:
            store.execute("UPDATE chunks SET state = ?, last_error = ? WHERE chunk_id = ?", (QUARANTINED, "file missing after restart", r["chunk_id"]))
            store.audit("recovery_file_missing", chunk_id=r["chunk_id"], recording_id=r["recording_id"])
            report["missing_quarantined"] += 1
        elif size != r["size_bytes"]:
            store.execute("UPDATE chunks SET state = ?, last_error = ? WHERE chunk_id = ?", (QUARANTINED, "file size differs from the recorded size", r["chunk_id"]))
            store.audit("recovery_size_mismatch", chunk_id=r["chunk_id"], recording_id=r["recording_id"], expected=r["size_bytes"], actual=size)
            report["size_quarantined"] += 1

    # purged rows keep their (now absent) path out of the "known" set on purpose: a stray file there is an orphan too.
    orphan_root = os.path.join(media.site_dir, ORPHAN_DIRNAME)
    for dirpath, dirnames, filenames in os.walk(media.site_dir):
        dirnames[:] = [d for d in dirnames if d not in (TMP_DIRNAME, ORPHAN_DIRNAME, ".quarantine")]
        for name in filenames:
            full = os.path.abspath(os.path.join(dirpath, name))
            if full in known or not name.endswith(".mp4"):
                continue
            dest_dir = os.path.join(orphan_root, os.path.basename(dirpath))
            os.makedirs(dest_dir, exist_ok=True)
            dest = os.path.join(dest_dir, f"{int(time.time())}_{name}")
            try:
                shutil.move(full, dest)
            except OSError:
                continue
            store.audit("recovery_orphan_file_moved", name=name, to=os.path.relpath(dest, media.site_dir))
            report["orphans_moved"] += 1
    store.audit("recovery_finished", **report)
    return report
