"""
Durable file storage for received chunks.

Layout:   <storage_root>/<site_id>/<recording_id>/<chunk_id>.mp4        (final, immutable)
          <storage_root>/<site_id>/.tmp/<random>.part                   (in-flight uploads)

Rules:
  * Every path component is a UUID that was parsed and re-serialized, never client text, and the final path is
    additionally checked to lie inside the storage root (no path traversal).
  * A file is written to .tmp, flushed and fsynced, then atomically renamed into place (same filesystem) and the
    directory is fsynced where the OS supports it. Only then may the caller commit metadata and acknowledge.
  * Chunk files are never modified after they are in place. The "original evidence" is exactly this file.
  * Stale .tmp files from interrupted uploads are removed on start-up and periodically.
"""
import hashlib
import os
import shutil
import time
import uuid
from typing import Optional

TMP_DIRNAME = ".tmp"
STALE_TMP_SECONDS = 3600


class StorageFull(Exception):
    pass


class StagedUpload:
    """An upload being written. Use as: staged = storage.stage(); staged.write(b); staged.finalize(path) or staged.abort()."""

    def __init__(self, tmp_path: str):
        self.path = tmp_path
        self.size = 0
        self._hasher = hashlib.sha256()
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        self._fh = open(tmp_path, "wb")

    def write(self, data: bytes) -> None:
        self._hasher.update(data)
        self._fh.write(data)
        self.size += len(data)

    @property
    def sha256(self) -> str:
        return self._hasher.hexdigest()

    def finalize(self, final_path: str) -> None:
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        os.replace(self.path, final_path)
        _fsync_dir(os.path.dirname(final_path))

    def abort(self) -> None:
        try:
            self._fh.close()
        finally:
            try:
                os.remove(self.path)
            except OSError:
                pass


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return  # not supported on this platform/filesystem (e.g. Windows): best effort
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class MediaStorage:
    def __init__(self, root: str, site_id: uuid.UUID):
        self.root = os.path.abspath(root)
        self.site_dir = os.path.join(self.root, str(site_id))
        os.makedirs(self.site_dir, exist_ok=True)

    def chunk_path(self, recording_id: uuid.UUID, chunk_id: uuid.UUID, ext: str = ".mp4") -> str:
        path = os.path.abspath(os.path.join(self.site_dir, str(recording_id), f"{chunk_id}{ext}"))
        if os.path.commonpath([path, self.root]) != self.root:
            raise ValueError("path escapes the storage root")
        return path

    def stage(self) -> StagedUpload:
        return StagedUpload(os.path.join(self.site_dir, TMP_DIRNAME, f"{uuid.uuid4().hex}.part"))

    def free_bytes(self) -> int:
        return shutil.disk_usage(self.site_dir).free

    def usage(self) -> dict:
        du = shutil.disk_usage(self.site_dir)
        return {"total": du.total, "free": du.free, "used": du.used}

    def exists(self, path: str) -> bool:
        return os.path.isfile(path)

    def size(self, path: str) -> Optional[int]:
        try:
            return os.path.getsize(path)
        except OSError:
            return None

    def sha256_of(self, path: str) -> Optional[str]:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for piece in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(piece)
        except OSError:
            return None
        return h.hexdigest()

    def delete(self, path: str) -> bool:
        try:
            os.remove(path)
            return True
        except OSError:
            return False

    def quarantine_file(self, path: str) -> Optional[str]:
        """Moves a damaged file out of the evidence tree into `.quarantine/` (never deletes it). Returns the new path."""
        dest_dir = os.path.join(self.site_dir, ".quarantine", os.path.basename(os.path.dirname(path)))
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, f"{int(time.time())}_{os.path.basename(path)}")
        try:
            os.replace(path, dest)
        except OSError:
            return None
        return dest

    def clean_stale_tmp(self) -> int:
        tmp = os.path.join(self.site_dir, TMP_DIRNAME)
        removed = 0
        if not os.path.isdir(tmp):
            return 0
        cutoff = time.time() - STALE_TMP_SECONDS
        for name in os.listdir(tmp):
            p = os.path.join(tmp, name)
            try:
                if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
                    os.remove(p)
                    removed += 1
            except OSError:
                continue
        return removed
