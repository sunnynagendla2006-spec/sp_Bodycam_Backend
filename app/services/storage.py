"""
Evidence storage abstraction.

`Evidence.storage_key` (e.g. "evidence/{incident_id}/{evidence_id}.mp4") is
the canonical, backend-agnostic identifier for a piece of evidence's bytes.
Everything above this module (routers, schemas, audit, events) deals only
in `storage_key` -- never in an absolute filesystem path or an S3 URI.
Swapping the backend is a one-line configuration change
(`EVIDENCE_STORAGE_BACKEND=s3`), not an API or schema change.

Two backends are provided:
  - LocalFilesystemStorage: the existing, fully working, tested backend
    (local disk under EVIDENCE_UPLOAD_ROOT). This is the default and the
    only one exercised by the test suite in this environment.
  - S3StorageBackend: a structurally-correct implementation using the
    standard boto3 API (put/head/get-with-Range/delete object), so the
    system is S3/MinIO-ready. boto3 is imported lazily (only when this
    backend is actually selected) so its absence never breaks local/dev
    usage, and it has NOT been exercised against a real S3/MinIO instance
    in this environment (none is available here) -- see the phase report.
"""
import abc
import os
import shutil
import logging
from typing import Iterator, Optional

logger = logging.getLogger("evidence_storage")

_READ_CHUNK_SIZE = 1024 * 1024  # 1 MiB -- never load a whole file into memory


class EvidenceStorageBackend(abc.ABC):
    """Common interface every evidence storage backend implements."""

    @abc.abstractmethod
    def open_write(self, storage_key: str):
        """
        Context manager yielding a binary writable file-like object for
        `storage_key`. On a `with` block that exits via an exception, the
        implementation must guarantee no partial object is left behind
        (see LocalFilesystemStorage/S3StorageBackend for how each backend
        satisfies this).
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, storage_key: str) -> None:
        """Delete the object if it exists. Never raises if it's already missing."""
        raise NotImplementedError

    @abc.abstractmethod
    def exists(self, storage_key: str) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def get_size(self, storage_key: str) -> Optional[int]:
        """Returns the object's size in bytes, or None if it doesn't exist."""
        raise NotImplementedError

    @abc.abstractmethod
    def read_range(self, storage_key: str, start: int, end: int) -> Iterator[bytes]:
        """
        Yields bytes for the inclusive byte range [start, end], in bounded
        chunks (never the whole object at once). Caller is responsible for
        validating start/end against the object's actual size first.
        """
        raise NotImplementedError


def _read_range_from_local_path(absolute_path: str, start: int, end: int) -> Iterator[bytes]:
    """
    Shared range-reading core used by LocalFilesystemStorage AND by
    media.py's legacy-`file_path`-only fallback (evidence rows that predate
    `storage_key` -- see media.py's _resolve_evidence_read_target). Reads
    in bounded chunks; never loads the whole file into memory regardless
    of how large the requested range is.
    """
    remaining = end - start + 1
    with open(absolute_path, "rb") as f:
        f.seek(start)
        while remaining > 0:
            chunk = f.read(min(_READ_CHUNK_SIZE, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk


class LocalFilesystemStorage(EvidenceStorageBackend):
    """
    The existing, working backend: evidence bytes live under `root` at a
    path equal to `storage_key` (e.g.
    "{root}/evidence/{incident_id}/{evidence_id}.mp4"). `storage_key`
    components are always server-generated UUIDs (see media.py's
    _build_storage_key), so joining them onto `root` can never escape it --
    there is no user-controlled path segment anywhere in this join.
    """

    def __init__(self, root: str):
        self.root = root
        os.makedirs(self.root, exist_ok=True)

    def _abs_path(self, storage_key: str) -> str:
        return os.path.join(self.root, storage_key)

    def open_write(self, storage_key: str):
        abs_path = self._abs_path(storage_key)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        return open(abs_path, "wb")

    def delete(self, storage_key: str) -> None:
        abs_path = self._abs_path(storage_key)
        try:
            if os.path.exists(abs_path):
                os.remove(abs_path)
        except OSError as exc:
            # Cleanup failures must never be swallowed silently -- log
            # loudly so an orphaned file on disk is at least discoverable,
            # even though we don't want a cleanup failure to mask the
            # original error that triggered it (see media.py callers).
            logger.error("Failed to delete evidence object storage_key=%s path=%s: %s", storage_key, abs_path, exc)

    def exists(self, storage_key: str) -> bool:
        return os.path.exists(self._abs_path(storage_key))

    def get_size(self, storage_key: str) -> Optional[int]:
        abs_path = self._abs_path(storage_key)
        if not os.path.exists(abs_path):
            return None
        return os.path.getsize(abs_path)

    def read_range(self, storage_key: str, start: int, end: int) -> Iterator[bytes]:
        yield from _read_range_from_local_path(self._abs_path(storage_key), start, end)


class S3StorageBackend(EvidenceStorageBackend):
    """
    S3/MinIO-compatible backend using boto3's standard object API.
    `EVIDENCE_S3_ENDPOINT_URL` (optional; set this for MinIO or any
    S3-compatible endpoint that isn't AWS itself) and `EVIDENCE_S3_BUCKET`
    (required) configure it.

    NOT exercised against a live S3/MinIO instance in this environment --
    no such service is available here. boto3 is imported lazily in
    __init__ specifically so this class can exist (and be unit-testable in
    isolation, e.g. with a mocked client) without requiring boto3 to be
    installed at all for the local-filesystem-only default path most
    deployments and all current tests use.
    """

    def __init__(self, bucket: str, endpoint_url: Optional[str] = None, client=None):
        self.bucket = bucket
        if client is not None:
            self.client = client
        else:
            import boto3  # lazy import -- see class docstring
            self.client = boto3.client("s3", endpoint_url=endpoint_url)

    def open_write(self, storage_key: str):
        """
        S3 has no simple incremental-append API without multipart upload
        complexity, and evidence uploads here are already bounded by
        MAX_EVIDENCE_SIZE_MB. So this buffers to a local temp file during
        the `with` block, then uploads it as a single object on a clean
        exit -- and deletes the temp file whether the upload succeeded,
        failed, or the `with` block raised, so nothing is left behind
        either locally or (on a genuine failure) in S3.
        """
        import tempfile
        from contextlib import contextmanager

        @contextmanager
        def _writer():
            tmp = tempfile.NamedTemporaryFile(delete=False)
            try:
                yield tmp
                tmp.flush()
                tmp.close()
                self.client.upload_file(tmp.name, self.bucket, storage_key)
            finally:
                try:
                    if not tmp.closed:
                        tmp.close()
                    os.remove(tmp.name)
                except OSError as exc:
                    logger.error("Failed to remove temp upload buffer %s: %s", tmp.name, exc)

        return _writer()

    def delete(self, storage_key: str) -> None:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=storage_key)
        except Exception as exc:
            logger.error("Failed to delete S3 object storage_key=%s: %s", storage_key, exc)

    def exists(self, storage_key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=storage_key)
            return True
        except Exception:
            return False

    def get_size(self, storage_key: str) -> Optional[int]:
        try:
            resp = self.client.head_object(Bucket=self.bucket, Key=storage_key)
            return resp["ContentLength"]
        except Exception:
            return None

    def read_range(self, storage_key: str, start: int, end: int) -> Iterator[bytes]:
        resp = self.client.get_object(Bucket=self.bucket, Key=storage_key, Range=f"bytes={start}-{end}")
        body = resp["Body"]
        while True:
            chunk = body.read(_READ_CHUNK_SIZE)
            if not chunk:
                break
            yield chunk


def get_storage_backend() -> EvidenceStorageBackend:
    """
    Selects the backend from environment configuration. Defaults to the
    local filesystem backend (unchanged from before this phase) unless
    EVIDENCE_STORAGE_BACKEND=s3 is explicitly set, in which case
    EVIDENCE_S3_BUCKET is required.
    """
    backend_name = os.getenv("EVIDENCE_STORAGE_BACKEND", "local").lower()
    if backend_name == "s3":
        bucket = os.getenv("EVIDENCE_S3_BUCKET")
        if not bucket:
            raise RuntimeError("EVIDENCE_STORAGE_BACKEND=s3 requires EVIDENCE_S3_BUCKET to be set")
        return S3StorageBackend(bucket=bucket, endpoint_url=os.getenv("EVIDENCE_S3_ENDPOINT_URL"))
    root = os.getenv("EVIDENCE_UPLOAD_ROOT", "/app/uploads")
    return LocalFilesystemStorage(root=root)
