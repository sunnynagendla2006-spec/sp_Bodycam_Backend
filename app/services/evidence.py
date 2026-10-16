"""
Evidence preservation helpers for recordings.

POLICY: the bytes exactly as captured by the phone are the SOURCE EVIDENCE. They are stored once under an
`original/` key and never rewritten. The control room may still produce a watermarked DERIVATIVE (the file the
dashboard plays); that derivative is a separate artifact with its own hash, recorded in `Chunk.processing` with the
input and output hashes, so custody is auditable. A SHA-256 proves a byte string did not change after it was
hashed; it does not by itself prove authenticity or capture time, so custody metadata (who uploaded, via which
receiver, which grant, when) is kept alongside it.

Set PRESERVE_ORIGINAL_EVIDENCE=false only to reproduce the previous behaviour (watermark replaces the upload in
place, so no pristine copy remains). It defaults to true.
"""
import datetime
import hashlib
import os
import re
from typing import Optional

from . import storage as storage_service

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def preserve_enabled() -> bool:
    return os.getenv("PRESERVE_ORIGINAL_EVIDENCE", "true").strip().lower() in ("1", "true", "yes")


def normalize_sha256(value: Optional[str]) -> Optional[str]:
    """Returns the lower-case hex digest, or raises ValueError for a malformed one. None passes through."""
    if value is None or not value.strip():
        return None
    v = value.strip().lower()
    if not _HASH_RE.match(v):
        raise ValueError("sha256 must be 64 hexadecimal characters")
    return v


def original_key_for(recording_id, chunk_number: int, ext: str, token: Optional[str] = None) -> str:
    """`token` makes the key unique to one ingest request, so a request that loses a race can only ever delete its own object."""
    suffix = f"_{token}" if token else ""
    return f"recordings/{recording_id}/original/chunk_{chunk_number:06d}{suffix}{ext}"


def preserve_original(storage: storage_service.EvidenceStorageBackend, storage_key: str, original_key: str) -> bool:
    """Copies the stored object to `original_key` (streamed, 1 MiB at a time). Returns True on success; never raises."""
    try:
        size = storage.get_size(storage_key)
        if not size:
            return False
        with storage.open_write(original_key) as out:
            for piece in storage.read_range(storage_key, 0, size - 1):
                out.write(piece)
        return True
    except Exception:
        try:
            storage.delete(original_key)
        except Exception:
            pass
        return False


def hash_stored(storage: storage_service.EvidenceStorageBackend, storage_key: str) -> Optional[str]:
    size = storage.get_size(storage_key)
    if not size:
        return None
    h = hashlib.sha256()
    for piece in storage.read_range(storage_key, 0, size - 1):
        h.update(piece)
    return h.hexdigest()


def provenance(step: str, tool: str, input_hash: Optional[str], output_hash: Optional[str], **extra) -> dict:
    return {
        "step": step, "tool": tool, "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "input_hash": input_hash, "output_hash": output_hash, **extra,
    }
