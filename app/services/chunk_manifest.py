"""
Phase 2 (body-camera system): reusable chunk-manifest / missing-chunk
detection logic, kept separate from app/routers/recordings.py so both the
manifest endpoint and the completion-validation logic use the exact same
definition of "missing" -- no duplicated/divergent logic.

DEFINITION OF "MISSING" (documented explicitly, not left implicit):
Given the set of chunk_numbers actually received for a recording, the
"contiguous missing set" is every integer in [1, highest_received] that is
NOT present in that set. Chunk numbering starts at 1 (chunk 0 is not
used -- the spec's own worked example numbers chunks 1..5).

This deliberately does NOT guess that chunks beyond the highest received
number are missing -- an actively-recording session that has only
uploaded chunks 1-4 so far has NOT "lost" chunk 5; chunk 5 simply hasn't
been created/uploaded yet. Missing-chunk detection only makes sense
relative to what has already been received (gaps within that range) or,
separately, once a recording is being finalized (see
routers/recordings.py::complete_recording for how that distinction is
actually used).
"""
from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass(frozen=True)
class ChunkManifestSummary:
    received_chunk_numbers: List[int]      # sorted ascending
    highest_received: Optional[int]
    contiguous_count: int                  # length of the unbroken 1..N run at the start
    missing_chunk_numbers: List[int]       # gaps within [1, highest_received]
    is_contiguous: bool                    # True iff no gaps at all (missing_chunk_numbers == [])


def summarize_chunks(chunk_numbers: List[int]) -> ChunkManifestSummary:
    if not chunk_numbers:
        return ChunkManifestSummary(
            received_chunk_numbers=[],
            highest_received=None,
            contiguous_count=0,
            missing_chunk_numbers=[],
            is_contiguous=True,  # vacuously true -- no chunks, no gaps to speak of
        )

    received: Set[int] = set(chunk_numbers)
    sorted_received = sorted(received)
    highest = sorted_received[-1]

    missing = [n for n in range(1, highest) if n not in received]

    contiguous_count = 0
    for n in range(1, highest + 1):
        if n in received:
            contiguous_count += 1
        else:
            break

    return ChunkManifestSummary(
        received_chunk_numbers=sorted_received,
        highest_received=highest,
        contiguous_count=contiguous_count,
        missing_chunk_numbers=missing,
        is_contiguous=(len(missing) == 0),
    )
