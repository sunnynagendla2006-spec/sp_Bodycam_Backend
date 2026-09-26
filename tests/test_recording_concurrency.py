"""
Genuine concurrent-request tests for chunk upload races (see
app/routers/recordings.py::upload_chunk). Same established pattern as
tests/test_device_concurrency.py, tests/test_dispatch_concurrency.py, and
tests/test_evidence_verification_concurrency.py -- concurrent asyncio
tasks sharing the same event loop/Motor client, `asyncio.Barrier` for a
genuine simultaneous start, calling the actual router functions directly
(not a reimplementation).

Needs a reachable MongoDB replica set (see tests/conftest.py's
requires_mongo / TEST_MONGODB_URL) -- skips otherwise.
"""
import asyncio
import io
import uuid as uuid_module

import pytest
from starlette.datastructures import UploadFile

from conftest import requires_mongo

pytestmark = [pytest.mark.concurrency, requires_mongo]

MP4_BYTES = b"\x00\x00\x00\x18ftypmp42" + (b"0123456789" * 20)


async def _setup_recording():
    """Creates a user+constable+device+recording session, returns (user, recording_id)."""
    from app import models
    from app.auth.security import hash_password
    from app.routers.devices import register_device
    from app.routers.recordings import start_recording
    import app.schemas as schemas

    user = models.User(
        phone=f"pgtest-rec-{uuid_module.uuid4().hex[:8]}",
        role=models.UserRole.constable,
        status=models.UserStatus.active,
        hashed_password=hash_password("pw"),
    )
    await user.insert()

    constable = models.Constable(user_id=user.id, badge_number=f"BADGE-REC-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
    await constable.insert()

    device_identifier = f"pgtest-rec-device-{uuid_module.uuid4().hex[:10]}"
    device_resp = await register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), user)

    session_resp = await start_recording(
        schemas.RecordingStartRequest(device_identifier=device_identifier, trigger_type=models.RecordingTriggerType.manual), user
    )
    return user, session_resp.id


# ---------------------------------------------------------------------------
# A. Concurrent duplicate chunk upload
# ---------------------------------------------------------------------------
async def test_concurrent_duplicate_chunk_upload_exactly_one_succeeds(mongo_db):
    from app import models
    from app.routers.recordings import upload_chunk
    from fastapi import HTTPException

    user, recording_id = await _setup_recording()
    barrier = asyncio.Barrier(2)

    async def attempt(key):
        upload_file = UploadFile(filename=f"chunk-{key}.mp4", file=io.BytesIO(MP4_BYTES))
        await barrier.wait()
        try:
            response = await upload_chunk(recording_id, 1, 2.5, False, None, None, None, upload_file, user)
            return key, ("succeeded", response.id)
        except HTTPException as exc:
            return key, (f"rejected_{exc.status_code}", None)

    outcomes = dict(await asyncio.gather(attempt("a"), attempt("b")))

    results = [outcomes["a"][0], outcomes["b"][0]]
    succeeded = [r for r in results if r == "succeeded"]
    rejected = [r for r in results if r.startswith("rejected_")]
    assert len(succeeded) == 1, f"Expected exactly one success: {outcomes}"
    assert len(rejected) == 1, f"Expected exactly one rejection: {outcomes}"
    assert rejected[0] == "rejected_409", f"Unexpected rejection status: {outcomes}"

    session = await models.RecordingSession.get(recording_id)
    matching = [c for c in session.chunks if c.chunk_number == 1]
    assert len(matching) == 1, f"Expected exactly one chunk, found {len(matching)}"


# ---------------------------------------------------------------------------
# B. Concurrent DIFFERENT chunk uploads
# ---------------------------------------------------------------------------
async def test_concurrent_different_chunk_uploads_both_succeed(mongo_db):
    from app import models
    from app.routers.recordings import upload_chunk

    user, recording_id = await _setup_recording()
    barrier = asyncio.Barrier(2)

    async def attempt(key, chunk_number):
        upload_file = UploadFile(filename=f"chunk-{chunk_number}.mp4", file=io.BytesIO(MP4_BYTES))
        await barrier.wait()
        try:
            response = await upload_chunk(recording_id, chunk_number, 2.5, False, None, None, None, upload_file, user)
            return key, ("succeeded", response.chunk_number)
        except Exception as exc:
            return key, (f"error: {exc}", None)

    outcomes = dict(await asyncio.gather(attempt("a", 3), attempt("b", 4)))

    assert outcomes["a"][0] == "succeeded", outcomes
    assert outcomes["b"][0] == "succeeded", outcomes

    session = await models.RecordingSession.get(recording_id)
    numbers = {c.chunk_number for c in session.chunks}
    assert numbers == {3, 4}


# ---------------------------------------------------------------------------
# C. Concurrent completion/upload race
# ---------------------------------------------------------------------------
async def test_concurrent_complete_and_chunk_upload_consistent_final_state(mongo_db):
    """
    One request completes the recording while another simultaneously
    uploads its final chunk. Whichever order they actually resolve in at
    the database level, the final state must be self-consistent: if the
    chunk upload committed before completion read the chunk list, it's
    correctly counted; if completion ran first, the chunk upload
    afterward correctly gets rejected with 409 (recording no longer
    'recording'). What must NEVER happen: a completed recording silently
    missing a chunk that was, in fact, successfully stored with no
    record of it, or a corrupted/ambiguous final status.
    """
    from app import models
    from app.routers.recordings import upload_chunk, complete_recording

    user, recording_id = await _setup_recording()

    # Chunk 1 already present so completion has SOMETHING to report on either way.
    upload_file = UploadFile(filename="chunk-1.mp4", file=io.BytesIO(MP4_BYTES))
    await upload_chunk(recording_id, 1, 2.5, False, None, None, None, upload_file, user)

    barrier = asyncio.Barrier(2)
    results = {}

    async def attempt_upload():
        upload_file = UploadFile(filename="chunk-2.mp4", file=io.BytesIO(MP4_BYTES))
        await barrier.wait()
        try:
            response = await upload_chunk(recording_id, 2, 2.5, True, None, None, None, upload_file, user)
            results["upload"] = ("succeeded", response.chunk_number)
        except Exception as exc:
            results["upload"] = (f"rejected: {exc}", None)

    async def attempt_complete():
        await barrier.wait()
        try:
            response = await complete_recording(recording_id, user)
            results["complete"] = ("succeeded", response.status, response.missing_chunk_numbers)
        except Exception as exc:
            results["complete"] = (f"error: {exc}", None, None)

    await asyncio.gather(attempt_upload(), attempt_complete())

    # complete_recording must always succeed exactly once here (it was
    # 'recording' when the race started, and only one lifecycle transition
    # is possible from that state in this scenario).
    assert results["complete"][0] == "succeeded", results

    final_session = await models.RecordingSession.get(recording_id)
    assert final_session.status == models.RecordingStatus.completed

    chunk_numbers = {c.chunk_number for c in final_session.chunks}
    # Whatever chunks actually got INTO the database, the completed
    # recording's own report must match reality: chunk 2 is either
    # genuinely present (upload won the race) or genuinely absent
    # (completion won, upload got a 409) -- never a mismatch between
    # what's stored and what the recording claims.
    if 2 in chunk_numbers:
        assert results["upload"][0] == "succeeded", f"Chunk 2 exists in DB but upload reported failure: {results}"
    else:
        assert results["upload"][0] != "succeeded", f"Chunk 2 missing from DB but upload reported success: {results}"
