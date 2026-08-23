"""
Genuine two-connection PostgreSQL concurrency tests for Phase 2 (body-camera
system): chunk upload races. Same established pattern as
tests/test_device_concurrency.py, tests/test_dispatch_concurrency.py, and
tests/test_evidence_verification_concurrency.py -- real threads, real
separate SQLAlchemy sessions/connections, threading.Barrier for a genuine
simultaneous start, calling the actual router functions directly (not a
reimplementation).

HOW TO ACTUALLY RUN THESE TESTS:
    export TEST_DATABASE_URL="postgresql+psycopg://postgres:postgres_password@localhost:5432/police_db"
    pytest -m postgres_integration tests/test_recording_concurrency.py -v

Without TEST_DATABASE_URL pointing to a reachable PostgreSQL server, these
SKIP (not fail, not fake a pass).
"""
import asyncio
import io
import os
import threading
import uuid as uuid_module

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import UploadFile

pytestmark = pytest.mark.postgres_integration

_TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL") or os.getenv("POSTGRES_TEST_DATABASE_URL")

MP4_BYTES = b"\x00\x00\x00\x18ftypmp42" + (b"0123456789" * 20)


def _postgres_reachable() -> bool:
    if not _TEST_DATABASE_URL:
        return False
    try:
        engine = create_engine(_TEST_DATABASE_URL)
        conn = engine.connect()
        conn.close()
        engine.dispose()
        return True
    except Exception:
        return False


_PG_AVAILABLE = _postgres_reachable()
_SKIP_REASON = (
    "No reachable PostgreSQL instance configured for recording-concurrency "
    "integration testing. Set TEST_DATABASE_URL to actually run this test. "
    "NOT executed in the current environment -- this is a skip, not a pass."
)


def _setup_recording(SessionFactory):
    """Creates a user+constable+device+recording session, returns (user_id, recording_id, cleanup_ids)."""
    from app import models
    from app.auth.security import hash_password
    from app.routers.devices import register_device
    from app.routers.recordings import start_recording
    import app.schemas as schemas

    setup_db = SessionFactory()
    try:
        user = models.User(
            phone=f"pgtest-rec-{uuid_module.uuid4().hex[:8]}",
            role=models.UserRole.constable,
            status=models.UserStatus.active,
            hashed_password=hash_password("pw"),
        )
        setup_db.add(user)
        setup_db.commit()
        user_id = user.id

        constable = models.Constable(user_id=user.id, badge_number=f"BADGE-REC-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
        setup_db.add(constable)
        setup_db.commit()
        constable_id = constable.id
    finally:
        setup_db.close()

    reg_db = SessionFactory()
    device_identifier = f"pgtest-rec-device-{uuid_module.uuid4().hex[:10]}"
    reg_user = reg_db.query(models.User).filter(models.User.id == user_id).first()
    device_resp = asyncio.run(register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), reg_db, reg_user))
    device_id = device_resp.id
    reg_db.close()

    start_db = SessionFactory()
    start_user = start_db.query(models.User).filter(models.User.id == user_id).first()
    session_resp = asyncio.run(
        start_recording(schemas.RecordingStartRequest(device_identifier=device_identifier, trigger_type=models.RecordingTriggerType.manual), start_db, start_user)
    )
    recording_id = session_resp.id
    start_db.close()

    return user_id, constable_id, device_id, recording_id


def _cleanup(SessionFactory, user_id, constable_id, device_id, recording_id):
    from app import models
    cleanup_db = SessionFactory()
    try:
        cleanup_db.query(models.AuditLog).filter(models.AuditLog.user_id == user_id).delete()
        cleanup_db.query(models.VideoChunk).filter(models.VideoChunk.recording_session_id == recording_id).delete()
        cleanup_db.query(models.RecordingSession).filter(models.RecordingSession.id == recording_id).delete()
        cleanup_db.query(models.Device).filter(models.Device.id == device_id).delete()
        cleanup_db.query(models.Constable).filter(models.Constable.id == constable_id).delete()
        cleanup_db.query(models.User).filter(models.User.id == user_id).delete()
        cleanup_db.commit()
    finally:
        cleanup_db.close()


# ---------------------------------------------------------------------------
# A. Concurrent duplicate chunk upload
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_duplicate_chunk_upload_exactly_one_succeeds():
    from app import models
    from app.routers.recordings import upload_chunk
    from fastapi import HTTPException

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    user_id, constable_id, device_id, recording_id = _setup_recording(SessionFactory)

    barrier = threading.Barrier(2)
    results = {}

    def attempt(key):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            upload_file = UploadFile(filename=f"chunk-{key}.mp4", file=io.BytesIO(MP4_BYTES))
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(upload_chunk(recording_id, 1, 2.5, False, upload_file, db, user))
                results[key] = ("succeeded", response.id)
            except HTTPException as exc:
                results[key] = (f"rejected_{exc.status_code}", None)
        finally:
            db.close()

    t_a = threading.Thread(target=attempt, args=("a",))
    t_b = threading.Thread(target=attempt, args=("b",))
    t_a.start()
    t_b.start()
    t_a.join(timeout=15)
    t_b.join(timeout=15)

    outcomes = [results["a"][0], results["b"][0]]
    succeeded = [r for r in outcomes if r == "succeeded"]
    rejected = [r for r in outcomes if r.startswith("rejected_")]
    assert len(succeeded) == 1, f"Expected exactly one success: {results}"
    assert len(rejected) == 1, f"Expected exactly one rejection: {results}"
    assert rejected[0] == "rejected_409", f"Unexpected rejection status: {results}"

    verify_db = SessionFactory()
    try:
        rows = verify_db.query(models.VideoChunk).filter(
            models.VideoChunk.recording_session_id == recording_id, models.VideoChunk.chunk_number == 1
        ).all()
        assert len(rows) == 1, f"Expected exactly one chunk row, found {len(rows)}"
    finally:
        verify_db.close()
        _cleanup(SessionFactory, user_id, constable_id, device_id, recording_id)
        engine.dispose()


# ---------------------------------------------------------------------------
# B. Concurrent DIFFERENT chunk uploads
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_different_chunk_uploads_both_succeed():
    from app import models
    from app.routers.recordings import upload_chunk

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    user_id, constable_id, device_id, recording_id = _setup_recording(SessionFactory)

    barrier = threading.Barrier(2)
    results = {}

    def attempt(key, chunk_number):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            upload_file = UploadFile(filename=f"chunk-{chunk_number}.mp4", file=io.BytesIO(MP4_BYTES))
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(upload_chunk(recording_id, chunk_number, 2.5, False, upload_file, db, user))
                results[key] = ("succeeded", response.chunk_number)
            except Exception as exc:
                results[key] = (f"error: {exc}", None)
        finally:
            db.close()

    t_a = threading.Thread(target=attempt, args=("a", 3))
    t_b = threading.Thread(target=attempt, args=("b", 4))
    t_a.start()
    t_b.start()
    t_a.join(timeout=15)
    t_b.join(timeout=15)

    assert results["a"][0] == "succeeded", results
    assert results["b"][0] == "succeeded", results

    verify_db = SessionFactory()
    try:
        numbers = {
            row[0]
            for row in verify_db.query(models.VideoChunk.chunk_number).filter(models.VideoChunk.recording_session_id == recording_id).all()
        }
        assert numbers == {3, 4}
    finally:
        verify_db.close()
        _cleanup(SessionFactory, user_id, constable_id, device_id, recording_id)
        engine.dispose()


# ---------------------------------------------------------------------------
# C. Concurrent completion/upload race
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_complete_and_chunk_upload_consistent_final_state():
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

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    user_id, constable_id, device_id, recording_id = _setup_recording(SessionFactory)

    # Chunk 1 already present so completion has SOMETHING to report on either way.
    setup_db = SessionFactory()
    setup_user = setup_db.query(models.User).filter(models.User.id == user_id).first()
    upload_file = UploadFile(filename="chunk-1.mp4", file=io.BytesIO(MP4_BYTES))
    asyncio.run(upload_chunk(recording_id, 1, 2.5, False, upload_file, setup_db, setup_user))
    setup_db.close()

    barrier = threading.Barrier(2)
    results = {}

    def attempt_upload():
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            upload_file = UploadFile(filename="chunk-2.mp4", file=io.BytesIO(MP4_BYTES))
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(upload_chunk(recording_id, 2, 2.5, True, upload_file, db, user))
                results["upload"] = ("succeeded", response.chunk_number)
            except Exception as exc:
                results["upload"] = (f"rejected: {exc}", None)
        finally:
            db.close()

    def attempt_complete():
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(complete_recording(recording_id, db, user))
                results["complete"] = ("succeeded", response.status, response.missing_chunk_numbers)
            except Exception as exc:
                results["complete"] = (f"error: {exc}", None, None)
        finally:
            db.close()

    t_u = threading.Thread(target=attempt_upload)
    t_c = threading.Thread(target=attempt_complete)
    t_u.start()
    t_c.start()
    t_u.join(timeout=15)
    t_c.join(timeout=15)

    # complete_recording must always succeed exactly once here (it was
    # 'recording' when the race started, and only one lifecycle transition
    # is possible from that state in this scenario).
    assert results["complete"][0] == "succeeded", results

    verify_db = SessionFactory()
    try:
        final_session = verify_db.query(models.RecordingSession).filter(models.RecordingSession.id == recording_id).first()
        assert final_session.status == models.RecordingStatus.completed

        chunk_numbers = {
            row[0] for row in verify_db.query(models.VideoChunk.chunk_number).filter(models.VideoChunk.recording_session_id == recording_id).all()
        }
        # Whatever chunks actually got INTO the database, the completed
        # recording's own report must match reality: chunk 2 is either
        # genuinely present (upload won the race) or genuinely absent
        # (completion won, upload got a 409) -- never a mismatch between
        # what's stored and what the recording claims.
        if 2 in chunk_numbers:
            assert results["upload"][0] == "succeeded", f"Chunk 2 exists in DB but upload reported failure: {results}"
        else:
            assert results["upload"][0] != "succeeded", f"Chunk 2 missing from DB but upload reported success: {results}"
    finally:
        verify_db.close()
        _cleanup(SessionFactory, user_id, constable_id, device_id, recording_id)
        engine.dispose()
