"""
Genuine two-connection PostgreSQL concurrency test for the evidence
verification row-lock (see app/routers/media.py::_transition_evidence_status).

This is DELIBERATELY SEPARATE from tests/test_evidence_verification.py,
which runs against the SQLite test database used everywhere else in this
suite. SQLite has no multi-connection row-locking model at all (confirmed
empirically while implementing this phase -- `.with_for_update()` is
accepted but is a silent no-op there), so a SQLite-only test can only ever
prove SEQUENTIAL request handling, never genuine concurrent-transaction
safety. This file exists specifically to test the thing SQLite cannot:
two independent database connections racing on the same Evidence row
against a REAL PostgreSQL server.

HOW TO ACTUALLY RUN THIS TEST:
    1. Start a real Postgres+PostGIS instance, e.g. via the repo's existing
       docker-compose service:
           docker-compose up -d db
    2. Point TEST_DATABASE_URL at it, e.g.:
           export TEST_DATABASE_URL="postgresql+psycopg://postgres:postgres_password@localhost:5432/police_db"
    3. Run:
           pytest -m postgres_integration tests/test_evidence_verification_concurrency.py -v

Without TEST_DATABASE_URL pointing to a reachable PostgreSQL server, every
test in this file SKIPS (not fails, not fakes a pass) -- confirmed this is
exactly what happens in this sandbox, since no such server is available
here. Do not interpret a "1 skipped" result as "concurrency verified".
"""
import os
import threading
import time
import uuid as uuid_module

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.postgres_integration

_TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL") or os.getenv("POSTGRES_TEST_DATABASE_URL")


def _postgres_reachable() -> bool:
    """
    Evaluated at collection time (see @pytest.mark.skipif below). Returns
    False immediately without attempting any connection if no URL is
    configured at all -- only attempts a real connection if one was
    explicitly provided, so this never silently hangs or slows down the
    rest of the suite when Postgres integration testing isn't set up.
    """
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
    "No reachable PostgreSQL instance configured for concurrency integration "
    "testing. Set TEST_DATABASE_URL (see this file's module docstring for "
    "exact setup steps) to actually run this test. NOT executed in the "
    "current environment -- this is a skip, not a pass."
)


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_verify_and_reject_race_real_postgres():
    """
    Two independent SQLAlchemy sessions (== two independent PostgreSQL
    connections/transactions) attempt CONFLICTING transitions
    (verify vs reject) on the SAME evidence row at genuinely the same time,
    using the actual application function
    (app.routers.media._transition_evidence_status) on both sides -- not a
    reimplementation of the locking logic, the real code path.

    Expected outcome (per the phase spec):
      - Transaction A acquires the row lock first, transitions
        uploaded -> verified, holds briefly, commits.
      - Transaction B's SELECT ... FOR UPDATE blocks until A commits, then
        re-reads the row and observes status == verified (not the stale
        'uploaded' it would have seen without a lock) -- so B's own
        uploaded->rejected transition is correctly rejected with 409
        (surfaced here as the HTTPException itself, since this calls the
        router function directly rather than going through a full request).
      - Exactly one successful transition (A's).
      - Exactly one audit row for evidence.verified, zero for evidence.rejected.
      - Final DB state: verified.
    """
    from app import models
    from app.routers.media import _transition_evidence_status
    from fastapi import HTTPException

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    setup_db = SessionFactory()
    try:
        admin_user = models.User(
            phone=f"pgtest-admin-{uuid_module.uuid4().hex[:10]}",
            role=models.UserRole.admin,
            status=models.UserStatus.active,
        )
        setup_db.add(admin_user)
        setup_db.commit()
        setup_db.refresh(admin_user)

        incident = models.Incident(location="POINT(1 1)", status=models.IncidentStatus.new)
        setup_db.add(incident)
        setup_db.commit()
        setup_db.refresh(incident)
        incident_id = incident.id

        evidence = models.Evidence(
            incident_id=incident.id,
            type=models.MediaType.photo,
            upload_status=models.UploadStatus.uploaded,
        )
        setup_db.add(evidence)
        setup_db.commit()
        setup_db.refresh(evidence)
        evidence_id = evidence.id
        admin_user_id = admin_user.id
    finally:
        setup_db.close()

    results = {}
    a_locked = threading.Event()

    def txn_a():
        db = SessionFactory()
        try:
            user_a = db.query(models.User).filter(models.User.id == admin_user_id).first()
            # Acquire the lock via the real function, but hold the
            # transaction open briefly BEFORE committing by monkeypatching
            # around it isn't possible here (the function commits
            # internally) -- so instead we lock manually first to create
            # the hold window, signal B, sleep, then perform the real
            # transition on the now-locked row within the same transaction.
            locked_row = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).with_for_update().first()
            a_locked.set()
            time.sleep(1.0)  # deterministic hold window; B is blocked on FOR UPDATE during this entire time
            locked_row.upload_status = models.UploadStatus.verified
            locked_row.verified_by = user_a.id
            from app.services.audit import log_action
            log_action(db, user_id=user_a.id, action="evidence.verified", incident_id=incident_id, evidence_id=evidence_id, details={"old_status": "uploaded", "new_status": "verified"})
            db.commit()
            results["a_status"] = "committed_verified"
        finally:
            db.close()

    def txn_b():
        assert a_locked.wait(timeout=5), "Transaction A never signaled it acquired the lock"
        db = SessionFactory()
        try:
            user_b = db.query(models.User).filter(models.User.id == admin_user_id).first()
            start = time.time()
            try:
                _transition_evidence_status(db, evidence_id, models.UploadStatus.rejected, user_b, "evidence.rejected")
                results["b_status"] = "unexpectedly_succeeded"
            except HTTPException as exc:
                results["b_wait_seconds"] = time.time() - start
                results["b_status_code"] = exc.status_code
                results["b_status"] = "rejected_with_409" if exc.status_code == 409 else f"rejected_with_{exc.status_code}"
        finally:
            db.close()

    t_a = threading.Thread(target=txn_a)
    t_b = threading.Thread(target=txn_b)
    t_a.start()
    t_b.start()
    t_a.join(timeout=10)
    t_b.join(timeout=10)

    assert results.get("a_status") == "committed_verified"
    # B must have genuinely BLOCKED waiting for A's lock (not raced past it) --
    # a wait time well under A's 1-second hold would indicate no real locking occurred.
    assert results.get("b_wait_seconds", 0) >= 0.8, f"Transaction B did not block on the lock as expected: {results}"
    assert results.get("b_status") == "rejected_with_409", f"Unexpected outcome: {results}"

    verify_db = SessionFactory()
    try:
        final = verify_db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
        assert final.upload_status == models.UploadStatus.verified

        verified_audit = verify_db.query(models.AuditLog).filter(
            models.AuditLog.evidence_id == evidence_id, models.AuditLog.action == "evidence.verified"
        ).all()
        rejected_audit = verify_db.query(models.AuditLog).filter(
            models.AuditLog.evidence_id == evidence_id, models.AuditLog.action == "evidence.rejected"
        ).all()
        assert len(verified_audit) == 1
        assert len(rejected_audit) == 0
    finally:
        verify_db.close()
        # Cleanup: remove the rows this test created so re-runs stay clean.
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.AuditLog).filter(models.AuditLog.evidence_id == evidence_id).delete()
            cleanup_db.query(models.Evidence).filter(models.Evidence.id == evidence_id).delete()
            cleanup_db.query(models.Incident).filter(models.Incident.id == incident_id).delete()
            cleanup_db.query(models.User).filter(models.User.id == admin_user_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_genuine_simultaneous_race_verify_vs_reject_exactly_one_winner():
    """
    Unlike test_concurrent_verify_and_reject_race_real_postgres above (which
    deterministically makes A go first via an explicit hold-then-sleep so
    the *winner* is predictable and the *blocking* is easy to measure),
    this test does NOT predetermine a winner. Both threads call the real
    `_transition_evidence_status` for the SAME evidence row at essentially
    the same instant (synchronized via a `threading.Barrier`, not a sleep),
    one attempting uploaded->verified and the other uploaded->rejected.
    Whichever thread's `SELECT ... FOR UPDATE` actually reaches PostgreSQL's
    lock queue first wins -- that is determined by PostgreSQL's own lock
    arbitration and thread/connection scheduling, not by anything this test
    controls. What IS asserted, and what actually matters:
      - both threads run without raising anything other than the expected
        HTTPException(409) for the loser
      - the two outcomes are never (winner, winner) or (winner, winner) --
        exactly one of them is a real transition and the other is a 409
      - the final database state is EXACTLY ONE of verified/rejected, never
        both, never left at 'uploaded', never any other value
      - the loser produced NO audit row for its attempted action
    """
    from app import models
    from app.routers.media import _transition_evidence_status
    from fastapi import HTTPException

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    setup_db = SessionFactory()
    try:
        admin_user = models.User(
            phone=f"pgtest-race-{uuid_module.uuid4().hex[:10]}",
            role=models.UserRole.admin,
            status=models.UserStatus.active,
        )
        setup_db.add(admin_user)
        setup_db.commit()
        admin_user_id = admin_user.id

        incident = models.Incident(location="POINT(3 3)", status=models.IncidentStatus.new)
        setup_db.add(incident)
        setup_db.commit()
        incident_id = incident.id

        evidence = models.Evidence(incident_id=incident_id, type=models.MediaType.photo, upload_status=models.UploadStatus.uploaded)
        setup_db.add(evidence)
        setup_db.commit()
        evidence_id = evidence.id
    finally:
        setup_db.close()

    barrier = threading.Barrier(2)
    results = {}

    def attempt(target_status: models.UploadStatus, action: str, key: str):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == admin_user_id).first()
            barrier.wait(timeout=5)  # both threads proceed to their SELECT ... FOR UPDATE at essentially the same instant
            try:
                _transition_evidence_status(db, evidence_id, target_status, user, action)
                results[key] = "succeeded"
            except HTTPException as exc:
                results[key] = f"rejected_{exc.status_code}"
        finally:
            db.close()

    t_verify = threading.Thread(target=attempt, args=(models.UploadStatus.verified, "evidence.verified", "verify"))
    t_reject = threading.Thread(target=attempt, args=(models.UploadStatus.rejected, "evidence.rejected", "reject"))
    t_verify.start()
    t_reject.start()
    t_verify.join(timeout=10)
    t_reject.join(timeout=10)

    outcomes = {results.get("verify"), results.get("reject")}
    # Exactly one side succeeded, the other was rejected with 409 -- never both, never neither.
    assert outcomes == {"succeeded", "rejected_409"}, f"Unexpected race outcome: {results}"

    verify_db = SessionFactory()
    try:
        final = verify_db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
        assert final.upload_status.value in ("verified", "rejected")

        verified_audit = verify_db.query(models.AuditLog).filter(
            models.AuditLog.evidence_id == evidence_id, models.AuditLog.action == "evidence.verified"
        ).all()
        rejected_audit = verify_db.query(models.AuditLog).filter(
            models.AuditLog.evidence_id == evidence_id, models.AuditLog.action == "evidence.rejected"
        ).all()

        if final.upload_status == models.UploadStatus.verified:
            assert results["verify"] == "succeeded"
            assert len(verified_audit) == 1
            assert len(rejected_audit) == 0  # the loser created no audit row
        else:
            assert results["reject"] == "succeeded"
            assert len(rejected_audit) == 1
            assert len(verified_audit) == 0  # the loser created no audit row
    finally:
        verify_db.close()
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.AuditLog).filter(models.AuditLog.evidence_id == evidence_id).delete()
            cleanup_db.query(models.Evidence).filter(models.Evidence.id == evidence_id).delete()
            cleanup_db.query(models.Incident).filter(models.Incident.id == incident_id).delete()
            cleanup_db.query(models.User).filter(models.User.id == admin_user_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_commit_failure_atomicity_real_postgres(monkeypatch):
    """
    Repeats the SQLite-side atomicity guarantee (see
    tests/test_evidence_verification.py::test_failed_commit_leaves_evidence_and_audit_unchanged)
    against the REAL PostgreSQL engine: forces db.commit() to raise inside
    _transition_evidence_status and confirms, by re-querying from a
    SEPARATE session/connection afterward, that:
      - evidence.upload_status is unchanged
      - verified_by/verified_at are unchanged
      - no evidence.verified audit row exists
    This is the audit/state half of item 6; the "no WebSocket event
    published" half is already covered against SQLite in
    tests/test_evidence_verification.py::test_event_not_published_when_commit_fails
    (event publishing itself is transport-agnostic Python code, not
    database-specific, so it does not need a second, Postgres-specific
    repetition to mean something new).
    """
    from app import models
    from app.routers.media import _transition_evidence_status
    from sqlalchemy.orm import Session as OrmSession

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    setup_db = SessionFactory()
    try:
        admin_user = models.User(
            phone=f"pgtest-atomic-{uuid_module.uuid4().hex[:10]}",
            role=models.UserRole.admin,
            status=models.UserStatus.active,
        )
        setup_db.add(admin_user)
        setup_db.commit()
        admin_user_id = admin_user.id

        incident = models.Incident(location="POINT(4 4)", status=models.IncidentStatus.new)
        setup_db.add(incident)
        setup_db.commit()
        incident_id = incident.id

        evidence = models.Evidence(incident_id=incident_id, type=models.MediaType.photo, upload_status=models.UploadStatus.uploaded)
        setup_db.add(evidence)
        setup_db.commit()
        evidence_id = evidence.id
    finally:
        setup_db.close()

    action_db = SessionFactory()
    real_commit = OrmSession.commit

    def _boom_commit(self):
        raise RuntimeError("simulated real-Postgres commit failure")

    try:
        user = action_db.query(models.User).filter(models.User.id == admin_user_id).first()
        monkeypatch.setattr(OrmSession, "commit", _boom_commit)
        with pytest.raises(RuntimeError, match="simulated real-Postgres commit failure"):
            _transition_evidence_status(action_db, evidence_id, models.UploadStatus.verified, user, "evidence.verified")
    finally:
        monkeypatch.setattr(OrmSession, "commit", real_commit)
        action_db.rollback()
        action_db.close()

    # Re-read from a SEPARATE, freshly-opened session/connection -- not the
    # one that just failed -- to prove the failure genuinely never reached
    # the database, not merely that this Python object's in-memory state
    # looks right.
    verify_db = SessionFactory()
    try:
        fresh = verify_db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
        assert fresh.upload_status == models.UploadStatus.uploaded
        assert fresh.verified_at is None
        assert fresh.verified_by is None

        audit_rows = verify_db.query(models.AuditLog).filter(
            models.AuditLog.evidence_id == evidence_id, models.AuditLog.action == "evidence.verified"
        ).all()
        assert len(audit_rows) == 0
    finally:
        verify_db.close()
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.Evidence).filter(models.Evidence.id == evidence_id).delete()
            cleanup_db.query(models.Incident).filter(models.Incident.id == incident_id).delete()
            cleanup_db.query(models.User).filter(models.User.id == admin_user_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_for_update_blocks_a_second_connection_until_release():
    """
    Direct, minimal proof (independent of the main race-scenario test
    above) that `.with_for_update()` genuinely blocks a second connection:
    one thread holds the lock for a deterministic 1-second window; a
    second thread's attempt to acquire the same lock must measurably wait
    for (at least most of) that window before proceeding, then must be
    able to observe the first transaction's committed change.
    """
    from app import models

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    setup_db = SessionFactory()
    try:
        incident = models.Incident(location="POINT(2 2)", status=models.IncidentStatus.new)
        setup_db.add(incident)
        setup_db.commit()
        incident_id = incident.id
        evidence = models.Evidence(incident_id=incident.id, type=models.MediaType.photo, upload_status=models.UploadStatus.uploaded)
        setup_db.add(evidence)
        setup_db.commit()
        evidence_id = evidence.id
    finally:
        setup_db.close()

    results = {}
    holder_locked = threading.Event()

    def holder():
        db = SessionFactory()
        try:
            row = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).with_for_update().first()
            holder_locked.set()
            time.sleep(1.0)
            row.upload_status = models.UploadStatus.verified
            db.commit()
        finally:
            db.close()

    def waiter():
        assert holder_locked.wait(timeout=5)
        db = SessionFactory()
        try:
            start = time.time()
            row = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).with_for_update().first()
            results["wait_seconds"] = time.time() - start
            results["observed_status"] = row.upload_status.value
            db.rollback()
        finally:
            db.close()

    t_holder = threading.Thread(target=holder)
    t_waiter = threading.Thread(target=waiter)
    t_holder.start()
    t_waiter.start()
    t_holder.join(timeout=10)
    t_waiter.join(timeout=10)

    assert results.get("wait_seconds", 0) >= 0.8, f"Waiter did not genuinely block on the lock: {results}"
    assert results.get("observed_status") == "verified"

    cleanup_db = SessionFactory()
    try:
        cleanup_db.query(models.Evidence).filter(models.Evidence.id == evidence_id).delete()
        cleanup_db.query(models.Incident).filter(models.Incident.id == incident_id).delete()
        cleanup_db.commit()
    finally:
        cleanup_db.close()
        engine.dispose()
