"""
Genuine two-connection PostgreSQL concurrency test for incident dispatch
(see app/routers/incidents.py::dispatch_incident).

This was a genuine gap identified during the production-hardening audit:
tests/test_evidence_verification_concurrency.py already proved real
row-locking for evidence verification, but no equivalent real-PostgreSQL
concurrency test existed for dispatch, even though dispatch_incident uses
the same `SELECT ... FOR UPDATE SKIP LOCKED` strategy and is at least as
important to verify for real (a double-booked constable is a genuine
officer-safety risk, not just a data-integrity nicety).

HOW TO ACTUALLY RUN THIS TEST:
    export TEST_DATABASE_URL="postgresql+psycopg://postgres:postgres_password@localhost:5432/police_db"
    pytest -m postgres_integration tests/test_dispatch_concurrency.py -v

Without TEST_DATABASE_URL pointing to a reachable PostgreSQL server, this
SKIPS (not fails, not fakes a pass).
"""
import asyncio
import os
import threading
import uuid as uuid_module

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.postgres_integration

_TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL") or os.getenv("POSTGRES_TEST_DATABASE_URL")


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
    "No reachable PostgreSQL instance configured for dispatch concurrency "
    "integration testing. Set TEST_DATABASE_URL to actually run this test. "
    "NOT executed in the current environment -- this is a skip, not a pass."
)


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_two_simultaneous_dispatches_cannot_double_book_the_same_constable():
    """
    Two DIFFERENT incidents, both verified and at the same location, both
    dispatched at essentially the same instant (synchronized via a
    `threading.Barrier`, not an artificial sleep -- a genuine race, no
    predetermined winner) while only ONE constable is available. Calls the
    real `dispatch_incident` function directly (not a reimplementation).

    Expected outcome:
      - exactly one of the two dispatch calls returns status="dispatched"
        with that constable_id
      - the other returns status="no_available_constable" (SELECT ... FOR
        UPDATE SKIP LOCKED means the loser's query simply doesn't see the
        row the winner has locked, rather than blocking and eventually
        double-assigning it)
      - exactly one active IncidentAssignment row exists for that
        constable across both incidents
      - the constable's final status is `busy`, not left inconsistent
      - exactly one `incident.dispatched` audit row exists (not two)
    """
    from app import models
    from app.routers.incidents import dispatch_incident

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    setup_db = SessionFactory()
    try:
        admin_user = models.User(
            phone=f"pgtest-dispatch-{uuid_module.uuid4().hex[:10]}",
            role=models.UserRole.admin,
            status=models.UserStatus.active,
        )
        setup_db.add(admin_user)
        setup_db.commit()
        admin_user_id = admin_user.id

        # Two separate incidents, same location, both verified and dispatchable.
        incident_a = models.Incident(location="POINT(77.1 28.6)", status=models.IncidentStatus.verified)
        incident_b = models.Incident(location="POINT(77.1 28.6)", status=models.IncidentStatus.verified)
        setup_db.add(incident_a)
        setup_db.add(incident_b)
        setup_db.commit()
        incident_a_id = incident_a.id
        incident_b_id = incident_b.id

        # A single constable user + Constable row, available, with a fresh location.
        constable_user = models.User(
            phone=f"pgtest-dispatch-c-{uuid_module.uuid4().hex[:10]}",
            role=models.UserRole.constable,
            status=models.UserStatus.active,
        )
        setup_db.add(constable_user)
        setup_db.commit()
        constable_user_id = constable_user.id

        constable = models.Constable(
            user_id=constable_user.id,
            badge_number=f"BADGE-{uuid_module.uuid4().hex[:8]}",
            status=models.ConstableStatus.available,
            battery_level=100,
        )
        setup_db.add(constable)
        setup_db.commit()
        constable_id = constable.id

        location = models.ConstableLocation(constable_id=constable.id, location="POINT(77.1 28.6)")
        setup_db.add(location)
        setup_db.commit()
    finally:
        setup_db.close()

    barrier = threading.Barrier(2)
    results = {}

    def attempt(incident_id, key: str):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == admin_user_id).first()
            barrier.wait(timeout=5)  # both threads reach dispatch_incident at essentially the same instant
            response = asyncio.run(dispatch_incident(incident_id, db, user))
            results[key] = {"status": response.status, "constable_id": response.constable_id}
        finally:
            db.close()

    t_a = threading.Thread(target=attempt, args=(incident_a_id, "a"))
    t_b = threading.Thread(target=attempt, args=(incident_b_id, "b"))
    t_a.start()
    t_b.start()
    t_a.join(timeout=15)
    t_b.join(timeout=15)

    statuses = {results["a"]["status"], results["b"]["status"]}
    assert statuses == {"dispatched", "no_available_constable"}, f"Unexpected outcome: {results}"

    winner_key = "a" if results["a"]["status"] == "dispatched" else "b"
    assert results[winner_key]["constable_id"] == constable_id

    verify_db = SessionFactory()
    try:
        active_assignments = verify_db.query(models.IncidentAssignment).filter(
            models.IncidentAssignment.constable_id == constable_id,
            models.IncidentAssignment.status.in_([
                models.AssignmentStatus.pending, models.AssignmentStatus.accepted,
                models.AssignmentStatus.en_route, models.AssignmentStatus.arrived,
            ]),
        ).all()
        assert len(active_assignments) == 1, f"Constable was double-booked: {active_assignments}"

        final_constable = verify_db.query(models.Constable).filter(models.Constable.id == constable_id).first()
        assert final_constable.status == models.ConstableStatus.busy

        dispatched_audit = verify_db.query(models.AuditLog).filter(
            models.AuditLog.action == "incident.dispatched",
            models.AuditLog.details.like(f"%{constable_id}%"),
        ).all()
        assert len(dispatched_audit) == 1, f"Expected exactly one dispatch audit row, got {len(dispatched_audit)}"
    finally:
        verify_db.close()
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.AuditLog).filter(
                models.AuditLog.user_id == admin_user_id
            ).delete()
            cleanup_db.query(models.IncidentAssignment).filter(
                models.IncidentAssignment.constable_id == constable_id
            ).delete()
            cleanup_db.query(models.ConstableLocation).filter(
                models.ConstableLocation.constable_id == constable_id
            ).delete()
            cleanup_db.query(models.Constable).filter(models.Constable.id == constable_id).delete()
            cleanup_db.query(models.Incident).filter(
                models.Incident.id.in_([incident_a_id, incident_b_id])
            ).delete(synchronize_session=False)
            cleanup_db.query(models.User).filter(
                models.User.id.in_([admin_user_id, constable_user_id])
            ).delete(synchronize_session=False)
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()
