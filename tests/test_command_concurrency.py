"""
Genuine two-connection PostgreSQL concurrency tests for Phase 3 (body-camera
system): RemoteCommand ACK races and non-battery alert deduplication.

HOW TO ACTUALLY RUN THESE TESTS:
    export TEST_DATABASE_URL="postgresql+psycopg://postgres:postgres_password@localhost:5432/police_db"
    pytest -m postgres_integration tests/test_command_concurrency.py -v

Without TEST_DATABASE_URL pointing to a reachable PostgreSQL server, these
SKIP (not fail, not fake a pass).
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
    "No reachable PostgreSQL instance configured for command-concurrency "
    "integration testing. Set TEST_DATABASE_URL to actually run this test. "
    "NOT executed in the current environment -- this is a skip, not a pass."
)


def _setup_command(SessionFactory, initial_status=None):
    from app import models
    from app.auth.security import hash_password
    from app.routers.devices import register_device
    from app.routers.commands import create_command, ack_command
    import app.schemas as schemas

    setup_db = SessionFactory()
    try:
        constable_user = models.User(
            phone=f"pgtest-cmd-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable,
            status=models.UserStatus.active, hashed_password=hash_password("pw"),
        )
        admin_user = models.User(
            phone=f"pgtest-cmdadmin-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.admin,
            status=models.UserStatus.active, hashed_password=hash_password("pw"),
        )
        setup_db.add(constable_user)
        setup_db.add(admin_user)
        setup_db.commit()
        constable_user_id, admin_user_id = constable_user.id, admin_user.id

        constable = models.Constable(user_id=constable_user.id, badge_number=f"BADGE-CMD-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
        setup_db.add(constable)
        setup_db.commit()
        constable_id = constable.id
    finally:
        setup_db.close()

    reg_db = SessionFactory()
    device_identifier = f"pgtest-cmd-device-{uuid_module.uuid4().hex[:10]}"
    reg_user = reg_db.query(models.User).filter(models.User.id == constable_user_id).first()
    device_resp = asyncio.run(register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), reg_db, reg_user))
    device_id = device_resp.id
    reg_db.close()

    create_db = SessionFactory()
    admin = create_db.query(models.User).filter(models.User.id == admin_user_id).first()
    command_resp = asyncio.run(create_command(device_id, schemas.RemoteCommandCreateRequest(command_type=models.RemoteCommandType.start_recording), create_db, admin))
    command_id = command_resp.id
    create_db.close()

    if initial_status == "acknowledged":
        ack_db = SessionFactory()
        ack_user = ack_db.query(models.User).filter(models.User.id == constable_user_id).first()
        asyncio.run(ack_command(command_id, ack_db, ack_user))
        ack_db.close()

    return constable_user_id, admin_user_id, constable_id, device_id, command_id


def _cleanup(SessionFactory, constable_user_id, admin_user_id, constable_id, device_id, command_id):
    from app import models
    cleanup_db = SessionFactory()
    try:
        cleanup_db.query(models.AuditLog).filter(models.AuditLog.user_id.in_([constable_user_id, admin_user_id])).delete(synchronize_session=False)
        cleanup_db.query(models.Alert).filter(models.Alert.device_id == device_id).delete()
        cleanup_db.query(models.RemoteCommand).filter(models.RemoteCommand.id == command_id).delete()
        cleanup_db.query(models.Device).filter(models.Device.id == device_id).delete()
        cleanup_db.query(models.Constable).filter(models.Constable.id == constable_id).delete()
        cleanup_db.query(models.User).filter(models.User.id.in_([constable_user_id, admin_user_id])).delete(synchronize_session=False)
        cleanup_db.commit()
    finally:
        cleanup_db.close()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_ack_race_exactly_one_succeeds():
    from app import models
    from app.routers.commands import ack_command
    from fastapi import HTTPException

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    constable_user_id, admin_user_id, constable_id, device_id, command_id = _setup_command(SessionFactory)

    barrier = threading.Barrier(2)
    results = {}

    def attempt(key):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == constable_user_id).first()
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(ack_command(command_id, db, user))
                results[key] = ("succeeded", response.status)
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
        final = verify_db.query(models.RemoteCommand).filter(models.RemoteCommand.id == command_id).first()
        assert final.status == models.RemoteCommandStatus.acknowledged
        assert final.acknowledged_at is not None
    finally:
        verify_db.close()
        _cleanup(SessionFactory, constable_user_id, admin_user_id, constable_id, device_id, command_id)
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_ack_vs_premature_result_final_state_always_valid():
    """
    ACK and RESULT race from a SENT command. SELECT...FOR UPDATE
    genuinely serializes the two calls against the same row, so there are
    exactly two legitimate outcomes depending purely on which request's
    lock acquisition wins:
      (a) RESULT's lock is granted first -> sees status=SENT (its
          precondition, ACKNOWLEDGED, isn't met yet) -> correctly 409.
          ACK then proceeds normally -> final state ACKNOWLEDGED.
      (b) ACK's lock is granted first -> transitions to ACKNOWLEDGED and
          commits, releasing the lock. RESULT's blocked query then
          unblocks and genuinely observes ACKNOWLEDGED -> its precondition
          IS met now, so it legitimately proceeds too -> final state
          EXECUTED/FAILED.
    Both are correct, non-corrupting, fully serialized outcomes -- what
    must NEVER happen is RESULT succeeding while ACK never happened
    (impossible here, since RESULT's only path to success is observing a
    genuinely-committed ACKNOWLEDGED state), or an ambiguous/corrupted
    final status.
    """
    from app import models
    from app.routers.commands import ack_command, command_result
    from fastapi import HTTPException
    import app.schemas as schemas

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    constable_user_id, admin_user_id, constable_id, device_id, command_id = _setup_command(SessionFactory)

    barrier = threading.Barrier(2)
    results = {}

    def attempt_ack():
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == constable_user_id).first()
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(ack_command(command_id, db, user))
                results["ack"] = ("succeeded", response.status)
            except HTTPException as exc:
                results["ack"] = (f"rejected_{exc.status_code}", None)
        finally:
            db.close()

    def attempt_result():
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == constable_user_id).first()
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(command_result(command_id, schemas.RemoteCommandResultRequest(success=True), db, user))
                results["result"] = ("succeeded", response.status)
            except HTTPException as exc:
                results["result"] = (f"rejected_{exc.status_code}", None)
        finally:
            db.close()

    t_ack = threading.Thread(target=attempt_ack)
    t_result = threading.Thread(target=attempt_result)
    t_ack.start()
    t_result.start()
    t_ack.join(timeout=15)
    t_result.join(timeout=15)

    # ACK's precondition (SENT) is satisfiable regardless of ordering, so
    # it must always succeed. RESULT is conditional -- accept BOTH valid
    # orderings rather than assuming only one (see docstring).
    assert results["ack"][0] == "succeeded", results
    assert results["result"][0] in ("succeeded", "rejected_409"), f"RESULT got an outcome that isn't either legitimate possibility: {results}"

    verify_db = SessionFactory()
    try:
        final = verify_db.query(models.RemoteCommand).filter(models.RemoteCommand.id == command_id).first()
        if results["result"][0] == "succeeded":
            assert final.status in (models.RemoteCommandStatus.executed, models.RemoteCommandStatus.failed), f"RESULT succeeded but final state is invalid: {final.status}"
        else:
            assert final.status == models.RemoteCommandStatus.acknowledged, f"RESULT was rejected but final state isn't ACKNOWLEDGED: {final.status}"
    finally:
        verify_db.close()
        _cleanup(SessionFactory, constable_user_id, admin_user_id, constable_id, device_id, command_id)
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_result_race_from_acknowledged_exactly_one_succeeds():
    """A genuine race where BOTH sides have a legitimate chance to win: two simultaneous /result calls from an already-ACKNOWLEDGED command."""
    from app import models
    from app.routers.commands import command_result
    from fastapi import HTTPException
    import app.schemas as schemas

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    constable_user_id, admin_user_id, constable_id, device_id, command_id = _setup_command(SessionFactory, initial_status="acknowledged")

    barrier = threading.Barrier(2)
    results = {}

    def attempt(key, success):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == constable_user_id).first()
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(command_result(command_id, schemas.RemoteCommandResultRequest(success=success), db, user))
                results[key] = ("succeeded", response.status)
            except HTTPException as exc:
                results[key] = (f"rejected_{exc.status_code}", None)
        finally:
            db.close()

    t_a = threading.Thread(target=attempt, args=("a", True))
    t_b = threading.Thread(target=attempt, args=("b", False))
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
        final = verify_db.query(models.RemoteCommand).filter(models.RemoteCommand.id == command_id).first()
        assert final.status in (models.RemoteCommandStatus.executed, models.RemoteCommandStatus.failed)
    finally:
        verify_db.close()
        _cleanup(SessionFactory, constable_user_id, admin_user_id, constable_id, device_id, command_id)
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_device_offline_alert_creation_exactly_one_open_alert():
    """Same class of race already proven for battery alerts in Phase 1, now proven for the Phase 3 uq_open_alert_per_device_and_type partial index."""
    from app import models
    from app.services import alerts as alerts_service
    from app.auth.security import hash_password

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    setup_db = SessionFactory()
    try:
        user = models.User(phone=f"pgtest-alertrace-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
        setup_db.add(user)
        setup_db.commit()
        user_id = user.id

        constable = models.Constable(user_id=user.id, badge_number=f"BADGE-AR-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
        setup_db.add(constable)
        setup_db.commit()
        constable_id = constable.id

        device = models.Device(constable_id=constable.id, device_identifier=f"pgtest-alertrace-device-{uuid_module.uuid4().hex[:8]}", status=models.DeviceStatus.offline)
        setup_db.add(device)
        setup_db.commit()
        device_id = device.id
    finally:
        setup_db.close()

    barrier = threading.Barrier(2)
    results = {}

    def attempt(key):
        db = SessionFactory()
        try:
            dev = db.query(models.Device).filter(models.Device.id == device_id).first()
            barrier.wait(timeout=5)
            alert, action = alerts_service.upsert_open_alert(db, dev, models.AlertType.device_offline, models.AlertSeverity.critical, "concurrent test")
            db.commit()
            results[key] = (action, alert.id if alert else None)
        finally:
            db.close()

    t_a = threading.Thread(target=attempt, args=("a",))
    t_b = threading.Thread(target=attempt, args=("b",))
    t_a.start()
    t_b.start()
    t_a.join(timeout=15)
    t_b.join(timeout=15)

    actions = [results["a"][0], results["b"][0]]
    assert actions.count("created") == 1, f"Expected exactly one 'created', got: {results}"
    assert results["a"][1] == results["b"][1], f"Both calls must resolve to the SAME alert id: {results}"

    verify_db = SessionFactory()
    try:
        open_alerts = verify_db.query(models.Alert).filter(
            models.Alert.device_id == device_id, models.Alert.type == models.AlertType.device_offline, models.Alert.status == models.AlertStatus.open
        ).all()
        assert len(open_alerts) == 1, f"Expected exactly one open alert, found {len(open_alerts)}"
    finally:
        verify_db.close()
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.Alert).filter(models.Alert.device_id == device_id).delete()
            cleanup_db.query(models.Device).filter(models.Device.id == device_id).delete()
            cleanup_db.query(models.Constable).filter(models.Constable.id == constable_id).delete()
            cleanup_db.query(models.User).filter(models.User.id == user_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()
