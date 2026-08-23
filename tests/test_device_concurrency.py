"""
Genuine two-connection PostgreSQL concurrency tests for device
registration (Phase 1, body-camera system).

Proves the `device_identifier` unique constraint is a REAL database-level
safety net -- not merely an application-level `if device: ...` check that
a race could slip past. See tests/test_evidence_verification_concurrency.py
and tests/test_dispatch_concurrency.py for the same established pattern
(real threads, real separate connections, threading.Barrier for a genuine
simultaneous start, never an artificial sleep to fake a race).

HOW TO ACTUALLY RUN THIS TEST:
    export TEST_DATABASE_URL="postgresql+psycopg://postgres:postgres_password@localhost:5432/police_db"
    pytest -m postgres_integration tests/test_device_concurrency.py -v

Without TEST_DATABASE_URL pointing to a reachable PostgreSQL server, this
SKIPS (not fails, not fakes a pass).
"""
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
    "No reachable PostgreSQL instance configured for device-concurrency "
    "integration testing. Set TEST_DATABASE_URL to actually run this test. "
    "NOT executed in the current environment -- this is a skip, not a pass."
)


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_registration_same_identifier_only_one_device_row_survives():
    """
    Two DIFFERENT constables attempt to register a device with the SAME
    device_identifier at essentially the same instant (barrier-
    synchronized, no artificial ordering). Calls the real
    `register_device` router function directly (via asyncio.run, exactly
    like the dispatch-concurrency test does), not a reimplementation of
    the uniqueness check.

    Expected outcome:
      - exactly one registration succeeds
      - the other fails with 403 (already claimed) OR 409 (lost the raw
        INSERT race against the unique constraint) -- either is a correct,
        safe outcome; what must NEVER happen is both succeeding, or two
        device rows existing for the same identifier.
      - exactly one `devices` row exists for this device_identifier at the end
    """
    from app import models
    from app.routers.devices import register_device
    from app.auth.security import hash_password
    from fastapi import HTTPException
    import app.schemas as schemas

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    device_identifier = f"pgtest-race-device-{uuid_module.uuid4().hex[:10]}"

    setup_db = SessionFactory()
    try:
        user_a = models.User(phone=f"pgtest-dev-a-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
        user_b = models.User(phone=f"pgtest-dev-b-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
        setup_db.add(user_a)
        setup_db.add(user_b)
        setup_db.commit()
        user_a_id, user_b_id = user_a.id, user_b.id

        constable_a = models.Constable(user_id=user_a.id, badge_number=f"BADGE-A-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
        constable_b = models.Constable(user_id=user_b.id, badge_number=f"BADGE-B-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
        setup_db.add(constable_a)
        setup_db.add(constable_b)
        setup_db.commit()
        constable_a_id, constable_b_id = constable_a.id, constable_b.id
    finally:
        setup_db.close()

    barrier = threading.Barrier(2)
    results = {}

    def attempt(user_id, key):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            payload = schemas.DeviceRegisterRequest(device_identifier=device_identifier, platform="android")
            barrier.wait(timeout=5)
            import asyncio
            try:
                response = asyncio.run(register_device(payload, db, user))
                results[key] = ("succeeded", response.id)
            except HTTPException as exc:
                results[key] = (f"rejected_{exc.status_code}", None)
        finally:
            db.close()

    t_a = threading.Thread(target=attempt, args=(user_a_id, "a"))
    t_b = threading.Thread(target=attempt, args=(user_b_id, "b"))
    t_a.start()
    t_b.start()
    t_a.join(timeout=15)
    t_b.join(timeout=15)

    outcomes = [results["a"][0], results["b"][0]]
    succeeded = [r for r in outcomes if r == "succeeded"]
    rejected = [r for r in outcomes if r.startswith("rejected_")]
    assert len(succeeded) == 1, f"Expected exactly one success: {results}"
    assert len(rejected) == 1, f"Expected exactly one rejection: {results}"
    assert rejected[0] in ("rejected_403", "rejected_409"), f"Unexpected rejection status: {results}"

    verify_db = SessionFactory()
    try:
        rows = verify_db.query(models.Device).filter(models.Device.device_identifier == device_identifier).all()
        assert len(rows) == 1, f"Expected exactly one device row, found {len(rows)}"
    finally:
        verify_db.close()
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.AuditLog).filter(models.AuditLog.user_id.in_([user_a_id, user_b_id])).delete(synchronize_session=False)
            cleanup_db.query(models.Device).filter(models.Device.device_identifier == device_identifier).delete()
            cleanup_db.query(models.Constable).filter(models.Constable.id.in_([constable_a_id, constable_b_id])).delete(synchronize_session=False)
            cleanup_db.query(models.User).filter(models.User.id.in_([user_a_id, user_b_id])).delete(synchronize_session=False)
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_heartbeats_leave_consistent_final_state():
    """
    Task 1.B: two independent connections send heartbeats for the SAME
    device at essentially the same instant. There is no meaningful
    "winner"/"loser" here (heartbeats are pure idempotent overwrites, not a
    create-vs-reject race) -- what must be verified is that the database
    ends up in a single, well-formed, non-corrupted state: exactly one
    Device row, a valid last_seen_at (a real timestamp, not null/garbage),
    and a valid effective status.
    """
    from app import models
    from app.routers.devices import register_device, device_heartbeat, compute_effective_status
    from app.auth.security import hash_password
    from app.routers.settings import load_settings
    import app.schemas as schemas
    import asyncio

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    device_identifier = f"pgtest-hb-device-{uuid_module.uuid4().hex[:10]}"
    setup_db = SessionFactory()
    try:
        user = models.User(phone=f"pgtest-hb-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
        setup_db.add(user)
        setup_db.commit()
        user_id = user.id
        constable = models.Constable(user_id=user.id, badge_number=f"BADGE-HB-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
        setup_db.add(constable)
        setup_db.commit()
        constable_id = constable.id

        reg_db = SessionFactory()
        reg_user = reg_db.query(models.User).filter(models.User.id == user_id).first()
        asyncio.run(register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), reg_db, reg_user))
        reg_db.close()
    finally:
        setup_db.close()

    barrier = threading.Barrier(2)
    results = {}

    def attempt(key, battery):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            payload = schemas.DeviceHeartbeatRequest(device_identifier=device_identifier, battery_percent=battery)
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(device_heartbeat(payload, db, user))
                results[key] = ("ok", response.status)
            except Exception as exc:
                results[key] = ("error", str(exc))
        finally:
            db.close()

    t_a = threading.Thread(target=attempt, args=("a", 70))
    t_b = threading.Thread(target=attempt, args=("b", 72))
    t_a.start()
    t_b.start()
    t_a.join(timeout=15)
    t_b.join(timeout=15)

    assert results["a"][0] == "ok", results
    assert results["b"][0] == "ok", results
    assert results["a"][1] in ("online", "stale", "offline")
    assert results["b"][1] in ("online", "stale", "offline")

    verify_db = SessionFactory()
    try:
        devices = verify_db.query(models.Device).filter(models.Device.device_identifier == device_identifier).all()
        assert len(devices) == 1, f"Expected exactly one device row, found {len(devices)}"
        device = devices[0]
        assert device.last_seen_at is not None
        settings = load_settings()
        effective = compute_effective_status(device, settings)
        assert effective in (models.DeviceStatus.online, models.DeviceStatus.stale, models.DeviceStatus.offline)
    finally:
        verify_db.close()
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.BatteryReading).filter(models.BatteryReading.device_id == device.id).delete()
            cleanup_db.query(models.AuditLog).filter(models.AuditLog.user_id == user_id).delete()
            cleanup_db.query(models.Device).filter(models.Device.id == device.id).delete()
            cleanup_db.query(models.Constable).filter(models.Constable.id == constable_id).delete()
            cleanup_db.query(models.User).filter(models.User.id == user_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_battery_reports_both_persisted_no_lost_reading():
    """
    Task 1.C: two simultaneous battery reports for the same device. Since
    BatteryReading is explicitly append-only (not an overwritten scalar),
    BOTH readings must be persisted -- neither request should silently
    lose the other's row.
    """
    from app import models
    from app.routers.devices import register_device, report_battery
    from app.auth.security import hash_password
    import app.schemas as schemas
    import asyncio

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    device_identifier = f"pgtest-batt-device-{uuid_module.uuid4().hex[:10]}"
    setup_db = SessionFactory()
    try:
        user = models.User(phone=f"pgtest-batt-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
        setup_db.add(user)
        setup_db.commit()
        user_id = user.id
        constable = models.Constable(user_id=user.id, badge_number=f"BADGE-BT-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
        setup_db.add(constable)
        setup_db.commit()
        constable_id = constable.id

        reg_db = SessionFactory()
        reg_user = reg_db.query(models.User).filter(models.User.id == user_id).first()
        device_resp = asyncio.run(register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), reg_db, reg_user))
        device_id = device_resp.id
        reg_db.close()
    finally:
        setup_db.close()

    barrier = threading.Barrier(2)
    results = {}

    def attempt(key, battery):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            payload = schemas.DeviceBatteryReportRequest(device_identifier=device_identifier, battery_percent=battery)
            barrier.wait(timeout=5)
            try:
                response = asyncio.run(report_battery(payload, db, user))
                results[key] = ("ok", response.battery_percent)
            except Exception as exc:
                results[key] = ("error", str(exc))
        finally:
            db.close()

    t_a = threading.Thread(target=attempt, args=("a", 55))
    t_b = threading.Thread(target=attempt, args=("b", 56))
    t_a.start()
    t_b.start()
    t_a.join(timeout=15)
    t_b.join(timeout=15)

    assert results["a"][0] == "ok", results
    assert results["b"][0] == "ok", results

    verify_db = SessionFactory()
    try:
        readings = verify_db.query(models.BatteryReading).filter(models.BatteryReading.device_id == device_id).all()
        assert len(readings) == 2, f"Expected both readings persisted, found {len(readings)}"
        percents = {r.battery_percent for r in readings}
        assert percents == {55, 56}
    finally:
        verify_db.close()
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.BatteryReading).filter(models.BatteryReading.device_id == device_id).delete()
            cleanup_db.query(models.AuditLog).filter(models.AuditLog.user_id == user_id).delete()
            cleanup_db.query(models.Device).filter(models.Device.id == device_id).delete()
            cleanup_db.query(models.Constable).filter(models.Constable.id == constable_id).delete()
            cleanup_db.query(models.User).filter(models.User.id == user_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()


@pytest.mark.skipif(not _PG_AVAILABLE, reason=_SKIP_REASON)
def test_concurrent_low_battery_reports_create_exactly_one_open_alert():
    """
    Task 1.D -- THE IMPORTANT ONE. Two simultaneous battery reports, both
    crossing the SAME threshold for the SAME device at essentially the
    same instant (barrier-synchronized, no artificial ordering). Before
    the fix (see migration 7c4e9b1a5f38 and the SAVEPOINT-retry logic in
    _process_battery_thresholds), this was a genuine check-then-insert
    race that could produce two duplicate open alerts. Proves the fix:
    exactly ONE open alert exists for this device afterward, regardless
    of which request "won".
    """
    from app import models
    from app.routers.devices import register_device, report_battery
    from app.auth.security import hash_password
    import app.schemas as schemas
    import asyncio

    engine = create_engine(_TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)

    device_identifier = f"pgtest-alert-race-{uuid_module.uuid4().hex[:10]}"
    setup_db = SessionFactory()
    try:
        user = models.User(phone=f"pgtest-alert-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
        setup_db.add(user)
        setup_db.commit()
        user_id = user.id
        constable = models.Constable(user_id=user.id, badge_number=f"BADGE-AL-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
        setup_db.add(constable)
        setup_db.commit()
        constable_id = constable.id

        reg_db = SessionFactory()
        reg_user = reg_db.query(models.User).filter(models.User.id == user_id).first()
        device_resp = asyncio.run(register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), reg_db, reg_user))
        device_id = device_resp.id
        reg_db.close()
    finally:
        setup_db.close()

    barrier = threading.Barrier(2)
    results = {}

    def attempt(key, battery):
        db = SessionFactory()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            payload = schemas.DeviceBatteryReportRequest(device_identifier=device_identifier, battery_percent=battery)
            barrier.wait(timeout=5)
            try:
                asyncio.run(report_battery(payload, db, user))
                results[key] = "ok"
            except Exception as exc:
                results[key] = f"error: {exc}"
        finally:
            db.close()

    # Both requests cross the SAME (default warning=20) threshold at once.
    t_a = threading.Thread(target=attempt, args=("a", 19))
    t_b = threading.Thread(target=attempt, args=("b", 18))
    t_a.start()
    t_b.start()
    t_a.join(timeout=15)
    t_b.join(timeout=15)

    assert results["a"] == "ok", results
    assert results["b"] == "ok", results

    verify_db = SessionFactory()
    try:
        open_alerts = verify_db.query(models.Alert).filter(
            models.Alert.device_id == device_id, models.Alert.status == models.AlertStatus.open
        ).all()
        assert len(open_alerts) == 1, f"Expected exactly ONE open alert, found {len(open_alerts)}: {open_alerts}"
        assert open_alerts[0].type == models.AlertType.low_battery
    finally:
        verify_db.close()
        cleanup_db = SessionFactory()
        try:
            cleanup_db.query(models.Alert).filter(models.Alert.device_id == device_id).delete()
            cleanup_db.query(models.BatteryReading).filter(models.BatteryReading.device_id == device_id).delete()
            cleanup_db.query(models.AuditLog).filter(models.AuditLog.user_id == user_id).delete()
            cleanup_db.query(models.Device).filter(models.Device.id == device_id).delete()
            cleanup_db.query(models.Constable).filter(models.Constable.id == constable_id).delete()
            cleanup_db.query(models.User).filter(models.User.id == user_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()
        engine.dispose()
