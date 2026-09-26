"""
Genuine concurrent-request tests for device registration/heartbeat/battery
races, against a real MongoDB replica set. Same established
asyncio.gather + asyncio.Barrier pattern as tests/test_dispatch_concurrency.py.

Proves the `device_identifier` unique index is a REAL database-level
safety net -- not merely an application-level `if device: ...` check that
a race could slip past.

Needs a reachable MongoDB replica set (see tests/conftest.py's
requires_mongo / TEST_MONGODB_URL) -- skips otherwise.
"""
import asyncio
import uuid as uuid_module

import pytest

from conftest import requires_mongo

pytestmark = [pytest.mark.concurrency, requires_mongo]


async def test_concurrent_registration_same_identifier_only_one_device_row_survives(mongo_db):
    """
    Two DIFFERENT constables attempt to register a device with the SAME
    device_identifier at essentially the same instant (barrier-
    synchronized, no artificial ordering). Calls the real
    `register_device` router function directly, not a reimplementation of
    the uniqueness check.

    Expected outcome:
      - exactly one registration succeeds
      - the other fails with 403 (already claimed) OR 409 (lost the raw
        insert race against the unique index) -- either is a correct,
        safe outcome; what must NEVER happen is both succeeding, or two
        device documents existing for the same identifier.
      - exactly one `devices` document exists for this device_identifier at the end
    """
    from app import models
    from app.routers.devices import register_device
    from app.auth.security import hash_password
    from fastapi import HTTPException
    import app.schemas as schemas

    device_identifier = f"pgtest-race-device-{uuid_module.uuid4().hex[:10]}"

    user_a = models.User(phone=f"pgtest-dev-a-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
    user_b = models.User(phone=f"pgtest-dev-b-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
    await user_a.insert()
    await user_b.insert()

    constable_a = models.Constable(user_id=user_a.id, badge_number=f"BADGE-A-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
    constable_b = models.Constable(user_id=user_b.id, badge_number=f"BADGE-B-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
    await constable_a.insert()
    await constable_b.insert()

    barrier = asyncio.Barrier(2)

    async def attempt(user, key):
        payload = schemas.DeviceRegisterRequest(device_identifier=device_identifier, platform="android")
        await barrier.wait()
        try:
            response = await register_device(payload, user)
            return key, ("succeeded", response.id)
        except HTTPException as exc:
            return key, (f"rejected_{exc.status_code}", None)

    outcomes = dict(await asyncio.gather(attempt(user_a, "a"), attempt(user_b, "b")))

    results = [outcomes["a"][0], outcomes["b"][0]]
    succeeded = [r for r in results if r == "succeeded"]
    rejected = [r for r in results if r.startswith("rejected_")]
    assert len(succeeded) == 1, f"Expected exactly one success: {outcomes}"
    assert len(rejected) == 1, f"Expected exactly one rejection: {outcomes}"
    assert rejected[0] in ("rejected_403", "rejected_409"), f"Unexpected rejection status: {outcomes}"

    rows = await models.Device.find(models.Device.device_identifier == device_identifier).to_list()
    assert len(rows) == 1, f"Expected exactly one device row, found {len(rows)}"


async def test_concurrent_heartbeats_leave_consistent_final_state(mongo_db):
    """
    Two independent requests send heartbeats for the SAME device at
    essentially the same instant. There is no meaningful "winner"/"loser"
    here (heartbeats are pure idempotent overwrites, not a create-vs-reject
    race) -- what must be verified is that the database ends up in a
    single, well-formed, non-corrupted state: exactly one Device document,
    a valid last_seen_at (a real timestamp, not null/garbage), and a valid
    effective status.
    """
    from app import models
    from app.routers.devices import register_device, device_heartbeat, compute_effective_status
    from app.auth.security import hash_password
    from app.routers.settings import load_settings
    import app.schemas as schemas

    device_identifier = f"pgtest-hb-device-{uuid_module.uuid4().hex[:10]}"
    user = models.User(phone=f"pgtest-hb-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
    await user.insert()
    constable = models.Constable(user_id=user.id, badge_number=f"BADGE-HB-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
    await constable.insert()

    await register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), user)

    barrier = asyncio.Barrier(2)

    async def attempt(key, battery):
        payload = schemas.DeviceHeartbeatRequest(device_identifier=device_identifier, battery_percent=battery)
        await barrier.wait()
        try:
            response = await device_heartbeat(payload, user)
            return key, ("ok", response.status)
        except Exception as exc:
            return key, ("error", str(exc))

    outcomes = dict(await asyncio.gather(attempt("a", 70), attempt("b", 72)))

    assert outcomes["a"][0] == "ok", outcomes
    assert outcomes["b"][0] == "ok", outcomes
    assert outcomes["a"][1] in ("online", "stale", "offline")
    assert outcomes["b"][1] in ("online", "stale", "offline")

    devices = await models.Device.find(models.Device.device_identifier == device_identifier).to_list()
    assert len(devices) == 1, f"Expected exactly one device row, found {len(devices)}"
    device = devices[0]
    assert device.last_seen_at is not None
    settings = load_settings()
    effective = compute_effective_status(device, settings)
    assert effective in (models.DeviceStatus.online, models.DeviceStatus.stale, models.DeviceStatus.offline)


async def test_concurrent_battery_reports_both_persisted_no_lost_reading(mongo_db):
    """
    Two simultaneous battery reports for the same device. Since
    BatteryReading is explicitly append-only (not an overwritten scalar),
    BOTH readings must be persisted -- neither request should silently
    lose the other's document.
    """
    from app import models
    from app.routers.devices import register_device, report_battery
    from app.auth.security import hash_password
    import app.schemas as schemas

    device_identifier = f"pgtest-batt-device-{uuid_module.uuid4().hex[:10]}"
    user = models.User(phone=f"pgtest-batt-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
    await user.insert()
    constable = models.Constable(user_id=user.id, badge_number=f"BADGE-BT-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
    await constable.insert()

    device_resp = await register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), user)
    device_id = device_resp.id

    barrier = asyncio.Barrier(2)

    async def attempt(key, battery):
        payload = schemas.DeviceBatteryReportRequest(device_identifier=device_identifier, battery_percent=battery)
        await barrier.wait()
        try:
            response = await report_battery(payload, user)
            return key, ("ok", response.battery_percent)
        except Exception as exc:
            return key, ("error", str(exc))

    outcomes = dict(await asyncio.gather(attempt("a", 55), attempt("b", 56)))

    assert outcomes["a"][0] == "ok", outcomes
    assert outcomes["b"][0] == "ok", outcomes

    readings = await models.BatteryReading.find(models.BatteryReading.device_id == device_id).to_list()
    assert len(readings) == 2, f"Expected both readings persisted, found {len(readings)}"
    percents = {r.battery_percent for r in readings}
    assert percents == {55, 56}


async def test_concurrent_low_battery_reports_create_exactly_one_open_alert(mongo_db):
    """
    THE IMPORTANT ONE. Two simultaneous battery reports, both crossing the
    SAME threshold for the SAME device at essentially the same instant
    (barrier-synchronized, no artificial ordering). Before the fix (see
    the DuplicateKeyError-retry logic in _process_battery_thresholds),
    this was a genuine check-then-insert race that could produce two
    duplicate open alerts. Proves the fix: exactly ONE open alert exists
    for this device afterward, regardless of which request "won".
    """
    from app import models
    from app.routers.devices import register_device, report_battery
    from app.auth.security import hash_password
    import app.schemas as schemas

    device_identifier = f"pgtest-alert-race-{uuid_module.uuid4().hex[:10]}"
    user = models.User(phone=f"pgtest-alert-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
    await user.insert()
    constable = models.Constable(user_id=user.id, badge_number=f"BADGE-AL-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
    await constable.insert()

    device_resp = await register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), user)
    device_id = device_resp.id

    barrier = asyncio.Barrier(2)

    async def attempt(key, battery):
        payload = schemas.DeviceBatteryReportRequest(device_identifier=device_identifier, battery_percent=battery)
        await barrier.wait()
        try:
            await report_battery(payload, user)
            return key, "ok"
        except Exception as exc:
            return key, f"error: {exc}"

    # Both requests cross the SAME (default warning=20) threshold at once.
    outcomes = dict(await asyncio.gather(attempt("a", 19), attempt("b", 18)))

    assert outcomes["a"] == "ok", outcomes
    assert outcomes["b"] == "ok", outcomes

    open_alerts = await models.Alert.find(
        models.Alert.device_id == device_id, models.Alert.status == models.AlertStatus.open
    ).to_list()
    assert len(open_alerts) == 1, f"Expected exactly ONE open alert, found {len(open_alerts)}: {open_alerts}"
    assert open_alerts[0].type == models.AlertType.low_battery
