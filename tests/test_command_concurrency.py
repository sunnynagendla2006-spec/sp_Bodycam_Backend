"""
Genuine concurrent-request tests for RemoteCommand ACK races and
non-battery alert deduplication, against a real MongoDB replica set. Same
established asyncio.gather + asyncio.Barrier pattern as
tests/test_dispatch_concurrency.py.

Needs a reachable MongoDB replica set (see tests/conftest.py's
requires_mongo / TEST_MONGODB_URL) -- skips otherwise.
"""
import asyncio
import uuid as uuid_module

import pytest

from conftest import requires_mongo

pytestmark = [pytest.mark.concurrency, requires_mongo]


async def _setup_command(initial_status=None):
    from app import models
    from app.auth.security import hash_password
    from app.routers.devices import register_device
    from app.routers.commands import create_command, ack_command
    import app.schemas as schemas

    constable_user = models.User(
        phone=f"pgtest-cmd-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable,
        status=models.UserStatus.active, hashed_password=hash_password("pw"),
    )
    await constable_user.insert()
    admin_user = models.User(
        phone=f"pgtest-cmdadmin-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.admin,
        status=models.UserStatus.active, hashed_password=hash_password("pw"),
    )
    await admin_user.insert()

    constable = models.Constable(user_id=constable_user.id, badge_number=f"BADGE-CMD-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
    await constable.insert()

    device_identifier = f"pgtest-cmd-device-{uuid_module.uuid4().hex[:10]}"
    device_resp = await register_device(schemas.DeviceRegisterRequest(device_identifier=device_identifier), constable_user)
    device_id = device_resp.id

    command_resp = await create_command(device_id, schemas.RemoteCommandCreateRequest(command_type=models.RemoteCommandType.start_recording), admin_user)
    command_id = command_resp.id

    if initial_status == "acknowledged":
        await ack_command(command_id, constable_user)

    return constable_user, admin_user, constable.id, device_id, command_id


async def test_concurrent_ack_race_exactly_one_succeeds(mongo_db):
    from app import models
    from app.routers.commands import ack_command
    from fastapi import HTTPException

    constable_user, admin_user, constable_id, device_id, command_id = await _setup_command()
    barrier = asyncio.Barrier(2)

    async def attempt(key):
        await barrier.wait()
        try:
            response = await ack_command(command_id, constable_user)
            return key, ("succeeded", response.status)
        except HTTPException as exc:
            return key, (f"rejected_{exc.status_code}", None)

    outcomes = dict(await asyncio.gather(attempt("a"), attempt("b")))

    results = [outcomes["a"][0], outcomes["b"][0]]
    succeeded = [r for r in results if r == "succeeded"]
    rejected = [r for r in results if r.startswith("rejected_")]
    assert len(succeeded) == 1, f"Expected exactly one success: {outcomes}"
    assert len(rejected) == 1, f"Expected exactly one rejection: {outcomes}"
    assert rejected[0] == "rejected_409", f"Unexpected rejection status: {outcomes}"

    final = await models.RemoteCommand.get(command_id)
    assert final.status == models.RemoteCommandStatus.acknowledged
    assert final.acknowledged_at is not None


async def test_concurrent_ack_vs_premature_result_final_state_always_valid(mongo_db):
    """
    ACK and RESULT race from a SENT command. The atomic compare-and-swap
    genuinely serializes the two calls against the same document, so there
    are exactly two legitimate outcomes depending purely on which request's
    update wins:
      (a) RESULT's update runs first -> sees status=SENT (its
          precondition, ACKNOWLEDGED, isn't met yet) -> correctly 409.
          ACK then proceeds normally -> final state ACKNOWLEDGED.
      (b) ACK's update runs first -> transitions to ACKNOWLEDGED. RESULT's
          update then genuinely observes ACKNOWLEDGED -> its precondition
          IS met now, so it legitimately proceeds too -> final state
          EXECUTED/FAILED.
    Both are correct, non-corrupting outcomes -- what must NEVER happen is
    RESULT succeeding while ACK never happened, or an ambiguous/corrupted
    final status.
    """
    from app import models
    from app.routers.commands import ack_command, command_result
    from fastapi import HTTPException
    import app.schemas as schemas

    constable_user, admin_user, constable_id, device_id, command_id = await _setup_command()
    barrier = asyncio.Barrier(2)

    async def attempt_ack():
        await barrier.wait()
        try:
            response = await ack_command(command_id, constable_user)
            return "ack", ("succeeded", response.status)
        except HTTPException as exc:
            return "ack", (f"rejected_{exc.status_code}", None)

    async def attempt_result():
        await barrier.wait()
        try:
            response = await command_result(command_id, schemas.RemoteCommandResultRequest(success=True), constable_user)
            return "result", ("succeeded", response.status)
        except HTTPException as exc:
            return "result", (f"rejected_{exc.status_code}", None)

    results = dict(await asyncio.gather(attempt_ack(), attempt_result()))

    # ACK's precondition (SENT) is satisfiable regardless of ordering, so
    # it must always succeed. RESULT is conditional -- accept BOTH valid
    # orderings rather than assuming only one (see docstring).
    assert results["ack"][0] == "succeeded", results
    assert results["result"][0] in ("succeeded", "rejected_409"), f"RESULT got an outcome that isn't either legitimate possibility: {results}"

    final = await models.RemoteCommand.get(command_id)
    if results["result"][0] == "succeeded":
        assert final.status in (models.RemoteCommandStatus.executed, models.RemoteCommandStatus.failed), f"RESULT succeeded but final state is invalid: {final.status}"
    else:
        assert final.status == models.RemoteCommandStatus.acknowledged, f"RESULT was rejected but final state isn't ACKNOWLEDGED: {final.status}"


async def test_concurrent_result_race_from_acknowledged_exactly_one_succeeds(mongo_db):
    """A genuine race where BOTH sides have a legitimate chance to win: two simultaneous /result calls from an already-ACKNOWLEDGED command."""
    from app import models
    from app.routers.commands import command_result
    from fastapi import HTTPException
    import app.schemas as schemas

    constable_user, admin_user, constable_id, device_id, command_id = await _setup_command(initial_status="acknowledged")
    barrier = asyncio.Barrier(2)

    async def attempt(key, success):
        await barrier.wait()
        try:
            response = await command_result(command_id, schemas.RemoteCommandResultRequest(success=success), constable_user)
            return key, ("succeeded", response.status)
        except HTTPException as exc:
            return key, (f"rejected_{exc.status_code}", None)

    outcomes = dict(await asyncio.gather(attempt("a", True), attempt("b", False)))

    results = [outcomes["a"][0], outcomes["b"][0]]
    succeeded = [r for r in results if r == "succeeded"]
    rejected = [r for r in results if r.startswith("rejected_")]
    assert len(succeeded) == 1, f"Expected exactly one success: {outcomes}"
    assert len(rejected) == 1, f"Expected exactly one rejection: {outcomes}"
    assert rejected[0] == "rejected_409", f"Unexpected rejection status: {outcomes}"

    final = await models.RemoteCommand.get(command_id)
    assert final.status in (models.RemoteCommandStatus.executed, models.RemoteCommandStatus.failed)


async def test_concurrent_device_offline_alert_creation_exactly_one_open_alert(mongo_db):
    """Same class of race already proven for battery alerts, now proven for the non-battery uq_open_alert_per_device_and_type partial index."""
    from app import models
    from app.services import alerts as alerts_service
    from app.auth.security import hash_password

    user = models.User(phone=f"pgtest-alertrace-{uuid_module.uuid4().hex[:8]}", role=models.UserRole.constable, status=models.UserStatus.active, hashed_password=hash_password("pw"))
    await user.insert()
    constable = models.Constable(user_id=user.id, badge_number=f"BADGE-AR-{uuid_module.uuid4().hex[:8]}", status=models.ConstableStatus.available)
    await constable.insert()
    device = models.Device(constable_id=constable.id, device_identifier=f"pgtest-alertrace-device-{uuid_module.uuid4().hex[:8]}", status=models.DeviceStatus.offline)
    await device.insert()

    barrier = asyncio.Barrier(2)

    async def attempt(key):
        await barrier.wait()
        alert, action = await alerts_service.upsert_open_alert(device, models.AlertType.device_offline, models.AlertSeverity.critical, "concurrent test")
        return key, (action, alert.id if alert else None)

    outcomes = dict(await asyncio.gather(attempt("a"), attempt("b")))

    actions = [outcomes["a"][0], outcomes["b"][0]]
    assert actions.count("created") == 1, f"Expected exactly one 'created', got: {outcomes}"
    assert outcomes["a"][1] == outcomes["b"][1], f"Both calls must resolve to the SAME alert id: {outcomes}"

    open_alerts = await models.Alert.find(
        models.Alert.device_id == device.id,
        models.Alert.type == models.AlertType.device_offline,
        models.Alert.status == models.AlertStatus.open,
    ).to_list()
    assert len(open_alerts) == 1, f"Expected exactly one open alert, found {len(open_alerts)}"
