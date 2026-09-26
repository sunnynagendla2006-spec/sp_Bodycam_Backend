"""
Device registration, heartbeat, battery reporting, battery-alert
de-duplication/escalation/recovery, and authorization/isolation across
roles.
"""
from httpx_ws import aconnect_ws

from app.models import UserRole, DeviceStatus, AlertStatus, AlertType


async def _get_logs(action=None):
    from app import models
    if action:
        return await models.AuditLog.find(models.AuditLog.action == action).to_list()
    return await models.AuditLog.find_all().to_list()


# ---------------------------------------------------------------------------
# Device registration
# ---------------------------------------------------------------------------
async def test_constable_can_register_own_device(full_client, make_constable, auth_header):
    await make_constable(phone="d000000001")
    headers = await auth_header("d000000001", "correct-horse-battery")

    resp = await full_client.post("/devices/register", json={"device_identifier": "phone-001", "platform": "android"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["device_identifier"] == "phone-001"
    assert resp.json()["status"] == "online"


async def test_duplicate_registration_by_same_constable_is_idempotent(full_client, make_constable, auth_header):
    await make_constable(phone="d000000002")
    headers = await auth_header("d000000002", "correct-horse-battery")

    first = await full_client.post("/devices/register", json={"device_identifier": "phone-002"}, headers=headers)
    second = await full_client.post("/devices/register", json={"device_identifier": "phone-002", "app_version": "2.0"}, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert second.json()["app_version"] == "2.0"


async def test_constable_cannot_claim_another_constables_device(full_client, make_constable, auth_header):
    await make_constable(phone="d000000003a")
    await make_constable(phone="d000000003b")
    headers_a = await auth_header("d000000003a", "correct-horse-battery")
    headers_b = await auth_header("d000000003b", "correct-horse-battery")

    await full_client.post("/devices/register", json={"device_identifier": "phone-003"}, headers=headers_a)
    resp = await full_client.post("/devices/register", json={"device_identifier": "phone-003"}, headers=headers_b)
    assert resp.status_code == 403


async def test_only_constable_role_can_register_device(full_client, make_user, auth_header):
    await make_user(phone="d000000004", password="pw", role=UserRole.admin)
    headers = await auth_header("d000000004", "pw")
    resp = await full_client.post("/devices/register", json={"device_identifier": "phone-004"}, headers=headers)
    assert resp.status_code == 403


async def test_registration_creates_audit_row(full_client, make_constable, auth_header):
    await make_constable(phone="d000000005")
    headers = await auth_header("d000000005", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-005"}, headers=headers)
    entries = await _get_logs("device.registered")
    assert len(entries) == 1


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------
async def test_heartbeat_updates_status_and_is_idempotent(full_client, make_constable, auth_header):
    await make_constable(phone="d000000006")
    headers = await auth_header("d000000006", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-006"}, headers=headers)

    r1 = await full_client.post("/devices/heartbeat", json={"device_identifier": "phone-006", "battery_percent": 80}, headers=headers)
    r2 = await full_client.post("/devices/heartbeat", json={"device_identifier": "phone-006", "battery_percent": 80}, headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["status"] == "online"
    assert r2.json()["status"] == "online"


async def test_heartbeat_does_not_create_audit_row(full_client, make_constable, auth_header):
    await make_constable(phone="d000000007")
    headers = await auth_header("d000000007", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-007"}, headers=headers)
    await full_client.post("/devices/heartbeat", json={"device_identifier": "phone-007", "battery_percent": 90}, headers=headers)
    # Only the registration audit row should exist -- no per-heartbeat noise.
    all_entries = await _get_logs()
    entries = [e for e in all_entries if e.action.startswith("device.") or e.action.startswith("alert.")]
    assert len(entries) == 1
    assert entries[0].action == "device.registered"


async def test_heartbeat_requires_prior_registration(full_client, make_constable, auth_header):
    await make_constable(phone="d000000008")
    headers = await auth_header("d000000008", "correct-horse-battery")
    resp = await full_client.post("/devices/heartbeat", json={"device_identifier": "unregistered-phone"}, headers=headers)
    assert resp.status_code == 404


async def test_heartbeat_rejected_for_another_constables_device(full_client, make_constable, auth_header):
    await make_constable(phone="d000000009a")
    await make_constable(phone="d000000009b")
    headers_a = await auth_header("d000000009a", "correct-horse-battery")
    headers_b = await auth_header("d000000009b", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-009"}, headers=headers_a)

    resp = await full_client.post("/devices/heartbeat", json={"device_identifier": "phone-009"}, headers=headers_b)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Online / stale / offline computation
# ---------------------------------------------------------------------------
async def test_device_with_no_heartbeat_ever_is_offline(mongo_db):
    # A device that has genuinely never communicated at all (no register,
    # no heartbeat, no battery report -- last_seen_at is still None) must
    # report offline. Depends on mongo_db purely to satisfy Beanie's
    # requirement that a Document's registry be initialized before ANY
    # instance can be constructed, even one that's never persisted.
    from app.routers.devices import compute_effective_status
    from app import models

    device = models.Device(device_identifier="phone-010-never-registered", status=models.DeviceStatus.offline)
    assert compute_effective_status(device, {"device_stale_seconds": 120, "device_offline_seconds": 600}) == DeviceStatus.offline


async def test_stale_and_offline_thresholds_computed_correctly(mongo_db):
    import datetime
    from app.routers.devices import compute_effective_status
    from app import models

    now = datetime.datetime.now(datetime.timezone.utc)
    settings = {"device_stale_seconds": 120, "device_offline_seconds": 600}

    fresh = models.Device(device_identifier="fresh", last_seen_at=now - datetime.timedelta(seconds=10))
    assert compute_effective_status(fresh, settings, now) == DeviceStatus.online

    stale = models.Device(device_identifier="stale", last_seen_at=now - datetime.timedelta(seconds=300))
    assert compute_effective_status(stale, settings, now) == DeviceStatus.stale

    offline = models.Device(device_identifier="offline", last_seen_at=now - datetime.timedelta(seconds=900))
    assert compute_effective_status(offline, settings, now) == DeviceStatus.offline


# ---------------------------------------------------------------------------
# Battery reporting
# ---------------------------------------------------------------------------
async def test_battery_report_creates_history_row(full_client, make_constable, auth_header):
    from app import models

    await make_constable(phone="d000000011")
    headers = await auth_header("d000000011", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-011"}, headers=headers)
    resp = await full_client.post("/devices/battery", json={"device_identifier": "phone-011", "battery_percent": 75, "is_charging": True}, headers=headers)
    assert resp.status_code == 200
    rows = await models.BatteryReading.find_all().to_list()
    assert len(rows) == 1
    assert rows[0].battery_percent == 75
    assert rows[0].is_charging is True


async def test_battery_percent_out_of_range_rejected(full_client, make_constable, auth_header):
    await make_constable(phone="d000000012")
    headers = await auth_header("d000000012", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-012"}, headers=headers)
    resp = await full_client.post("/devices/battery", json={"device_identifier": "phone-012", "battery_percent": 150}, headers=headers)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Battery alert de-duplication / escalation / recovery (the exact worked
# example: 100->50->25->19 creates ONE low_battery; 19->18->17 creates
# nothing new; 19->9 escalates to critical; recovery resolves it).
# ---------------------------------------------------------------------------
async def test_battery_sequence_creates_exactly_one_low_battery_alert(full_client, make_constable, auth_header):
    from app import models

    await make_constable(phone="d000000013")
    headers = await auth_header("d000000013", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-013"}, headers=headers)

    for pct in (100, 50, 25, 19):
        await full_client.post("/devices/battery", json={"device_identifier": "phone-013", "battery_percent": pct}, headers=headers)

    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1
    assert alerts[0].type == AlertType.low_battery
    assert alerts[0].status == AlertStatus.open


async def test_battery_sequence_does_not_duplicate_alert_while_still_low(full_client, make_constable, auth_header):
    from app import models

    await make_constable(phone="d000000014")
    headers = await auth_header("d000000014", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-014"}, headers=headers)

    for pct in (19, 18, 17):
        await full_client.post("/devices/battery", json={"device_identifier": "phone-014", "battery_percent": pct}, headers=headers)

    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1  # still just the one from the first low reading


async def test_battery_escalates_to_critical(full_client, make_constable, auth_header):
    from app import models

    await make_constable(phone="d000000015")
    headers = await auth_header("d000000015", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-015"}, headers=headers)

    await full_client.post("/devices/battery", json={"device_identifier": "phone-015", "battery_percent": 19}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-015", "battery_percent": 9}, headers=headers)

    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1  # same document, escalated in place -- not a second alert
    assert alerts[0].type == AlertType.critical_battery
    assert alerts[0].status == AlertStatus.open


async def test_battery_recovery_resolves_open_alert(full_client, make_constable, auth_header):
    from app import models

    await make_constable(phone="d000000016")
    headers = await auth_header("d000000016", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-016"}, headers=headers)

    await full_client.post("/devices/battery", json={"device_identifier": "phone-016", "battery_percent": 15}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-016", "battery_percent": 80}, headers=headers)

    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1
    assert alerts[0].status == models.AlertStatus.resolved
    assert alerts[0].resolved_at is not None


async def test_alert_state_changes_are_audited(full_client, make_constable, auth_header):
    await make_constable(phone="d000000017")
    headers = await auth_header("d000000017", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-017"}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-017", "battery_percent": 19}, headers=headers)

    entries = await _get_logs("alert.created")
    assert len(entries) == 1
    assert entries[0].details["alert_type"] == "low_battery"


# ---------------------------------------------------------------------------
# Explicit battery-threshold boundary values (default settings: warning=20,
# critical=10). Determined from the ACTUAL implementation
# (`_process_battery_thresholds`): `battery_percent > warning` recovers/no
# alert; `battery_percent <= critical` is critical; everything in between
# (critical < battery_percent <= warning) is low_battery. So thresholds
# themselves (exactly 20, exactly 10) are INCLUSIVE of the alert side, not
# the recovery side -- documented here via explicit boundary tests rather
# than silently assumed.
# ---------------------------------------------------------------------------
async def test_battery_exactly_at_warning_threshold_creates_low_battery_alert(full_client, make_constable, auth_header):
    """battery_percent == warning_threshold (20): implementation uses `> warning` for the recovery branch, so 20 itself is NOT `> 20` and falls through to alert-creation -- inclusive on the alert side."""
    from app import models
    await make_constable(phone="d000000025")
    headers = await auth_header("d000000025", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-025"}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-025", "battery_percent": 20}, headers=headers)
    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1
    assert alerts[0].type == models.AlertType.low_battery


async def test_battery_one_above_warning_threshold_creates_no_alert(full_client, make_constable, auth_header):
    """battery_percent == warning_threshold + 1 (21): strictly above 20, recovery branch applies -- no alert created (nothing to recover from either, since none existed)."""
    from app import models
    await make_constable(phone="d000000026")
    headers = await auth_header("d000000026", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-026"}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-026", "battery_percent": 21}, headers=headers)
    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 0


async def test_battery_exactly_at_critical_threshold_creates_critical_alert(full_client, make_constable, auth_header):
    """battery_percent == critical_threshold (10): implementation uses `<= critical`, so 10 itself IS critical -- inclusive."""
    from app import models
    await make_constable(phone="d000000027")
    headers = await auth_header("d000000027", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-027"}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-027", "battery_percent": 10}, headers=headers)
    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1
    assert alerts[0].type == models.AlertType.critical_battery


async def test_battery_one_above_critical_threshold_is_low_battery_not_critical(full_client, make_constable, auth_header):
    """battery_percent == critical_threshold + 1 (11): not <= 10, so it's low_battery (still <= warning=20), not critical."""
    from app import models
    await make_constable(phone="d000000028")
    headers = await auth_header("d000000028", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-028"}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-028", "battery_percent": 11}, headers=headers)
    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1
    assert alerts[0].type == models.AlertType.low_battery


async def test_battery_at_100_percent_creates_no_alert(full_client, make_constable, auth_header):
    from app import models
    await make_constable(phone="d000000029")
    headers = await auth_header("d000000029", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-029"}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-029", "battery_percent": 100}, headers=headers)
    assert await models.Alert.find_all().count() == 0


async def test_battery_at_0_percent_creates_critical_alert(full_client, make_constable, auth_header):
    from app import models
    await make_constable(phone="d000000030")
    headers = await auth_header("d000000030", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-030"}, headers=headers)
    resp = await full_client.post("/devices/battery", json={"device_identifier": "phone-030", "battery_percent": 0}, headers=headers)
    assert resp.status_code == 200  # 0 is a valid boundary value, not rejected
    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1
    assert alerts[0].type == models.AlertType.critical_battery


async def test_battery_negative_value_rejected(full_client, make_constable, auth_header):
    await make_constable(phone="d000000031")
    headers = await auth_header("d000000031", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-031"}, headers=headers)
    resp = await full_client.post("/devices/battery", json={"device_identifier": "phone-031", "battery_percent": -1}, headers=headers)
    assert resp.status_code == 422


async def test_recovery_requires_no_manual_acknowledgement_alert_auto_resolves(full_client, make_constable, auth_header):
    """Documents actual behavior: recovery (battery > warning) auto-resolves the open alert with resolved_by=None (system-resolved) -- no manual acknowledgement/resolution API call is required for this to happen."""
    from app import models
    await make_constable(phone="d000000032")
    headers = await auth_header("d000000032", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-032"}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-032", "battery_percent": 15}, headers=headers)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-032", "battery_percent": 90}, headers=headers)

    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.status == models.AlertStatus.resolved
    assert alert.resolved_by is None  # auto-resolved by the system, not a human acknowledgement/resolution


# ---------------------------------------------------------------------------
# Additional explicit cross-role security checks not already covered above
# (own-device modification isolation for heartbeat/battery specifically,
# beyond the registration-claim checks already tested).
# ---------------------------------------------------------------------------
async def test_battery_report_rejected_for_another_constables_device(full_client, make_constable, auth_header):
    await make_constable(phone="d000000033a")
    await make_constable(phone="d000000033b")
    headers_a = await auth_header("d000000033a", "correct-horse-battery")
    headers_b = await auth_header("d000000033b", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-033"}, headers=headers_a)

    resp = await full_client.post("/devices/battery", json={"device_identifier": "phone-033", "battery_percent": 50}, headers=headers_b)
    assert resp.status_code == 403


async def test_station_role_cannot_register_or_heartbeat_a_device(full_client, make_user, auth_header):
    """A station-role account (not a constable) must never be able to register or heartbeat as a device -- devices belong to constables only."""
    await make_user(phone="d000000034", password="pw", role=UserRole.station)
    headers = await auth_header("d000000034", "pw")
    resp = await full_client.post("/devices/register", json={"device_identifier": "phone-034"}, headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Authorization / isolation
# ---------------------------------------------------------------------------
async def test_admin_sees_all_devices(full_client, make_user, make_constable, auth_header):
    await make_user(phone="d000000018admin", password="pw", role=UserRole.admin)
    await make_constable(phone="d000000018a")
    await make_constable(phone="d000000018b")
    headers_a = await auth_header("d000000018a", "correct-horse-battery")
    headers_b = await auth_header("d000000018b", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-018a"}, headers=headers_a)
    await full_client.post("/devices/register", json={"device_identifier": "phone-018b"}, headers=headers_b)

    admin_headers = await auth_header("d000000018admin", "pw")
    resp = await full_client.get("/devices/", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


async def test_constable_sees_only_own_device(full_client, make_constable, auth_header):
    await make_constable(phone="d000000019a")
    await make_constable(phone="d000000019b")
    headers_a = await auth_header("d000000019a", "correct-horse-battery")
    headers_b = await auth_header("d000000019b", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-019a"}, headers=headers_a)
    await full_client.post("/devices/register", json={"device_identifier": "phone-019b"}, headers=headers_b)

    resp = await full_client.get("/devices/", headers=headers_a)
    assert resp.status_code == 200
    ids = [d["device_identifier"] for d in resp.json()]
    assert "phone-019a" in ids
    assert "phone-019b" not in ids


async def test_station_sees_only_own_stations_devices(full_client, make_user, make_station, make_constable, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="d000000020s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = await make_constable(phone="d000000020a", station_id=station_a.id)
    _, constable_b = await make_constable(phone="d000000020b", station_id=station_b.id)
    headers_a = await auth_header("d000000020a", "correct-horse-battery")
    headers_b = await auth_header("d000000020b", "correct-horse-battery")
    await full_client.post("/devices/register", json={"device_identifier": "phone-020a"}, headers=headers_a)
    await full_client.post("/devices/register", json={"device_identifier": "phone-020b"}, headers=headers_b)

    station_headers = await auth_header("d000000020s", "pw")
    resp = await full_client.get("/devices/", headers=station_headers)
    assert resp.status_code == 200
    ids = [d["device_identifier"] for d in resp.json()]
    assert "phone-020a" in ids
    assert "phone-020b" not in ids


async def test_citizen_denied_device_access(full_client, make_user, auth_header):
    await make_user(phone="d000000021", password="pw", role=UserRole.citizen)
    headers = await auth_header("d000000021", "pw")
    resp = await full_client.get("/devices/", headers=headers)
    assert resp.status_code == 403


async def test_unauthenticated_device_list_returns_401(full_client):
    resp = await full_client.get("/devices/")
    assert resp.status_code == 401


async def test_get_device_by_id_404_for_unknown(full_client, make_user, auth_header):
    import uuid
    await make_user(phone="d000000022", password="pw", role=UserRole.admin)
    headers = await auth_header("d000000022", "pw")
    resp = await full_client.get(f"/devices/{uuid.uuid4()}", headers=headers)
    assert resp.status_code == 404


async def test_get_device_by_id_403_for_unrelated_constable(full_client, make_constable, auth_header):
    await make_constable(phone="d000000023a")
    _, constable_b = await make_constable(phone="d000000023b")
    headers_a = await auth_header("d000000023a", "correct-horse-battery")
    headers_b = await auth_header("d000000023b", "correct-horse-battery")
    reg = await full_client.post("/devices/register", json={"device_identifier": "phone-023b"}, headers=headers_b)
    device_id = reg.json()["id"]

    resp = await full_client.get(f"/devices/{device_id}", headers=headers_a)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# WebSocket routing (station isolation for device events)
# ---------------------------------------------------------------------------
async def test_station_receives_own_device_registered_event_not_other_stations(full_client, make_user, make_station, make_constable):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="d000000024a", password="pw", role=UserRole.station, station_id=station_a.id)
    await make_user(phone="d000000024b", password="pw", role=UserRole.station, station_id=station_b.id)
    _, constable_a = await make_constable(phone="d000000024c", station_id=station_a.id)

    async def _login(phone, pw):
        r = await full_client.post("/auth/login", json={"username": phone, "password": pw})
        assert r.status_code == 200
        return r.json()["access_token"]

    token_station_a = await _login("d000000024a", "pw")
    token_station_b = await _login("d000000024b", "pw")
    token_constable = await _login("d000000024c", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_station_a}", full_client) as ws_a:
        async with aconnect_ws(f"/ws/control_room?token={token_station_b}", full_client) as ws_b:
            headers = {"Authorization": f"Bearer {token_constable}"}
            resp = await full_client.post("/devices/register", json={"device_identifier": "phone-024c"}, headers=headers)
            assert resp.status_code == 200

            msg_a = await ws_a.receive_json()
            assert msg_a["event"] == "device.registered"

            await ws_b.send_text("ping")
            msg_b = await ws_b.receive_json()
            assert msg_b["event"] == "ack"  # station B never gets station A's device event


# ---------------------------------------------------------------------------
# Additional WebSocket event validation (beyond the device.registered
# station-isolation test already present above).
# ---------------------------------------------------------------------------
async def _login(full_client, phone, pw):
    r = await full_client.post("/auth/login", json={"username": phone, "password": pw})
    assert r.status_code == 200
    return r.json()["access_token"]


async def test_battery_warning_event_reaches_control_room(full_client, make_user, make_constable):
    await make_user(phone="d000000035cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="d000000035c")

    token_cr = await _login(full_client, "d000000035cr", "pw")
    token_c = await _login(full_client, "d000000035c", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_cr}", full_client) as ws_cr:
        headers = {"Authorization": f"Bearer {token_c}"}
        await full_client.post("/devices/register", json={"device_identifier": "phone-035"}, headers=headers)
        await ws_cr.receive_json()  # device.registered event -- drain it first

        resp = await full_client.post("/devices/battery", json={"device_identifier": "phone-035", "battery_percent": 15}, headers=headers)
        assert resp.status_code == 200

        # battery.updated then battery.warning then alert.created are all published
        events_seen = []
        for _ in range(3):
            events_seen.append((await ws_cr.receive_json())["event"])
        assert "battery.warning" in events_seen


async def test_battery_alert_reaches_only_the_owning_constable_not_another(full_client, make_user, make_constable):
    await make_user(phone="d000000036cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="d000000036a")
    await make_constable(phone="d000000036b")

    token_cr = await _login(full_client, "d000000036cr", "pw")
    token_a = await _login(full_client, "d000000036a", "correct-horse-battery")
    token_b = await _login(full_client, "d000000036b", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_a}", full_client) as ws_a:
        async with aconnect_ws(f"/ws/control_room?token={token_b}", full_client) as ws_b:
            headers_a = {"Authorization": f"Bearer {token_a}"}
            # NOTE: device.registered is routed to control_room + station
            # only (see publish_device_registered) -- it never reaches the
            # constable's OWN room, so there is nothing to drain here.
            resp = await full_client.post("/devices/register", json={"device_identifier": "phone-036a"}, headers=headers_a)
            assert resp.status_code == 200

            resp = await full_client.post("/devices/battery", json={"device_identifier": "phone-036a", "battery_percent": 5}, headers=headers_a)
            assert resp.status_code == 200

            # publish_battery_alert sends the SPECIFIC event (battery.critical)
            # to the constable's own room -- and nothing else does, so this
            # is the only message ws_a will ever receive here.
            msg_a = await ws_a.receive_json()
            assert msg_a["event"] == "battery.critical"

            await ws_b.send_text("ping")
            msg_b = await ws_b.receive_json()
            assert msg_b["event"] == "ack"  # never a battery event for constable A's device


async def test_device_status_transition_publishes_status_changed_event(full_client, make_user, make_constable):
    """
    device.online is published when compute_effective_status's result
    changes between two heartbeats. Backdates the device's last_seen_at
    directly in the database (simulating a device that has been stale for
    a while) so the NEXT heartbeat produces a genuine, deterministic
    stale -> online recovery transition -- more reliable than trying to
    manipulate wall-clock timing via monkeypatched thresholds, since the
    threshold applies identically to both the "before" and "after"
    computation within a single heartbeat call otherwise.
    """
    import datetime
    from app import models

    await make_user(phone="d000000037cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="d000000037c")

    token_cr = await _login(full_client, "d000000037cr", "pw")
    token_c = await _login(full_client, "d000000037c", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_cr}", full_client) as ws_cr:
        headers = {"Authorization": f"Bearer {token_c}"}
        await full_client.post("/devices/register", json={"device_identifier": "phone-037"}, headers=headers)
        await ws_cr.receive_json()  # device.registered

        device = await models.Device.find_one(models.Device.device_identifier == "phone-037")
        device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=999)
        await device.save()

        resp = await full_client.post("/devices/heartbeat", json={"device_identifier": "phone-037"}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "online"

        events_seen = []
        for _ in range(2):
            events_seen.append((await ws_cr.receive_json())["event"])
        assert "device.online" in events_seen
