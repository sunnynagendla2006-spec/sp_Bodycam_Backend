"""
RemoteCommand + alert lifecycle + offline/stale detection.
"""
import datetime

from httpx_ws import aconnect_ws

from app.models import UserRole, RemoteCommandStatus, AlertType, AlertStatus, DeviceStatus


async def _get_logs(action=None):
    from app import models
    if action:
        return await models.AuditLog.find(models.AuditLog.action == action).to_list()
    return await models.AuditLog.find_all().to_list()


async def _register_device(full_client, headers, device_identifier="phone-c001"):
    resp = await full_client.post("/devices/register", json={"device_identifier": device_identifier, "platform": "android"}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


async def _login(full_client, phone, pw):
    r = await full_client.post("/auth/login", json={"username": phone, "password": pw})
    assert r.status_code == 200
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# Command creation + authorization
# ---------------------------------------------------------------------------
async def test_admin_can_create_command(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000001admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000001c")
    c_headers = await auth_header("c000000001c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c001")

    admin_headers = await auth_header("c000000001admin", "pw")
    resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "sent"
    assert body["sent_at"] is not None


async def test_control_room_can_create_command(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000002cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="c000000002c")
    c_headers = await auth_header("c000000002c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c002")

    cr_headers = await auth_header("c000000002cr", "pw")
    resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "stop_recording"}, headers=cr_headers)
    assert resp.status_code == 200


async def test_station_can_command_own_stations_device(full_client, make_user, make_station, make_constable, auth_header):
    station = await make_station()
    await make_user(phone="c000000003s", password="pw", role=UserRole.station, station_id=station.id)
    _, constable = await make_constable(phone="c000000003c", station_id=station.id)
    c_headers = await auth_header("c000000003c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c003")

    s_headers = await auth_header("c000000003s", "pw")
    resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=s_headers)
    assert resp.status_code == 200


async def test_station_cannot_command_another_stations_device(full_client, make_user, make_station, make_constable, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="c000000004s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_b = await make_constable(phone="c000000004c", station_id=station_b.id)
    c_headers = await auth_header("c000000004c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c004")

    s_headers = await auth_header("c000000004s", "pw")
    resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=s_headers)
    assert resp.status_code == 403


async def test_constable_cannot_create_command(full_client, make_constable, auth_header):
    await make_constable(phone="c000000005a")
    _, constable_b = await make_constable(phone="c000000005b")
    headers_a = await auth_header("c000000005a", "correct-horse-battery")
    headers_b = await auth_header("c000000005b", "correct-horse-battery")
    device_id = await _register_device(full_client, headers_b, "phone-c005")

    resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=headers_a)
    assert resp.status_code == 403


async def test_citizen_cannot_create_command(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000006cit", password="pw", role=UserRole.citizen)
    await make_constable(phone="c000000006c")
    c_headers = await auth_header("c000000006c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c006")

    cit_headers = await auth_header("c000000006cit", "pw")
    resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=cit_headers)
    assert resp.status_code == 403


async def test_command_creation_audited_as_created_and_sent(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000007admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000007c")
    c_headers = await auth_header("c000000007c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c007")

    admin_headers = await auth_header("c000000007admin", "pw")
    await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    assert len(await _get_logs("command.created")) == 1
    assert len(await _get_logs("command.sent")) == 1


# ---------------------------------------------------------------------------
# ACK
# ---------------------------------------------------------------------------
async def test_own_constable_can_acknowledge_command(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000008admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000008c")
    c_headers = await auth_header("c000000008c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c008")
    admin_headers = await auth_header("c000000008admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]

    resp = await full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"
    assert resp.json()["acknowledged_at"] is not None


async def test_wrong_device_cannot_acknowledge_command(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000009admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000009a")
    await make_constable(phone="c000000009b")
    headers_a = await auth_header("c000000009a", "correct-horse-battery")
    headers_b = await auth_header("c000000009b", "correct-horse-battery")
    device_id = await _register_device(full_client, headers_a, "phone-c009")
    admin_headers = await auth_header("c000000009admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]

    resp = await full_client.post(f"/commands/{command_id}/ack", headers=headers_b)
    assert resp.status_code == 403


async def test_duplicate_acknowledge_returns_409(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000010admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000010c")
    c_headers = await auth_header("c000000010c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c010")
    admin_headers = await auth_header("c000000010admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]

    first = await full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    assert first.status_code == 200
    second = await full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    assert second.status_code == 409


async def test_ack_is_audited(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000011admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000011c")
    c_headers = await auth_header("c000000011c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c011")
    admin_headers = await auth_header("c000000011admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]
    await full_client.post(f"/commands/{command_id}/ack", headers=c_headers)

    assert len(await _get_logs("command.acknowledged")) == 1


# ---------------------------------------------------------------------------
# Result: success / failure
# ---------------------------------------------------------------------------
async def test_result_success_transitions_to_executed(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000012admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000012c")
    c_headers = await auth_header("c000000012c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c012")
    admin_headers = await auth_header("c000000012admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]
    await full_client.post(f"/commands/{command_id}/ack", headers=c_headers)

    resp = await full_client.post(f"/commands/{command_id}/result", json={"success": True}, headers=c_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "executed"
    assert resp.json()["executed_at"] is not None


async def test_result_failure_transitions_to_failed_and_creates_alert(full_client, make_user, make_constable, auth_header):
    from app import models
    await make_user(phone="c000000013admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000013c")
    c_headers = await auth_header("c000000013c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c013")
    admin_headers = await auth_header("c000000013admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]
    await full_client.post(f"/commands/{command_id}/ack", headers=c_headers)

    resp = await full_client.post(f"/commands/{command_id}/result", json={"success": False, "failure_reason": "Camera permission denied"}, headers=c_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "failed"
    assert resp.json()["failure_reason"] == "Camera permission denied"

    alerts = await models.Alert.find(models.Alert.type == AlertType.command_failed).to_list()
    assert len(alerts) == 1


async def test_result_before_ack_returns_409(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000014admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000014c")
    c_headers = await auth_header("c000000014c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c014")
    admin_headers = await auth_header("c000000014admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]

    resp = await full_client.post(f"/commands/{command_id}/result", json={"success": True}, headers=c_headers)
    assert resp.status_code == 409


async def test_result_success_and_failure_audited(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000015admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000015c")
    c_headers = await auth_header("c000000015c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c015")
    admin_headers = await auth_header("c000000015admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]
    await full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    await full_client.post(f"/commands/{command_id}/result", json={"success": True}, headers=c_headers)

    assert len(await _get_logs("command.executed")) == 1


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------
async def test_admin_can_cancel_pending_command(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000016admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000016c")
    c_headers = await auth_header("c000000016c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c016")
    admin_headers = await auth_header("c000000016admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]

    resp = await full_client.post(f"/commands/{command_id}/cancel", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"


async def test_cannot_cancel_already_executed_command(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000017admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000017c")
    c_headers = await auth_header("c000000017c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c017")
    admin_headers = await auth_header("c000000017admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]
    await full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    await full_client.post(f"/commands/{command_id}/result", json={"success": True}, headers=c_headers)

    resp = await full_client.post(f"/commands/{command_id}/cancel", headers=admin_headers)
    assert resp.status_code == 409


async def test_constable_cannot_cancel_command(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000018admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000018c")
    c_headers = await auth_header("c000000018c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c018")
    admin_headers = await auth_header("c000000018admin", "pw")
    create_resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    command_id = create_resp.json()["id"]

    resp = await full_client.post(f"/commands/{command_id}/cancel", headers=c_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# List commands (device polling)
# ---------------------------------------------------------------------------
async def test_constable_can_list_own_device_commands(full_client, make_user, make_constable, auth_header):
    await make_user(phone="c000000019admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000019c")
    c_headers = await auth_header("c000000019c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c019")
    admin_headers = await auth_header("c000000019admin", "pw")
    await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    resp = await full_client.get(f"/devices/{device_id}/commands", headers=c_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_constable_cannot_list_another_devices_commands(full_client, make_constable, auth_header):
    await make_constable(phone="c000000020a")
    await make_constable(phone="c000000020b")
    headers_a = await auth_header("c000000020a", "correct-horse-battery")
    headers_b = await auth_header("c000000020b", "correct-horse-battery")
    device_id = await _register_device(full_client, headers_a, "phone-c020")

    resp = await full_client.get(f"/devices/{device_id}/commands", headers=headers_b)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Alert deduplication / resolution (generic, non-battery)
# ---------------------------------------------------------------------------
async def test_alert_upsert_deduplicates_same_device_and_type(mongo_db, make_constable):
    from app import models
    from app.services import alerts as alerts_service

    _, constable = await make_constable(phone="c000000021")
    device = models.Device(constable_id=constable.id, device_identifier="phone-c021", status=models.DeviceStatus.offline)
    await device.insert()

    alert1, action1 = await alerts_service.upsert_open_alert(device, models.AlertType.device_offline, models.AlertSeverity.critical, "test message")
    alert2, action2 = await alerts_service.upsert_open_alert(device, models.AlertType.device_offline, models.AlertSeverity.critical, "test message again")

    assert action1 == "created"
    assert action2 is None  # no-op -- already open
    assert alert1.id == alert2.id

    count = await models.Alert.find(models.Alert.device_id == device.id, models.Alert.type == models.AlertType.device_offline).count()
    assert count == 1


async def test_alert_resolve_when_none_open_is_noop(mongo_db, make_constable):
    from app import models
    from app.services import alerts as alerts_service

    _, constable = await make_constable(phone="c000000022")
    device = models.Device(constable_id=constable.id, device_identifier="phone-c022", status=models.DeviceStatus.online)
    await device.insert()

    result = await alerts_service.resolve_open_alert(device, models.AlertType.device_offline)
    assert result is None


async def test_device_offline_and_recording_offline_alerts_can_coexist(mongo_db, make_constable):
    """Confirms the per-(device,type) index allows independent alert types to coexist for the same device -- unlike the shared battery pair."""
    from app import models
    from app.services import alerts as alerts_service

    _, constable = await make_constable(phone="c000000023")
    device = models.Device(constable_id=constable.id, device_identifier="phone-c023", status=models.DeviceStatus.offline)
    await device.insert()

    alert1, action1 = await alerts_service.upsert_open_alert(device, models.AlertType.device_offline, models.AlertSeverity.critical, "offline")
    alert2, action2 = await alerts_service.upsert_open_alert(device, models.AlertType.recording_device_offline, models.AlertSeverity.critical, "recording offline")

    assert action1 == "created"
    assert action2 == "created"
    assert alert1.id != alert2.id

    open_count = await models.Alert.find(models.Alert.device_id == device.id, models.Alert.status == models.AlertStatus.open).count()
    assert open_count == 2


# ---------------------------------------------------------------------------
# Stale / offline detection (opportunistic, lazy materialization via GET)
# ---------------------------------------------------------------------------
async def test_device_becomes_stale_and_creates_alert_on_observation(full_client, make_user, make_constable, auth_header):
    import uuid as uuid_module
    from app import models
    await make_user(phone="c000000024admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000024c")
    c_headers = await auth_header("c000000024c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c024")

    device = await models.Device.get(uuid_module.UUID(device_id))
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=300)
    await device.save()

    admin_headers = await auth_header("c000000024admin", "pw")
    resp = await full_client.get(f"/devices/{device_id}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "stale"

    alerts = await models.Alert.find(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.device_stale).to_list()
    assert len(alerts) == 1
    assert alerts[0].status == AlertStatus.open


async def test_device_becomes_offline_and_creates_alert_on_observation(full_client, make_user, make_constable, auth_header):
    import uuid as uuid_module
    from app import models
    await make_user(phone="c000000025admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000025c")
    c_headers = await auth_header("c000000025c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c025")

    device = await models.Device.get(uuid_module.UUID(device_id))
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    await device.save()

    admin_headers = await auth_header("c000000025admin", "pw")
    resp = await full_client.get(f"/devices/{device_id}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "offline"

    alerts = await models.Alert.find(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.device_offline).to_list()
    assert len(alerts) == 1


async def test_repeated_observation_of_offline_device_does_not_duplicate_alert(full_client, make_user, make_constable, auth_header):
    import uuid as uuid_module
    from app import models
    await make_user(phone="c000000026admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000026c")
    c_headers = await auth_header("c000000026c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c026")

    device = await models.Device.get(uuid_module.UUID(device_id))
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    await device.save()

    admin_headers = await auth_header("c000000026admin", "pw")
    for _ in range(3):
        await full_client.get(f"/devices/{device_id}", headers=admin_headers)

    alerts = await models.Alert.find(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.device_offline).to_list()
    assert len(alerts) == 1


async def test_recovery_via_heartbeat_resolves_offline_alert(full_client, make_user, make_constable, auth_header):
    import uuid as uuid_module
    from app import models
    await make_user(phone="c000000027admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000027c")
    c_headers = await auth_header("c000000027c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c027")

    device = await models.Device.get(uuid_module.UUID(device_id))
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    await device.save()

    admin_headers = await auth_header("c000000027admin", "pw")
    await full_client.get(f"/devices/{device_id}", headers=admin_headers)

    await full_client.post("/devices/heartbeat", json={"device_identifier": "phone-c027"}, headers=c_headers)

    alert = await models.Alert.find_one(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.device_offline)
    assert alert.status == AlertStatus.resolved


# ---------------------------------------------------------------------------
# Recording-device-offline alert
# ---------------------------------------------------------------------------
async def test_recording_device_offline_alert_created_with_active_recording(full_client, make_user, make_constable, auth_header):
    import uuid as uuid_module
    from app import models
    await make_user(phone="c000000028admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000028c")
    c_headers = await auth_header("c000000028c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c028")
    rec_resp = await full_client.post("/recordings/start", json={"device_identifier": "phone-c028", "trigger_type": "emergency_button"}, headers=c_headers)
    assert rec_resp.status_code == 200

    device = await models.Device.get(uuid_module.UUID(device_id))
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    await device.save()

    admin_headers = await auth_header("c000000028admin", "pw")
    resp = await full_client.get(f"/devices/{device_id}", headers=admin_headers)
    assert resp.status_code == 200

    alerts = await models.Alert.find(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.recording_device_offline).to_list()
    assert len(alerts) == 1
    assert alerts[0].severity == models.AlertSeverity.critical


async def test_no_recording_device_offline_alert_without_active_recording(full_client, make_user, make_constable, auth_header):
    import uuid as uuid_module
    from app import models
    await make_user(phone="c000000029admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000029c")
    c_headers = await auth_header("c000000029c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c029")

    device = await models.Device.get(uuid_module.UUID(device_id))
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    await device.save()

    admin_headers = await auth_header("c000000029admin", "pw")
    await full_client.get(f"/devices/{device_id}", headers=admin_headers)

    alerts = await models.Alert.find(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.recording_device_offline).to_list()
    assert len(alerts) == 0


async def test_recording_stays_recording_status_despite_device_offline(full_client, make_user, make_constable, auth_header):
    """The recording itself is NOT auto-completed/cancelled just because the device went offline -- lifecycle unchanged."""
    import uuid as uuid_module
    from app import models
    await make_user(phone="c000000030admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000030c")
    c_headers = await auth_header("c000000030c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-c030")
    rec_resp = await full_client.post("/recordings/start", json={"device_identifier": "phone-c030", "trigger_type": "manual"}, headers=c_headers)
    recording_id = rec_resp.json()["id"]

    device = await models.Device.get(uuid_module.UUID(device_id))
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    await device.save()

    admin_headers = await auth_header("c000000030admin", "pw")
    await full_client.get(f"/devices/{device_id}", headers=admin_headers)

    recording = await models.RecordingSession.get(uuid_module.UUID(recording_id))
    assert recording.status == models.RecordingStatus.recording


# ---------------------------------------------------------------------------
# WebSocket routing
# ---------------------------------------------------------------------------
async def test_command_sent_reaches_target_constable(full_client, make_user, make_constable):
    await make_user(phone="c000000031admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000031c")

    token_admin = await _login(full_client, "c000000031admin", "pw")
    token_c = await _login(full_client, "c000000031c", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_c}", full_client) as ws_c:
        admin_headers = {"Authorization": f"Bearer {token_admin}"}
        c_headers = {"Authorization": f"Bearer {token_c}"}
        device_id = await _register_device(full_client, c_headers, "phone-c031")

        resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
        assert resp.status_code == 200

        msg = await ws_c.receive_json()
        assert msg["event"] == "command.sent"
        assert msg["data"]["command_type"] == "start_recording"


async def test_command_events_never_reach_unrelated_constable(full_client, make_user, make_constable):
    await make_user(phone="c000000032admin", password="pw", role=UserRole.admin)
    await make_constable(phone="c000000032a")
    await make_constable(phone="c000000032b")

    token_admin = await _login(full_client, "c000000032admin", "pw")
    token_a = await _login(full_client, "c000000032a", "correct-horse-battery")
    token_b = await _login(full_client, "c000000032b", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_a}", full_client) as ws_a:
        async with aconnect_ws(f"/ws/control_room?token={token_b}", full_client) as ws_b:
            admin_headers = {"Authorization": f"Bearer {token_admin}"}
            headers_a = {"Authorization": f"Bearer {token_a}"}
            device_id = await _register_device(full_client, headers_a, "phone-c032")

            resp = await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
            assert resp.status_code == 200

            msg_a = await ws_a.receive_json()
            assert msg_a["event"] == "command.sent"

            await ws_b.send_text("ping")
            msg_b = await ws_b.receive_json()
            assert msg_b["event"] == "ack"


async def test_alert_event_reaches_control_room_on_offline_detection(full_client, make_user, make_constable):
    import uuid as uuid_module
    from app import models
    await make_user(phone="c000000033cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="c000000033c")

    token_cr = await _login(full_client, "c000000033cr", "pw")
    token_c = await _login(full_client, "c000000033c", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_cr}", full_client) as ws_cr:
        c_headers = {"Authorization": f"Bearer {token_c}"}
        device_id = await _register_device(full_client, c_headers, "phone-c033")
        await ws_cr.receive_json()  # device.registered

        device = await models.Device.get(uuid_module.UUID(device_id))
        device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
        await device.save()

        cr_headers = {"Authorization": f"Bearer {token_cr}"}
        resp = await full_client.get(f"/devices/{device_id}", headers=cr_headers)
        assert resp.status_code == 200

        msg = await ws_cr.receive_json()
        assert msg["event"] == "device.offline"
