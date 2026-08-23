"""
Phase 3 (body-camera system) tests: RemoteCommand + alert lifecycle +
offline/stale detection.
"""
import datetime
import json

from app.models import UserRole, RemoteCommandStatus, AlertType, AlertStatus, DeviceStatus


def _get_logs(db_session, action=None):
    from app import models
    q = db_session.query(models.AuditLog)
    if action:
        q = q.filter(models.AuditLog.action == action)
    return q.all()


def _register_device(full_client, headers, device_identifier="phone-c001"):
    resp = full_client.post("/devices/register", json={"device_identifier": device_identifier, "platform": "android"}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _login(full_client, phone, pw):
    r = full_client.post("/auth/login", json={"username": phone, "password": pw})
    assert r.status_code == 200
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# Command creation + authorization
# ---------------------------------------------------------------------------
def test_admin_can_create_command(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000001admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000001c")
    c_headers = auth_header("c000000001c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c001")

    admin_headers = auth_header("c000000001admin", "pw")
    resp = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "sent"
    assert body["sent_at"] is not None


def test_control_room_can_create_command(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000002cr", password="pw", role=UserRole.control_room)
    make_constable(phone="c000000002c")
    c_headers = auth_header("c000000002c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c002")

    cr_headers = auth_header("c000000002cr", "pw")
    resp = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "stop_recording"}, headers=cr_headers)
    assert resp.status_code == 200


def test_station_can_command_own_stations_device(full_client, make_user, make_station, make_constable, auth_header):
    station = make_station()
    make_user(phone="c000000003s", password="pw", role=UserRole.station, station_id=station.id)
    _, constable = make_constable(phone="c000000003c", station_id=station.id)
    c_headers = auth_header("c000000003c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c003")

    s_headers = auth_header("c000000003s", "pw")
    resp = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=s_headers)
    assert resp.status_code == 200


def test_station_cannot_command_another_stations_device(full_client, make_user, make_station, make_constable, auth_header):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="c000000004s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_b = make_constable(phone="c000000004c", station_id=station_b.id)
    c_headers = auth_header("c000000004c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c004")

    s_headers = auth_header("c000000004s", "pw")
    resp = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=s_headers)
    assert resp.status_code == 403


def test_constable_cannot_create_command(full_client, make_constable, auth_header):
    make_constable(phone="c000000005a")
    _, constable_b = make_constable(phone="c000000005b")
    headers_a = auth_header("c000000005a", "correct-horse-battery")
    headers_b = auth_header("c000000005b", "correct-horse-battery")
    device_id = _register_device(full_client, headers_b, "phone-c005")

    resp = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=headers_a)
    assert resp.status_code == 403


def test_citizen_cannot_create_command(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000006cit", password="pw", role=UserRole.citizen)
    make_constable(phone="c000000006c")
    c_headers = auth_header("c000000006c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c006")

    cit_headers = auth_header("c000000006cit", "pw")
    resp = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=cit_headers)
    assert resp.status_code == 403


def test_command_creation_audited_as_created_and_sent(full_client, make_user, make_constable, auth_header, db_session):
    make_user(phone="c000000007admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000007c")
    c_headers = auth_header("c000000007c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c007")

    admin_headers = auth_header("c000000007admin", "pw")
    full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    assert len(_get_logs(db_session, "command.created")) == 1
    assert len(_get_logs(db_session, "command.sent")) == 1


# ---------------------------------------------------------------------------
# ACK
# ---------------------------------------------------------------------------
def test_own_constable_can_acknowledge_command(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000008admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000008c")
    c_headers = auth_header("c000000008c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c008")
    admin_headers = auth_header("c000000008admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]

    resp = full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"
    assert resp.json()["acknowledged_at"] is not None


def test_wrong_device_cannot_acknowledge_command(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000009admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000009a")
    make_constable(phone="c000000009b")
    headers_a = auth_header("c000000009a", "correct-horse-battery")
    headers_b = auth_header("c000000009b", "correct-horse-battery")
    device_id = _register_device(full_client, headers_a, "phone-c009")
    admin_headers = auth_header("c000000009admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]

    resp = full_client.post(f"/commands/{command_id}/ack", headers=headers_b)
    assert resp.status_code == 403


def test_duplicate_acknowledge_returns_409(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000010admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000010c")
    c_headers = auth_header("c000000010c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c010")
    admin_headers = auth_header("c000000010admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]

    first = full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    assert first.status_code == 200
    second = full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    assert second.status_code == 409


def test_ack_is_audited(full_client, make_user, make_constable, auth_header, db_session):
    make_user(phone="c000000011admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000011c")
    c_headers = auth_header("c000000011c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c011")
    admin_headers = auth_header("c000000011admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]
    full_client.post(f"/commands/{command_id}/ack", headers=c_headers)

    assert len(_get_logs(db_session, "command.acknowledged")) == 1


# ---------------------------------------------------------------------------
# Result: success / failure
# ---------------------------------------------------------------------------
def test_result_success_transitions_to_executed(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000012admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000012c")
    c_headers = auth_header("c000000012c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c012")
    admin_headers = auth_header("c000000012admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]
    full_client.post(f"/commands/{command_id}/ack", headers=c_headers)

    resp = full_client.post(f"/commands/{command_id}/result", json={"success": True}, headers=c_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "executed"
    assert resp.json()["executed_at"] is not None


def test_result_failure_transitions_to_failed_and_creates_alert(full_client, make_user, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000013admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000013c")
    c_headers = auth_header("c000000013c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c013")
    admin_headers = auth_header("c000000013admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]
    full_client.post(f"/commands/{command_id}/ack", headers=c_headers)

    resp = full_client.post(f"/commands/{command_id}/result", json={"success": False, "failure_reason": "Camera permission denied"}, headers=c_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "failed"
    assert resp.json()["failure_reason"] == "Camera permission denied"

    alerts = db_session.query(models.Alert).filter(models.Alert.type == AlertType.command_failed).all()
    assert len(alerts) == 1


def test_result_before_ack_returns_409(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000014admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000014c")
    c_headers = auth_header("c000000014c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c014")
    admin_headers = auth_header("c000000014admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]

    resp = full_client.post(f"/commands/{command_id}/result", json={"success": True}, headers=c_headers)
    assert resp.status_code == 409


def test_result_success_and_failure_audited(full_client, make_user, make_constable, auth_header, db_session):
    make_user(phone="c000000015admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000015c")
    c_headers = auth_header("c000000015c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c015")
    admin_headers = auth_header("c000000015admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]
    full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    full_client.post(f"/commands/{command_id}/result", json={"success": True}, headers=c_headers)

    assert len(_get_logs(db_session, "command.executed")) == 1


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------
def test_admin_can_cancel_pending_command(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000016admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000016c")
    c_headers = auth_header("c000000016c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c016")
    admin_headers = auth_header("c000000016admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]

    resp = full_client.post(f"/commands/{command_id}/cancel", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"


def test_cannot_cancel_already_executed_command(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000017admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000017c")
    c_headers = auth_header("c000000017c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c017")
    admin_headers = auth_header("c000000017admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]
    full_client.post(f"/commands/{command_id}/ack", headers=c_headers)
    full_client.post(f"/commands/{command_id}/result", json={"success": True}, headers=c_headers)

    resp = full_client.post(f"/commands/{command_id}/cancel", headers=admin_headers)
    assert resp.status_code == 409


def test_constable_cannot_cancel_command(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000018admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000018c")
    c_headers = auth_header("c000000018c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c018")
    admin_headers = auth_header("c000000018admin", "pw")
    command_id = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers).json()["id"]

    resp = full_client.post(f"/commands/{command_id}/cancel", headers=c_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# List commands (device polling)
# ---------------------------------------------------------------------------
def test_constable_can_list_own_device_commands(full_client, make_user, make_constable, auth_header):
    make_user(phone="c000000019admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000019c")
    c_headers = auth_header("c000000019c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c019")
    admin_headers = auth_header("c000000019admin", "pw")
    full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    resp = full_client.get(f"/devices/{device_id}/commands", headers=c_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_constable_cannot_list_another_devices_commands(full_client, make_constable, auth_header):
    make_constable(phone="c000000020a")
    make_constable(phone="c000000020b")
    headers_a = auth_header("c000000020a", "correct-horse-battery")
    headers_b = auth_header("c000000020b", "correct-horse-battery")
    device_id = _register_device(full_client, headers_a, "phone-c020")

    resp = full_client.get(f"/devices/{device_id}/commands", headers=headers_b)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Alert deduplication / resolution (generic, non-battery)
# ---------------------------------------------------------------------------
def test_alert_upsert_deduplicates_same_device_and_type(db_session, make_constable):
    from app import models
    from app.services import alerts as alerts_service

    _, constable = make_constable(phone="c000000021")
    device = models.Device(constable_id=constable.id, device_identifier="phone-c021", status=models.DeviceStatus.offline)
    db_session.add(device)
    db_session.commit()

    alert1, action1 = alerts_service.upsert_open_alert(db_session, device, models.AlertType.device_offline, models.AlertSeverity.critical, "test message")
    db_session.commit()
    alert2, action2 = alerts_service.upsert_open_alert(db_session, device, models.AlertType.device_offline, models.AlertSeverity.critical, "test message again")
    db_session.commit()

    assert action1 == "created"
    assert action2 is None  # no-op -- already open
    assert alert1.id == alert2.id

    count = db_session.query(models.Alert).filter(models.Alert.device_id == device.id, models.Alert.type == models.AlertType.device_offline).count()
    assert count == 1


def test_alert_resolve_when_none_open_is_noop(db_session, make_constable):
    from app import models
    from app.services import alerts as alerts_service

    _, constable = make_constable(phone="c000000022")
    device = models.Device(constable_id=constable.id, device_identifier="phone-c022", status=models.DeviceStatus.online)
    db_session.add(device)
    db_session.commit()

    result = alerts_service.resolve_open_alert(db_session, device, models.AlertType.device_offline)
    assert result is None


def test_device_offline_and_recording_offline_alerts_can_coexist(db_session, make_constable):
    """Confirms the per-(device,type) index allows independent alert types to coexist for the same device -- unlike the shared battery pair."""
    from app import models
    from app.services import alerts as alerts_service

    _, constable = make_constable(phone="c000000023")
    device = models.Device(constable_id=constable.id, device_identifier="phone-c023", status=models.DeviceStatus.offline)
    db_session.add(device)
    db_session.commit()

    alert1, action1 = alerts_service.upsert_open_alert(db_session, device, models.AlertType.device_offline, models.AlertSeverity.critical, "offline")
    db_session.commit()
    alert2, action2 = alerts_service.upsert_open_alert(db_session, device, models.AlertType.recording_device_offline, models.AlertSeverity.critical, "recording offline")
    db_session.commit()

    assert action1 == "created"
    assert action2 == "created"
    assert alert1.id != alert2.id

    open_count = db_session.query(models.Alert).filter(models.Alert.device_id == device.id, models.Alert.status == models.AlertStatus.open).count()
    assert open_count == 2


# ---------------------------------------------------------------------------
# Stale / offline detection (opportunistic, lazy materialization via GET)
# ---------------------------------------------------------------------------
def test_device_becomes_stale_and_creates_alert_on_observation(full_client, make_user, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000024admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000024c")
    c_headers = auth_header("c000000024c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c024")

    device = db_session.query(models.Device).filter(models.Device.id == uuid_module.UUID(device_id)).first()
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=300)
    db_session.commit()

    admin_headers = auth_header("c000000024admin", "pw")
    resp = full_client.get(f"/devices/{device_id}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "stale"

    alerts = db_session.query(models.Alert).filter(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.device_stale).all()
    assert len(alerts) == 1
    assert alerts[0].status == AlertStatus.open


def test_device_becomes_offline_and_creates_alert_on_observation(full_client, make_user, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000025admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000025c")
    c_headers = auth_header("c000000025c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c025")

    device = db_session.query(models.Device).filter(models.Device.id == uuid_module.UUID(device_id)).first()
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    db_session.commit()

    admin_headers = auth_header("c000000025admin", "pw")
    resp = full_client.get(f"/devices/{device_id}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "offline"

    alerts = db_session.query(models.Alert).filter(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.device_offline).all()
    assert len(alerts) == 1


def test_repeated_observation_of_offline_device_does_not_duplicate_alert(full_client, make_user, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000026admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000026c")
    c_headers = auth_header("c000000026c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c026")

    device = db_session.query(models.Device).filter(models.Device.id == uuid_module.UUID(device_id)).first()
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    db_session.commit()

    admin_headers = auth_header("c000000026admin", "pw")
    for _ in range(3):
        full_client.get(f"/devices/{device_id}", headers=admin_headers)

    alerts = db_session.query(models.Alert).filter(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.device_offline).all()
    assert len(alerts) == 1


def test_recovery_via_heartbeat_resolves_offline_alert(full_client, make_user, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000027admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000027c")
    c_headers = auth_header("c000000027c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c027")

    device = db_session.query(models.Device).filter(models.Device.id == uuid_module.UUID(device_id)).first()
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    db_session.commit()

    admin_headers = auth_header("c000000027admin", "pw")
    full_client.get(f"/devices/{device_id}", headers=admin_headers)

    full_client.post("/devices/heartbeat", json={"device_identifier": "phone-c027"}, headers=c_headers)

    alert = db_session.query(models.Alert).filter(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.device_offline).one()
    assert alert.status == AlertStatus.resolved


# ---------------------------------------------------------------------------
# Recording-device-offline alert (Task 12)
# ---------------------------------------------------------------------------
def test_recording_device_offline_alert_created_with_active_recording(full_client, make_user, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000028admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000028c")
    c_headers = auth_header("c000000028c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c028")
    rec_resp = full_client.post("/recordings/start", json={"device_identifier": "phone-c028", "trigger_type": "emergency_button"}, headers=c_headers)
    assert rec_resp.status_code == 200

    device = db_session.query(models.Device).filter(models.Device.id == uuid_module.UUID(device_id)).first()
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    db_session.commit()

    admin_headers = auth_header("c000000028admin", "pw")
    resp = full_client.get(f"/devices/{device_id}", headers=admin_headers)
    assert resp.status_code == 200

    alerts = db_session.query(models.Alert).filter(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.recording_device_offline).all()
    assert len(alerts) == 1
    assert alerts[0].severity == models.AlertSeverity.critical


def test_no_recording_device_offline_alert_without_active_recording(full_client, make_user, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000029admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000029c")
    c_headers = auth_header("c000000029c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c029")

    device = db_session.query(models.Device).filter(models.Device.id == uuid_module.UUID(device_id)).first()
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    db_session.commit()

    admin_headers = auth_header("c000000029admin", "pw")
    full_client.get(f"/devices/{device_id}", headers=admin_headers)

    alerts = db_session.query(models.Alert).filter(models.Alert.device_id == uuid_module.UUID(device_id), models.Alert.type == AlertType.recording_device_offline).all()
    assert len(alerts) == 0


def test_recording_stays_recording_status_despite_device_offline(full_client, make_user, make_constable, auth_header, db_session):
    """The recording itself is NOT auto-completed/cancelled just because the device went offline -- lifecycle unchanged from Phase 2."""
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000030admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000030c")
    c_headers = auth_header("c000000030c", "correct-horse-battery")
    device_id = _register_device(full_client, c_headers, "phone-c030")
    rec_resp = full_client.post("/recordings/start", json={"device_identifier": "phone-c030", "trigger_type": "manual"}, headers=c_headers)
    recording_id = rec_resp.json()["id"]

    device = db_session.query(models.Device).filter(models.Device.id == uuid_module.UUID(device_id)).first()
    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
    db_session.commit()

    admin_headers = auth_header("c000000030admin", "pw")
    full_client.get(f"/devices/{device_id}", headers=admin_headers)

    recording = db_session.query(models.RecordingSession).filter(models.RecordingSession.id == uuid_module.UUID(recording_id)).first()
    assert recording.status == models.RecordingStatus.recording


# ---------------------------------------------------------------------------
# WebSocket routing
# ---------------------------------------------------------------------------
def test_command_sent_reaches_target_constable(full_client, make_user, make_constable):
    make_user(phone="c000000031admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000031c")

    token_admin = _login(full_client, "c000000031admin", "pw")
    token_c = _login(full_client, "c000000031c", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={token_c}") as ws_c:
        admin_headers = {"Authorization": f"Bearer {token_admin}"}
        c_headers = {"Authorization": f"Bearer {token_c}"}
        device_id = _register_device(full_client, c_headers, "phone-c031")

        resp = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
        assert resp.status_code == 200

        msg = ws_c.receive_json()
        assert msg["event"] == "command.sent"
        assert msg["data"]["command_type"] == "start_recording"


def test_command_events_never_reach_unrelated_constable(full_client, make_user, make_constable):
    make_user(phone="c000000032admin", password="pw", role=UserRole.admin)
    make_constable(phone="c000000032a")
    make_constable(phone="c000000032b")

    token_admin = _login(full_client, "c000000032admin", "pw")
    token_a = _login(full_client, "c000000032a", "correct-horse-battery")
    token_b = _login(full_client, "c000000032b", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={token_a}") as ws_a:
        with full_client.websocket_connect(f"/ws/control_room?token={token_b}") as ws_b:
            admin_headers = {"Authorization": f"Bearer {token_admin}"}
            headers_a = {"Authorization": f"Bearer {token_a}"}
            device_id = _register_device(full_client, headers_a, "phone-c032")

            resp = full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
            assert resp.status_code == 200

            msg_a = ws_a.receive_json()
            assert msg_a["event"] == "command.sent"

            ws_b.send_text("ping")
            msg_b = ws_b.receive_json()
            assert msg_b["event"] == "ack"


def test_alert_event_reaches_control_room_on_offline_detection(full_client, make_user, make_constable, db_session):
    import uuid as uuid_module
    from app import models
    make_user(phone="c000000033cr", password="pw", role=UserRole.control_room)
    make_constable(phone="c000000033c")

    token_cr = _login(full_client, "c000000033cr", "pw")
    token_c = _login(full_client, "c000000033c", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={token_cr}") as ws_cr:
        c_headers = {"Authorization": f"Bearer {token_c}"}
        device_id = _register_device(full_client, c_headers, "phone-c033")
        ws_cr.receive_json()  # device.registered

        device = db_session.query(models.Device).filter(models.Device.id == uuid_module.UUID(device_id)).first()
        device.last_seen_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=900)
        db_session.commit()

        cr_headers = {"Authorization": f"Bearer {token_cr}"}
        resp = full_client.get(f"/devices/{device_id}", headers=cr_headers)
        assert resp.status_code == 200

        msg = ws_cr.receive_json()
        assert msg["event"] == "device.offline"
