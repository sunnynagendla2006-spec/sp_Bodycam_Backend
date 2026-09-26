"""
Read-only listing endpoints for Alerts, Recordings, and Commands.
"""
from app.models import UserRole, AlertType, AlertSeverity, AlertStatus, RecordingStatus, RemoteCommandStatus


async def _register_device(full_client, headers, device_identifier="phone-p4a"):
    resp = await full_client.post("/devices/register", json={"device_identifier": device_identifier, "platform": "android"}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# GET /alerts/
# ---------------------------------------------------------------------------
async def test_control_room_lists_alerts(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000001cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="p4a000001c")
    c_headers = await auth_header("p4a000001c", "correct-horse-battery")
    await _register_device(full_client, c_headers, "phone-p4a001")

    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a001", "battery_percent": 15}, headers=c_headers)

    cr_headers = await auth_header("p4a000001cr", "pw")
    resp = await full_client.get("/alerts/", headers=cr_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["type"] == "low_battery"


async def test_alerts_filter_by_status_severity_type_device(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000002cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="p4a000002c")
    c_headers = await auth_header("p4a000002c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-p4a002")
    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a002", "battery_percent": 5}, headers=c_headers)

    cr_headers = await auth_header("p4a000002cr", "pw")
    resp = await full_client.get("/alerts/", params={"status": "open", "severity": "critical", "type": "critical_battery", "device_id": device_id}, headers=cr_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp_wrong = await full_client.get("/alerts/", params={"type": "low_battery"}, headers=cr_headers)
    assert resp_wrong.status_code == 200
    assert len(resp_wrong.json()) == 0


async def test_alerts_ordered_newest_first(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000003cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="p4a000003a")
    await make_constable(phone="p4a000003b")
    headers_a = await auth_header("p4a000003a", "correct-horse-battery")
    headers_b = await auth_header("p4a000003b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-p4a003a")
    await _register_device(full_client, headers_b, "phone-p4a003b")
    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a003a", "battery_percent": 15}, headers=headers_a)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a003b", "battery_percent": 15}, headers=headers_b)

    cr_headers = await auth_header("p4a000003cr", "pw")
    resp = await full_client.get("/alerts/", headers=cr_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    timestamps = [a["created_at"] for a in body]
    assert timestamps == sorted(timestamps, reverse=True)


async def test_citizen_denied_alerts_access(full_client, make_user, auth_header):
    await make_user(phone="p4a000004", password="pw", role=UserRole.citizen)
    headers = await auth_header("p4a000004", "pw")
    resp = await full_client.get("/alerts/", headers=headers)
    assert resp.status_code == 403


async def test_station_only_sees_own_stations_alerts(full_client, make_user, make_station, make_constable, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p4a000005s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = await make_constable(phone="p4a000005a", station_id=station_a.id)
    _, constable_b = await make_constable(phone="p4a000005b", station_id=station_b.id)
    headers_a = await auth_header("p4a000005a", "correct-horse-battery")
    headers_b = await auth_header("p4a000005b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-p4a005a")
    await _register_device(full_client, headers_b, "phone-p4a005b")
    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a005a", "battery_percent": 15}, headers=headers_a)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a005b", "battery_percent": 15}, headers=headers_b)

    station_headers = await auth_header("p4a000005s", "pw")
    resp = await full_client.get("/alerts/", headers=station_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_constable_only_sees_own_alerts(full_client, make_constable, auth_header):
    await make_constable(phone="p4a000006a")
    await make_constable(phone="p4a000006b")
    headers_a = await auth_header("p4a000006a", "correct-horse-battery")
    headers_b = await auth_header("p4a000006b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-p4a006a")
    await _register_device(full_client, headers_b, "phone-p4a006b")
    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a006a", "battery_percent": 15}, headers=headers_a)
    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a006b", "battery_percent": 15}, headers=headers_b)

    resp = await full_client.get("/alerts/", headers=headers_a)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_alerts_empty_result_when_none_exist(full_client, make_user, auth_header):
    await make_user(phone="p4a000007cr", password="pw", role=UserRole.control_room)
    headers = await auth_header("p4a000007cr", "pw")
    resp = await full_client.get("/alerts/", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_get_alerts_does_not_mutate_alert_state(full_client, make_user, make_constable, auth_header):
    from app import models
    await make_user(phone="p4a000008cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="p4a000008c")
    c_headers = await auth_header("p4a000008c", "correct-horse-battery")
    await _register_device(full_client, c_headers, "phone-p4a008")
    await full_client.post("/devices/battery", json={"device_identifier": "phone-p4a008", "battery_percent": 15}, headers=c_headers)

    cr_headers = await auth_header("p4a000008cr", "pw")
    for _ in range(3):
        await full_client.get("/alerts/", headers=cr_headers)

    alerts = await models.Alert.find_all().to_list()
    assert len(alerts) == 1
    assert alerts[0].status == models.AlertStatus.open  # unchanged by repeated GETs


# ---------------------------------------------------------------------------
# GET /recordings/
# ---------------------------------------------------------------------------
async def test_control_room_lists_recordings(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000009cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="p4a000009c")
    c_headers = await auth_header("p4a000009c", "correct-horse-battery")
    await _register_device(full_client, c_headers, "phone-p4a009")
    await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a009", "trigger_type": "manual"}, headers=c_headers)

    cr_headers = await auth_header("p4a000009cr", "pw")
    resp = await full_client.get("/recordings/", headers=cr_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["status"] == "recording"


async def test_recordings_filter_by_device_and_status(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000010cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="p4a000010c")
    c_headers = await auth_header("p4a000010c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-p4a010")
    start_resp = await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a010", "trigger_type": "manual"}, headers=c_headers)
    rec_id = start_resp.json()["id"]
    await full_client.post(f"/recordings/{rec_id}/cancel", headers=c_headers)

    cr_headers = await auth_header("p4a000010cr", "pw")
    resp = await full_client.get("/recordings/", params={"device_id": device_id, "status": "cancelled"}, headers=cr_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp_wrong = await full_client.get("/recordings/", params={"status": "recording"}, headers=cr_headers)
    assert resp_wrong.status_code == 200
    assert len(resp_wrong.json()) == 0


async def test_recordings_ordered_newest_first(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000011cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="p4a000011c")
    c_headers = await auth_header("p4a000011c", "correct-horse-battery")
    await _register_device(full_client, c_headers, "phone-p4a011")
    await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a011", "trigger_type": "manual"}, headers=c_headers)
    await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a011", "trigger_type": "manual"}, headers=c_headers)

    cr_headers = await auth_header("p4a000011cr", "pw")
    resp = await full_client.get("/recordings/", headers=cr_headers)
    body = resp.json()
    assert len(body) == 2
    timestamps = [r["created_at"] for r in body]
    assert timestamps == sorted(timestamps, reverse=True)


async def test_citizen_denied_recordings_access(full_client, make_user, auth_header):
    await make_user(phone="p4a000012", password="pw", role=UserRole.citizen)
    headers = await auth_header("p4a000012", "pw")
    resp = await full_client.get("/recordings/", headers=headers)
    assert resp.status_code == 403


async def test_station_only_sees_own_stations_recordings(full_client, make_user, make_station, make_constable, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p4a000013s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = await make_constable(phone="p4a000013a", station_id=station_a.id)
    _, constable_b = await make_constable(phone="p4a000013b", station_id=station_b.id)
    headers_a = await auth_header("p4a000013a", "correct-horse-battery")
    headers_b = await auth_header("p4a000013b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-p4a013a")
    await _register_device(full_client, headers_b, "phone-p4a013b")
    await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a013a", "trigger_type": "manual"}, headers=headers_a)
    await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a013b", "trigger_type": "manual"}, headers=headers_b)

    station_headers = await auth_header("p4a000013s", "pw")
    resp = await full_client.get("/recordings/", headers=station_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_constable_only_sees_own_recordings(full_client, make_constable, auth_header):
    await make_constable(phone="p4a000014a")
    await make_constable(phone="p4a000014b")
    headers_a = await auth_header("p4a000014a", "correct-horse-battery")
    headers_b = await auth_header("p4a000014b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-p4a014a")
    await _register_device(full_client, headers_b, "phone-p4a014b")
    await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a014a", "trigger_type": "manual"}, headers=headers_a)
    await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a014b", "trigger_type": "manual"}, headers=headers_b)

    resp = await full_client.get("/recordings/", headers=headers_a)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_recordings_empty_result_when_none_exist(full_client, make_user, auth_header):
    await make_user(phone="p4a000015cr", password="pw", role=UserRole.control_room)
    headers = await auth_header("p4a000015cr", "pw")
    resp = await full_client.get("/recordings/", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_get_recordings_does_not_mutate_recording_state(full_client, make_user, make_constable, auth_header):
    from app import models
    await make_user(phone="p4a000016cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="p4a000016c")
    c_headers = await auth_header("p4a000016c", "correct-horse-battery")
    await _register_device(full_client, c_headers, "phone-p4a016")
    await full_client.post("/recordings/start", json={"device_identifier": "phone-p4a016", "trigger_type": "manual"}, headers=c_headers)

    cr_headers = await auth_header("p4a000016cr", "pw")
    for _ in range(3):
        await full_client.get("/recordings/", headers=cr_headers)

    recordings = await models.RecordingSession.find_all().to_list()
    assert len(recordings) == 1
    assert recordings[0].status == models.RecordingStatus.recording


# ---------------------------------------------------------------------------
# GET /commands/
# ---------------------------------------------------------------------------
async def test_control_room_lists_all_commands(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000017admin", password="pw", role=UserRole.admin)
    await make_constable(phone="p4a000017c")
    c_headers = await auth_header("p4a000017c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-p4a017")
    admin_headers = await auth_header("p4a000017admin", "pw")
    await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    resp = await full_client.get("/commands/", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_commands_filter_by_device_status_type(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000018admin", password="pw", role=UserRole.admin)
    await make_constable(phone="p4a000018c")
    c_headers = await auth_header("p4a000018c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-p4a018")
    admin_headers = await auth_header("p4a000018admin", "pw")
    await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    resp = await full_client.get("/commands/", params={"device_id": device_id, "status": "sent", "command_type": "start_recording"}, headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp_wrong = await full_client.get("/commands/", params={"command_type": "stop_recording"}, headers=admin_headers)
    assert resp_wrong.status_code == 200
    assert len(resp_wrong.json()) == 0


async def test_commands_ordered_newest_first(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000019admin", password="pw", role=UserRole.admin)
    await make_constable(phone="p4a000019c")
    c_headers = await auth_header("p4a000019c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-p4a019")
    admin_headers = await auth_header("p4a000019admin", "pw")
    await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "stop_recording"}, headers=admin_headers)

    resp = await full_client.get("/commands/", headers=admin_headers)
    body = resp.json()
    assert len(body) == 2
    timestamps = [c["created_at"] for c in body]
    assert timestamps == sorted(timestamps, reverse=True)


async def test_citizen_denied_commands_access(full_client, make_user, auth_header):
    await make_user(phone="p4a000020", password="pw", role=UserRole.citizen)
    headers = await auth_header("p4a000020", "pw")
    resp = await full_client.get("/commands/", headers=headers)
    assert resp.status_code == 403


async def test_station_only_sees_own_stations_commands(full_client, make_user, make_station, make_constable, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p4a000021admin", password="pw", role=UserRole.admin)
    await make_user(phone="p4a000021s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = await make_constable(phone="p4a000021a", station_id=station_a.id)
    _, constable_b = await make_constable(phone="p4a000021b", station_id=station_b.id)
    headers_a = await auth_header("p4a000021a", "correct-horse-battery")
    headers_b = await auth_header("p4a000021b", "correct-horse-battery")
    device_a = await _register_device(full_client, headers_a, "phone-p4a021a")
    device_b = await _register_device(full_client, headers_b, "phone-p4a021b")
    admin_headers = await auth_header("p4a000021admin", "pw")
    await full_client.post(f"/devices/{device_a}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    await full_client.post(f"/devices/{device_b}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    station_headers = await auth_header("p4a000021s", "pw")
    resp = await full_client.get("/commands/", headers=station_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_constable_only_sees_own_device_commands(full_client, make_user, make_constable, auth_header):
    await make_user(phone="p4a000022admin", password="pw", role=UserRole.admin)
    await make_constable(phone="p4a000022a")
    await make_constable(phone="p4a000022b")
    headers_a = await auth_header("p4a000022a", "correct-horse-battery")
    headers_b = await auth_header("p4a000022b", "correct-horse-battery")
    device_a = await _register_device(full_client, headers_a, "phone-p4a022a")
    device_b = await _register_device(full_client, headers_b, "phone-p4a022b")
    admin_headers = await auth_header("p4a000022admin", "pw")
    await full_client.post(f"/devices/{device_a}/commands", json={"command_type": "start_recording"}, headers=admin_headers)
    await full_client.post(f"/devices/{device_b}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    resp = await full_client.get("/commands/", headers=headers_a)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_commands_empty_result_when_none_exist(full_client, make_user, auth_header):
    await make_user(phone="p4a000023admin", password="pw", role=UserRole.admin)
    headers = await auth_header("p4a000023admin", "pw")
    resp = await full_client.get("/commands/", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_get_commands_does_not_mutate_command_state(full_client, make_user, make_constable, auth_header):
    from app import models
    await make_user(phone="p4a000024admin", password="pw", role=UserRole.admin)
    await make_constable(phone="p4a000024c")
    c_headers = await auth_header("p4a000024c", "correct-horse-battery")
    device_id = await _register_device(full_client, c_headers, "phone-p4a024")
    admin_headers = await auth_header("p4a000024admin", "pw")
    await full_client.post(f"/devices/{device_id}/commands", json={"command_type": "start_recording"}, headers=admin_headers)

    for _ in range(3):
        await full_client.get("/commands/", headers=admin_headers)

    commands = await models.RemoteCommand.find_all().to_list()
    assert len(commands) == 1
    assert commands[0].status == models.RemoteCommandStatus.sent  # unchanged by repeated GETs
