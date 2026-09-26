"""
Police Station CRUD + cross-station isolation across incidents,
constables, media, audit logs, and dispatch.
"""
from app.models import UserRole, IncidentStatus, ConstableStatus, UserStatus


# ---------------------------------------------------------------------------
# Police Station CRUD authorization
# ---------------------------------------------------------------------------
async def test_admin_can_create_update_delete_station(full_client, make_user, auth_header):
    await make_user(phone="p000000001", password="pw", role=UserRole.admin)
    headers = await auth_header("p000000001", "pw")

    create_resp = await full_client.post(
        "/police-stations/",
        json={"name": "Central", "contact": "100", "latitude": 20.5, "longitude": 78.9},
        headers=headers,
    )
    assert create_resp.status_code == 200
    station_id = create_resp.json()["id"]

    update_resp = await full_client.put(
        f"/police-stations/{station_id}", json={"name": "Central Updated"}, headers=headers
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["name"] == "Central Updated"

    delete_resp = await full_client.delete(f"/police-stations/{station_id}", headers=headers)
    assert delete_resp.status_code == 200


async def test_control_room_can_read_but_not_write_stations(full_client, make_user, make_station, auth_header):
    station = await make_station()
    await make_user(phone="p000000002", password="pw", role=UserRole.control_room)
    headers = await auth_header("p000000002", "pw")

    get_resp = await full_client.get(f"/police-stations/{station.id}", headers=headers)
    assert get_resp.status_code == 200

    create_resp = await full_client.post(
        "/police-stations/", json={"name": "X", "latitude": 1.0, "longitude": 1.0}, headers=headers
    )
    assert create_resp.status_code == 403

    update_resp = await full_client.put(f"/police-stations/{station.id}", json={"name": "Y"}, headers=headers)
    assert update_resp.status_code == 403

    delete_resp = await full_client.delete(f"/police-stations/{station.id}", headers=headers)
    assert delete_resp.status_code == 403


async def test_station_reads_own_station(full_client, make_user, make_station, auth_header):
    station = await make_station()
    await make_user(phone="p000000003", password="pw", role=UserRole.station, station_id=station.id)
    headers = await auth_header("p000000003", "pw")

    resp = await full_client.get(f"/police-stations/{station.id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == str(station.id)


async def test_station_cannot_read_another_station(full_client, make_user, make_station, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p000000004", password="pw", role=UserRole.station, station_id=station_a.id)
    headers = await auth_header("p000000004", "pw")

    resp = await full_client.get(f"/police-stations/{station_b.id}", headers=headers)
    assert resp.status_code == 403


async def test_constable_denied_station_management(full_client, make_constable, make_station, auth_header):
    station = await make_station()
    await make_constable(phone="p000000005")
    headers = await auth_header("p000000005", "correct-horse-battery")

    resp = await full_client.get(f"/police-stations/{station.id}", headers=headers)
    assert resp.status_code == 403


async def test_citizen_denied_station_management(full_client, make_user, make_station, auth_header):
    station = await make_station()
    await make_user(phone="p000000006", password="pw", role=UserRole.citizen)
    headers = await auth_header("p000000006", "pw")

    resp = await full_client.get(f"/police-stations/{station.id}", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Incident creation auto-assigns nearest station
# ---------------------------------------------------------------------------
async def test_new_incident_auto_assigns_nearest_station(full_client, make_user, make_station, auth_header):
    station = await make_station(longitude=78.90, latitude=20.50)
    await make_user(phone="p000000007", password="pw", role=UserRole.citizen)
    headers = await auth_header("p000000007", "pw")

    resp = await full_client.post(
        "/incidents/",
        json={"location_lon": 78.901, "location_lat": 20.501, "description": "help"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["station_id"] == str(station.id)


# ---------------------------------------------------------------------------
# Station cannot modify/dispatch another station's incident; can act on own
# ---------------------------------------------------------------------------
async def test_station_cannot_verify_another_stations_incident(full_client, make_user, make_station, make_incident, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p000000008", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = await make_incident(status_=IncidentStatus.new, station_id=station_b.id)
    headers = await auth_header("p000000008", "pw")

    resp = await full_client.post(f"/incidents/{incident_b.id}/verify", headers=headers)
    assert resp.status_code == 403


async def test_station_can_verify_own_stations_incident(full_client, make_user, make_station, make_incident, auth_header):
    station_a = await make_station(name="A")
    await make_user(phone="p000000009", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_a = await make_incident(status_=IncidentStatus.new, station_id=station_a.id)
    headers = await auth_header("p000000009", "pw")

    resp = await full_client.post(f"/incidents/{incident_a.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified"


async def test_station_cannot_dispatch_another_stations_incident(
    full_client, make_user, make_station, make_incident, auth_header
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p000000010", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = await make_incident(status_=IncidentStatus.verified, station_id=station_b.id)
    headers = await auth_header("p000000010", "pw")

    resp = await full_client.post(f"/incidents/{incident_b.id}/dispatch", headers=headers)
    assert resp.status_code == 403


async def test_station_can_dispatch_own_stations_incident(
    full_client, make_user, make_station, make_incident, make_constable, make_location, auth_header
):
    station_a = await make_station(name="A", longitude=78.9, latitude=20.5)
    await make_user(phone="p000000011", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_a = await make_incident(status_=IncidentStatus.verified, station_id=station_a.id, longitude=78.9, latitude=20.5)
    _, constable = await make_constable(phone="p000000011c", station_id=station_a.id)
    await make_location(constable.id, longitude=78.9, latitude=20.5, age_seconds=5)
    headers = await auth_header("p000000011", "pw")

    resp = await full_client.post(f"/incidents/{incident_a.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "dispatched"


async def test_station_cannot_update_status_of_another_stations_incident(
    full_client, make_user, make_station, make_incident, auth_header
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p000000012", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = await make_incident(status_=IncidentStatus.new, station_id=station_b.id)
    headers = await auth_header("p000000012", "pw")

    resp = await full_client.put(
        f"/incidents/{incident_b.id}/status", params={"status": "closed"}, headers=headers
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Dispatch: wrong-station constable skipped even if nearest geographically
# ---------------------------------------------------------------------------
async def test_dispatch_skips_wrong_station_constable(
    full_client, make_user, make_station, make_incident, make_constable, make_location, auth_header
):
    station_a = await make_station(name="A", longitude=78.9, latitude=20.5)
    station_b = await make_station(name="B", longitude=90.0, latitude=25.0)
    await make_user(phone="p000000013", password="pw", role=UserRole.control_room)
    incident_a = await make_incident(status_=IncidentStatus.verified, station_id=station_a.id, longitude=78.9, latitude=20.5)

    # Constable belongs to station B but happens to be geographically very close
    _, wrong_station_constable = await make_constable(phone="p000000013a", station_id=station_b.id)
    await make_location(wrong_station_constable.id, longitude=78.9, latitude=20.5, age_seconds=5)

    # Constable belongs to station A (the incident's own station) but is a bit farther
    _, right_station_constable = await make_constable(phone="p000000013b", station_id=station_a.id)
    await make_location(right_station_constable.id, longitude=78.95, latitude=20.55, age_seconds=5)

    headers = await auth_header("p000000013", "pw")
    resp = await full_client.post(f"/incidents/{incident_a.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "dispatched"
    assert resp.json()["constable_id"] == str(right_station_constable.id)


# ---------------------------------------------------------------------------
# Media: station cross-isolation
# ---------------------------------------------------------------------------
async def test_station_can_access_own_station_evidence(
    full_client, make_user, make_station, make_incident, make_evidence, auth_header
):
    station_a = await make_station(name="A")
    await make_user(phone="p000000014", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_a = await make_incident(station_id=station_a.id)
    evidence = await make_evidence(incident_id=incident_a.id)
    headers = await auth_header("p000000014", "pw")

    list_resp = await full_client.get("/media/", headers=headers)
    assert list_resp.status_code == 200
    ids = [row["id"] for row in list_resp.json()]
    assert str(evidence.id) in ids

    download_resp = await full_client.get(f"/media/{evidence.id}/download", headers=headers)
    assert download_resp.status_code == 200


async def test_station_cannot_access_another_stations_evidence(
    full_client, make_user, make_station, make_incident, make_evidence, auth_header
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p000000015", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = await make_incident(station_id=station_b.id)
    evidence_b = await make_evidence(incident_id=incident_b.id)
    headers = await auth_header("p000000015", "pw")

    list_resp = await full_client.get("/media/", headers=headers)
    assert list_resp.status_code == 200
    ids = [row["id"] for row in list_resp.json()]
    assert str(evidence_b.id) not in ids


async def test_station_cannot_download_another_stations_evidence(
    full_client, make_user, make_station, make_incident, make_evidence, auth_header
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p000000016", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = await make_incident(station_id=station_b.id)
    evidence_b = await make_evidence(incident_id=incident_b.id)
    headers = await auth_header("p000000016", "pw")

    resp = await full_client.get(f"/media/{evidence_b.id}/download", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Audit: station-scoped visibility
# ---------------------------------------------------------------------------
async def test_station_sees_only_own_station_audit_records(
    full_client, make_user, make_station, make_incident, auth_header
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p000000017", password="pw", role=UserRole.station, station_id=station_a.id)
    await make_user(phone="p000000017cr", password="pw", role=UserRole.control_room)
    incident_a = await make_incident(status_=IncidentStatus.new, station_id=station_a.id)
    incident_b = await make_incident(status_=IncidentStatus.new, station_id=station_b.id)

    cr_headers = await auth_header("p000000017cr", "pw")
    await full_client.post(f"/incidents/{incident_a.id}/verify", headers=cr_headers)
    await full_client.post(f"/incidents/{incident_b.id}/verify", headers=cr_headers)

    station_headers = await auth_header("p000000017", "pw")
    resp = await full_client.get("/audit-logs/", headers=station_headers)
    assert resp.status_code == 200
    incident_ids_seen = {row["incident_id"] for row in resp.json() if row["incident_id"]}
    assert str(incident_a.id) in incident_ids_seen
    assert str(incident_b.id) not in incident_ids_seen


async def test_station_cannot_see_global_login_audit_records(full_client, make_user, auth_header, make_station):
    station = await make_station()
    await make_user(phone="p000000018", password="pw", role=UserRole.station, station_id=station.id)
    # A login by some unrelated admin generates a global auth.login_success record.
    await make_user(phone="p000000018admin", password="pw", role=UserRole.admin)
    await full_client.post("/auth/login", json={"username": "p000000018admin", "password": "pw"})

    headers = await auth_header("p000000018", "pw")
    resp = await full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 200
    actions_seen = {row["action"] for row in resp.json()}
    assert "auth.login_success" not in actions_seen
    assert "auth.login_failed" not in actions_seen


async def test_admin_sees_all_audit_records_including_other_stations(
    full_client, make_user, make_station, make_incident, auth_header
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="p000000019", password="pw", role=UserRole.admin)
    incident_a = await make_incident(status_=IncidentStatus.new, station_id=station_a.id)
    incident_b = await make_incident(status_=IncidentStatus.new, station_id=station_b.id)

    headers = await auth_header("p000000019", "pw")
    await full_client.post(f"/incidents/{incident_a.id}/verify", headers=headers)
    await full_client.post(f"/incidents/{incident_b.id}/verify", headers=headers)

    resp = await full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 200
    incident_ids_seen = {row["incident_id"] for row in resp.json() if row["incident_id"]}
    assert str(incident_a.id) in incident_ids_seen
    assert str(incident_b.id) in incident_ids_seen
