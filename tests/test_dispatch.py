"""
Police Station association, incident verification workflow,
nearest-station routing, dispatch (with eligibility filtering), and the
constable self-service ("/me") API surface.
"""
from app.models import UserRole, IncidentStatus, AssignmentStatus, ConstableStatus, UserStatus


async def _set_assignment_status(incident_id, assignment_id, status):
    from app import models
    incident_doc = await models.Incident.get(incident_id)
    for a in incident_doc.assignments:
        if a.id == assignment_id:
            a.status = status
    await incident_doc.save()


# ---------------------------------------------------------------------------
# AUTH / STATION (1-4)
# ---------------------------------------------------------------------------
async def test_station_user_has_station_id(full_client, make_user, make_station, auth_header):
    station = await make_station()
    await make_user(phone="s000000001", password="pw", role=UserRole.station, station_id=station.id)
    headers = await auth_header("s000000001", "pw")
    resp = await full_client.get("/auth/me", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["station_id"] == str(station.id)


async def test_station_user_cannot_access_another_stations_incidents(full_client, make_user, make_station, make_incident, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="s000000002", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = await make_incident(station_id=station_b.id, description="belongs to B")

    headers = await auth_header("s000000002", "pw")
    resp = await full_client.get("/incidents/", headers=headers)
    assert resp.status_code == 200
    ids = [row["id"] for row in resp.json()]
    assert str(incident_b.id) not in ids


async def test_station_user_can_access_own_station_incidents(full_client, make_user, make_station, make_incident, auth_header):
    station_a = await make_station(name="A")
    await make_user(phone="s000000003", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_a = await make_incident(station_id=station_a.id, description="belongs to A")

    headers = await auth_header("s000000003", "pw")
    resp = await full_client.get("/incidents/", headers=headers)
    assert resp.status_code == 200
    ids = [row["id"] for row in resp.json()]
    assert str(incident_a.id) in ids


async def test_station_user_cannot_see_another_stations_constables(full_client, make_user, make_station, make_constable, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="s000000004", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_b = await make_constable(phone="c000000004", station_id=station_b.id)

    headers = await auth_header("s000000004", "pw")
    resp = await full_client.get("/constables/", headers=headers)
    assert resp.status_code == 200
    ids = [row["id"] for row in resp.json()]
    assert str(constable_b.id) not in ids


# ---------------------------------------------------------------------------
# VERIFICATION (5-10)
# ---------------------------------------------------------------------------
async def test_control_room_can_verify_incident(full_client, make_user, make_incident, auth_header):
    await make_user(phone="v000000001", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.new)
    headers = await auth_header("v000000001", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified"


async def test_control_room_can_reject_incident(full_client, make_user, make_incident, auth_header):
    await make_user(phone="v000000002", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.new)
    headers = await auth_header("v000000002", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/reject", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"


async def test_constable_cannot_verify_incident(full_client, make_constable, make_incident, auth_header):
    await make_constable(phone="v000000003")
    incident = await make_incident(status_=IncidentStatus.new)
    headers = await auth_header("v000000003", "correct-horse-battery")

    resp = await full_client.post(f"/incidents/{incident.id}/verify", headers=headers)
    assert resp.status_code == 403


async def test_citizen_cannot_verify_incident(full_client, make_user, make_incident, auth_header):
    await make_user(phone="v000000004", password="pw", role=UserRole.citizen)
    incident = await make_incident(status_=IncidentStatus.new)
    headers = await auth_header("v000000004", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/verify", headers=headers)
    assert resp.status_code == 403


async def test_cannot_dispatch_rejected_incident(full_client, make_user, make_incident, auth_header):
    await make_user(phone="v000000005", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.rejected)
    headers = await auth_header("v000000005", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 409


async def test_cannot_dispatch_unverified_incident(full_client, make_user, make_incident, auth_header):
    await make_user(phone="v000000006", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.new)
    headers = await auth_header("v000000006", "pw")
    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# STATION ROUTING (11-12)
# ---------------------------------------------------------------------------
async def test_nearest_station_calculation(full_client, make_user, make_station, auth_header):
    await make_user(phone="r000000001", password="pw", role=UserRole.control_room)
    near = await make_station(name="Near", longitude=78.90, latitude=20.50)
    far = await make_station(name="Far", longitude=79.50, latitude=21.10)
    headers = await auth_header("r000000001", "pw")

    resp = await full_client.get("/police-stations/nearest", params={"latitude": 20.501, "longitude": 78.901}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["primary_station"]["id"] == str(near.id)


async def test_second_nearest_station_calculation(full_client, make_user, make_station, auth_header):
    await make_user(phone="r000000002", password="pw", role=UserRole.control_room)
    near = await make_station(name="Near", longitude=78.90, latitude=20.50)
    mid = await make_station(name="Mid", longitude=79.00, latitude=20.60)
    far = await make_station(name="Far", longitude=85.00, latitude=25.00)
    headers = await auth_header("r000000002", "pw")

    resp = await full_client.get("/police-stations/nearest", params={"latitude": 20.501, "longitude": 78.901}, headers=headers)
    body = resp.json()
    assert body["primary_station"]["id"] == str(near.id)
    assert body["backup_station"]["id"] == str(mid.id)
    assert body["primary_station"]["distance_meters"] < body["backup_station"]["distance_meters"]


# ---------------------------------------------------------------------------
# DISPATCH (13-20)
# ---------------------------------------------------------------------------
async def test_verified_incident_can_be_dispatched(
    full_client, make_user, make_incident, make_constable, make_location, auth_header
):
    await make_user(phone="d000000001", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.verified, longitude=78.90, latitude=20.50)
    _, constable = await make_constable(phone="dc000000001")
    await make_location(constable.id, longitude=78.90, latitude=20.50, age_seconds=5)
    headers = await auth_header("d000000001", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "dispatched"
    assert body["constable_id"] == str(constable.id)


async def test_unverified_incident_cannot_be_dispatched(full_client, make_user, make_incident, auth_header):
    await make_user(phone="d000000002", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.new)
    headers = await auth_header("d000000002", "pw")
    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 409


async def test_resolved_incident_cannot_be_dispatched(full_client, make_user, make_incident, auth_header):
    await make_user(phone="d000000003", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.resolved)
    headers = await auth_header("d000000003", "pw")
    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 409


async def test_inactive_constable_not_assigned(
    full_client, make_user, make_incident, make_constable, make_location, auth_header
):
    await make_user(phone="d000000004", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.verified, longitude=78.90, latitude=20.50)
    _, constable = await make_constable(phone="dc000000004", user_status=UserStatus.inactive)
    await make_location(constable.id, longitude=78.90, latitude=20.50, age_seconds=5)
    headers = await auth_header("d000000004", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "no_available_constable"


async def test_busy_constable_not_assigned(
    full_client, make_user, make_incident, make_constable, make_location, auth_header
):
    await make_user(phone="d000000005", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.verified, longitude=78.90, latitude=20.50)
    _, constable = await make_constable(phone="dc000000005", status=ConstableStatus.busy)
    await make_location(constable.id, longitude=78.90, latitude=20.50, age_seconds=5)
    headers = await auth_header("d000000005", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "no_available_constable"


async def test_stale_location_constable_not_assigned(
    full_client, make_user, make_incident, make_constable, make_location, auth_header
):
    await make_user(phone="d000000006", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.verified, longitude=78.90, latitude=20.50)
    _, constable = await make_constable(phone="dc000000006")
    await make_location(constable.id, longitude=78.90, latitude=20.50, age_seconds=99999)  # way stale
    headers = await auth_header("d000000006", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "no_available_constable"


async def test_nearest_eligible_constable_is_selected(
    full_client, make_user, make_incident, make_constable, make_location, auth_header
):
    await make_user(phone="d000000007", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.verified, longitude=78.90, latitude=20.50)
    _, near = await make_constable(phone="dc000000007a")
    await make_location(near.id, longitude=78.901, latitude=20.501, age_seconds=5)
    _, far = await make_constable(phone="dc000000007b")
    await make_location(far.id, longitude=85.0, latitude=25.0, age_seconds=5)
    headers = await auth_header("d000000007", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["constable_id"] == str(near.id)


async def test_duplicate_active_assignment_prevented(
    full_client, make_user, make_incident, make_constable, make_location, auth_header
):
    await make_user(phone="d000000008", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.verified, longitude=78.90, latitude=20.50)
    _, constable = await make_constable(phone="dc000000008")
    await make_location(constable.id, longitude=78.90, latitude=20.50, age_seconds=5)
    headers = await auth_header("d000000008", "pw")

    resp1 = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "dispatched"

    # incident already has an active assignment now -> second dispatch call is rejected
    resp2 = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp2.status_code == 409


# ---------------------------------------------------------------------------
# CONSTABLE SELF-SERVICE (21-31)
# ---------------------------------------------------------------------------
async def test_constable_can_get_me(full_client, make_constable, auth_header):
    user, constable = await make_constable(phone="m000000001")
    headers = await auth_header("m000000001", "correct-horse-battery")
    resp = await full_client.get("/constables/me", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == str(constable.id)


async def test_constable_only_sees_own_incidents(
    full_client, make_constable, make_incident, make_user, auth_header
):
    _, constable_a = await make_constable(phone="m000000002a")
    _, constable_b = await make_constable(phone="m000000002b")
    incident_a = await make_incident(status_=IncidentStatus.assigned)
    incident_b = await make_incident(status_=IncidentStatus.assigned)

    await make_user(phone="m000000002admin", password="pw", role=UserRole.admin)
    admin_headers = await auth_header("m000000002admin", "pw")
    await full_client.post(
        f"/constables/{constable_a.id}/tasks", json={"incident_id": str(incident_a.id)}, headers=admin_headers
    )
    await full_client.post(
        f"/constables/{constable_b.id}/tasks", json={"incident_id": str(incident_b.id)}, headers=admin_headers
    )

    headers_a = await auth_header("m000000002a", "correct-horse-battery")
    resp = await full_client.get("/constables/me/incidents", headers=headers_a)
    assert resp.status_code == 200
    ids = [row["incident_id"] for row in resp.json()]
    assert str(incident_a.id) in ids
    assert str(incident_b.id) not in ids


async def test_constable_cannot_see_another_constables_assignment_via_accept(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable_a = await make_constable(phone="m000000003a")
    _, constable_b = await make_constable(phone="m000000003b")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable_b.id, incident_id=incident.id)

    headers_a = await auth_header("m000000003a", "correct-horse-battery")
    resp = await full_client.post(f"/constables/me/incidents/{incident.id}/accept", headers=headers_a)
    assert resp.status_code == 404  # no assignment exists for constable A on this incident


async def test_constable_can_accept_own_pending_assignment(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = await make_constable(phone="m000000004")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = await auth_header("m000000004", "correct-horse-battery")

    resp = await full_client.post(f"/constables/me/incidents/{incident.id}/accept", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["assignment_status"] == "accepted"


async def test_constable_cannot_accept_another_constables_assignment(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable_a = await make_constable(phone="m000000005a")
    _, constable_b = await make_constable(phone="m000000005b")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable_b.id, incident_id=incident.id)

    headers_a = await auth_header("m000000005a", "correct-horse-battery")
    resp = await full_client.post(f"/constables/me/incidents/{incident.id}/accept", headers=headers_a)
    assert resp.status_code == 404


async def test_constable_can_reject_own_pending_assignment(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = await make_constable(phone="m000000006")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = await auth_header("m000000006", "correct-horse-battery")

    resp = await full_client.post(f"/constables/me/incidents/{incident.id}/reject", headers=headers, json={"reason": "busy"})
    assert resp.status_code == 200
    assert resp.json()["assignment_status"] == "rejected"


async def test_constable_cannot_reject_accepted_assignment(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = await make_constable(phone="m000000007")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = await auth_header("m000000007", "correct-horse-battery")

    accept_resp = await full_client.post(f"/constables/me/incidents/{incident.id}/accept", headers=headers)
    assert accept_resp.status_code == 200

    reject_resp = await full_client.post(f"/constables/me/incidents/{incident.id}/reject", headers=headers)
    assert reject_resp.status_code == 409


async def test_constable_can_update_en_route(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = await make_constable(phone="m000000008")
    incident = await make_incident(status_=IncidentStatus.assigned)
    assignment = await make_assignment(constable_id=constable.id, incident_id=incident.id)
    await _set_assignment_status(incident.id, assignment.id, AssignmentStatus.accepted)
    headers = await auth_header("m000000008", "correct-horse-battery")

    resp = await full_client.put(f"/constables/me/incidents/{incident.id}/status", json={"status": "en_route"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["assignment_status"] == "en_route"


async def test_constable_can_update_arrived(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = await make_constable(phone="m000000009")
    incident = await make_incident(status_=IncidentStatus.assigned)
    assignment = await make_assignment(constable_id=constable.id, incident_id=incident.id)
    await _set_assignment_status(incident.id, assignment.id, AssignmentStatus.en_route)
    headers = await auth_header("m000000009", "correct-horse-battery")

    resp = await full_client.put(f"/constables/me/incidents/{incident.id}/status", json={"status": "arrived"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["assignment_status"] == "arrived"


async def test_constable_can_update_completed(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = await make_constable(phone="m000000010")
    incident = await make_incident(status_=IncidentStatus.assigned)
    assignment = await make_assignment(constable_id=constable.id, incident_id=incident.id)
    await _set_assignment_status(incident.id, assignment.id, AssignmentStatus.arrived)
    headers = await auth_header("m000000010", "correct-horse-battery")

    resp = await full_client.put(f"/constables/me/incidents/{incident.id}/status", json={"status": "completed"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["assignment_status"] == "completed"


async def test_invalid_status_transition_rejected(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = await make_constable(phone="m000000011")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable.id, incident_id=incident.id)  # still pending
    headers = await auth_header("m000000011", "correct-horse-battery")

    # pending -> completed is not a legal jump
    resp = await full_client.put(f"/constables/me/incidents/{incident.id}/status", json={"status": "completed"}, headers=headers)
    assert resp.status_code == 409


async def test_constable_cannot_set_verified_via_me_status(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = await make_constable(phone="m000000012")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = await auth_header("m000000012", "correct-horse-battery")

    resp = await full_client.put(f"/constables/me/incidents/{incident.id}/status", json={"status": "verified"}, headers=headers)
    assert resp.status_code in (403, 422)


# ---------------------------------------------------------------------------
# LOCATION (32-37)
# ---------------------------------------------------------------------------
async def test_constable_can_update_own_location_via_me(full_client, make_constable, auth_header):
    _, constable = await make_constable(phone="l000000001")
    headers = await auth_header("l000000001", "correct-horse-battery")
    resp = await full_client.post(
        "/constables/me/location", json={"latitude": 16.5062, "longitude": 80.6480, "accuracy": 8.5}, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["constable_id"] == str(constable.id)


async def test_constable_cannot_target_another_constable_through_me_endpoint(full_client, make_constable, auth_header):
    """The /me endpoint takes no constable_id at all -- there's structurally
    nothing to spoof. This just re-confirms the response always reflects
    the caller's own id regardless of what's in the (nonexistent) target field."""
    _, constable_a = await make_constable(phone="l000000002a")
    _, constable_b = await make_constable(phone="l000000002b")
    headers_a = await auth_header("l000000002a", "correct-horse-battery")

    resp = await full_client.post(
        "/constables/me/location", json={"latitude": 1.0, "longitude": 1.0}, headers=headers_a
    )
    assert resp.json()["constable_id"] == str(constable_a.id)
    assert resp.json()["constable_id"] != str(constable_b.id)


async def test_invalid_latitude_rejected(full_client, make_constable, auth_header):
    await make_constable(phone="l000000003")
    headers = await auth_header("l000000003", "correct-horse-battery")
    resp = await full_client.post(
        "/constables/me/location", json={"latitude": 999, "longitude": 80.0}, headers=headers
    )
    assert resp.status_code == 422


async def test_invalid_longitude_rejected(full_client, make_constable, auth_header):
    await make_constable(phone="l000000004")
    headers = await auth_header("l000000004", "correct-horse-battery")
    resp = await full_client.post(
        "/constables/me/location", json={"latitude": 16.0, "longitude": 999}, headers=headers
    )
    assert resp.status_code == 422


async def test_negative_accuracy_rejected(full_client, make_constable, auth_header):
    await make_constable(phone="l000000005")
    headers = await auth_header("l000000005", "correct-horse-battery")
    resp = await full_client.post(
        "/constables/me/location", json={"latitude": 16.0, "longitude": 80.0, "accuracy": -5}, headers=headers
    )
    assert resp.status_code == 422


async def test_server_timestamp_used_for_location(full_client, make_constable, auth_header):
    _, constable = await make_constable(phone="l000000006")
    headers = await auth_header("l000000006", "correct-horse-battery")
    resp = await full_client.post(
        "/constables/me/location", json={"latitude": 16.0, "longitude": 80.0}, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["timestamp"] is not None  # server-assigned, no client timestamp accepted at all
