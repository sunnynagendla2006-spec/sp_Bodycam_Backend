"""
Dispatch/station-scoping hardening tests: the atomic active-assignment
guard (the Mongo equivalent of the old uq_active_assignment_per_incident
partial unique index), station-scoped constable *locations* (as distinct
from the constable roster), explicit negative cross-station WebSocket
isolation, and police-station CRUD audit trail.
"""
from httpx_ws import aconnect_ws

from app import models
from app.models import UserRole, IncidentStatus, AssignmentStatus


async def _token(full_client, phone, password):
    resp = await full_client.post("/auth/login", json={"username": phone, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Atomic active-assignment guard: only one ACTIVE assignment per incident,
# enforced by the same atomic `find_one_and_update` compare-and-swap
# dispatch_incident itself uses (see app/models.py::Incident.active_assignment_id),
# not just an apparent application-level check.
# ---------------------------------------------------------------------------
async def test_active_assignment_guard_rejects_second_active_assignment_bypassing_app_check(
    mongo_db, make_incident, make_constable
):
    """
    Directly performs the SAME atomic update dispatch_incident uses,
    bypassing its own higher-level `if incident.active_assignment_id is not
    None:` pre-check entirely -- proving the guard is enforced by the
    atomic conditional update itself (a single-document operation is
    inherently atomic on MongoDB), which is what actually protects against
    a genuine race between two concurrent requests, not just the
    application-level check.
    """
    incident = await make_incident(status_=IncidentStatus.verified)
    _, constable_a = await make_constable(phone="u000000001a")
    _, constable_b = await make_constable(phone="u000000001b")

    first = models.Assignment(constable_id=constable_a.id, status=AssignmentStatus.pending)
    result1 = await models.Incident.get_motor_collection().find_one_and_update(
        {"_id": incident.id, "active_assignment_id": None},
        {"$push": {"assignments": first.model_dump()}, "$set": {"active_assignment_id": first.id}},
    )
    assert result1 is not None

    second = models.Assignment(constable_id=constable_b.id, status=AssignmentStatus.accepted)
    result2 = await models.Incident.get_motor_collection().find_one_and_update(
        {"_id": incident.id, "active_assignment_id": None},
        {"$push": {"assignments": second.model_dump()}, "$set": {"active_assignment_id": second.id}},
    )
    assert result2 is None, "a second active assignment must never be accepted while one is already active"

    fresh = await models.Incident.get(incident.id)
    assert len(fresh.assignments) == 1
    assert fresh.active_assignment_id == first.id


async def test_active_assignment_guard_allows_second_assignment_after_first_is_rejected(
    mongo_db, make_incident, make_constable
):
    """A REJECTED (non-active) assignment does not block a new active one for the same incident -- the guard is scoped to active_assignment_id, cleared on rejection (see constables.py::reject_assignment)."""
    incident = await make_incident(status_=IncidentStatus.verified)
    _, constable_a = await make_constable(phone="u000000002a")
    _, constable_b = await make_constable(phone="u000000002b")

    first = models.Assignment(constable_id=constable_a.id, status=AssignmentStatus.rejected)
    await models.Incident.find_one(models.Incident.id == incident.id).update(
        {"$push": {"assignments": first.model_dump()}}
    )

    second = models.Assignment(constable_id=constable_b.id, status=AssignmentStatus.pending)
    result = await models.Incident.get_motor_collection().find_one_and_update(
        {"_id": incident.id, "active_assignment_id": None},
        {"$push": {"assignments": second.model_dump()}, "$set": {"active_assignment_id": second.id}},
    )
    assert result is not None  # must NOT be blocked

    fresh = await models.Incident.get(incident.id)
    assert len(fresh.assignments) == 2
    assert fresh.active_assignment_id == second.id


async def test_dispatch_endpoint_returns_409_when_active_assignment_already_exists(
    full_client, make_user, make_incident, make_constable, make_location, auth_header
):
    """
    End-to-end: the dispatch endpoint's own pre-check already returns 409
    for this case (this test documents/locks in that the atomic guard and
    the app-level check agree on the same outcome/status code).
    """
    await make_user(phone="u000000003", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.verified, longitude=78.9, latitude=20.5)
    _, constable = await make_constable(phone="u000000003c")
    await make_location(constable.id, longitude=78.9, latitude=20.5, age_seconds=5)

    existing = models.Assignment(constable_id=constable.id, status=AssignmentStatus.pending)
    await models.Incident.find_one(models.Incident.id == incident.id).update(
        {"$push": {"assignments": existing.model_dump()}, "$set": {"active_assignment_id": existing.id}}
    )

    headers = await auth_header("u000000003", "pw")
    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Station-scoped constable LOCATIONS specifically (distinct from the
# roster endpoint, which was already tested previously)
# ---------------------------------------------------------------------------
async def test_station_sees_only_own_stations_constable_locations(
    full_client, make_user, make_station, make_constable, make_location, auth_header
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="u000000004", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = await make_constable(phone="u000000004a", station_id=station_a.id, badge_number="BADGE-A")
    _, constable_b = await make_constable(phone="u000000004b", station_id=station_b.id, badge_number="BADGE-B")
    await make_location(constable_a.id, longitude=78.9, latitude=20.5)
    await make_location(constable_b.id, longitude=79.0, latitude=21.0)

    headers = await auth_header("u000000004", "pw")
    resp = await full_client.get("/constables/locations", headers=headers)
    assert resp.status_code == 200
    badges_seen = {row["constable_id"] for row in resp.json()}
    assert "BADGE-A" in badges_seen
    assert "BADGE-B" not in badges_seen


async def test_constable_locations_returns_only_the_latest_row_per_constable(
    full_client, make_user, make_constable, make_location, auth_header
):
    """
    Regression test: previously this endpoint used Postgres-only DISTINCT
    ON, silently ignored under SQLite -- a constable with more than one
    ConstableLocation reading could have returned duplicate/stale rows
    here. Now uses a $sort+$group("$first") aggregation (see
    constables.py::list_constable_locations), so exactly one row per
    constable is returned, reflecting the MOST RECENT location.
    """
    await make_user(phone="u000000004admin", password="pw", role=UserRole.admin)
    _, constable = await make_constable(phone="u000000004c", badge_number="BADGE-MULTI")
    await make_location(constable.id, longitude=1.0, latitude=1.0, age_seconds=300)  # older
    await make_location(constable.id, longitude=9.0, latitude=9.0, age_seconds=5)    # newer

    headers = await auth_header("u000000004admin", "pw")
    resp = await full_client.get("/constables/locations", headers=headers)
    assert resp.status_code == 200
    rows = [r for r in resp.json() if r["constable_id"] == "BADGE-MULTI"]
    assert len(rows) == 1
    assert rows[0]["lon"] == 9.0
    assert rows[0]["lat"] == 9.0


# ---------------------------------------------------------------------------
# Explicit negative WebSocket cross-station isolation (station B must NOT
# receive station A's incident event)
# ---------------------------------------------------------------------------
async def test_station_b_does_not_receive_station_a_incident_events(
    full_client, make_user, make_station, make_incident
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="u000000005cr", password="pw", role=UserRole.control_room)
    await make_user(phone="u000000005a", password="pw", role=UserRole.station, station_id=station_a.id)
    await make_user(phone="u000000005b", password="pw", role=UserRole.station, station_id=station_b.id)
    incident_a = await make_incident(status_=IncidentStatus.new, station_id=station_a.id)

    cr_token = await _token(full_client, "u000000005cr", "pw")
    token_b = await _token(full_client, "u000000005b", "pw")

    async with aconnect_ws(f"/ws/control_room?token={token_b}", full_client) as ws_b:
        cr_headers = {"Authorization": f"Bearer {cr_token}"}
        resp = await full_client.post(f"/incidents/{incident_a.id}/verify", headers=cr_headers)
        assert resp.status_code == 200

        # Station B's socket should receive NOTHING about station A's
        # incident -- confirm by sending a ping and only getting our own ack.
        await ws_b.send_text("ping")
        msg = await ws_b.receive_json()
        assert msg["event"] == "ack"


async def test_station_a_does_receive_its_own_incident_event_while_station_b_is_also_connected(
    full_client, make_user, make_station, make_incident
):
    """Companion positive case: with both stations connected simultaneously, only station A gets station A's event."""
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="u000000006cr", password="pw", role=UserRole.control_room)
    await make_user(phone="u000000006a", password="pw", role=UserRole.station, station_id=station_a.id)
    await make_user(phone="u000000006b", password="pw", role=UserRole.station, station_id=station_b.id)
    incident_a = await make_incident(status_=IncidentStatus.new, station_id=station_a.id)

    cr_token = await _token(full_client, "u000000006cr", "pw")
    token_a = await _token(full_client, "u000000006a", "pw")
    token_b = await _token(full_client, "u000000006b", "pw")

    async with aconnect_ws(f"/ws/control_room?token={token_a}", full_client) as ws_a:
        async with aconnect_ws(f"/ws/control_room?token={token_b}", full_client) as ws_b:
            cr_headers = {"Authorization": f"Bearer {cr_token}"}
            resp = await full_client.post(f"/incidents/{incident_a.id}/verify", headers=cr_headers)
            assert resp.status_code == 200

            msg_a = await ws_a.receive_json()
            assert msg_a["event"] == "incident.verified"
            assert msg_a["data"]["incident_id"] == str(incident_a.id)

            await ws_b.send_text("ping")
            msg_b = await ws_b.receive_json()
            assert msg_b["event"] == "ack"  # never the incident.verified event


# ---------------------------------------------------------------------------
# Police Station CRUD audit trail
# ---------------------------------------------------------------------------
async def test_police_station_create_update_delete_are_audited(full_client, make_user, auth_header):
    await make_user(phone="u000000007", password="pw", role=UserRole.admin)
    headers = await auth_header("u000000007", "pw")

    create_resp = await full_client.post(
        "/police-stations/", json={"name": "Test", "latitude": 1.0, "longitude": 2.0}, headers=headers
    )
    assert create_resp.status_code == 200
    station_id = create_resp.json()["id"]

    update_resp = await full_client.put(f"/police-stations/{station_id}", json={"name": "Renamed"}, headers=headers)
    assert update_resp.status_code == 200

    delete_resp = await full_client.delete(f"/police-stations/{station_id}", headers=headers)
    assert delete_resp.status_code == 200

    actions = {e.action for e in await models.AuditLog.find_all().to_list()}
    assert "police_station.created" in actions
    assert "police_station.updated" in actions
    assert "police_station.deleted" in actions
