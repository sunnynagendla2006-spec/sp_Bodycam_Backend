"""
Phase 6 (continuation) tests: focused on the specific gaps identified by
re-inspecting the current codebase against this phase's spec --
DB-level assignment uniqueness, station-scoped constable *locations*
(as distinct from the constable roster), explicit negative cross-station
WebSocket isolation, and police-station CRUD audit trail.

Most of "Police Station scoping + dispatch hardening" was already
implemented and tested in tests/test_station_scoping.py / test_dispatch.py
/ test_audit.py / test_websocket_auth.py during the prior phase -- this
file adds only what a fresh, skeptical re-inspection found missing rather
than duplicating existing coverage.
"""
import pytest
from sqlalchemy.exc import IntegrityError
from starlette.websockets import WebSocketDisconnect

from app.models import UserRole, IncidentStatus, AssignmentStatus


def _token(full_client, phone, password):
    resp = full_client.post("/auth/login", json={"username": phone, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# DB-level uniqueness: only one ACTIVE assignment per incident, enforced by
# a real partial unique index (uq_active_assignment_per_incident), not just
# the application-level pre-check in dispatch_incident.
# ---------------------------------------------------------------------------
def test_db_level_constraint_rejects_second_active_assignment_bypassing_app_check(
    db_session, make_incident, make_constable
):
    """
    Directly inserts two ACTIVE IncidentAssignment rows for the same
    incident via the ORM session, bypassing dispatch_incident's own
    application-level `if existing_active_assignment:` guard entirely --
    proving the constraint is enforced by the DATABASE itself, which is
    what actually protects against a genuine race between two concurrent
    transactions (see models.py's uq_active_assignment_per_incident and
    migration 2b7f4e9a1d63 for why the app-level check alone is
    insufficient).
    """
    from app import models

    incident = make_incident(status_=IncidentStatus.verified)
    _, constable_a = make_constable(phone="u000000001a")
    _, constable_b = make_constable(phone="u000000001b")

    first = models.IncidentAssignment(
        incident_id=incident.id, constable_id=constable_a.id, status=AssignmentStatus.pending
    )
    db_session.add(first)
    db_session.commit()

    second = models.IncidentAssignment(
        incident_id=incident.id, constable_id=constable_b.id, status=AssignmentStatus.accepted
    )
    db_session.add(second)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_db_level_constraint_allows_second_assignment_after_first_is_rejected(
    db_session, make_incident, make_constable
):
    """A REJECTED (non-active) assignment does not block a new active one for the same incident -- the constraint is scoped to active statuses only."""
    from app import models

    incident = make_incident(status_=IncidentStatus.verified)
    _, constable_a = make_constable(phone="u000000002a")
    _, constable_b = make_constable(phone="u000000002b")

    first = models.IncidentAssignment(
        incident_id=incident.id, constable_id=constable_a.id, status=AssignmentStatus.rejected
    )
    db_session.add(first)
    db_session.commit()

    second = models.IncidentAssignment(
        incident_id=incident.id, constable_id=constable_b.id, status=AssignmentStatus.pending
    )
    db_session.add(second)
    db_session.commit()  # must NOT raise
    assert second.id is not None


def test_dispatch_endpoint_returns_409_when_active_assignment_already_exists(
    full_client, make_user, make_incident, make_constable, make_location, auth_header, db_session
):
    """
    End-to-end: the dispatch endpoint's own pre-check already returns 409
    for this case (this test documents/locks in that the DB constraint and
    the app-level check agree on the same outcome/status code).
    """
    from app import models

    make_user(phone="u000000003", password="pw", role=UserRole.control_room)
    incident = make_incident(status_=IncidentStatus.verified, longitude=78.9, latitude=20.5)
    _, constable = make_constable(phone="u000000003c")
    make_location(constable.id, longitude=78.9, latitude=20.5, age_seconds=5)

    existing = models.IncidentAssignment(
        incident_id=incident.id, constable_id=constable.id, status=AssignmentStatus.pending
    )
    db_session.add(existing)
    db_session.commit()

    headers = auth_header("u000000003", "pw")
    resp = full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Station-scoped constable LOCATIONS specifically (distinct from the
# roster endpoint, which was already tested previously)
# ---------------------------------------------------------------------------
def test_station_sees_only_own_stations_constable_locations(
    full_client, make_user, make_station, make_constable, make_location, auth_header
):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="u000000004", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = make_constable(phone="u000000004a", station_id=station_a.id, badge_number="BADGE-A")
    _, constable_b = make_constable(phone="u000000004b", station_id=station_b.id, badge_number="BADGE-B")
    make_location(constable_a.id, longitude=78.9, latitude=20.5)
    make_location(constable_b.id, longitude=79.0, latitude=21.0)

    headers = auth_header("u000000004", "pw")
    resp = full_client.get("/constables/locations", headers=headers)
    assert resp.status_code == 200
    badges_seen = {row["constable_id"] for row in resp.json()}
    assert "BADGE-A" in badges_seen
    assert "BADGE-B" not in badges_seen


def test_constable_locations_returns_only_the_latest_row_per_constable(
    full_client, make_user, make_constable, make_location, auth_header
):
    """
    Regression test: previously this endpoint used Postgres-only DISTINCT
    ON, silently ignored under SQLite -- a constable with more than one
    ConstableLocation row could have returned duplicate/stale rows here.
    Now uses a cross-dialect GROUP BY+MAX(timestamp) join-back (see
    constables.py::list_constable_locations), so exactly one row per
    constable is returned, reflecting the MOST RECENT location.
    """
    make_user(phone="u000000004admin", password="pw", role=UserRole.admin)
    _, constable = make_constable(phone="u000000004c", badge_number="BADGE-MULTI")
    make_location(constable.id, longitude=1.0, latitude=1.0, age_seconds=300)  # older
    make_location(constable.id, longitude=9.0, latitude=9.0, age_seconds=5)    # newer

    headers = auth_header("u000000004admin", "pw")
    resp = full_client.get("/constables/locations", headers=headers)
    assert resp.status_code == 200
    rows = [r for r in resp.json() if r["constable_id"] == "BADGE-MULTI"]
    assert len(rows) == 1
    assert rows[0]["lon"] == 9.0
    assert rows[0]["lat"] == 9.0


# ---------------------------------------------------------------------------
# Explicit negative WebSocket cross-station isolation (station B must NOT
# receive station A's incident event)
# ---------------------------------------------------------------------------
def test_station_b_does_not_receive_station_a_incident_events(
    full_client, make_user, make_station, make_incident
):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="u000000005cr", password="pw", role=UserRole.control_room)
    make_user(phone="u000000005a", password="pw", role=UserRole.station, station_id=station_a.id)
    make_user(phone="u000000005b", password="pw", role=UserRole.station, station_id=station_b.id)
    incident_a = make_incident(status_=IncidentStatus.new, station_id=station_a.id)

    cr_token = _token(full_client, "u000000005cr", "pw")
    token_b = _token(full_client, "u000000005b", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={token_b}") as ws_b:
        cr_headers = {"Authorization": f"Bearer {cr_token}"}
        resp = full_client.post(f"/incidents/{incident_a.id}/verify", headers=cr_headers)
        assert resp.status_code == 200

        # Station B's socket should receive NOTHING about station A's
        # incident -- confirm by sending a ping and only getting our own ack.
        ws_b.send_text("ping")
        msg = ws_b.receive_json()
        assert msg["event"] == "ack"


def test_station_a_does_receive_its_own_incident_event_while_station_b_is_also_connected(
    full_client, make_user, make_station, make_incident
):
    """Companion positive case: with both stations connected simultaneously, only station A gets station A's event."""
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="u000000006cr", password="pw", role=UserRole.control_room)
    make_user(phone="u000000006a", password="pw", role=UserRole.station, station_id=station_a.id)
    make_user(phone="u000000006b", password="pw", role=UserRole.station, station_id=station_b.id)
    incident_a = make_incident(status_=IncidentStatus.new, station_id=station_a.id)

    cr_token = _token(full_client, "u000000006cr", "pw")
    token_a = _token(full_client, "u000000006a", "pw")
    token_b = _token(full_client, "u000000006b", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={token_a}") as ws_a:
        with full_client.websocket_connect(f"/ws/control_room?token={token_b}") as ws_b:
            cr_headers = {"Authorization": f"Bearer {cr_token}"}
            resp = full_client.post(f"/incidents/{incident_a.id}/verify", headers=cr_headers)
            assert resp.status_code == 200

            msg_a = ws_a.receive_json()
            assert msg_a["event"] == "incident.verified"
            assert msg_a["data"]["incident_id"] == str(incident_a.id)

            ws_b.send_text("ping")
            msg_b = ws_b.receive_json()
            assert msg_b["event"] == "ack"  # never the incident.verified event


# ---------------------------------------------------------------------------
# Police Station CRUD audit trail
# ---------------------------------------------------------------------------
def test_police_station_create_update_delete_are_audited(full_client, make_user, auth_header, db_session):
    from app import models

    make_user(phone="u000000007", password="pw", role=UserRole.admin)
    headers = auth_header("u000000007", "pw")

    create_resp = full_client.post(
        "/police-stations/", json={"name": "Test", "latitude": 1.0, "longitude": 2.0}, headers=headers
    )
    assert create_resp.status_code == 200
    station_id = create_resp.json()["id"]

    update_resp = full_client.put(f"/police-stations/{station_id}", json={"name": "Renamed"}, headers=headers)
    assert update_resp.status_code == 200

    delete_resp = full_client.delete(f"/police-stations/{station_id}", headers=headers)
    assert delete_resp.status_code == 200

    actions = {e.action for e in db_session.query(models.AuditLog).all()}
    assert "police_station.created" in actions
    assert "police_station.updated" in actions
    assert "police_station.deleted" in actions
