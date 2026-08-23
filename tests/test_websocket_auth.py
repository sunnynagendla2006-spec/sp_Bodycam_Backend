"""
Phase 5 tests: WebSocket authentication, role-scoped rooms, and event
routing/location-privacy. Uses TestClient's `websocket_connect`, which
raises `starlette.websockets.WebSocketDisconnect` if the server closes the
connection before/without accepting it.
"""
import time

import pytest
from starlette.websockets import WebSocketDisconnect

from app.models import UserRole, IncidentStatus


def _token(full_client, phone, password):
    resp = full_client.post("/auth/login", json={"username": phone, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# 20. Unauthenticated WebSocket connection rejected
# ---------------------------------------------------------------------------
def test_unauthenticated_websocket_rejected(full_client):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with full_client.websocket_connect("/ws/control_room"):
            pass
    assert exc_info.value.code == 4401


# ---------------------------------------------------------------------------
# 21. Invalid JWT rejected
# ---------------------------------------------------------------------------
def test_invalid_jwt_websocket_rejected(full_client):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with full_client.websocket_connect("/ws/control_room?token=not-a-real-token"):
            pass
    assert exc_info.value.code == 4401


# ---------------------------------------------------------------------------
# 22. Expired JWT rejected
# ---------------------------------------------------------------------------
def test_expired_jwt_websocket_rejected(full_client, make_user):
    from app.auth.security import create_access_token

    user = make_user(phone="w000000001", password="pw", role=UserRole.admin)
    token, _ = create_access_token(subject=str(user.id), role="admin", expires_minutes=-1)

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with full_client.websocket_connect(f"/ws/control_room?token={token}"):
            pass
    assert exc_info.value.code == 4401


# ---------------------------------------------------------------------------
# 23. Inactive user rejected
# ---------------------------------------------------------------------------
def test_inactive_user_websocket_rejected(full_client, make_user, db_session):
    from app.models import UserStatus

    user = make_user(phone="w000000003", password="pw", role=UserRole.admin, status=UserStatus.active)
    token = _token(full_client, "w000000003", "pw")

    # Deactivate the user AFTER the token was issued -- get_current_user's
    # equivalent WebSocket check re-loads the user from the DB on every
    # connect attempt, so a still-unexpired token for a since-deactivated
    # user must still be rejected.
    user.status = UserStatus.inactive
    db_session.commit()

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with full_client.websocket_connect(f"/ws/control_room?token={token}"):
            pass
    assert exc_info.value.code == 4401


# ---------------------------------------------------------------------------
# 24. admin/control_room can connect to control room
# ---------------------------------------------------------------------------
def test_admin_can_connect_to_control_room(full_client, make_user):
    make_user(phone="w000000004", password="pw", role=UserRole.admin)
    token = _token(full_client, "w000000004", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={token}") as ws:
        ws.send_text("ping")
        msg = ws.receive_json()
        assert msg["event"] == "ack"


def test_control_room_role_can_connect(full_client, make_user):
    make_user(phone="w000000005", password="pw", role=UserRole.control_room)
    token = _token(full_client, "w000000005", "pw")
    with full_client.websocket_connect(f"/ws/control_room?token={token}") as ws:
        ws.send_text("ping")
        msg = ws.receive_json()
        assert msg["event"] == "ack"


# ---------------------------------------------------------------------------
# 25. station connects only to its station room
# ---------------------------------------------------------------------------
def test_station_connects_to_own_station_room(full_client, make_user, make_station):
    station = make_station()
    make_user(phone="w000000006", password="pw", role=UserRole.station, station_id=station.id)
    token = _token(full_client, "w000000006", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={token}") as ws:
        from app.routers.websocket import manager
        assert station.id in manager.station_connections
        assert len(manager.station_connections[station.id]) == 1


def test_station_without_station_id_rejected(full_client, make_user):
    make_user(phone="w000000007", password="pw", role=UserRole.station, station_id=None)
    token = _token(full_client, "w000000007", "pw")

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with full_client.websocket_connect(f"/ws/control_room?token={token}"):
            pass
    assert exc_info.value.code == 4403


# ---------------------------------------------------------------------------
# 26. constable connects only to own constable room
# ---------------------------------------------------------------------------
def test_constable_connects_to_own_room(full_client, make_constable):
    _, constable = make_constable(phone="w000000008")
    resp = full_client.post("/auth/login", json={"username": "w000000008", "password": "correct-horse-battery"})
    token = resp.json()["access_token"]

    with full_client.websocket_connect(f"/ws/control_room?token={token}") as ws:
        from app.routers.websocket import manager
        assert constable.id in manager.constable_connections
        assert len(manager.constable_connections[constable.id]) == 1


# ---------------------------------------------------------------------------
# 27. constable cannot subscribe to another constable's room (there is no
#     client-selectable room parameter at all -- room is entirely
#     server-derived from the JWT, so this is structurally impossible; we
#     confirm two different constables land in two DISTINCT rooms)
# ---------------------------------------------------------------------------
def test_constable_rooms_are_distinct_per_constable(full_client, make_constable):
    _, constable_a = make_constable(phone="w000000009a")
    _, constable_b = make_constable(phone="w000000009b")
    token_a = _token(full_client, "w000000009a", "correct-horse-battery")
    token_b = _token(full_client, "w000000009b", "correct-horse-battery")

    from app.routers.websocket import manager
    with full_client.websocket_connect(f"/ws/control_room?token={token_a}"):
        with full_client.websocket_connect(f"/ws/control_room?token={token_b}"):
            assert constable_a.id in manager.constable_connections
            assert constable_b.id in manager.constable_connections
            assert manager.constable_connections[constable_a.id] != manager.constable_connections[constable_b.id]


# ---------------------------------------------------------------------------
# 28. citizen cannot connect to operational WebSocket rooms
# ---------------------------------------------------------------------------
def test_citizen_cannot_connect(full_client, make_user):
    make_user(phone="w000000010", password="pw", role=UserRole.citizen)
    token = _token(full_client, "w000000010", "pw")

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with full_client.websocket_connect(f"/ws/control_room?token={token}"):
            pass
    assert exc_info.value.code == 4403


# ---------------------------------------------------------------------------
# 29 & 30. incident event reaches control room AND responsible station
# ---------------------------------------------------------------------------
def test_incident_verified_event_reaches_control_room_and_station(
    full_client, make_user, make_station, make_incident
):
    station = make_station()
    make_user(phone="w000000011", password="pw", role=UserRole.control_room)
    make_user(phone="w000000011s", password="pw", role=UserRole.station, station_id=station.id)
    incident = make_incident(status_=IncidentStatus.new, station_id=station.id)

    cr_token = _token(full_client, "w000000011", "pw")
    station_token = _token(full_client, "w000000011s", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={cr_token}") as cr_ws:
        with full_client.websocket_connect(f"/ws/control_room?token={station_token}") as station_ws:
            verify_headers = {"Authorization": f"Bearer {cr_token}"}
            resp = full_client.post(f"/incidents/{incident.id}/verify", headers=verify_headers)
            assert resp.status_code == 200

            cr_msg = cr_ws.receive_json()
            assert cr_msg["event"] == "incident.verified"
            assert cr_msg["data"]["incident_id"] == str(incident.id)

            station_msg = station_ws.receive_json()
            assert station_msg["event"] == "incident.verified"
            assert station_msg["data"]["incident_id"] == str(incident.id)


# ---------------------------------------------------------------------------
# 31 & 32. assignment event reaches assigned constable, not an unrelated one
# ---------------------------------------------------------------------------
def test_assignment_event_reaches_only_assigned_constable(
    full_client, make_user, make_incident, make_constable, make_location
):
    make_user(phone="w000000012", password="pw", role=UserRole.control_room)
    incident = make_incident(status_=IncidentStatus.verified, longitude=78.9, latitude=20.5)
    _, constable_assigned = make_constable(phone="w000000012a")
    make_location(constable_assigned.id, longitude=78.9, latitude=20.5, age_seconds=5)
    _, constable_other = make_constable(phone="w000000012b")

    cr_token = _token(full_client, "w000000012", "pw")
    assigned_token = _token(full_client, "w000000012a", "correct-horse-battery")
    other_token = _token(full_client, "w000000012b", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={assigned_token}") as assigned_ws:
        with full_client.websocket_connect(f"/ws/control_room?token={other_token}") as other_ws:
            dispatch_headers = {"Authorization": f"Bearer {cr_token}"}
            resp = full_client.post(f"/incidents/{incident.id}/dispatch", headers=dispatch_headers)
            assert resp.status_code == 200
            assert resp.json()["constable_id"] == str(constable_assigned.id)

            assigned_msg = assigned_ws.receive_json()
            assert assigned_msg["event"] == "assignment.created"
            assert assigned_msg["data"]["incident_id"] == str(incident.id)

            # The unrelated constable must receive NOTHING about this dispatch.
            other_ws.send_text("ping")
            other_msg = other_ws.receive_json()
            assert other_msg["event"] == "ack"  # only their own keep-alive ack, never the dispatch event


# ---------------------------------------------------------------------------
# 33 & 34 & 35. location privacy: unrelated constable never sees it; station
#               sees only its own constables' locations; control room does.
# ---------------------------------------------------------------------------
def test_location_update_does_not_leak_to_unrelated_constable(full_client, make_constable):
    _, constable_a = make_constable(phone="w000000013a")
    _, constable_b = make_constable(phone="w000000013b")
    token_a = _token(full_client, "w000000013a", "correct-horse-battery")
    token_b = _token(full_client, "w000000013b", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={token_b}") as ws_b:
        a_headers = {"Authorization": f"Bearer {token_a}"}
        resp = full_client.post(
            "/constables/me/location", json={"latitude": 10.0, "longitude": 20.0}, headers=a_headers
        )
        assert resp.status_code == 200

        ws_b.send_text("ping")
        msg = ws_b.receive_json()
        assert msg["event"] == "ack"  # never constable.location_updated for constable A


def test_station_receives_only_its_own_constables_locations(full_client, make_user, make_station, make_constable):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="w000000014s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = make_constable(phone="w000000014a", station_id=station_a.id)
    _, constable_b = make_constable(phone="w000000014b", station_id=station_b.id)

    station_token = _token(full_client, "w000000014s", "pw")
    token_b = _token(full_client, "w000000014b", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={station_token}") as station_ws:
        b_headers = {"Authorization": f"Bearer {token_b}"}
        resp = full_client.post(
            "/constables/me/location", json={"latitude": 1.0, "longitude": 2.0}, headers=b_headers
        )
        assert resp.status_code == 200

        station_ws.send_text("ping")
        msg = station_ws.receive_json()
        assert msg["event"] == "ack"  # station A never gets constable B's (station B) location


def test_control_room_receives_location_updates(full_client, make_user, make_constable):
    make_user(phone="w000000015", password="pw", role=UserRole.control_room)
    _, constable = make_constable(phone="w000000015c")

    cr_token = _token(full_client, "w000000015", "pw")
    c_token = _token(full_client, "w000000015c", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={cr_token}") as cr_ws:
        c_headers = {"Authorization": f"Bearer {c_token}"}
        resp = full_client.post(
            "/constables/me/location", json={"latitude": 5.0, "longitude": 6.0}, headers=c_headers
        )
        assert resp.status_code == 200

        msg = cr_ws.receive_json()
        assert msg["event"] == "constable.location_updated"
        assert msg["data"]["constable_id"] == str(constable.id)


# ---------------------------------------------------------------------------
# 36. WebSocket disconnect cleans connection state
# ---------------------------------------------------------------------------
def test_disconnect_cleans_connection_state(full_client, make_user):
    make_user(phone="w000000016", password="pw", role=UserRole.admin)
    token = _token(full_client, "w000000016", "pw")

    from app.routers.websocket import manager

    with full_client.websocket_connect(f"/ws/control_room?token={token}") as ws:
        assert len(manager.control_room_connections) == 1

    # After the `with` block exits, the client-side close should have
    # propagated to a server-side disconnect and cleanup.
    assert len(manager.control_room_connections) == 0


# ---------------------------------------------------------------------------
# 37. failed broadcast does not break the database operation
# ---------------------------------------------------------------------------
def test_failed_broadcast_does_not_break_business_operation(full_client, make_user, make_incident, monkeypatch):
    """
    Simulate a broken/dead WebSocket connection by making send_text raise --
    ConnectionManager._send_to_all already catches this internally, so the
    verify operation (DB commit + HTTP response) must still succeed.
    """
    make_user(phone="w000000017", password="pw", role=UserRole.control_room)
    incident = make_incident(status_=IncidentStatus.new)
    token = _token(full_client, "w000000017", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={token}") as ws:
        from app.routers.websocket import manager

        async def _broken_send(*args, **kwargs):
            raise RuntimeError("simulated broken connection")

        for conn in manager.control_room_connections:
            monkeypatch.setattr(conn, "send_text", _broken_send)

        headers = {"Authorization": f"Bearer {token}"}
        resp = full_client.post(f"/incidents/{incident.id}/verify", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "verified"
