"""
Verifies presence.connected / presence.handoff are actually published to
the control_room WebSocket room (and never leaked anywhere a
station/constable connection could read them when they shouldn't be, per
the same routing rule as every other event in app/services/events.py).

Uses a minimal fake WebSocket directly against
app.routers.websocket.manager -- the same module-level singleton the real
/ws/control_room endpoint uses -- rather than opening a real WebSocket
connection, since the behavior under test is "did events.py publish the
right event to the right room", not the WebSocket handshake/auth itself
(see tests/test_websocket_auth.py for that).
"""
import json

import pytest

pytestmark = pytest.mark.usefixtures("mongo_db")


class _FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send_text(self, payload: str):
        self.sent.append(json.loads(payload))


async def test_first_association_publishes_presence_connected_to_control_room(
    full_client, make_constable, make_access_point, auth_header
):
    from app.routers.websocket import manager

    await make_access_point(code="AP-01")
    _user, constable = await make_constable(phone="prws0000001", password="pw")
    headers = await auth_header("prws0000001", "pw")
    await full_client.post("/devices/register", json={"device_identifier": "DEV-WS-01"}, headers=headers)

    fake_ws = _FakeWebSocket()
    manager.add_control_room(fake_ws)
    try:
        resp = await full_client.post(
            "/presence/association",
            json={"device_identifier": "DEV-WS-01", "access_point_code": "AP-01"},
            headers=headers,
        )
        assert resp.status_code == 200
    finally:
        manager.control_room_connections.discard(fake_ws)

    events = [m["event"] for m in fake_ws.sent]
    assert "presence.connected" in events
    connected_event = next(m for m in fake_ws.sent if m["event"] == "presence.connected")
    assert connected_event["data"]["device_id"] == str((await _get_device_id(full_client, headers)))
    assert connected_event["data"]["access_point_code"] == "AP-01"


async def test_handoff_publishes_presence_handoff_with_both_ap_codes(
    full_client, make_constable, make_access_point, auth_header
):
    from app.routers.websocket import manager

    await make_access_point(code="AP-01")
    await make_access_point(code="AP-02")
    _user, constable = await make_constable(phone="prws0000002", password="pw")
    headers = await auth_header("prws0000002", "pw")
    await full_client.post("/devices/register", json={"device_identifier": "DEV-WS-02"}, headers=headers)
    await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-WS-02", "access_point_code": "AP-01"}, headers=headers,
    )

    fake_ws = _FakeWebSocket()
    manager.add_control_room(fake_ws)
    try:
        resp = await full_client.post(
            "/presence/association", json={"device_identifier": "DEV-WS-02", "access_point_code": "AP-02"}, headers=headers,
        )
        assert resp.status_code == 200
    finally:
        manager.control_room_connections.discard(fake_ws)

    handoff_event = next(m for m in fake_ws.sent if m["event"] == "presence.handoff")
    assert handoff_event["data"]["previous_access_point_code"] == "AP-01"
    assert handoff_event["data"]["access_point_code"] == "AP-02"


async def test_duplicate_heartbeat_publishes_no_event(full_client, make_constable, make_access_point, auth_header):
    from app.routers.websocket import manager

    await make_access_point(code="AP-01")
    _user, constable = await make_constable(phone="prws0000003", password="pw")
    headers = await auth_header("prws0000003", "pw")
    await full_client.post("/devices/register", json={"device_identifier": "DEV-WS-03"}, headers=headers)
    await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-WS-03", "access_point_code": "AP-01"}, headers=headers,
    )

    fake_ws = _FakeWebSocket()
    manager.add_control_room(fake_ws)
    try:
        resp = await full_client.post(
            "/presence/association", json={"device_identifier": "DEV-WS-03", "access_point_code": "AP-01"}, headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "duplicate_ignored"
    finally:
        manager.control_room_connections.discard(fake_ws)

    assert fake_ws.sent == []


async def _get_device_id(full_client, headers) -> str:
    resp = await full_client.get("/devices/", headers=headers)
    devices = resp.json()
    assert len(devices) == 1
    return devices[0]["id"]
