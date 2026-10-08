"""
CCTV nearby-camera geo search ($geoNear / 2dsphere), stream-session
lifecycle (including the honest "not implemented" media-bridge outcome),
concurrent stream-request protection, and the control-room-only WebSocket
event routing.
"""
import json

import pytest

pytestmark = pytest.mark.usefixtures("mongo_db")


async def _admin_headers(make_user, auth_header, phone="cctvgeo_admin"):
    await make_user(phone=phone, password="pw", role="admin")
    return await auth_header(phone, "pw")


# ===========================================================================
# Geo / nearby
# ===========================================================================

async def test_2dsphere_index_exists_on_cctv_camera_location():
    from app import models

    indexes = await models.CCTVCamera.get_motor_collection().index_information()
    matching = [spec for spec in indexes.values() if spec.get("key") == [("location", "2dsphere")]]
    assert matching, "no 2dsphere index found on CCTVCamera.location"


async def test_active_stream_session_unique_index_exists():
    from app import models

    indexes = await models.CCTVStreamSession.get_motor_collection().index_information()
    idx = indexes.get("uq_active_stream_session_per_camera")
    assert idx is not None
    assert idx.get("unique") is True
    assert "partialFilterExpression" in idx


async def test_nearby_search_orders_by_distance_and_excludes_disabled_by_default(
    full_client, make_user, auth_header, make_cctv_camera
):
    # "far" is ~7.6km away (0.05 deg at this latitude) -- clearly farther
    # than "near"/"disabled" but still comfortably inside the endpoint's
    # own 50km radius_m cap (a deliberate production safety limit, not a
    # bug -- see routers/cctv.py's nearby_cameras Query(..., le=50000)).
    # A prior version of this test used a 200km query radius that
    # exceeded that cap outright (422), caught only by actually running
    # this test for real.
    near = await make_cctv_camera(camera_code="CAM-NEAR", longitude=78.90, latitude=20.50)
    far = await make_cctv_camera(camera_code="CAM-FAR", longitude=78.95, latitude=20.55)
    disabled = await make_cctv_camera(camera_code="CAM-DISABLED-NEAR", longitude=78.901, latitude=20.501, enabled=False)
    headers = await _admin_headers(make_user, auth_header)

    resp = await full_client.get(
        "/cctv/cameras/nearby", params={"latitude": 20.50, "longitude": 78.90, "radius_m": 20000}, headers=headers,
    )
    assert resp.status_code == 200
    codes = [c["camera_code"] for c in resp.json()]
    assert codes[0] == "CAM-NEAR"
    assert "CAM-FAR" in codes
    assert "CAM-DISABLED-NEAR" not in codes  # enabled_only defaults to True

    include_disabled = await full_client.get(
        "/cctv/cameras/nearby",
        params={"latitude": 20.50, "longitude": 78.90, "radius_m": 20000, "enabled_only": False},
        headers=headers,
    )
    codes_incl = {c["camera_code"] for c in include_disabled.json()}
    assert "CAM-DISABLED-NEAR" in codes_incl


async def test_incident_nearby_cameras_anchors_on_incident_location(
    full_client, make_user, auth_header, make_cctv_camera, make_incident
):
    incident = await make_incident(longitude=78.90, latitude=20.50)
    await make_cctv_camera(camera_code="CAM-INC-NEAR", longitude=78.901, latitude=20.501)
    await make_cctv_camera(camera_code="CAM-INC-FAR", longitude=90.0, latitude=30.0)
    headers = await _admin_headers(make_user, auth_header)

    resp = await full_client.get(f"/cctv/incidents/{incident.id}/nearby-cameras", params={"radius_m": 5000}, headers=headers)
    assert resp.status_code == 200
    codes = {c["camera_code"] for c in resp.json()}
    assert codes == {"CAM-INC-NEAR"}


async def test_incident_without_location_returns_422(full_client, make_user, auth_header):
    from app import models

    incident = models.Incident(status=models.IncidentStatus.new)  # no location set
    await incident.insert()
    headers = await _admin_headers(make_user, auth_header)

    resp = await full_client.get(f"/cctv/incidents/{incident.id}/nearby-cameras", headers=headers)
    assert resp.status_code == 422


async def test_station_denied_incident_nearby_cameras(full_client, make_user, auth_header, make_incident, make_station):
    station = await make_station()
    incident = await make_incident(longitude=78.90, latitude=20.50, station_id=station.id)
    await make_user(phone="cctvgeo_station", password="pw", role="station", station_id=station.id)
    headers = await auth_header("cctvgeo_station", "pw")

    resp = await full_client.get(f"/cctv/incidents/{incident.id}/nearby-cameras", headers=headers)
    assert resp.status_code == 403


async def test_nearby_search_respects_radius(full_client, make_user, auth_header, make_cctv_camera):
    await make_cctv_camera(camera_code="CAM-CLOSE", longitude=78.90, latitude=20.50)
    await make_cctv_camera(camera_code="CAM-FAR-AWAY", longitude=90.0, latitude=30.0)
    headers = await _admin_headers(make_user, auth_header)

    resp = await full_client.get(
        "/cctv/cameras/nearby", params={"latitude": 20.50, "longitude": 78.90, "radius_m": 1000}, headers=headers,
    )
    codes = {c["camera_code"] for c in resp.json()}
    assert codes == {"CAM-CLOSE"}


# ===========================================================================
# Stream session lifecycle
# ===========================================================================

async def test_requesting_a_stream_on_disabled_camera_is_rejected(full_client, make_user, auth_header, make_cctv_camera):
    camera = await make_cctv_camera(enabled=False)
    headers = await _admin_headers(make_user, auth_header)
    resp = await full_client.post(f"/cctv/cameras/{camera.id}/stream", headers=headers)
    assert resp.status_code == 409


async def test_requesting_a_stream_honestly_fails_with_no_media_gateway(full_client, make_user, auth_header, make_cctv_camera):
    """Per cctv_providers.py's documented scope: no fabricated success. Session ends up status=failed, never active, with a real error message."""
    camera = await make_cctv_camera()
    headers = await _admin_headers(make_user, auth_header)
    resp = await full_client.post(f"/cctv/cameras/{camera.id}/stream", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["session"]["status"] == "failed"
    assert body["session"]["error"]
    assert body["token"] is None
    assert body["livekit_url"] is None


async def test_concurrent_stream_requests_for_same_camera_are_rejected(full_client, make_user, auth_header, make_cctv_camera):
    """
    The FIRST request's session ends up `failed` almost immediately
    (see above -- no media gateway), which frees the unique-active-session
    slot. To exercise the actual concurrency guard, this test inserts a
    stuck `active` session directly (simulating a provider that DID
    successfully start one) and confirms a second request is rejected.
    """
    from app import models

    camera = await make_cctv_camera()
    stuck_session = models.CCTVStreamSession(
        camera_id=camera.id, requested_by=camera.id, provider=camera.provider_type,
        protocol=camera.stream_protocol, status=models.CCTVStreamSessionStatus.active,
    )
    await stuck_session.insert()

    headers = await _admin_headers(make_user, auth_header)
    resp = await full_client.post(f"/cctv/cameras/{camera.id}/stream", headers=headers)
    assert resp.status_code == 409


async def test_stop_stream_with_no_active_session_is_404(full_client, make_user, auth_header, make_cctv_camera):
    camera = await make_cctv_camera()
    headers = await _admin_headers(make_user, auth_header)
    resp = await full_client.post(f"/cctv/cameras/{camera.id}/stream/stop", headers=headers)
    assert resp.status_code == 404


async def test_stop_stream_transitions_an_active_session_to_stopped(full_client, make_user, auth_header, make_cctv_camera):
    from app import models

    camera = await make_cctv_camera()
    active_session = models.CCTVStreamSession(
        camera_id=camera.id, requested_by=camera.id, provider=camera.provider_type,
        protocol=camera.stream_protocol, status=models.CCTVStreamSessionStatus.active,
    )
    await active_session.insert()

    headers = await _admin_headers(make_user, auth_header)
    resp = await full_client.post(f"/cctv/cameras/{camera.id}/stream/stop", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "stopped"

    # Idempotency check -- stopping again is a 404 (nothing active left), not a silent 200.
    again = await full_client.post(f"/cctv/cameras/{camera.id}/stream/stop", headers=headers)
    assert again.status_code == 404


# ===========================================================================
# WebSocket routing -- control_room only (same fake-connection technique
# as tests/test_presence_websocket.py).
# ===========================================================================

class _FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send_text(self, payload: str):
        self.sent.append(json.loads(payload))


async def test_camera_registered_event_reaches_control_room_only(full_client, make_user, auth_header, monkeypatch):
    from app.routers.websocket import manager

    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    headers = await _admin_headers(make_user, auth_header)

    fake_ws = _FakeWebSocket()
    manager.add_control_room(fake_ws)
    try:
        resp = await full_client.post(
            "/cctv/cameras",
            json={"name": "WS Cam", "camera_code": "CAM-WS-1", "latitude": 1.0, "longitude": 1.0, "stream_host": "127.0.0.1"},
            headers=headers,
        )
        assert resp.status_code == 200
    finally:
        manager.control_room_connections.discard(fake_ws)

    events = [m["event"] for m in fake_ws.sent]
    assert "cctv.registered" in events
    payload = next(m for m in fake_ws.sent if m["event"] == "cctv.registered")["data"]
    assert "encrypted_secret" not in payload
    assert "stream_host" not in payload  # WS payloads carry even less than REST responses -- see events.py::_cctv_camera_summary


async def test_stream_failed_event_is_published(full_client, make_user, auth_header, make_cctv_camera):
    from app.routers.websocket import manager

    camera = await make_cctv_camera()
    headers = await _admin_headers(make_user, auth_header)

    fake_ws = _FakeWebSocket()
    manager.add_control_room(fake_ws)
    try:
        await full_client.post(f"/cctv/cameras/{camera.id}/stream", headers=headers)
    finally:
        manager.control_room_connections.discard(fake_ws)

    events = [m["event"] for m in fake_ws.sent]
    assert "cctv.stream_requested" in events
    assert "cctv.stream_failed" in events
