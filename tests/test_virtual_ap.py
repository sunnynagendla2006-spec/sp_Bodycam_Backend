"""
Virtual AP mode: association via VirtualAPAssociationProvider (source
tagging, same PresenceService path as the real endpoint), moving-ping
(pure WebSocket passthrough, zero persistence), nearest-AP lookup, the
constable-safe virtual map view, zone summaries (including the in-memory
moving-count), zone enable/disable, and zone emergency-alert targeting.
"""
import json

import pytest

pytestmark = pytest.mark.usefixtures("mongo_db")


class _FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send_text(self, payload: str):
        self.sent.append(json.loads(payload))


async def _register_constable_with_device(full_client, make_constable, auth_header, phone, device_identifier):
    _user, constable = await make_constable(phone=phone, password="pw")
    headers = await auth_header(phone, "pw")
    resp = await full_client.post("/devices/register", json={"device_identifier": device_identifier}, headers=headers)
    assert resp.status_code == 200, resp.text
    return constable, headers


# ===========================================================================
# Virtual association -- source tagging + same business logic
# ===========================================================================

async def test_virtual_association_tags_source_simulator(full_client, make_constable, make_access_point, auth_header):
    import uuid as uuid_module
    from app import models

    await make_access_point(code="AP-01")
    _constable, headers = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000001", "DEV-VA-01")

    resp = await full_client.post(
        "/presence/association/virtual",
        json={"device_identifier": "DEV-VA-01", "access_point_code": "AP-01"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "connected"

    device_id = uuid_module.UUID(resp.json()["presence"]["device_id"])
    handoff = await models.PresenceHandoff.find_one(models.PresenceHandoff.device_id == device_id)
    assert handoff.source == models.PresenceEventSource.simulator


async def test_virtual_association_duplicate_and_handoff_behave_like_real(full_client, make_constable, make_access_point, auth_header):
    await make_access_point(code="AP-01")
    await make_access_point(code="AP-02")
    _constable, headers = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000002", "DEV-VA-02")

    body = {"device_identifier": "DEV-VA-02", "access_point_code": "AP-01"}
    first = await full_client.post("/presence/association/virtual", json=body, headers=headers)
    assert first.json()["status"] == "connected"

    dup = await full_client.post("/presence/association/virtual", json=body, headers=headers)
    assert dup.json()["status"] == "duplicate_ignored"

    handoff = await full_client.post(
        "/presence/association/virtual", json={"device_identifier": "DEV-VA-02", "access_point_code": "AP-02"}, headers=headers,
    )
    assert handoff.json()["status"] == "handoff"
    assert handoff.json()["presence"]["handoff_count"] == 1


async def test_virtual_mode_can_be_disabled(full_client, make_constable, make_access_point, auth_header, monkeypatch):
    from app.routers import presence as presence_router_module

    await make_access_point(code="AP-01")
    _constable, headers = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000003", "DEV-VA-03")

    monkeypatch.setattr(presence_router_module, "VIRTUAL_AP_MODE_ENABLED", False)
    resp = await full_client.post(
        "/presence/association/virtual", json={"device_identifier": "DEV-VA-03", "access_point_code": "AP-01"}, headers=headers,
    )
    assert resp.status_code == 403


async def test_virtual_association_rejects_unauthorized_device_and_disabled_ap(
    full_client, make_constable, make_access_point, auth_header
):
    await make_access_point(code="AP-DISABLED-VA", enabled=False)
    _constable, headers = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000004", "DEV-VA-04")

    disabled_resp = await full_client.post(
        "/presence/association/virtual", json={"device_identifier": "DEV-VA-04", "access_point_code": "AP-DISABLED-VA"}, headers=headers,
    )
    assert disabled_resp.status_code == 409

    unknown_resp = await full_client.post(
        "/presence/association/virtual", json={"device_identifier": "DEV-VA-04", "access_point_code": "AP-DOES-NOT-EXIST"}, headers=headers,
    )
    assert unknown_resp.status_code == 404

    # A different constable may never report presence for someone else's device.
    _other_user, _other_constable = await make_constable(phone="va0000004b", password="pw")
    other_headers = await auth_header("va0000004b", "pw")
    spoof_resp = await full_client.post(
        "/presence/association/virtual", json={"device_identifier": "DEV-VA-04", "access_point_code": "AP-DISABLED-VA"}, headers=other_headers,
    )
    assert spoof_resp.status_code == 403


# ===========================================================================
# Moving-ping: pure passthrough, zero persistence
# ===========================================================================

async def test_moving_ping_never_creates_a_presence_or_handoff_row(full_client, make_constable, make_access_point, auth_header):
    from app import models

    await make_access_point(code="AP-01")
    await make_access_point(code="AP-02", zone="ZONE_TWO")
    _constable, headers = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000005", "DEV-VA-05")

    resp = await full_client.post(
        "/presence/virtual/moving-ping",
        json={"device_identifier": "DEV-VA-05", "target_access_point_code": "AP-02", "progress": 42},
        headers=headers,
    )
    assert resp.status_code == 200

    count = await models.PolicePresence.find_all().count()
    handoff_count = await models.PresenceHandoff.find_all().count()
    assert count == 0
    assert handoff_count == 0


async def test_moving_ping_publishes_presence_moving_event(full_client, make_constable, make_access_point, auth_header):
    from app.routers.websocket import manager

    await make_access_point(code="AP-01")
    await make_access_point(code="AP-02")
    _constable, headers = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000006", "DEV-VA-06")

    fake_ws = _FakeWebSocket()
    manager.add_control_room(fake_ws)
    try:
        resp = await full_client.post(
            "/presence/virtual/moving-ping",
            json={"device_identifier": "DEV-VA-06", "target_access_point_code": "AP-02", "progress": 55},
            headers=headers,
        )
        assert resp.status_code == 200
    finally:
        manager.control_room_connections.discard(fake_ws)

    events = [m["event"] for m in fake_ws.sent]
    assert "presence.moving" in events
    payload = next(m for m in fake_ws.sent if m["event"] == "presence.moving")["data"]
    assert payload["target_access_point_code"] == "AP-02"
    assert payload["progress"] == 55
    assert payload["source"] == "SIMULATOR"


async def test_moving_ping_is_cleared_by_a_real_handoff(full_client, make_constable, make_access_point, auth_header):
    from app.services import movement_state

    await make_access_point(code="AP-01")
    await make_access_point(code="AP-02")
    _constable, headers = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000007", "DEV-VA-07")

    await full_client.post(
        "/presence/association/virtual", json={"device_identifier": "DEV-VA-07", "access_point_code": "AP-01"}, headers=headers,
    )
    ping_resp = await full_client.post(
        "/presence/virtual/moving-ping",
        json={"device_identifier": "DEV-VA-07", "target_access_point_code": "AP-02", "progress": 80},
        headers=headers,
    )
    device_id = None
    me = await full_client.get("/presence/me", headers=headers)
    device_id = me.json()[0]["device_id"]
    assert movement_state.is_moving(device_id) is True

    await full_client.post(
        "/presence/association/virtual", json={"device_identifier": "DEV-VA-07", "access_point_code": "AP-02"}, headers=headers,
    )
    assert movement_state.is_moving(device_id) is False


# ===========================================================================
# Nearest AP + virtual map
# ===========================================================================

async def test_nearest_ap_returns_closest_enabled_ap(full_client, make_user, auth_header, make_access_point):
    from app import models

    close = models.AccessPoint(code="AP-NEAR-01", name="Near", location=models.GeoPoint(coordinates=[78.90, 20.50]), is_demo=True)
    far = models.AccessPoint(code="AP-FAR-01", name="Far", location=models.GeoPoint(coordinates=[90.0, 30.0]), is_demo=True)
    await close.insert()
    await far.insert()

    await make_user(phone="va0000008", password="pw", role="constable")
    headers = await auth_header("va0000008", "pw")

    resp = await full_client.get("/presence/virtual/nearest-ap", params={"latitude": 20.501, "longitude": 78.901}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["code"] == "AP-NEAR-01"


async def test_virtual_map_excludes_disabled_aps_and_is_constable_accessible(full_client, make_user, auth_header, make_access_point):
    await make_access_point(code="AP-VM-ENABLED", enabled=True)
    await make_access_point(code="AP-VM-DISABLED", enabled=False)
    await make_user(phone="va0000009", password="pw", role="constable")
    headers = await auth_header("va0000009", "pw")

    resp = await full_client.get("/presence/virtual/map", headers=headers)
    assert resp.status_code == 200
    codes = {a["code"] for a in resp.json()}
    assert "AP-VM-ENABLED" in codes
    assert "AP-VM-DISABLED" not in codes


async def test_virtual_map_denies_citizen(full_client, make_user, auth_header):
    await make_user(phone="va0000010", password="pw", role="citizen")
    headers = await auth_header("va0000010", "pw")
    resp = await full_client.get("/presence/virtual/map", headers=headers)
    assert resp.status_code == 403


# ===========================================================================
# Zones (derived view)
# ===========================================================================

async def test_zone_summary_reflects_police_and_moving_counts(full_client, make_user, make_constable, make_access_point, auth_header):
    await make_access_point(code="AP-Z1", zone="ZONE-Z1")
    await make_access_point(code="AP-Z2", zone="ZONE-Z2")
    _constable, dev_headers = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000011", "DEV-VA-11")

    await full_client.post(
        "/presence/association/virtual", json={"device_identifier": "DEV-VA-11", "access_point_code": "AP-Z1"}, headers=dev_headers,
    )
    await full_client.post(
        "/presence/virtual/moving-ping",
        json={"device_identifier": "DEV-VA-11", "target_access_point_code": "AP-Z2", "progress": 30},
        headers=dev_headers,
    )

    await make_user(phone="va0000011a", password="pw", role="admin")
    admin_headers = await auth_header("va0000011a", "pw")
    resp = await full_client.get("/access-points/zones", headers=admin_headers)
    assert resp.status_code == 200
    by_zone = {z["zone"]: z for z in resp.json()}
    assert by_zone["ZONE-Z1"]["police_count"] == 1
    assert by_zone["ZONE-Z2"]["moving_count"] == 1


async def test_zone_enable_disable_toggles_all_aps_in_zone(full_client, make_user, auth_header, make_access_point):
    await make_access_point(code="AP-ZT-1", zone="ZONE-TOGGLE", enabled=True)
    await make_access_point(code="AP-ZT-2", zone="ZONE-TOGGLE", enabled=True)
    await make_user(phone="va0000012", password="pw", role="admin")
    headers = await auth_header("va0000012", "pw")

    resp = await full_client.post("/access-points/zones/ZONE-TOGGLE/disable", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["access_point_count"] == 2

    listing = await full_client.get("/access-points/?enabled=true", headers=headers)
    codes = {a["code"] for a in listing.json()}
    assert "AP-ZT-1" not in codes and "AP-ZT-2" not in codes


# ===========================================================================
# Zone emergency alert targeting
# ===========================================================================

async def test_zone_alert_targets_only_currently_connected_constables_in_zone(
    full_client, make_user, make_constable, make_access_point, auth_header
):
    await make_access_point(code="AP-ALERT-1", zone="ZONE-ALERT")
    await make_access_point(code="AP-ALERT-2", zone="ZONE-OTHER")

    _c1, h1 = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000013a", "DEV-VA-13A")
    _c2, h2 = await _register_constable_with_device(full_client, make_constable, auth_header, "va0000013b", "DEV-VA-13B")

    await full_client.post("/presence/association/virtual", json={"device_identifier": "DEV-VA-13A", "access_point_code": "AP-ALERT-1"}, headers=h1)
    await full_client.post("/presence/association/virtual", json={"device_identifier": "DEV-VA-13B", "access_point_code": "AP-ALERT-2"}, headers=h2)

    await make_user(phone="va0000013c", password="pw", role="control_room")
    cr_headers = await auth_header("va0000013c", "pw")

    resp = await full_client.post(
        "/presence/zones/ZONE-ALERT/alert", json={"message": "EMERGENCY AT MAIN TEMPLE"}, headers=cr_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["targeted_device_count"] == 1


async def test_zone_alert_denied_for_constable(full_client, make_user, auth_header):
    await make_user(phone="va0000014", password="pw", role="constable")
    headers = await auth_header("va0000014", "pw")
    resp = await full_client.post("/presence/zones/ZONE-X/alert", json={"message": "x"}, headers=headers)
    assert resp.status_code == 403
