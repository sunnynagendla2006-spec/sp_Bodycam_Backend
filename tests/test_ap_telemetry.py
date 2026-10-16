"""
Physical AP Telemetry Ingestion Tests (Stage 2B).

Verifies edge controller authentication boundary, schema validation,
timestamp skew checks, replay protection, enrolled device mapping,
AP roam handoffs, and syslog/RADIUS adapters.
"""
import datetime
import uuid
import pytest
import pytest_asyncio

from app import models
from app.auth.deps import EDGE_CONTROLLER_API_KEY


def _edge_headers(controller_id: str = "edge-controller-north", key: str = EDGE_CONTROLLER_API_KEY) -> dict:
    return {
        "X-Edge-Controller-Key": key,
        "X-Edge-Controller-Id": controller_id,
    }


@pytest_asyncio.fixture()
async def enrolled_officer_and_device(make_station, make_constable):
    station = await make_station(name="Jathara Command Post", longitude=80.12, latitude=16.31)
    _, constable = await make_constable(station_id=station.id, badge_number="AP-CONST-991", phone="9988776655")
    device = models.Device(
        device_identifier="BODYCAM-AP-991",
        constable_id=constable.id,
        status=models.DeviceStatus.online,
    )
    await device.insert()
    return station, constable, device




@pytest.mark.asyncio
async def test_edge_telemetry_rejects_missing_credentials(full_client):
    """POST /telemetry/ap-events without edge authentication returns 401."""
    payload = {
        "controller_event_id": str(uuid.uuid4()),
        "controller_id": "edge-01",
        "ap_code": "AP-01",
        "event_type": "association",
        "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device_identifier": "BODYCAM-01",
    }
    resp = await full_client.post("/telemetry/ap-events", json=payload)
    assert resp.status_code == 401
    assert "Missing edge controller credentials" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_edge_telemetry_rejects_invalid_key(full_client):
    """POST /telemetry/ap-events with invalid key returns 401."""
    payload = {
        "controller_event_id": str(uuid.uuid4()),
        "controller_id": "edge-01",
        "ap_code": "AP-01",
        "event_type": "association",
        "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device_identifier": "BODYCAM-01",
    }
    resp = await full_client.post(
        "/telemetry/ap-events",
        json=payload,
        headers=_edge_headers(key="completely-wrong-edge-key"),
    )
    assert resp.status_code == 401
    assert "Invalid edge controller credentials" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_edge_telemetry_rejects_constable_jwt_as_edge_key(full_client, make_user, auth_header):
    """Constable user JWT cannot be reused as edge controller credential."""
    await make_user(phone="constable001", password="pw", role=models.UserRole.constable)
    user_headers = await auth_header("constable001", "pw")

    # Passing the Bearer token as X-Edge-Controller-Key or Authorization


    resp = await full_client.post(
        "/telemetry/ap-events",
        json={
            "controller_event_id": str(uuid.uuid4()),
            "controller_id": "edge-01",
            "ap_code": "AP-01",
            "event_type": "association",
            "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "device_identifier": "BODYCAM-01",
        },
        headers=user_headers,
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_edge_telemetry_rejects_clock_skew(full_client, make_access_point, enrolled_officer_and_device):
    """Event timestamp far in the future (>300s) is rejected with 400."""
    _, _, device = enrolled_officer_and_device
    ap = await make_access_point(code="AP-GATE-01")

    future_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=600)
    payload = {
        "controller_event_id": str(uuid.uuid4()),
        "controller_id": "edge-01",
        "ap_code": ap.code,
        "event_type": "association",
        "occurred_at": future_time.isoformat(),
        "device_identifier": device.device_identifier,
    }
    resp = await full_client.post(
        "/telemetry/ap-events",
        json=payload,
        headers=_edge_headers(),
    )
    assert resp.status_code == 400
    assert "skew" in resp.json()["detail"].lower()



@pytest.mark.asyncio
async def test_edge_telemetry_rejects_unknown_ap(full_client, enrolled_officer_and_device):
    """Reporting association to an unregistered AP returns 404."""
    _, _, device = enrolled_officer_and_device
    payload = {
        "controller_event_id": str(uuid.uuid4()),
        "controller_id": "edge-01",
        "ap_code": "AP-NONEXISTENT",
        "event_type": "association",
        "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device_identifier": device.device_identifier,
    }
    resp = await full_client.post(
        "/telemetry/ap-events",
        json=payload,
        headers=_edge_headers(),
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_edge_telemetry_handles_unmapped_device(full_client, make_access_point):
    """Unmapped device/station MAC returns unmapped_device without creating ghost entities."""
    ap = await make_access_point(code="AP-GATE-02")
    payload = {
        "controller_event_id": str(uuid.uuid4()),
        "controller_id": "edge-01",
        "ap_code": ap.code,
        "event_type": "association",
        "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device_identifier": "UNKNOWN-PHONE-1234",
        "station_mac": "aa:bb:cc:dd:ee:ff",
    }
    resp = await full_client.post(
        "/telemetry/ap-events",
        json=payload,
        headers=_edge_headers(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "unmapped_device"
    assert data["handoff_created"] is False


@pytest.mark.asyncio
async def test_edge_telemetry_association_success(full_client, make_access_point, enrolled_officer_and_device):
    """Real AP association creates presence with source PHYSICAL_CONTROLLER."""
    _, constable, device = enrolled_officer_and_device
    ap = await make_access_point(code="AP-MAIN-01", name="Main Gate AP", zone="MAIN_GATE")

    event_id = f"evt-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "controller_event_id": event_id,
        "controller_id": "edge-controller-north",
        "ap_code": ap.code,
        "event_type": "association",
        "occurred_at": now.isoformat(),
        "device_identifier": device.device_identifier,
        "rssi_dbm": -62,
    }
    resp = await full_client.post(
        "/telemetry/ap-events",
        json=payload,
        headers=_edge_headers(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["event_id"] == event_id
    assert data["access_point_code"] == ap.code

    # Verify in DB
    presence = await models.PolicePresence.find_one(models.PolicePresence.device_id == device.id)
    assert presence is not None
    assert presence.current_access_point_id == ap.id
    handoff = await models.PresenceHandoff.find_one(models.PresenceHandoff.device_id == device.id)
    assert handoff is not None
    assert handoff.source == models.PresenceEventSource.controller



@pytest.mark.asyncio
async def test_edge_telemetry_replay_protection(full_client, make_access_point, enrolled_officer_and_device):
    """Submitting the exact same controller_event_id returns duplicate_ignored."""
    _, _, device = enrolled_officer_and_device
    ap = await make_access_point(code="AP-TEMPLE-01")

    event_id = f"evt-replay-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "controller_event_id": event_id,
        "controller_id": "edge-01",
        "ap_code": ap.code,
        "event_type": "association",
        "occurred_at": now.isoformat(),
        "device_identifier": device.device_identifier,
    }

    # First submission
    resp1 = await full_client.post("/telemetry/ap-events", json=payload, headers=_edge_headers())
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "accepted"

    # Second submission (replay)
    resp2 = await full_client.post("/telemetry/ap-events", json=payload, headers=_edge_headers())
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "duplicate_ignored"
    assert "Duplicate" in resp2.json()["message"]


@pytest.mark.asyncio
async def test_edge_telemetry_roam_creates_handoff(full_client, make_access_point, enrolled_officer_and_device):
    """Transition from AP1 to AP2 via real telemetry creates a handoff record."""
    _, constable, device = enrolled_officer_and_device
    ap1 = await make_access_point(code="AP-NORTH-01")
    ap2 = await make_access_point(code="AP-NORTH-02")

    t1 = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)
    t2 = datetime.datetime.now(datetime.timezone.utc)

    # Associate to AP1
    resp1 = await full_client.post(
        "/telemetry/ap-events",
        json={
            "controller_event_id": str(uuid.uuid4()),
            "controller_id": "edge-01",
            "ap_code": ap1.code,
            "event_type": "association",
            "occurred_at": t1.isoformat(),
            "device_identifier": device.device_identifier,
        },
        headers=_edge_headers(),
    )
    assert resp1.status_code == 200

    # Roam to AP2
    resp2 = await full_client.post(
        "/telemetry/ap-events",
        json={
            "controller_event_id": str(uuid.uuid4()),
            "controller_id": "edge-01",
            "ap_code": ap2.code,
            "event_type": "roam",
            "occurred_at": t2.isoformat(),
            "device_identifier": device.device_identifier,
        },
        headers=_edge_headers(),
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "accepted"
    assert resp2.json()["handoff_created"] is True

    # Verify handoff in DB
    handoff = await models.PresenceHandoff.find_one(
        models.PresenceHandoff.device_id == device.id,
        models.PresenceHandoff.access_point_id == ap2.id,
    )
    assert handoff is not None
    assert handoff.previous_access_point_id == ap1.id
    assert handoff.source == models.PresenceEventSource.controller


@pytest.mark.asyncio
async def test_edge_telemetry_disassociation(full_client, make_access_point, enrolled_officer_and_device):
    """Disassociation event marks presence status disconnected."""
    _, _, device = enrolled_officer_and_device
    ap = await make_access_point(code="AP-PARK-01")
    now = datetime.datetime.now(datetime.timezone.utc)

    # Connect
    await full_client.post(
        "/telemetry/ap-events",
        json={
            "controller_event_id": str(uuid.uuid4()),
            "controller_id": "edge-01",
            "ap_code": ap.code,
            "event_type": "association",
            "occurred_at": (now - datetime.timedelta(seconds=5)).isoformat(),
            "device_identifier": device.device_identifier,
        },
        headers=_edge_headers(),
    )

    # Disassociate
    resp = await full_client.post(
        "/telemetry/ap-events",
        json={
            "controller_event_id": str(uuid.uuid4()),
            "controller_id": "edge-01",
            "ap_code": ap.code,
            "event_type": "disassociation",
            "occurred_at": now.isoformat(),
            "device_identifier": device.device_identifier,
        },
        headers=_edge_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "disassociated"

    presence = await models.PolicePresence.find_one(models.PolicePresence.device_id == device.id)
    assert presence.status == models.PresenceConnectionStatus.disconnected


@pytest.mark.asyncio
async def test_syslog_adapter_ingestion(full_client, make_access_point, enrolled_officer_and_device):
    """POST /telemetry/ap-events/syslog parses standard controller syslog."""
    _, constable, device = enrolled_officer_and_device
    ap = await make_access_point(code="AP-GATE-09")

    syslog_msg = f"%DOT11-6-ASSOC: Client {device.device_identifier} associated to AP {ap.code} on SSID AP_POLICE_SECURE"
    resp = await full_client.post(
        "/telemetry/ap-events/syslog",
        json={
            "message": syslog_msg,
            "controller_id": "cisco-wlc-jathara",
            "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        headers=_edge_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_radius_accounting_adapter_ingestion(full_client, make_access_point, enrolled_officer_and_device):
    """POST /telemetry/ap-events/radius parses RFC 2866 RADIUS Accounting attributes."""
    _, constable, device = enrolled_officer_and_device
    ap = await make_access_point(code="AP-TEMPLE-CORE")

    radius_payload = {
        "Acct-Status-Type": 1,  # Start
        "Acct-Session-Id": f"radius-sess-{uuid.uuid4().hex[:6]}",
        "User-Name": constable.badge_number,  # mapped via 802.1X identity
        "Called-Station-Id": f"{ap.code}:AP_POLICE_SECURE",
        "Calling-Station-Id": "11:22:33:44:55:66",
        "NAS-Identifier": "radius-gateway-main",
        "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    resp = await full_client.post(
        "/telemetry/ap-events/radius",
        json=radius_payload,
        headers=_edge_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"
    assert resp.json()["access_point_code"] == ap.code


@pytest.mark.asyncio
async def test_telemetry_event_log_audit_endpoint(full_client, make_user, auth_header):
    """GET /telemetry/events provides audit log and requires admin/control_room role."""
    await make_user(phone="admin999", password="pw", role=models.UserRole.admin)
    await make_user(phone="citizen999", password="pw", role=models.UserRole.citizen)

    # Citizen is forbidden
    resp_cit = await full_client.get("/telemetry/events", headers=await auth_header("citizen999", "pw"))
    assert resp_cit.status_code == 403

    # Admin is authorized
    resp_adm = await full_client.get("/telemetry/events", headers=await auth_header("admin999", "pw"))
    assert resp_adm.status_code == 200
    assert isinstance(resp_adm.json(), list)



