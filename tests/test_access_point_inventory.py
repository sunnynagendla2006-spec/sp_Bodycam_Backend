"""
Access point inventory: validation, uniqueness, lifecycle, and -- above all --
the separation between "an administrator registered it" and "real
infrastructure confirmed it".
"""
import datetime
import uuid

import pytest

from app import models
from app.auth.deps import EDGE_CONTROLLER_API_KEY
from app.models import UserRole
from app.services import ap_integration

pytestmark = pytest.mark.usefixtures("mongo_db")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture()
async def admin(make_user, auth_header):
    await make_user(phone="ap1admin", password="pw", role=UserRole.admin)
    return await auth_header("ap1admin", "pw")


def ap_body(code="AP-INV-01", **extra):
    body = {
        "code": code, "name": "Main Gate AP", "zone": "MAIN_GATE",
        "manufacturer": "ExampleCo", "model": "EX-100", "serial_number": f"SN-{code}",
        "bssid": "AA:BB:CC:00:11:22", "ssid": "POLICE-EVENT", "management_ip": "10.20.0.11",
        "controller_source": "edge-controller-north", "building": "Gate House", "floor": "G",
        "latitude": 16.5, "longitude": 80.6,
    }
    body.update(extra)
    return body


# ---------------------------------------------------------------------------
# Registration: inventory, not proof
# ---------------------------------------------------------------------------
async def test_new_ap_is_configured_but_unverified_and_unknown_reachability(full_client, admin):
    resp = await full_client.post("/access-points/", json=ap_body(), headers=admin)
    assert resp.status_code == 200, resp.text
    ap = resp.json()
    assert ap["bssid"] == "aa:bb:cc:00:11:22"  # normalised
    assert ap["verification_status"] == "configured"
    assert ap["reachability"] == "unknown" and ap["status"] == "unknown"
    assert ap["verified_at"] is None and ap["last_seen_at"] is None
    assert ap["integration_health"] == "unconfigured"
    assert ap["lifecycle_status"] == "active"


async def test_ap_with_no_identifiers_is_only_registered(full_client, admin):
    ap = (await full_client.post("/access-points/", json={"code": "AP-BARE", "name": "Bare"}, headers=admin)).json()
    assert ap["verification_status"] == "registered"


@pytest.mark.parametrize(
    "override",
    [
        {"bssid": "not-a-mac"},
        {"bssid": "01:00:5e:00:00:01"},  # multicast
        {"bssid": "ff:ff:ff:ff:ff:ff"},
        {"bssid": "00:00:00:00:00:00"},
        {"management_ip": "999.1.1.1"},
        {"ssid": "x" * 33},
        {"latitude": 91.0},
        {"coverage_radius_m": -5},
        {"event_zone_codes": ["DOES-NOT-EXIST"]},
        {"manufacturer": None},  # serial present but manufacturer missing
    ],
)
async def test_invalid_inventory_is_rejected(full_client, admin, override):
    resp = await full_client.post("/access-points/", json=ap_body(**override), headers=admin)
    assert resp.status_code == 422, resp.text


async def test_uniqueness_of_code_bssid_and_manufacturer_serial(full_client, admin):
    assert (await full_client.post("/access-points/", json=ap_body("AP-U1"), headers=admin)).status_code == 200
    assert (await full_client.post("/access-points/", json=ap_body("AP-U1", bssid="aa:bb:cc:00:11:99", serial_number="X"), headers=admin)).status_code == 409
    # same radio, different spelling of the MAC
    dup_bssid = await full_client.post("/access-points/", json=ap_body("AP-U2", bssid="aa-bb-cc-00-11-22", serial_number="OTHER"), headers=admin)
    assert dup_bssid.status_code == 409 and "BSSID" in dup_bssid.json()["detail"]
    dup_serial = await full_client.post("/access-points/", json=ap_body("AP-U3", bssid="aa:bb:cc:00:11:33", serial_number="SN-AP-U1"), headers=admin)
    assert dup_serial.status_code == 409 and "serial" in dup_serial.json()["detail"]
    # a serial is only unique per manufacturer
    other_make = await full_client.post("/access-points/", json=ap_body("AP-U4", bssid="aa:bb:cc:00:11:44", serial_number="SN-AP-U1", manufacturer="OtherCo"), headers=admin)
    assert other_make.status_code == 200


async def test_event_zone_codes_must_exist(full_client, admin):
    ring = [[[80.6, 16.5], [80.61, 16.5], [80.61, 16.51], [80.6, 16.51], [80.6, 16.5]]]
    await full_client.post("/event-zones/", json={"code": "Z-OK", "name": "Zone OK", "coordinates": ring}, headers=admin)
    ok = await full_client.post("/access-points/", json=ap_body("AP-Z1", event_zone_codes=["Z-OK"]), headers=admin)
    assert ok.status_code == 200 and ok.json()["event_zone_codes"] == ["Z-OK"]


# ---------------------------------------------------------------------------
# Lifecycle never fabricates operational state
# ---------------------------------------------------------------------------
async def test_enable_and_disable_never_mark_an_ap_online(full_client, admin):
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    disabled = (await full_client.post(f"/access-points/{ap['id']}/disable", headers=admin)).json()
    assert disabled["lifecycle_status"] == "disabled" and disabled["enabled"] is False
    assert disabled["reachability"] == "unknown" and disabled["status"] == "unknown"  # NOT "offline": nobody measured that
    enabled = (await full_client.post(f"/access-points/{ap['id']}/enable", headers=admin)).json()
    assert enabled["lifecycle_status"] == "active" and enabled["enabled"] is True
    assert enabled["reachability"] == "unknown" and enabled["status"] == "unknown"  # NOT "online"
    assert enabled["verification_status"] == "configured"


async def test_zone_bulk_enable_does_not_fabricate_status(full_client, admin):
    await full_client.post("/access-points/", json=ap_body("AP-ZB1"), headers=admin)
    await full_client.post("/access-points/zones/MAIN_GATE/disable", headers=admin)
    await full_client.post("/access-points/zones/MAIN_GATE/enable", headers=admin)
    aps = (await full_client.get("/access-points/", headers=admin)).json()
    assert aps[0]["status"] == "unknown" and aps[0]["reachability"] == "unknown"


async def test_configuration_history_records_changes(full_client, admin):
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    await full_client.patch(f"/access-points/{ap['id']}", json={"name": "Renamed", "floor": "1"}, headers=admin)
    detail = (await full_client.get(f"/access-points/{ap['id']}", headers=admin)).json()
    actions = [h["action"] for h in detail["config_history"]]
    assert actions == ["updated", "created"]  # newest first
    changes = detail["config_history"][0]["changes"]
    assert changes["name"] == {"from": "Main Gate AP", "to": "Renamed"} and changes["floor"]["to"] == "1"
    assert await models.AuditLog.find(models.AuditLog.action == "access_point_updated").count() == 1


async def test_retire_is_terminal_and_requires_a_reason(full_client, admin):
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    assert (await full_client.post(f"/access-points/{ap['id']}/retire", json={}, headers=admin)).status_code == 422
    retired = await full_client.post(f"/access-points/{ap['id']}/retire", json={"reason": "Decommissioned after event"}, headers=admin)
    assert retired.status_code == 200
    body = retired.json()
    assert body["lifecycle_status"] == "retired" and body["enabled"] is False and body["retire_reason"] == "Decommissioned after event"
    assert (await full_client.post(f"/access-points/{ap['id']}/enable", headers=admin)).status_code == 409
    assert (await full_client.patch(f"/access-points/{ap['id']}", json={"name": "x"}, headers=admin)).status_code == 409
    assert (await full_client.post(f"/access-points/{ap['id']}/verify", headers=admin)).status_code == 409
    # the record (and its history) is kept
    assert (await full_client.get(f"/access-points/{ap['id']}", headers=admin)).status_code == 200


async def test_retire_blocked_while_officers_associated_unless_forced(full_client, admin, make_constable, make_access_point):
    ap = await make_access_point(code="AP-R1")
    _, constable = await make_constable(phone="ap1r1")
    device = models.Device(constable_id=constable.id, device_identifier="DEV-R1")
    await device.insert()
    await models.PolicePresence(device_id=device.id, constable_id=constable.id, current_access_point_id=ap.id).insert()
    resp = await full_client.post(f"/access-points/{ap.id}/retire", json={"reason": "no longer needed"}, headers=admin)
    assert resp.status_code == 409
    forced = await full_client.post(f"/access-points/{ap.id}/retire?force=true", json={"reason": "no longer needed"}, headers=admin)
    assert forced.status_code == 200


async def test_verified_active_ap_cannot_be_deleted_only_retired(full_client, admin):
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    await models.AccessPoint.get_motor_collection().update_one(
        {"_id": uuid.UUID(ap["id"])}, {"$set": {"verification_status": "verified"}}
    )
    assert (await full_client.delete(f"/access-points/{ap['id']}", headers=admin)).status_code == 409
    await full_client.post(f"/access-points/{ap['id']}/retire", json={"reason": "gone"}, headers=admin)
    assert (await full_client.delete(f"/access-points/{ap['id']}", headers=admin)).status_code == 200


# ---------------------------------------------------------------------------
# Verification: only a real integration may verify
# ---------------------------------------------------------------------------
async def test_integration_status_is_honestly_unconfigured(full_client, admin, monkeypatch):
    monkeypatch.delenv("AP_CONTROLLER_URL", raising=False)
    body = (await full_client.get("/access-points/integration", headers=admin)).json()
    assert body["configured"] is False and body["kind"] is None


async def test_verify_without_integration_changes_nothing_and_says_so(full_client, admin, monkeypatch):
    monkeypatch.delenv("AP_CONTROLLER_URL", raising=False)
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    resp = await full_client.post(f"/access-points/{ap['id']}/verify", headers=admin)
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "integration_unconfigured"
    after = (await full_client.get(f"/access-points/{ap['id']}", headers=admin)).json()
    assert after["verification_status"] == "configured" and after["verified_at"] is None
    assert after["reachability"] == "unknown"
    assert after["last_verification_attempt_at"] is not None  # the attempt is recorded, the claim is not


async def test_verify_requires_some_identifier(full_client, admin):
    ap = (await full_client.post("/access-points/", json={"code": "AP-V0", "name": "Bare"}, headers=admin)).json()
    assert (await full_client.post(f"/access-points/{ap['id']}/verify", headers=admin)).status_code == 422


def _stub_integration(monkeypatch, result=None, error=None):
    monkeypatch.setenv("AP_CONTROLLER_URL", "https://controller.invalid/api")

    async def _lookup(self, *, bssid, serial_number, management_ip):
        if error:
            raise ap_integration.IntegrationError(error)
        return result

    monkeypatch.setattr(ap_integration.HttpJsonController, "lookup_ap", _lookup)


async def test_controller_confirmation_verifies_and_enables_reachability(full_client, admin, monkeypatch):
    _stub_integration(monkeypatch, ap_integration.APLookupResult(found=True, reachable=True, serial_number="sn-ap-inv-01"))
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    body = (await full_client.post(f"/access-points/{ap['id']}/verify", headers=admin)).json()
    assert body["verification_status"] == "verified" and body["verification_source"] == "CONTROLLER_API"
    assert body["reachability"] == "reachable" and body["status"] == "online" and body["integration_health"] == "healthy"


async def test_controller_that_does_not_know_the_ap_marks_verification_failed(full_client, admin, monkeypatch):
    _stub_integration(monkeypatch, ap_integration.APLookupResult(found=False))
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    body = (await full_client.post(f"/access-points/{ap['id']}/verify", headers=admin)).json()
    assert body["verification_status"] == "verification_failed" and body["reachability"] == "unknown"
    assert "does not know" in body["last_verification_error"]


async def test_serial_mismatch_is_not_verified(full_client, admin, monkeypatch):
    _stub_integration(monkeypatch, ap_integration.APLookupResult(found=True, reachable=True, serial_number="SOMETHING-ELSE"))
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    body = (await full_client.post(f"/access-points/{ap['id']}/verify", headers=admin)).json()
    assert body["verification_status"] == "verification_failed"


async def test_controller_reporting_ap_down_is_unreachable_but_verified(full_client, admin, monkeypatch):
    _stub_integration(monkeypatch, ap_integration.APLookupResult(found=True, reachable=False))
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    body = (await full_client.post(f"/access-points/{ap['id']}/verify", headers=admin)).json()
    assert body["verification_status"] == "verified" and body["reachability"] == "unknown"  # no last_seen was ever recorded
    assert body["status"] == "unknown"


async def test_controller_error_is_reported_without_leaking_details(full_client, admin, monkeypatch):
    _stub_integration(monkeypatch, error="The controller could not be reached")
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    resp = await full_client.post(f"/access-points/{ap['id']}/verify", headers=admin)
    assert resp.status_code == 502 and resp.json()["detail"]["code"] == "integration_error"
    assert "controller.invalid" not in resp.text
    after = (await full_client.get(f"/access-points/{ap['id']}", headers=admin)).json()
    assert after["verification_status"] == "verification_failed" and after["integration_health"] == "error"


async def test_http_adapter_speaks_the_documented_contract(monkeypatch):
    """Exercises the real HttpJsonController (request shape, auth header, parsing, error mapping) against an in-process fake controller."""
    import httpx
    from fastapi import FastAPI, Header, Query

    fake = FastAPI()
    seen = {}

    @fake.get("/access-points/lookup")
    async def lookup(bssid: str = Query(None), serial: str = Query(None), authorization: str = Header(None)):
        seen.update(bssid=bssid, serial=serial, auth=authorization)
        if bssid == "aa:bb:cc:00:11:22":
            return {"found": True, "reachable": True, "serial_number": "S1", "model": "EX-100", "client_count": 4}
        return {"found": False}

    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.ASGITransport(app=fake), **kw))
    integ = ap_integration.HttpJsonController("http://controller.local", "s3cret-token", 2.0)
    found = await integ.lookup_ap(bssid="aa:bb:cc:00:11:22", serial_number="S1", management_ip=None)
    assert found.found and found.reachable and found.client_count == 4
    assert seen["auth"] == "Bearer s3cret-token" and seen["bssid"] == "aa:bb:cc:00:11:22"
    assert (await integ.lookup_ap(bssid="aa:bb:cc:99:99:99", serial_number=None, management_ip=None)).found is False

    bad = FastAPI()

    @bad.get("/access-points/lookup")
    async def _bad():
        return {"unexpected": True}

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.ASGITransport(app=bad), **kw))
    with pytest.raises(ap_integration.IntegrationError):
        await integ.lookup_ap(bssid="aa:bb:cc:00:11:22", serial_number=None, management_ip=None)


async def test_changing_hardware_identifiers_withdraws_verification(full_client, admin):
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    await models.AccessPoint.get_motor_collection().update_one(
        {"_id": uuid.UUID(ap["id"])},
        {"$set": {"verification_status": "verified", "verified_at": _now(), "last_seen_at": _now(), "status": "online"}},
    )
    harmless = (await full_client.patch(f"/access-points/{ap['id']}", json={"floor": "2"}, headers=admin)).json()
    assert harmless["verification_status"] == "verified" and harmless["reachability"] == "reachable"
    swapped = (await full_client.patch(f"/access-points/{ap['id']}", json={"bssid": "aa:bb:cc:00:11:77"}, headers=admin)).json()
    assert swapped["verification_status"] == "configured"  # the proof was about the OLD radio
    assert swapped["verified_at"] is None and swapped["last_seen_at"] is None and swapped["reachability"] == "unknown"


def test_reachability_goes_stale_without_telemetry():
    ap = models.AccessPoint(code="X", name="X", verification_status=models.APVerificationStatus.verified, last_seen_at=_now() - datetime.timedelta(hours=1))
    assert ap_integration.derive_reachability(ap) == "no_recent_telemetry"
    ap.last_seen_at = _now()
    assert ap_integration.derive_reachability(ap) == "reachable"
    ap.verification_status = models.APVerificationStatus.configured
    assert ap_integration.derive_reachability(ap) == "unknown"  # never claim anything for an unverified AP


# ---------------------------------------------------------------------------
# Real telemetry from an authenticated edge collector
# ---------------------------------------------------------------------------
def _edge_event(**kw):
    body = {
        "controller_event_id": str(uuid.uuid4()), "controller_id": "edge-north", "event_type": "association",
        "occurred_at": _now().isoformat(), "device_identifier": "UNKNOWN-DEV",
    }
    body.update(kw)
    return body


EDGE = {"X-Edge-Controller-Key": EDGE_CONTROLLER_API_KEY, "X-Edge-Controller-Id": "edge-north"}


async def test_edge_telemetry_with_matching_bssid_verifies_the_ap(full_client, admin):
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    resp = await full_client.post("/telemetry/ap-events", json=_edge_event(ap_bssid="AA:BB:CC:00:11:22"), headers=EDGE)
    assert resp.status_code == 200, resp.text
    after = (await full_client.get(f"/access-points/{ap['id']}", headers=admin)).json()
    assert after["verification_status"] == "verified" and after["verification_source"] == "EDGE_TELEMETRY"
    assert after["reachability"] == "reachable" and after["last_seen_at"] is not None
    assert [h["action"] for h in after["config_history"]][0] == "verified"


async def test_edge_telemetry_matched_only_by_code_does_not_verify(full_client, admin):
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    resp = await full_client.post("/telemetry/ap-events", json=_edge_event(ap_code="AP-INV-01"), headers=EDGE)
    assert resp.status_code == 200
    after = (await full_client.get(f"/access-points/{ap['id']}", headers=admin)).json()
    assert after["verification_status"] == "configured"  # a collector echoing our own label proves nothing
    assert after["reachability"] == "unknown"
    assert after["last_seen_at"] is not None


async def test_edge_telemetry_for_unknown_bssid_creates_no_ap(full_client):
    resp = await full_client.post("/telemetry/ap-events", json=_edge_event(ap_bssid="aa:bb:cc:de:ad:00"), headers=EDGE)
    assert resp.status_code == 404
    assert await models.AccessPoint.find().count() == 0  # never auto-registered from the network


# ---------------------------------------------------------------------------
# Authorisation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("role", [UserRole.control_room, UserRole.station, UserRole.constable, UserRole.citizen])
async def test_only_admin_can_mutate_access_points(full_client, make_user, auth_header, admin, role):
    ap = (await full_client.post("/access-points/", json=ap_body(), headers=admin)).json()
    await make_user(phone=f"ap1{role.value}", password="pw", role=role)
    h = await auth_header(f"ap1{role.value}", "pw")
    assert (await full_client.post("/access-points/", json=ap_body("AP-X"), headers=h)).status_code == 403
    assert (await full_client.patch(f"/access-points/{ap['id']}", json={"name": "z"}, headers=h)).status_code == 403
    for action in ("verify", "disable", "enable"):
        assert (await full_client.post(f"/access-points/{ap['id']}/{action}", headers=h)).status_code == 403
    assert (await full_client.post(f"/access-points/{ap['id']}/retire", json={"reason": "abc"}, headers=h)).status_code == 403
    assert (await full_client.delete(f"/access-points/{ap['id']}", headers=h)).status_code == 403


async def test_unauthenticated_access_points_are_401(full_client):
    assert (await full_client.get("/access-points/")).status_code == 401
    assert (await full_client.post("/access-points/", json=ap_body())).status_code == 401


async def test_station_cannot_see_history_or_other_stations_ap(full_client, admin, make_user, make_station, auth_header):
    st = await make_station(name="S")
    other = await make_station(name="O")
    own = (await full_client.post("/access-points/", json=ap_body("AP-S1", station_id=str(st.id)), headers=admin)).json()
    foreign = (await full_client.post("/access-points/", json=ap_body("AP-S2", station_id=str(other.id), bssid="aa:bb:cc:00:11:55", serial_number="Q"), headers=admin)).json()
    await make_user(phone="ap1station", password="pw", role=UserRole.station, station_id=st.id)
    h = await auth_header("ap1station", "pw")
    assert (await full_client.get(f"/access-points/{foreign['id']}", headers=h)).status_code == 403
    assert (await full_client.get(f"/access-points/{own['id']}", headers=h)).json()["config_history"] is None
