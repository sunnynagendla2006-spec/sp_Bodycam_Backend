"""
Access point (AP) management: CRUD, RBAC, and the associated_device_count
rollup. Mirrors tests/test_station_scoping.py's structure for the
equivalent PoliceStation endpoints.
"""
import pytest

pytestmark = pytest.mark.usefixtures("mongo_db")


async def test_admin_can_create_access_point(full_client, make_user, auth_header):
    await make_user(phone="ap0000001", password="pw", role="admin")
    headers = await auth_header("ap0000001", "pw")

    resp = await full_client.post(
        "/access-points/",
        json={"code": "AP-TEST-100", "name": "Test Gate", "zone": "GATE", "deployment": "TEST ZONE", "latitude": 17.43, "longitude": 78.45},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["code"] == "AP-TEST-100"
    assert body["enabled"] is True
    assert body["status"] == "online"


async def test_duplicate_code_is_rejected(full_client, make_user, auth_header, make_access_point):
    await make_access_point(code="AP-DUP-01")
    await make_user(phone="ap0000002", password="pw", role="admin")
    headers = await auth_header("ap0000002", "pw")

    resp = await full_client.post(
        "/access-points/",
        json={"code": "AP-DUP-01", "name": "Dup", "latitude": 1.0, "longitude": 1.0},
        headers=headers,
    )
    assert resp.status_code == 409


@pytest.mark.parametrize("role", ["station", "constable", "citizen"])
async def test_non_admin_cannot_create_access_point(full_client, make_user, auth_header, role):
    await make_user(phone=f"ap000role{role}", password="pw", role=role)
    headers = await auth_header(f"ap000role{role}", "pw")

    resp = await full_client.post(
        "/access-points/", json={"code": "AP-X", "name": "X", "latitude": 1.0, "longitude": 1.0}, headers=headers,
    )
    assert resp.status_code == 403


async def test_constable_cannot_list_access_points(full_client, make_user, auth_header):
    await make_user(phone="ap0000003", password="pw", role="constable")
    headers = await auth_header("ap0000003", "pw")

    resp = await full_client.get("/access-points/", headers=headers)
    assert resp.status_code == 403


async def test_station_only_sees_own_station_access_points(full_client, make_user, auth_header, make_station, make_access_point):
    station_a = await make_station(name="Station A")
    station_b = await make_station(name="Station B")
    await make_access_point(code="AP-A-1", station_id=station_a.id)
    await make_access_point(code="AP-B-1", station_id=station_b.id)

    await make_user(phone="ap0000004", password="pw", role="station", station_id=station_a.id)
    headers = await auth_header("ap0000004", "pw")

    resp = await full_client.get("/access-points/", headers=headers)
    assert resp.status_code == 200
    codes = {a["code"] for a in resp.json()}
    assert codes == {"AP-A-1"}


async def test_disable_then_enable_round_trip(full_client, make_user, auth_header, make_access_point):
    ap = await make_access_point(code="AP-TOGGLE-01")
    await make_user(phone="ap0000005", password="pw", role="admin")
    headers = await auth_header("ap0000005", "pw")

    resp = await full_client.post(f"/access-points/{ap.id}/disable", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False
    assert resp.json()["status"] == "offline"

    resp = await full_client.post(f"/access-points/{ap.id}/enable", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True
    assert resp.json()["status"] == "online"


async def test_delete_access_point(full_client, make_user, auth_header, make_access_point):
    ap = await make_access_point(code="AP-DEL-01")
    await make_user(phone="ap0000006", password="pw", role="admin")
    headers = await auth_header("ap0000006", "pw")

    resp = await full_client.delete(f"/access-points/{ap.id}", headers=headers)
    assert resp.status_code == 200

    resp = await full_client.get(f"/access-points/{ap.id}", headers=headers)
    assert resp.status_code == 404


async def test_delete_blocked_when_devices_currently_associated(
    full_client, make_user, make_constable, make_access_point, auth_header
):
    """Deleting an AP out from under devices that currently report it as their current_access_point_id would orphan those presence rows -- refused unless force=true."""
    ap = await make_access_point(code="AP-DEL-BUSY-01")
    _user, _constable = await make_constable(phone="ap0000006c", password="pw")
    device_headers = await auth_header("ap0000006c", "pw")
    await full_client.post("/devices/register", json={"device_identifier": "DEV-DEL-BUSY-01"}, headers=device_headers)
    assoc = await full_client.post(
        "/presence/association",
        json={"device_identifier": "DEV-DEL-BUSY-01", "access_point_code": "AP-DEL-BUSY-01"},
        headers=device_headers,
    )
    assert assoc.status_code == 200, assoc.text

    await make_user(phone="ap0000006a", password="pw", role="admin")
    admin_headers = await auth_header("ap0000006a", "pw")

    refused = await full_client.delete(f"/access-points/{ap.id}", headers=admin_headers)
    assert refused.status_code == 409
    assert "1" in refused.json()["detail"]

    still_there = await full_client.get(f"/access-points/{ap.id}", headers=admin_headers)
    assert still_there.status_code == 200

    forced = await full_client.delete(f"/access-points/{ap.id}", params={"force": "true"}, headers=admin_headers)
    assert forced.status_code == 200

    gone = await full_client.get(f"/access-points/{ap.id}", headers=admin_headers)
    assert gone.status_code == 404


async def test_associated_device_count_reflects_current_presence(
    full_client, make_user, make_constable, make_access_point, auth_header
):
    ap = await make_access_point(code="AP-COUNT-01")
    _user, constable = await make_constable(phone="ap0000007c", password="pw")
    device_resp_headers = await auth_header("ap0000007c", "pw")
    reg = await full_client.post(
        "/devices/register", json={"device_identifier": "DEV-COUNT-01"}, headers=device_resp_headers,
    )
    assert reg.status_code == 200

    assoc = await full_client.post(
        "/presence/association",
        json={"device_identifier": "DEV-COUNT-01", "access_point_code": "AP-COUNT-01"},
        headers=device_resp_headers,
    )
    assert assoc.status_code == 200, assoc.text

    await make_user(phone="ap0000007a", password="pw", role="admin")
    admin_headers = await auth_header("ap0000007a", "pw")
    resp = await full_client.get(f"/access-points/{ap.id}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["associated_device_count"] == 1
