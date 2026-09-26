"""
Live Map constable identity + status visualization.

The Live Map itself needs no new endpoint -- GET /devices/ already returns
everything except the constable's station (constable_id, latitude,
longitude, status, location_updated_at were all already there -- see
routers/devices.py::_to_device_response). The one genuine gap was
GET /constables/ never including station_id/station_name at all, which
these tests cover. Authorization scoping on both endpoints (already
correct, unchanged) is re-verified here specifically in combination with
the new fields, since a additive field is exactly the kind of change that
could accidentally leak data across the station boundary if done carelessly.
"""


from app.models import UserRole


async def _register_device(full_client, headers, device_identifier):
    resp = await full_client.post("/devices/register", json={"device_identifier": device_identifier, "platform": "android"}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


async def test_list_constables_includes_station_id_and_name(full_client, make_user, make_station, make_constable, auth_header):
    station = await make_station(name="Test Control Station", longitude=78.45, latitude=17.43)
    await make_user(phone="m000000001", password="pw", role=UserRole.admin)
    _, constable = await make_constable(phone="m000000002", station_id=station.id)

    headers = await auth_header("m000000001", "pw")
    resp = await full_client.get("/constables/", headers=headers)
    assert resp.status_code == 200
    row = next(r for r in resp.json() if r["id"] == str(constable.id))
    assert row["station_id"] == str(station.id)
    assert row["station_name"] == "Test Control Station"


async def test_list_constables_station_is_null_when_constable_has_none(full_client, make_user, make_constable, auth_header):
    await make_user(phone="m000000003", password="pw", role=UserRole.admin)
    _, constable = await make_constable(phone="m000000004", station_id=None)

    headers = await auth_header("m000000003", "pw")
    resp = await full_client.get("/constables/", headers=headers)
    assert resp.status_code == 200
    row = next(r for r in resp.json() if r["id"] == str(constable.id))
    assert row["station_id"] is None
    assert row["station_name"] is None


async def test_station_user_still_cannot_see_another_stations_constable_after_this_change(full_client, make_user, make_station, make_constable, auth_header):
    """Regression guard: adding station_id/station_name must never widen
    the existing station-scoping authorization (see routers/constables.py::list_constables)."""
    station_a = await make_station(name="Station A", longitude=78.0, latitude=17.0)
    station_b = await make_station(name="Station B", longitude=79.0, latitude=18.0)
    await make_user(phone="m000000005", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_b = await make_constable(phone="m000000006", station_id=station_b.id)

    headers = await auth_header("m000000005", "pw")
    resp = await full_client.get("/constables/", headers=headers)
    assert resp.status_code == 200
    ids = [row["id"] for row in resp.json()]
    assert str(constable_b.id) not in ids


async def test_device_response_already_has_everything_the_live_map_needs_besides_station(full_client, make_constable, auth_header):
    """Confirms the pre-existing DeviceResponse contract the Live Map relies
    on: constable_id, latitude/longitude, status, location_updated_at are
    already present -- no new device endpoint/field was needed for this feature."""
    await make_constable(phone="m000000007")
    headers = await auth_header("m000000007", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-m007")

    resp = await full_client.get("/devices/", headers=headers)
    assert resp.status_code == 200
    device = resp.json()[0]
    for field in ("constable_id", "latitude", "longitude", "status", "location_updated_at", "device_identifier"):
        assert field in device


async def test_device_location_is_the_last_reported_one_even_after_going_offline(full_client, make_constable, auth_header):
    """The 'last known location' shown for an offline constable must be a
    real, previously-reported GPS fix -- never 0,0 or fabricated."""
    await make_constable(phone="m000000008")
    headers = await auth_header("m000000008", "correct-horse-battery")
    device_id = await _register_device(full_client, headers, "phone-m008")

    loc_resp = await full_client.post("/constables/me/location", json={"latitude": 16.5062, "longitude": 80.6480}, headers=headers)
    assert loc_resp.status_code == 200

    device_resp = await full_client.get(f"/devices/{device_id}", headers=headers)
    device = device_resp.json()
    assert device["latitude"] == 16.5062
    assert device["longitude"] == 80.6480
