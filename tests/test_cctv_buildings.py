"""
CCTV buildings: model/API behaviour, RBAC, credential redaction, per-building
SSRF authorization, camera assignment/backward compatibility.

WRITTEN BUT NOT EXECUTED when added -- run in the separate testing phase against
a MongoDB replica set (tests are skipped, not failed, without one).
"""
import pytest

pytestmark = pytest.mark.usefixtures("mongo_db")

LOCAL = "127.0.0.1/32"


async def _headers(make_user, auth_header, role="admin", phone=None):
    phone = phone or f"bld_{role}"
    await make_user(phone=phone, password="pw", role=role)
    return await auth_header(phone, "pw")


def _building(code="BLD-A", **over):
    body = {
        "name": "Building A", "code": code, "zone": "ZONE-1", "latitude": 20.5, "longitude": 78.9,
        "connection_mode": "nvr", "network_access": "vpn", "authorized_networks": [LOCAL],
        "recorder_vendor": "hikvision", "recorder_host": "127.0.0.1", "recorder_port": 554,
        "recorder_username": "viewer", "recorder_secret": "s3cret-pass",
        "cameras": [{"name": f"Cam {i}"} for i in range(1, 5)],
    }
    body.update(over)
    return body


# --------------------------------------------------------------------------
# RBAC
# --------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["station", "constable", "citizen"])
async def test_other_roles_are_denied_everywhere(full_client, make_user, auth_header, role):
    headers = await _headers(make_user, auth_header, role)
    for method, path, body in [
        ("GET", "/cctv/buildings", None),
        ("POST", "/cctv/buildings", _building()),
        ("GET", "/cctv/buildings/zones", None),
        ("GET", "/cctv/streaming/config", None),
        ("GET", "/cctv/buildings/unassigned-cameras", None),
        ("POST", "/cctv/buildings/health/run", None),
    ]:
        resp = await full_client.request(method, path, json=body, headers=headers)
        assert resp.status_code == 403, f"{method} {path}"


async def test_control_room_can_view_but_not_manage(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header, "admin")
    created = (await full_client.post("/cctv/buildings", json=_building(), headers=admin)).json()
    cr = await _headers(make_user, auth_header, "control_room")

    assert (await full_client.get("/cctv/buildings", headers=cr)).status_code == 200
    assert (await full_client.get(f"/cctv/buildings/{created['id']}", headers=cr)).status_code == 200
    for method, path, body in [
        ("POST", "/cctv/buildings", _building("BLD-X")),
        ("PATCH", f"/cctv/buildings/{created['id']}", {"name": "n"}),
        ("POST", f"/cctv/buildings/{created['id']}/disable", None),
        ("DELETE", f"/cctv/buildings/{created['id']}", None),
        ("POST", f"/cctv/buildings/{created['id']}/cameras", {"name": "x"}),
        ("POST", "/cctv/buildings/health/run", None),
    ]:
        assert (await full_client.request(method, path, json=body, headers=cr)).status_code == 403, f"{method} {path}"


async def test_control_room_does_not_see_infrastructure_details(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header, "admin")
    b = (await full_client.post("/cctv/buildings", json=_building(public_ip="203.0.113.7", owner_contact="555-0100"), headers=admin)).json()
    cr = await _headers(make_user, auth_header, "control_room")
    view = (await full_client.get(f"/cctv/buildings/{b['id']}", headers=cr)).json()
    assert view["public_ip"] is None and view["recorder_host"] is None and view["owner_contact"] is None
    assert view["authorized_networks"] == []
    full = (await full_client.get(f"/cctv/buildings/{b['id']}", headers=admin)).json()
    assert full["public_ip"] == "203.0.113.7" and full["recorder_host"] == "127.0.0.1"


# --------------------------------------------------------------------------
# Create / read / derived counts
# --------------------------------------------------------------------------

async def test_create_building_with_four_and_six_cameras(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    a = await full_client.post("/cctv/buildings", json=_building("BLD-A"), headers=admin)
    b = await full_client.post(
        "/cctv/buildings",
        json=_building("BLD-B", name="Building B", zone="ZONE-2", cameras=[{"name": f"C{i}"} for i in range(6)]),
        headers=admin,
    )
    assert a.status_code == 201 and b.status_code == 201
    assert a.json()["camera_count"] == 4 and b.json()["camera_count"] == 6
    # NVR channels default to row position and rotation order is preserved
    assert [c["channel"] for c in b.json()["cameras"]] == [1, 2, 3, 4, 5, 6]
    assert [c["sort_order"] for c in b.json()["cameras"]] == [0, 1, 2, 3, 4, 5]


async def test_secrets_never_appear_in_any_response(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    resp = await full_client.post("/cctv/buildings", json=_building(), headers=admin)
    listing = await full_client.get("/cctv/buildings", headers=admin)
    cams = await full_client.get(f"/cctv/buildings/{resp.json()['id']}/cameras", headers=admin)
    for r in (resp, listing, cams):
        assert "s3cret-pass" not in r.text
        assert "encrypted_secret" not in r.text and "recorder_encrypted_secret" not in r.text
    assert resp.json()["recorder_credentials_configured"] is True


async def test_duplicate_code_is_409_and_invalid_input_is_422(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    assert (await full_client.post("/cctv/buildings", json=_building(), headers=admin)).status_code == 201
    assert (await full_client.post("/cctv/buildings", json=_building(), headers=admin)).status_code == 409
    assert (await full_client.post("/cctv/buildings", json=_building("BLD-Z", recorder_host="rtsp://evil/x"), headers=admin)).status_code == 422
    assert (await full_client.post("/cctv/buildings", json=_building("BLD-Y", recorder_vendor="custom"), headers=admin)).status_code == 422
    assert (await full_client.post("/cctv/buildings", json=_building("BLD-W", network_access="public_direct"), headers=admin)).status_code == 422
    dup_channels = _building("BLD-V", cameras=[{"name": "a", "channel": 1}, {"name": "b", "channel": 1}])
    assert (await full_client.post("/cctv/buildings", json=dup_channels, headers=admin)).status_code == 422


async def test_pagination_and_zone_filter(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    for i in range(5):
        await full_client.post("/cctv/buildings", json=_building(f"B{i:02d}", name=f"B{i}", zone="Z1" if i < 3 else "Z2", cameras=[]), headers=admin)
    page = (await full_client.get("/cctv/buildings?limit=2&offset=0", headers=admin)).json()
    assert page["total"] == 5 and len(page["items"]) == 2
    z2 = (await full_client.get("/cctv/buildings?zone=Z2", headers=admin)).json()
    assert z2["total"] == 2
    assert sorted((await full_client.get("/cctv/buildings/zones", headers=admin)).json()) == ["Z1", "Z2"]


# --------------------------------------------------------------------------
# Per-building SSRF authorization
# --------------------------------------------------------------------------

async def test_target_outside_global_and_building_networks_is_rejected(full_client, make_user, auth_header, monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "")
    admin = await _headers(make_user, auth_header)
    resp = await full_client.post("/cctv/buildings", json=_building(authorized_networks=[]), headers=admin)
    assert resp.status_code == 400


async def test_building_networks_authorize_only_that_building(full_client, make_user, auth_header, monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "")
    admin = await _headers(make_user, auth_header)
    assert (await full_client.post("/cctv/buildings", json=_building("OK-1", authorized_networks=[LOCAL]), headers=admin)).status_code == 201
    # a second building WITHOUT the authorization is still refused (policy was not widened globally)
    assert (await full_client.post("/cctv/buildings", json=_building("NO-1", authorized_networks=[]), headers=admin)).status_code == 400


async def test_overbroad_or_blocked_authorizations_are_rejected(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    for net in ("0.0.0.0/0", "10.0.0.0/8", "169.254.169.254/32", "not-a-cidr"):
        resp = await full_client.post("/cctv/buildings", json=_building("BLD-N", authorized_networks=[net]), headers=admin)
        assert resp.status_code == 422, net


# --------------------------------------------------------------------------
# Update / enable / delete / cameras
# --------------------------------------------------------------------------

async def test_update_keeps_secret_unless_replaced_and_updates_nvr_cameras(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    b = (await full_client.post("/cctv/buildings", json=_building(), headers=admin)).json()
    upd = await full_client.patch(f"/cctv/buildings/{b['id']}", json={"name": "Renamed", "recorder_port": 8554}, headers=admin)
    assert upd.status_code == 200 and upd.json()["recorder_credentials_configured"] is True
    cams = (await full_client.get(f"/cctv/buildings/{b['id']}/cameras", headers=admin)).json()
    assert {c["stream_port"] for c in cams} == {8554}


async def test_cannot_switch_connection_mode_with_cameras(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    b = (await full_client.post("/cctv/buildings", json=_building(), headers=admin)).json()
    resp = await full_client.patch(f"/cctv/buildings/{b['id']}", json={"connection_mode": "direct_ip"}, headers=admin)
    assert resp.status_code == 409


async def test_disable_building_and_delete_rules(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    b = (await full_client.post("/cctv/buildings", json=_building(), headers=admin)).json()
    dis = await full_client.post(f"/cctv/buildings/{b['id']}/disable", headers=admin)
    assert dis.json()["enabled"] is False and dis.json()["health"] == "disabled"

    assert (await full_client.delete(f"/cctv/buildings/{b['id']}", headers=admin)).status_code == 409  # cameras exist
    detached = await full_client.delete(f"/cctv/buildings/{b['id']}?cameras=detach", headers=admin)
    assert detached.status_code == 200 and detached.json()["camera_count"] == 4
    orphans = (await full_client.get("/cctv/buildings/unassigned-cameras", headers=admin)).json()
    assert len(orphans) == 4 and all(c["building_id"] is None for c in orphans)


async def test_add_reorder_and_channel_conflicts(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    b = (await full_client.post("/cctv/buildings", json=_building(cameras=[{"name": "a"}, {"name": "b"}]), headers=admin)).json()
    added = await full_client.post(f"/cctv/buildings/{b['id']}/cameras", json={"name": "c"}, headers=admin)
    assert added.status_code == 201 and added.json()["channel"] == 3
    dup = await full_client.post(f"/cctv/buildings/{b['id']}/cameras", json={"name": "d", "channel": 1}, headers=admin)
    assert dup.status_code == 409

    ids = [c["id"] for c in (await full_client.get(f"/cctv/buildings/{b['id']}/cameras", headers=admin)).json()]
    reordered = await full_client.post(f"/cctv/buildings/{b['id']}/cameras/reorder", json={"camera_ids": list(reversed(ids))}, headers=admin)
    assert [c["id"] for c in reordered.json()] == list(reversed(ids))


# --------------------------------------------------------------------------
# Backward compatibility: pre-existing standalone cameras
# --------------------------------------------------------------------------

async def test_existing_camera_works_unassigned_and_can_be_assigned(full_client, make_user, auth_header, make_cctv_camera):
    admin = await _headers(make_user, auth_header)
    legacy = await make_cctv_camera()
    got = await full_client.get(f"/cctv/cameras/{legacy.id}", headers=admin)
    assert got.status_code == 200 and got.json()["building_id"] is None

    b = (await full_client.post("/cctv/buildings", json=_building(cameras=[]), headers=admin)).json()
    no_channel = await full_client.put(f"/cctv/cameras/{legacy.id}/building", json={"building_id": b["id"]}, headers=admin)
    assert no_channel.status_code == 422  # NVR building needs a channel
    ok = await full_client.put(f"/cctv/cameras/{legacy.id}/building", json={"building_id": b["id"], "channel": 7}, headers=admin)
    assert ok.status_code == 200 and ok.json()["building_id"] == b["id"] and ok.json()["channel"] == 7

    detach = await full_client.put(f"/cctv/cameras/{legacy.id}/building", json={"building_id": None}, headers=admin)
    assert detach.json()["building_id"] is None


async def test_building_test_endpoint_reports_unreachable_recorder(full_client, make_user, auth_header):
    admin = await _headers(make_user, auth_header)
    b = (await full_client.post("/cctv/buildings", json=_building(recorder_port=1, cameras=[{"name": "a"}]), headers=admin)).json()
    resp = await full_client.post(f"/cctv/buildings/{b['id']}/test", headers=admin)
    assert resp.status_code == 200
    assert resp.json()["results"][0]["status"] == "offline"
    assert "127.0.0.1" not in (resp.json()["results"][0]["error"] or "")  # addresses are sanitised
