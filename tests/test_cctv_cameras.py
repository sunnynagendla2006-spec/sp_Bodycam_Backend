"""
CCTV camera management: CRUD, the CCTV-only RBAC matrix (admin manage,
admin+control_room view/test, station/constable/citizen denied
entirely), credential redaction, and the live connectivity test endpoint
against a local fake RTSP responder.
"""
import asyncio

import pytest

pytestmark = pytest.mark.usefixtures("mongo_db")


async def _admin_headers(full_client, make_user, auth_header, phone="cctv_admin"):
    await make_user(phone=phone, password="pw", role="admin")
    return await auth_header(phone, "pw")


async def _control_room_headers(full_client, make_user, auth_header, phone="cctv_cr"):
    await make_user(phone=phone, password="pw", role="control_room")
    return await auth_header(phone, "pw")


# ===========================================================================
# RBAC matrix -- the master requirement of this feature.
# ===========================================================================

@pytest.mark.parametrize("role", ["admin", "control_room"])
async def test_allowed_roles_can_list_cameras(full_client, make_user, auth_header, role):
    await make_user(phone=f"cctvlist_{role}", password="pw", role=role)
    headers = await auth_header(f"cctvlist_{role}", "pw")
    resp = await full_client.get("/cctv/cameras", headers=headers)
    assert resp.status_code == 200


@pytest.mark.parametrize("role", ["station", "constable", "citizen"])
async def test_denied_roles_get_403_on_every_cctv_endpoint(full_client, make_user, auth_header, make_cctv_camera, role):
    camera = await make_cctv_camera()
    await make_user(phone=f"cctvdenied_{role}", password="pw", role=role)
    headers = await auth_header(f"cctvdenied_{role}", "pw")

    endpoints = [
        ("GET", "/cctv/cameras", None),
        ("GET", "/cctv/cameras/nearby?latitude=1&longitude=1&radius_m=100", None),
        ("GET", f"/cctv/cameras/{camera.id}", None),
        ("PATCH", f"/cctv/cameras/{camera.id}", {"name": "x"}),
        ("DELETE", f"/cctv/cameras/{camera.id}", None),
        ("POST", f"/cctv/cameras/{camera.id}/enable", None),
        ("POST", f"/cctv/cameras/{camera.id}/disable", None),
        ("POST", f"/cctv/cameras/{camera.id}/test", None),
        ("GET", f"/cctv/cameras/{camera.id}/status", None),
        ("POST", f"/cctv/cameras/{camera.id}/stream", None),
        ("POST", f"/cctv/cameras/{camera.id}/stream/stop", None),
    ]
    for method, path, json_body in endpoints:
        resp = await full_client.request(method, path, json=json_body, headers=headers)
        assert resp.status_code == 403, f"{method} {path} should be 403 for role={role}, got {resp.status_code}"


async def test_control_room_cannot_create_update_or_delete_cameras(full_client, make_user, auth_header, make_cctv_camera):
    camera = await make_cctv_camera()
    headers = await _control_room_headers(full_client, make_user, auth_header)

    create = await full_client.post(
        "/cctv/cameras",
        json={"name": "x", "camera_code": "CAM-X", "latitude": 1.0, "longitude": 1.0, "stream_host": "127.0.0.1"},
        headers=headers,
    )
    assert create.status_code == 403

    update = await full_client.patch(f"/cctv/cameras/{camera.id}", json={"name": "y"}, headers=headers)
    assert update.status_code == 403

    delete = await full_client.delete(f"/cctv/cameras/{camera.id}", headers=headers)
    assert delete.status_code == 403

    enable = await full_client.post(f"/cctv/cameras/{camera.id}/enable", headers=headers)
    assert enable.status_code == 403


async def test_control_room_can_view_test_and_stream(full_client, make_user, auth_header, make_cctv_camera, monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    camera = await make_cctv_camera(stream_port=1)  # nothing listening -- still a legal "test" call, just offline
    headers = await _control_room_headers(full_client, make_user, auth_header)

    view = await full_client.get(f"/cctv/cameras/{camera.id}", headers=headers)
    assert view.status_code == 200

    test_resp = await full_client.post(f"/cctv/cameras/{camera.id}/test", headers=headers)
    assert test_resp.status_code == 200
    assert test_resp.json()["status"] == "offline"


# ===========================================================================
# CRUD + credential redaction
# ===========================================================================

async def test_create_camera_requires_ssrf_allowed_target(full_client, make_user, auth_header, monkeypatch):
    monkeypatch.delenv("CCTV_ALLOWED_NETWORKS", raising=False)
    headers = await _admin_headers(full_client, make_user, auth_header)
    resp = await full_client.post(
        "/cctv/cameras",
        json={"name": "x", "camera_code": "CAM-SSRF-1", "latitude": 1.0, "longitude": 1.0, "stream_host": "127.0.0.1"},
        headers=headers,
    )
    assert resp.status_code == 400


async def test_create_camera_with_secret_never_returns_it(full_client, make_user, auth_header, monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    headers = await _admin_headers(full_client, make_user, auth_header)
    resp = await full_client.post(
        "/cctv/cameras",
        json={
            "name": "Secure Cam", "camera_code": "CAM-SECRET-1", "latitude": 1.0, "longitude": 1.0,
            "stream_host": "127.0.0.1", "username": "admin", "secret": "super-secret-password",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["credentials_configured"] is True
    assert "secret" not in body
    assert "password" not in body
    assert "encrypted_secret" not in body
    assert "super-secret-password" not in resp.text

    listing = await full_client.get("/cctv/cameras", headers=headers)
    assert "super-secret-password" not in listing.text


async def test_duplicate_camera_code_is_rejected(full_client, make_user, auth_header, make_cctv_camera, monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    await make_cctv_camera(camera_code="CAM-DUP-1")
    headers = await _admin_headers(full_client, make_user, auth_header)
    resp = await full_client.post(
        "/cctv/cameras",
        json={"name": "x", "camera_code": "CAM-DUP-1", "latitude": 1.0, "longitude": 1.0, "stream_host": "127.0.0.1"},
        headers=headers,
    )
    assert resp.status_code == 409


async def test_update_clears_secret_when_requested(full_client, make_user, auth_header, make_cctv_camera, monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    from app.services import cctv_security
    camera = await make_cctv_camera()
    camera.encrypted_secret = cctv_security.encrypt_secret("old-secret")
    await camera.save()
    headers = await _admin_headers(full_client, make_user, auth_header)

    resp = await full_client.patch(f"/cctv/cameras/{camera.id}", json={"clear_secret": True}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["credentials_configured"] is False


async def test_enable_disable_round_trip_sets_status_not_just_enabled_flag(full_client, make_user, auth_header, make_cctv_camera):
    camera = await make_cctv_camera()
    headers = await _admin_headers(full_client, make_user, auth_header)

    disabled = await full_client.post(f"/cctv/cameras/{camera.id}/disable", headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    assert disabled.json()["status"] == "disabled"

    enabled = await full_client.post(f"/cctv/cameras/{camera.id}/enable", headers=headers)
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True
    assert enabled.json()["status"] == "unknown"  # reset, not fabricated as "online"


async def test_disabled_camera_test_result_does_not_override_persisted_disabled_status(
    full_client, make_user, auth_header, make_cctv_camera, monkeypatch
):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")

    async def handle(reader, writer):
        await reader.read(4096)
        writer.write(b"RTSP/1.0 200 OK\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        camera = await make_cctv_camera(stream_port=port, enabled=True)
        headers = await _admin_headers(full_client, make_user, auth_header)
        await full_client.post(f"/cctv/cameras/{camera.id}/disable", headers=headers)

        test_resp = await full_client.post(f"/cctv/cameras/{camera.id}/test", headers=headers)
        assert test_resp.status_code == 200
        assert test_resp.json()["status"] == "online"  # the live probe result is honest

        status_resp = await full_client.get(f"/cctv/cameras/{camera.id}/status", headers=headers)
        assert status_resp.json()["status"] == "disabled"  # but the persisted state stays "disabled"
    finally:
        server.close()
        await server.wait_closed()


async def test_delete_camera(full_client, make_user, auth_header, make_cctv_camera):
    camera = await make_cctv_camera()
    headers = await _admin_headers(full_client, make_user, auth_header)
    resp = await full_client.delete(f"/cctv/cameras/{camera.id}", headers=headers)
    assert resp.status_code == 200
    follow_up = await full_client.get(f"/cctv/cameras/{camera.id}", headers=headers)
    assert follow_up.status_code == 404


async def test_list_filters_by_enabled_and_name(full_client, make_user, auth_header, make_cctv_camera):
    await make_cctv_camera(camera_code="CAM-FILT-1", name="Gate Camera", enabled=True)
    await make_cctv_camera(camera_code="CAM-FILT-2", name="Parking Camera", enabled=False)
    headers = await _admin_headers(full_client, make_user, auth_header)

    enabled_only = await full_client.get("/cctv/cameras?enabled=true", headers=headers)
    codes = {c["camera_code"] for c in enabled_only.json()}
    assert codes == {"CAM-FILT-1"}

    by_name = await full_client.get("/cctv/cameras?name=gate", headers=headers)
    codes = {c["camera_code"] for c in by_name.json()}
    assert codes == {"CAM-FILT-1"}


async def test_invalid_coordinates_are_rejected(full_client, make_user, auth_header, monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    headers = await _admin_headers(full_client, make_user, auth_header)
    resp = await full_client.post(
        "/cctv/cameras",
        json={"name": "x", "camera_code": "CAM-BADCOORD", "latitude": 999.0, "longitude": 1.0, "stream_host": "127.0.0.1"},
        headers=headers,
    )
    assert resp.status_code == 422
