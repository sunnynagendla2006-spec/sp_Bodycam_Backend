"""
CCTV playback authorization, gateway auth callback, source resolution,
SSRF helpers and health monitoring.

WRITTEN BUT NOT EXECUTED when added -- run in the separate testing phase. The
MediaMTX control API is replaced by monkeypatched async functions: these tests
prove the backend's own logic, NOT that a real gateway or camera works.
"""
import uuid

import pytest

from app import models
from app.services import cctv_gateway, cctv_health, cctv_providers, cctv_security, cctv_sources

LOCAL = "127.0.0.1/32"


# ===========================================================================
# Pure unit tests (no database needed)
# ===========================================================================

def test_vendor_presets_build_channel_paths():
    b = models.Building(name="b", code="B1", connection_mode=models.CCTVConnectionMode.nvr, recorder_host="10.0.0.2",
                        recorder_vendor=models.CCTVVendorPreset.hikvision)
    cam = models.CCTVCamera(name="c", camera_code="c", stream_host="10.0.0.2", channel=3)
    assert cctv_sources.resolve_source(cam, b).path == "/Streaming/Channels/301"
    b.recorder_vendor = models.CCTVVendorPreset.dahua
    assert cctv_sources.resolve_source(cam, b).path == "/cam/realmonitor?channel=3&subtype=0"
    b.recorder_vendor = models.CCTVVendorPreset.custom
    b.stream_path_template = "/live/{channel}/main"
    assert cctv_sources.resolve_source(cam, b).path == "/live/3/main"


def test_nvr_camera_without_channel_or_template_is_a_configuration_error():
    b = models.Building(name="b", code="B1", connection_mode=models.CCTVConnectionMode.nvr, recorder_host="10.0.0.2")
    with pytest.raises(cctv_sources.SourceError) as e:
        cctv_sources.resolve_source(models.CCTVCamera(name="c", camera_code="c", stream_host="x", channel=None), b)
    assert e.value.code == "channel_missing"
    with pytest.raises(cctv_sources.SourceError) as e:
        cctv_sources.resolve_source(models.CCTVCamera(name="c", camera_code="c", stream_host="x", channel=1), b)
    assert e.value.code == "path_template_missing"


@pytest.mark.parametrize("bad", ["/a b", "/a#x", "/../etc", "/a\\b", "/x@y"])
def test_path_validation_rejects_unsafe_values(bad):
    with pytest.raises(ValueError):
        cctv_sources.validate_path(bad)


def test_template_may_only_use_channel_placeholder():
    assert cctv_sources.validate_path_template("/s/{channel}") == "/s/{channel}"
    with pytest.raises(ValueError):
        cctv_sources.validate_path_template("/s/{host}")


def test_gateway_url_quotes_credentials_pins_ip_and_hides_secret_in_repr():
    src = cctv_sources.ResolvedSource("rtsp", "cam.local", 554, "/x", "us er", "p@ss:w/rd", )
    url = cctv_sources.gateway_source_url(src, pinned_ip="10.0.0.9")
    assert url == "rtsp://us%20er:p%40ss%3Aw%2Frd@10.0.0.9:554/x"
    assert "p@ss" not in repr(src) and "p%40ss" not in repr(src)
    assert cctv_sources.gateway_source_url(src, pinned_ip="fd00::1").startswith("rtsp://us%20er:p%40ss%3Aw%2Frd@[fd00::1]:554")


def test_parse_authorized_networks_rules():
    assert [str(n) for n in cctv_security.parse_authorized_networks(["10.1.2.0/24", "203.0.113.5"])] == ["10.1.2.0/24", "203.0.113.5/32"]
    for bad in ("0.0.0.0/0", "10.0.0.0/8", "169.254.169.254/32", "224.0.0.0/24", "nope"):
        with pytest.raises(ValueError):
            cctv_security.parse_authorized_networks([bad])


def test_extra_networks_apply_only_inside_the_context(monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "")
    with pytest.raises(ValueError):
        cctv_security.resolve_and_validate("127.0.0.1", 554)
    with cctv_security.extra_networks(cctv_security.parse_authorized_networks([LOCAL])):
        assert cctv_security.resolve_and_validate("127.0.0.1", 554) == ["127.0.0.1"]
    with pytest.raises(ValueError):  # context ended -> policy back to fail-closed
        cctv_security.resolve_and_validate("127.0.0.1", 554)


def test_blocked_ranges_win_even_when_authorized_in_a_building(monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "0.0.0.0/0")
    with pytest.raises(ValueError):
        cctv_security.resolve_and_validate("169.254.169.254", 80)


def test_playback_tokens_are_scoped_and_garbage_is_rejected():
    cam, user = uuid.uuid4(), uuid.uuid4()
    token, _exp = cctv_gateway.mint_playback_token(user, cam)
    path = cctv_gateway.path_name(cam)
    assert cctv_gateway.verify_playback_token(token, path)["cam"] == str(cam)
    assert cctv_gateway.verify_playback_token(token, cctv_gateway.path_name(uuid.uuid4())) is None  # other camera's path
    assert cctv_gateway.verify_playback_token("garbage", path) is None


def test_health_error_text_hides_addresses_and_backoff_is_bounded(monkeypatch):
    assert "10.1.2.3" not in cctv_health.sanitize_error("[Errno 111] Connect call failed ('10.1.2.3', 554)")
    assert cctv_health.sanitize_error(None) is None
    monkeypatch.setenv("CCTV_HEALTH_INTERVAL_SECONDS", "60")
    monkeypatch.setenv("CCTV_HEALTH_MAX_BACKOFF_SECONDS", "900")
    assert [cctv_health._backoff(n) for n in (1, 2, 3, 10)] == [120, 240, 480, 900]


# ===========================================================================
# API tests
# ===========================================================================

@pytest.fixture()
def gateway(monkeypatch):
    """Configures the gateway env and replaces the control API with in-memory fakes."""
    monkeypatch.setenv("CCTV_GATEWAY_API_URL", "http://mediamtx:9997")
    monkeypatch.setenv("CCTV_GATEWAY_PUBLIC_URL", "https://cctv.example.test")
    monkeypatch.setenv("CCTV_GATEWAY_AUTH_KEY", "test-gateway-key")
    state = {"paths": {}, "active": set(), "deleted": []}

    async def ensure_path(name, url):
        state["paths"][name] = url

    async def delete_path(name):
        state["deleted"].append(name)

    async def active_viewer_paths():
        return set(state["active"])

    monkeypatch.setattr(cctv_gateway, "ensure_path", ensure_path)
    monkeypatch.setattr(cctv_gateway, "delete_path", delete_path)
    monkeypatch.setattr(cctv_gateway, "active_viewer_paths", active_viewer_paths)
    return state


async def _admin(make_user, auth_header, role="admin"):
    await make_user(phone=f"st_{role}", password="pw", role=role)
    return await auth_header(f"st_{role}", "pw")


async def _building_with_camera(full_client, headers, **over):
    body = {
        "name": "A", "code": "BLD-A", "latitude": 1.0, "longitude": 1.0, "authorized_networks": [LOCAL],
        "recorder_vendor": "hikvision", "recorder_host": "127.0.0.1", "recorder_username": "u", "recorder_secret": "topsecret",
        "cameras": [{"name": "one"}],
    }
    body.update(over)
    b = (await full_client.post("/cctv/buildings", json=body, headers=headers)).json()
    return b, b["cameras"][0]["id"]


@pytest.mark.usefixtures("mongo_db")
async def test_playback_requires_a_configured_gateway(full_client, make_user, auth_header, monkeypatch):
    for name in ("CCTV_GATEWAY_API_URL", "CCTV_GATEWAY_PUBLIC_URL", "CCTV_GATEWAY_AUTH_KEY"):
        monkeypatch.delenv(name, raising=False)
    h = await _admin(make_user, auth_header)
    _b, cam_id = await _building_with_camera(full_client, h)
    resp = await full_client.post(f"/cctv/cameras/{cam_id}/playback", headers=h)
    assert resp.status_code == 503
    assert resp.headers["x-cctv-error"] == "gateway_not_configured"
    cfg = (await full_client.get("/cctv/streaming/config", headers=h)).json()
    assert cfg["gateway_configured"] is False and cfg["rotation_seconds"] == 5


@pytest.mark.usefixtures("mongo_db")
async def test_playback_returns_scoped_token_and_never_credentials(full_client, make_user, auth_header, gateway):
    h = await _admin(make_user, auth_header, "control_room")
    admin = await _admin(make_user, auth_header, "admin")
    _b, cam_id = await _building_with_camera(full_client, admin)
    resp = await full_client.post(f"/cctv/cameras/{cam_id}/playback", headers=h)
    assert resp.status_code == 200
    body = resp.json()
    assert body["whep_url"].startswith("https://cctv.example.test/cctv-") and body["whep_url"].endswith("/whep")
    for forbidden in ("topsecret", "rtsp://", "127.0.0.1", "Streaming/Channels"):
        assert forbidden not in resp.text
    assert cctv_gateway.verify_playback_token(body["token"], body["path"]) is not None
    # the credential-bearing URL went to the gateway only, with the validated address pinned
    (url,) = gateway["paths"].values()
    assert url == "rtsp://u:topsecret@127.0.0.1:554/Streaming/Channels/101"


@pytest.mark.usefixtures("mongo_db")
async def test_playback_refused_for_disabled_camera_or_building(full_client, make_user, auth_header, gateway):
    admin = await _admin(make_user, auth_header)
    b, cam_id = await _building_with_camera(full_client, admin)
    await full_client.post(f"/cctv/buildings/{b['id']}/disable", headers=admin)
    resp = await full_client.post(f"/cctv/cameras/{cam_id}/playback", headers=admin)
    assert resp.status_code == 409 and resp.headers["x-cctv-error"] == "building_disabled"
    await full_client.post(f"/cctv/buildings/{b['id']}/enable", headers=admin)
    await full_client.post(f"/cctv/cameras/{cam_id}/disable", headers=admin)
    resp = await full_client.post(f"/cctv/cameras/{cam_id}/playback", headers=admin)
    assert resp.status_code == 409 and resp.headers["x-cctv-error"] == "camera_disabled"


@pytest.mark.usefixtures("mongo_db")
async def test_playback_respects_the_stream_cap(full_client, make_user, auth_header, gateway, monkeypatch):
    monkeypatch.setenv("CCTV_MAX_CONCURRENT_STREAMS", "2")
    admin = await _admin(make_user, auth_header)
    _b, cam_id = await _building_with_camera(full_client, admin)
    gateway["active"] = {"cctv-aaa", "cctv-bbb"}
    resp = await full_client.post(f"/cctv/cameras/{cam_id}/playback", headers=admin)
    assert resp.status_code == 429 and resp.headers["x-cctv-error"] == "stream_capacity"
    gateway["active"] = {cctv_gateway.path_name(uuid.UUID(cam_id)), "cctv-bbb"}  # already watching this one: allowed
    assert (await full_client.post(f"/cctv/cameras/{cam_id}/playback", headers=admin)).status_code == 200


@pytest.mark.usefixtures("mongo_db")
async def test_unauthorized_roles_cannot_request_playback(full_client, make_user, auth_header, gateway):
    admin = await _admin(make_user, auth_header)
    _b, cam_id = await _building_with_camera(full_client, admin)
    h = await _admin(make_user, auth_header, "station")
    assert (await full_client.post(f"/cctv/cameras/{cam_id}/playback", headers=h)).status_code == 403
    assert (await full_client.post(f"/cctv/cameras/{cam_id}/playback/report", json={"state": "error"}, headers=h)).status_code == 403


@pytest.mark.usefixtures("mongo_db")
async def test_stream_session_endpoint_now_returns_playback_when_gateway_ready(full_client, make_user, auth_header, gateway):
    admin = await _admin(make_user, auth_header)
    _b, cam_id = await _building_with_camera(full_client, admin)
    resp = await full_client.post(f"/cctv/cameras/{cam_id}/stream", headers=admin)
    body = resp.json()
    assert body["session"]["status"] == "active" and body["playback"]["token"]
    stop = await full_client.post(f"/cctv/cameras/{cam_id}/stream/stop", headers=admin)
    assert stop.status_code == 200 and cctv_gateway.path_name(uuid.UUID(cam_id)) in gateway["deleted"]


@pytest.mark.usefixtures("mongo_db")
async def test_playback_report_updates_camera_health(full_client, make_user, auth_header, gateway):
    admin = await _admin(make_user, auth_header)
    _b, cam_id = await _building_with_camera(full_client, admin)
    await models.CCTVCamera.get_motor_collection().update_one({"_id": uuid.UUID(cam_id)}, {"$set": {"status": "online"}})
    await full_client.post(f"/cctv/cameras/{cam_id}/playback/report", json={"state": "error", "reason": "timeout to 10.1.1.1:554"}, headers=admin)
    cam = (await full_client.get(f"/cctv/cameras/{cam_id}", headers=admin)).json()
    assert cam["status"] == "degraded" and "10.1.1.1" not in cam["last_error"]
    await full_client.post(f"/cctv/cameras/{cam_id}/playback/report", json={"state": "recovered"}, headers=admin)
    assert (await full_client.get(f"/cctv/cameras/{cam_id}", headers=admin)).json()["status"] == "online"


# ---- gateway auth callback ------------------------------------------------

def _auth_body(path, token, action="read"):
    return {"user": "", "password": "", "ip": "1.2.3.4", "action": action, "path": path, "protocol": "webrtc", "id": None, "query": f"token={token}"}


@pytest.mark.usefixtures("mongo_db")
async def test_gateway_auth_callback_rules(full_client, gateway):
    cam, user = uuid.uuid4(), uuid.uuid4()
    path = cctv_gateway.path_name(cam)
    token, _ = cctv_gateway.mint_playback_token(user, cam)
    ok = await full_client.post("/cctv/gateway/auth?key=test-gateway-key", json=_auth_body(path, token))
    assert ok.status_code == 200
    # wrong shared key, wrong path, publish action, missing/forged token: all refused
    assert (await full_client.post("/cctv/gateway/auth?key=nope", json=_auth_body(path, token))).status_code == 401
    assert (await full_client.post("/cctv/gateway/auth", json=_auth_body(path, token))).status_code == 401
    assert (await full_client.post("/cctv/gateway/auth?key=test-gateway-key", json=_auth_body(cctv_gateway.path_name(uuid.uuid4()), token))).status_code == 401
    assert (await full_client.post("/cctv/gateway/auth?key=test-gateway-key", json=_auth_body(path, token, action="publish"))).status_code == 401
    assert (await full_client.post("/cctv/gateway/auth?key=test-gateway-key", json=_auth_body(path, "forged"))).status_code == 401
    assert (await full_client.post("/cctv/gateway/auth?key=test-gateway-key", json=_auth_body("other-path", token))).status_code == 401


@pytest.mark.usefixtures("mongo_db")
async def test_gateway_auth_refuses_everything_when_key_unset(full_client, monkeypatch):
    monkeypatch.delenv("CCTV_GATEWAY_AUTH_KEY", raising=False)
    cam = uuid.uuid4()
    token, _ = cctv_gateway.mint_playback_token(uuid.uuid4(), cam)
    assert (await full_client.post("/cctv/gateway/auth?key=", json=_auth_body(cctv_gateway.path_name(cam), token))).status_code == 401


# ===========================================================================
# Health monitoring
# ===========================================================================

class _FakeProvider(cctv_providers.CCTVProvider):
    def __init__(self, status):
        self.status = status
        self.calls = 0

    async def validate_connection(self, camera):
        self.calls += 1
        return cctv_providers.CCTVConnectionResult(status=self.status, latency_ms=1.0, error=None if self.status == models.CCTVCameraStatus.online else "down")

    async def start_stream(self, camera, session):  # pragma: no cover - not used
        raise NotImplementedError


@pytest.mark.usefixtures("mongo_db")
async def test_health_cycle_probes_each_nvr_once_and_backs_off(full_client, make_user, auth_header, monkeypatch):
    admin = await _admin(make_user, auth_header)
    b, _ = await _building_with_camera(full_client, admin, cameras=[{"name": f"c{i}"} for i in range(4)])
    fake = _FakeProvider(models.CCTVCameraStatus.offline)
    monkeypatch.setitem(cctv_providers._PROVIDERS, models.CCTVProviderType.rtsp, fake)

    summary = await cctv_health.run_cycle(force=True)
    assert summary.targets_probed == 1 and summary.cameras_checked == 4 and fake.calls == 1  # one probe for all channels
    cams = await models.CCTVCamera.find(models.CCTVCamera.building_id == uuid.UUID(b["id"])).to_list()
    assert all(c.status == models.CCTVCameraStatus.offline and c.consecutive_failures == 1 for c in cams)

    # not due yet -> skipped (back-off), unless forced
    again = await cctv_health.run_cycle()
    assert again.targets_probed == 0 and again.skipped_not_due == 4

    fake.status = models.CCTVCameraStatus.online
    recovered = await cctv_health.run_cycle(force=True)
    assert recovered.status_changes == 4
    cams = await models.CCTVCamera.find(models.CCTVCamera.building_id == uuid.UUID(b["id"])).to_list()
    assert all(c.status == models.CCTVCameraStatus.online and c.consecutive_failures == 0 for c in cams)


@pytest.mark.usefixtures("mongo_db")
async def test_health_cycle_ignores_disabled_cameras_and_buildings(full_client, make_user, auth_header, monkeypatch):
    admin = await _admin(make_user, auth_header)
    b, cam_id = await _building_with_camera(full_client, admin)
    fake = _FakeProvider(models.CCTVCameraStatus.online)
    monkeypatch.setitem(cctv_providers._PROVIDERS, models.CCTVProviderType.rtsp, fake)
    await full_client.post(f"/cctv/buildings/{b['id']}/disable", headers=admin)
    assert (await cctv_health.run_cycle(force=True)).cameras_checked == 0
    await full_client.post(f"/cctv/buildings/{b['id']}/enable", headers=admin)
    await full_client.post(f"/cctv/cameras/{cam_id}/disable", headers=admin)
    assert (await cctv_health.run_cycle(force=True)).cameras_checked == 0
    assert fake.calls == 0


@pytest.mark.usefixtures("mongo_db")
async def test_manual_health_run_endpoint_is_admin_only(full_client, make_user, auth_header):
    cr = await _admin(make_user, auth_header, "control_room")
    assert (await full_client.post("/cctv/buildings/health/run", headers=cr)).status_code == 403
    admin = await _admin(make_user, auth_header)
    resp = await full_client.post("/cctv/buildings/health/run", headers=admin)
    assert resp.status_code == 200 and resp.json()["cameras_checked"] == 0
