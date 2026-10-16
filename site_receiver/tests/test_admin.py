"""Operator endpoints, storage planning and optional live-view token issuing at the receiver."""
import uuid

import pytest

from site_receiver.capacity import estimate
from site_receiver.store import QUARANTINED
from .conftest import make_chunk

ADMIN = {"X-Receiver-Admin-Key": "unit-test-admin-key"}


async def upload(receiver):
    h = await receiver.token()
    rid = await receiver.register(h)
    data, _ = make_chunk(1)
    cid = str(uuid.uuid4())
    assert (await receiver.put_chunk(h, rid, cid, 1, data)).status_code == 200
    return h, rid, cid, data


async def test_admin_endpoints_require_the_key(receiver):
    for path in ("/v1/admin/status", "/v1/admin/recordings", "/v1/admin/audit", "/v1/admin/capacity-estimate"):
        assert (await receiver.client.get(path)).status_code == 401
        assert (await receiver.client.get(path, headers={"X-Receiver-Admin-Key": "nope"})).status_code in (401, 429)


async def test_admin_disabled_without_a_configured_key(env, tmp_path):
    import httpx
    from site_receiver import main as m

    env(RECEIVER_ADMIN_KEY="")
    app = m.create_app()
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://r")
        r = await c.get("/v1/admin/status", headers=ADMIN)
        await c.aclose()
    assert r.status_code == 503 and r.json()["error"]["code"] == "admin_disabled"


async def test_status_recordings_audit_and_chunk_detail(receiver):
    h, rid, cid, data = await upload(receiver)
    st = (await receiver.client.get("/v1/admin/status", headers=ADMIN)).json()
    assert st["counts"]["pending_sync"] == 1 and st["pending_chunks"] == 1 and st["central_configured"] is False and st["last_central_ack_at"] is None
    recs = (await receiver.client.get("/v1/admin/recordings", headers=ADMIN)).json()["items"]
    assert recs[0]["recording_id"] == rid and recs[0]["chunks_total"] == 1 and recs[0]["chunks_synced"] == 0
    detail = (await receiver.client.get(f"/v1/admin/recordings/{rid}", headers=ADMIN)).json()
    assert detail["chunks"][0]["chunk_id"] == cid
    assert (await receiver.client.get(f"/v1/admin/recordings/{uuid.uuid4()}", headers=ADMIN)).status_code == 404
    events = [e["event"] for e in (await receiver.client.get("/v1/admin/audit?limit=50", headers=ADMIN)).json()["items"]]
    assert "chunk_received" in events and "session_issued" in events
    assert "grant" not in str((await receiver.client.get("/v1/admin/audit", headers=ADMIN)).json()).lower().replace("grant_id", ""), "no grant tokens in the audit trail"


async def test_retry_requeues_quarantined_chunks_and_is_audited(receiver):
    h, rid, cid, data = await upload(receiver)
    store = receiver.app.state.store
    store.execute("UPDATE chunks SET state = ?, last_error = 'x' WHERE chunk_id = ?", (QUARANTINED, cid))
    r = await receiver.client.post("/v1/admin/retry", headers=ADMIN, json={"chunk_id": cid})
    assert r.json() == {"requeued": 1}
    assert store.one("SELECT state, last_error FROM chunks WHERE chunk_id = ?", (cid,)) == {"state": "pending_sync", "last_error": None}
    assert (await receiver.client.post("/v1/admin/retry", headers=ADMIN, json={})).json() == {"requeued": 0}
    assert "admin_retry" in [e["event"] for e in store.recent_audit(5)]


async def test_chunk_stream_is_admin_only_audited_and_labelled_delayed(receiver):
    h, rid, cid, data = await upload(receiver)
    url = f"/v1/admin/recordings/{rid}/chunks/{cid}/stream"
    assert (await receiver.client.get(url)).status_code == 401
    assert (await receiver.client.get(url, headers=h)).status_code == 401, "a phone session is not an operator credential"
    r = await receiver.client.get(url, headers=ADMIN)
    assert r.status_code == 200 and r.content == data and r.headers["content-type"] == "video/mp4"
    assert "admin_chunk_access" in [e["event"] for e in receiver.app.state.store.recent_audit(5)]
    assert (await receiver.client.get(f"/v1/admin/recordings/{rid}/chunks/{uuid.uuid4()}/stream", headers=ADMIN)).status_code == 404


async def test_capacity_estimate_matches_an_independent_calculation(receiver):
    r = (await receiver.client.get("/v1/admin/capacity-estimate", params={"bitrate_kbps": 4000, "devices": 40, "recording_hours_per_device_per_day": 8, "outage_days": 3}, headers=ADMIN)).json()
    expected = 4000 * 1000 / 8 * 3600 * 8 * 40 * 3 * 1.10  # bytes
    assert abs(r["estimated_bytes"] - expected) < 2
    assert r["estimated_gib"] == round(expected / 1024 ** 3, 1) and r["disk_free_gib"] > 0
    cli = estimate(4000, 40, 8, 3)
    assert abs(cli["total_bytes"] - expected) < 2 and abs(cli["per_device_per_day_gib"] - 4000 * 1000 / 8 * 3600 * 8 / 1024 ** 3) < 1e-9
    assert (await receiver.client.get("/v1/admin/capacity-estimate", params={"devices": 0}, headers=ADMIN)).status_code == 422


async def test_live_token_endpoints_report_missing_local_livekit_clearly(receiver):
    h = await receiver.token()
    r = await receiver.client.post("/v1/live/start", headers=h)
    assert r.status_code == 404 and r.json()["error"]["code"] == "local_live_not_configured"
    assert "continue" in r.json()["error"]["message"], "the message says recording is unaffected"
    assert (await receiver.client.post("/v1/admin/live/viewer-token?room=site-SITE-T-x", headers=ADMIN)).status_code == 404
    live_less = await receiver.token(ops=("session", "upload"))
    assert (await receiver.client.post("/v1/live/start", headers=live_less)).status_code == 403, "the grant has no live operation"


async def test_config_reports_capacity_and_local_live_availability(receiver):
    h = await receiver.token()
    cfg = (await receiver.client.get("/v1/config", headers=h)).json()
    assert cfg["accepting_uploads"] is True and cfg["local_live_available"] is False and cfg["central_configured"] is False
    assert cfg["max_chunk_bytes"] == 2 * 1024 * 1024
