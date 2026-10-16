"""
Layered outage simulation: phone MODEL -> real receiver app (ASGI, real SQLite + files) -> forwarder -> MOCK control room.

This is NOT a real-phone test. The phone is a small Python model of the rules implemented in the Flutter app (keep every chunk,
delete only when the control room's manifest shows the same original hash). The real Dart logic is covered by the Flutter tests.
Set VALIDATION_LOG_DIR to also write a machine-readable log of the run.
"""
import hashlib
import json
import os
import time
import uuid

import httpx
import pytest

from site_receiver.store import ACKED, FAILED_RETRY, PENDING
from .conftest import make_chunk, make_grant


class MockControlRoom:
    """Stores chunks keyed by recording + number and recomputes hashes itself (never trusts the sender's claim)."""

    def __init__(self):
        self.up = False
        self.archive = {}  # (rid, n) -> bytes
        self.ids = {}  # (rid, n) -> chunk_id
        self.completed = {}  # rid -> missing numbers
        self.commit_then_lose_response = 0
        self.log = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        if not self.up:
            raise httpx.ConnectError("control room unreachable")
        path = req.url.path
        if req.method == "POST" and path.endswith("/heartbeat"):
            return httpx.Response(200, json={"status": "ok"})
        if req.method == "GET" and path.endswith("/sync"):
            return httpx.Response(200, json={"revoked_grant_ids": [], "commands": []})
        parts = path.strip("/").split("/")  # receiver/v1/recordings/{rid}[/chunks/{cid}|/complete]
        if req.method == "PUT" and len(parts) == 4:
            return httpx.Response(200, json={"created": True})
        if req.method == "PUT" and parts[-2] == "chunks":
            rid, cid = parts[3], parts[-1]
            body = req.read()
            data = _file_part(body)
            n = int(_field(body, "chunk_number"))
            declared = _field(body, "sha256")
            actual = hashlib.sha256(data).hexdigest()
            if actual != declared:
                return httpx.Response(422, headers={"x-conflict-reason": "hash_mismatch"})
            prior = self.archive.get((rid, n))
            if prior is not None:
                if hashlib.sha256(prior).hexdigest() != actual or self.ids[(rid, n)] != cid:
                    return httpx.Response(409, headers={"x-conflict-reason": "hash_conflict"})
                return httpx.Response(200, json={"original_hash": actual, "duplicate": True})
            self.archive[(rid, n)] = data
            self.ids[(rid, n)] = cid
            if self.commit_then_lose_response > 0:
                self.commit_then_lose_response -= 1
                raise httpx.ReadTimeout("response lost after commit")
            return httpx.Response(200, json={"original_hash": actual, "duplicate": False})
        if req.method == "POST" and parts[-1] == "complete":
            rid = parts[3]
            nums = sorted(n for (r, n) in self.archive if r == rid)
            missing = sorted(set(range(1, (nums[-1] if nums else 0) + 1)) - set(nums))
            self.completed[rid] = missing
            return httpx.Response(200, json={"missing_chunk_numbers": missing})
        return httpx.Response(404)

    def manifest(self, rid):
        return [{"chunk_number": n, "original_hash": hashlib.sha256(d).hexdigest()} for (r, n), d in sorted(self.archive.items()) if r == rid]


def _field(body: bytes, name: str) -> str:
    i = body.index(f'name="{name}"'.encode())
    j = body.index(b"\r\n\r\n", i) + 4
    return body[j:body.index(b"\r\n", j)].decode()


def _file_part(body: bytes) -> bytes:
    i = body.index(b'name="file"')
    j = body.index(b"\r\n\r\n", i) + 4
    k = body.index(b"\r\n--", j)
    return body[j:k]


class PhoneModel:
    """The rules of chunk_uploader.dart that matter for evidence: keep every file; delete only on a matching central manifest."""

    def __init__(self):
        self.files = {}  # chunk_number -> (chunk_id, bytes, sha)
        self.state = {}  # chunk_number -> pending | local_acked | uploaded

    def record(self, n):
        data, sha = make_chunk(n)
        self.files[n] = (str(uuid.uuid4()), data, sha)
        self.state[n] = "pending"

    def reconcile(self, manifest):
        remote = {m["chunk_number"]: m["original_hash"] for m in manifest}
        for n, (_cid, _data, sha) in list(self.files.items()):
            if self.state[n] == "local_acked" and remote.get(n) == sha:
                self.state[n] = "uploaded"
                del self.files[n]  # only now may the local copy go


async def pump(app, central_client):
    fwd = app.state.fwd
    fwd._client = central_client
    store = app.state.store
    for row in store.query("SELECT * FROM chunks WHERE state IN (?, ?) AND next_attempt_at <= ?", (PENDING, FAILED_RETRY, time.time())):
        await fwd._process_chunk(row)
    await fwd._finish_recordings()


async def test_phone_to_receiver_to_control_room_across_an_internet_outage(env, tmp_path):
    from site_receiver import main as m

    central = MockControlRoom()
    cclient = lambda: httpx.AsyncClient(base_url="https://central.test", transport=httpx.MockTransport(central.handler))
    env(RECEIVER_CENTRAL_URL="https://central.test", RECEIVER_CENTRAL_TOKEN="fake-token", RECEIVER_BACKOFF_BASE_SECONDS="1")
    events = []
    log = lambda step, **kw: events.append({"step": step, **kw})

    phone = PhoneModel()
    rid = str(uuid.uuid4())
    app = m.create_app()
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("10.0.0.5", 1)), base_url="http://receiver")
        tok = (await c.post("/v1/auth/session", json={"grant": make_grant(), "device_identifier": "test-device-0001"})).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        assert (await c.post("/v1/recordings", headers=h, json={"recording_id": rid, "started_at": "2026-01-01T00:00:00Z"})).status_code == 200
        # 1-4: internet is down (central.up False); the phone records 5 chunks and uploads them to the receiver
        for n in range(1, 6):
            phone.record(n)
        for n in range(1, 4):
            cid, data, sha = phone.files[n]
            r = await c.put(f"/v1/recordings/{rid}/chunks/{cid}", headers=h, data={"chunk_number": str(n), "sha256": sha, "size_bytes": str(len(data))}, files={"file": ("c.mp4", data, "video/mp4")})
            assert r.status_code == 200 and r.json()["ack"] == "local_received"
            # durability: the acknowledged bytes are on disk and in SQLite right now
            row = app.state.store.one("SELECT * FROM chunks WHERE chunk_id = ?", (cid,))
            assert hashlib.sha256(open(row["storage_path"], "rb").read()).hexdigest() == sha
            phone.state[n] = "local_acked"
        log("receiver_acknowledged_chunks_1_to_3_while_internet_down")
        # 5: nothing may be deleted from the phone yet: no central confirmation exists
        phone.reconcile(central.manifest(rid))
        assert sorted(phone.files) == [1, 2, 3, 4, 5], "phone keeps every chunk without central confirmation"
        await pump(app, cclient())
        assert all(r["state"] == FAILED_RETRY for r in app.state.store.query("SELECT state FROM chunks")), "central down => retry, not quarantine"
        log("forwarding_retries_while_central_down")
        await c.aclose()
    # 6: receiver restarts mid-outage
    app = m.create_app()
    async with app.router.lifespan_context(app):
        store = app.state.store
        assert len(store.query("SELECT * FROM chunks")) == 3 and all(r["state"] in (FAILED_RETRY, PENDING) for r in store.query("SELECT * FROM chunks"))
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("10.0.0.5", 1)), base_url="http://receiver")
        tok = (await c.post("/v1/auth/session", json={"grant": make_grant(), "device_identifier": "test-device-0001"})).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        for n in (4, 5):
            cid, data, sha = phone.files[n]
            r = await c.put(f"/v1/recordings/{rid}/chunks/{cid}", headers=h, data={"chunk_number": str(n), "sha256": sha}, files={"file": ("c.mp4", data, "video/mp4")})
            assert r.status_code == 200
            phone.state[n] = "local_acked"
        done = await c.post(f"/v1/recordings/{rid}/complete", headers=h, json={"chunk_count": 5})
        assert done.status_code == 200 and done.json()["central_received"] is False
        log("receiver_restarted_and_received_chunks_4_5_and_completion")
        # completion must not be forwarded while chunks are unconfirmed
        central.up = True
        central.commit_then_lose_response = 1  # one chunk is committed centrally but its response is lost
        store.execute("UPDATE chunks SET next_attempt_at = 0")
        await pump(app, cclient())
        assert central.completed == {}, "completion waits for every chunk"
        store.execute("UPDATE chunks SET next_attempt_at = 0")
        await pump(app, cclient())  # retries; the lost-response chunk comes back as a confirmed duplicate
        await pump(app, cclient())
        states = [r["state"] for r in store.query("SELECT state FROM chunks ORDER BY chunk_number")]
        assert states == [ACKED] * 5, states
        log("all_chunks_confirmed_after_reconnect", lost_response_retry="duplicate_confirmed")
        store.execute("UPDATE recordings SET complete_next_at = 0")
        await pump(app, cclient())
        assert central.completed == {rid: []}
        # 7: central recomputed hashes and holds byte-identical originals
        for n in range(1, 6):
            assert central.archive[(rid, n)] == make_chunk(n)[0]
        # 8: only now does the phone release its copies
        phone.reconcile(central.manifest(rid))
        assert phone.files == {} and set(phone.state.values()) == {"uploaded"}
        log("phone_released_copies_only_after_matching_central_manifest")
        # 9: dashboard-facing summary: nothing is left that is held only at the receiver
        assert store.local_recordings_summary() == [] or all(r["central_completed"] == 1 for r in store.local_recordings_summary())
        await c.aclose()
        # 10: a conflicting chunk (same number, different bytes) is rejected centrally and cannot overwrite evidence
        evil_id, evil_bytes = str(uuid.uuid4()), make_chunk(1, seed=b"evil")[0]
        r = await cclient().put(
            f"/receiver/v1/recordings/{rid}/chunks/{evil_id}", data={"chunk_number": "1", "sha256": hashlib.sha256(evil_bytes).hexdigest()}, files={"file": ("c.mp4", evil_bytes, "video/mp4")})
        assert r.status_code == 409 and r.headers["x-conflict-reason"] == "hash_conflict"
        assert central.archive[(rid, 1)] == make_chunk(1)[0], "existing evidence untouched"
        log("conflicting_chunk_rejected_without_overwrite")
    out = os.environ.get("VALIDATION_LOG_DIR")
    if out:
        os.makedirs(out, exist_ok=True)
        json.dump({"scenario": "phone-model -> real receiver -> mock control room, internet outage", "result": "pass", "events": events}, open(os.path.join(out, "outage-simulation.json"), "w"), indent=2)
