"""Forwarding to a MOCK control room: success confirmation, failure classes, durable retry, completion and retention."""
import datetime
import hashlib
import time
import uuid

import httpx
import pytest

from site_receiver.forwarder import Forwarder
from site_receiver.store import ACKED, FAILED_RETRY, PENDING, PURGED, QUARANTINED, Store, now_iso
from .conftest import make_chunk, seed_chunk, seed_recording


class Central:
    """Programmable stand-in for the control room."""

    def __init__(self):
        self.requests = []
        self.chunk_response = lambda req, sha: httpx.Response(200, json={"original_hash": sha, "duplicate": False})
        self.register_response = lambda req: httpx.Response(200, json={"created": True})
        self.complete_response = lambda req: httpx.Response(200, json={"missing_chunk_numbers": []})
        self.exception = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        if self.exception:
            raise self.exception
        path = request.url.path
        if request.method == "PUT" and "/chunks/" in path:
            body = request.read()
            sha = request.headers.get("x-test-sha") or _extract_field(body, "sha256")
            return self.chunk_response(request, sha)
        if request.method == "PUT":
            return self.register_response(request)
        if path.endswith("/complete"):
            return self.complete_response(request)
        if path.endswith("/heartbeat"):
            return httpx.Response(200, json={"status": "ok"})
        if path.endswith("/sync"):
            return httpx.Response(200, json={"revoked_grant_ids": [], "commands": []})
        return httpx.Response(404)

    def count(self, method, suffix=""):
        return sum(1 for m, p in self.requests if m == method and p.endswith(suffix))


def _extract_field(body: bytes, name: str):
    marker = f'name="{name}"'.encode()
    i = body.index(marker)
    j = body.index(b"\r\n\r\n", i) + 4
    return body[j:body.index(b"\r\n", j)].decode()


@pytest.fixture
def fwd(kit):
    s, store, media = kit
    central = Central()
    f = Forwarder(s, store, media)
    f._client = httpx.AsyncClient(base_url=s.central_url, transport=httpx.MockTransport(central.handler), headers={"Authorization": "Bearer t"})
    f.central = central
    f.kit = kit
    return f


def chunk_row(store, cid):
    return store.one("SELECT * FROM chunks WHERE chunk_id = ?", (cid,))


async def forward(f, row):
    await f._process_chunk(store_row(f, row["chunk_id"]))


def store_row(f, cid):
    return f.kit[1].one("SELECT * FROM chunks WHERE chunk_id = ?", (cid,))


async def test_success_requires_matching_hash_before_confirming(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    await forward(fwd, row)
    r = chunk_row(store, row["chunk_id"])
    assert r["state"] == ACKED and r["central_acked_at"]
    assert fwd.last_central_ack_at and fwd.central.count("PUT", ".mp4") == 0
    assert any(p.endswith("/chunks/" + row["chunk_id"]) for _m, p in fwd.central.requests), "the chunk really was sent to the control room"
    assert r["last_error"] is None


async def test_ack_naming_different_content_quarantines(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.chunk_response = lambda req, sha: httpx.Response(200, json={"original_hash": "f" * 64})
    await forward(fwd, row)
    assert chunk_row(store, row["chunk_id"])["state"] == QUARANTINED


async def test_ack_without_hash_is_not_confirmation(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.chunk_response = lambda req, sha: httpx.Response(200, json={})
    await forward(fwd, row)
    assert chunk_row(store, row["chunk_id"])["state"] != ACKED


@pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503, 504, 599])
async def test_outage_statuses_never_quarantine_however_long_they_last(fwd, status):
    s, store, media = fwd.kit  # RECEIVER_MAX_HARD_ERRORS is 2 in this fixture: many failures must still not quarantine
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.chunk_response = lambda req, sha: httpx.Response(status, headers={"retry-after": "120"} if status in (429, 503) else {})
    for _ in range(6):
        store.execute("UPDATE chunks SET next_attempt_at = 0 WHERE chunk_id = ?", (row["chunk_id"],))
        await forward(fwd, chunk_row(store, row["chunk_id"]))
    r = chunk_row(store, row["chunk_id"])
    assert r["state"] == FAILED_RETRY and r["hard_errors"] == 0 and r["attempts"] == 6
    assert r["next_attempt_at"] > time.time(), "a retry time is persisted"
    assert "unavailable" in (r["last_error"] or "") or "busy" in (r["last_error"] or "")


async def test_retry_after_is_honoured_and_capped(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.chunk_response = lambda req, sha: httpx.Response(503, headers={"retry-after": "300"})
    await forward(fwd, row)
    wait = chunk_row(store, row["chunk_id"])["next_attempt_at"] - time.time()
    assert 250 < wait <= 300 + 1
    fwd.central.chunk_response = lambda req, sha: httpx.Response(503, headers={"retry-after": "999999"})
    store.execute("UPDATE chunks SET next_attempt_at = 0 WHERE chunk_id = ?", (row["chunk_id"],))
    await forward(fwd, chunk_row(store, row["chunk_id"]))
    assert chunk_row(store, row["chunk_id"])["next_attempt_at"] - time.time() <= s.backoff_max + 1


@pytest.mark.parametrize("exc", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), httpx.ConnectTimeout("slow"), httpx.RemoteProtocolError("reset")])
async def test_network_failures_retry_and_persist(fwd, exc):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.exception = exc
    await forward(fwd, row)
    r = chunk_row(store, row["chunk_id"])
    assert r["state"] == FAILED_RETRY and r["hard_errors"] == 0 and r["next_attempt_at"] > time.time()
    # the schedule is in SQLite: a restarted receiver sees exactly the same
    reopened = Store(s.db_path)
    assert reopened.one("SELECT next_attempt_at, state FROM chunks WHERE chunk_id = ?", (row["chunk_id"],))["next_attempt_at"] == r["next_attempt_at"]
    reopened.close()
    assert fwd.central_reachable is False


@pytest.mark.parametrize("status,reason", [(409, "hash_conflict"), (400, ""), (413, ""), (422, "invalid"), (403, "grant_revoked"), (409, "recording_id_conflict")])
async def test_integrity_and_policy_failures_quarantine(fwd, status, reason):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.chunk_response = lambda req, sha: httpx.Response(status, headers={"x-conflict-reason": reason} if reason else {})
    await forward(fwd, row)
    assert chunk_row(store, row["chunk_id"])["state"] == QUARANTINED


async def test_hash_mismatch_in_transit_is_retried_not_quarantined(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.chunk_response = lambda req, sha: httpx.Response(422, headers={"x-conflict-reason": "hash_mismatch"})
    await forward(fwd, row)
    assert chunk_row(store, row["chunk_id"])["state"] == FAILED_RETRY


async def test_credential_rejection_pauses_forwarding_without_consuming_the_chunk(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.chunk_response = lambda req, sha: httpx.Response(401)
    await forward(fwd, row)
    r = chunk_row(store, row["chunk_id"])
    assert r["state"] == PENDING and fwd._paused_until > time.time() and r["hard_errors"] == 0


async def test_recording_refused_by_central_quarantines_its_chunks(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    a, _ = seed_chunk(store, media, s, rid, 1)
    b, _ = seed_chunk(store, media, s, rid, 2)
    fwd.central.register_response = lambda req: httpx.Response(403, headers={"x-conflict-reason": "grant_revoked"})
    await forward(fwd, a)
    assert chunk_row(store, a["chunk_id"])["state"] == QUARANTINED and chunk_row(store, b["chunk_id"])["state"] == QUARANTINED
    assert fwd.central.count("PUT", a["chunk_id"]) == 0


async def test_central_5xx_on_registration_is_retryable(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.register_response = lambda req: httpx.Response(503)
    await forward(fwd, row)
    assert chunk_row(store, row["chunk_id"])["state"] == FAILED_RETRY


async def test_locally_corrupted_file_is_never_sent(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, data = seed_chunk(store, media, s, rid, 1)
    damaged = bytearray(data)
    damaged[50] ^= 1
    open(row["storage_path"], "wb").write(bytes(damaged))
    await forward(fwd, row)
    assert chunk_row(store, row["chunk_id"])["state"] == QUARANTINED
    assert fwd.central.requests == [], "damaged bytes must never be sent as if they were the evidence"


async def test_timeout_after_central_commit_then_retry_is_a_confirmed_duplicate(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1)
    fwd.central.exception = httpx.ReadTimeout("response lost")  # central may have committed
    await forward(fwd, row)
    assert chunk_row(store, row["chunk_id"])["state"] == FAILED_RETRY
    fwd.central.exception = None
    fwd.central.chunk_response = lambda req, sha: httpx.Response(200, json={"original_hash": sha, "duplicate": True})
    store.execute("UPDATE chunks SET next_attempt_at = 0 WHERE chunk_id = ?", (row["chunk_id"],))
    await forward(fwd, chunk_row(store, row["chunk_id"]))
    assert chunk_row(store, row["chunk_id"])["state"] == ACKED


async def test_backoff_grows_is_capped_and_jittered(fwd):
    s = fwd.kit[0]
    vals = [fwd._backoff(n) for n in range(0, 20)]
    assert vals[0] <= s.backoff_base * 1.2 + 1e-9 and max(vals) <= s.backoff_max * 1.2 + 1e-9
    assert fwd._backoff(8) > fwd._backoff(1)
    assert len({round(fwd._backoff(5), 3) for _ in range(20)}) > 1, "jitter present"


# ------------------------------------------- completion -------------------------------------------

async def test_completion_waits_for_every_chunk(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store, status="completed", complete=True, expected=2)
    seed_chunk(store, media, s, rid, 1, state=ACKED)
    seed_chunk(store, media, s, rid, 2, state=PENDING)
    await fwd._finish_recordings()
    assert fwd.central.count("POST", "/complete") == 0
    rec = store.one("SELECT * FROM recordings WHERE recording_id = ?", (rid,))
    assert rec["central_completed"] == 0 and "not centrally confirmed" in rec["last_error"] and rec["complete_next_at"] > time.time()


async def test_completion_blocked_by_quarantine_is_visible_and_never_sent(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store, status="completed", complete=True, expected=2)
    seed_chunk(store, media, s, rid, 1, state=ACKED)
    seed_chunk(store, media, s, rid, 2, state=QUARANTINED)
    await fwd._finish_recordings()
    rec = store.one("SELECT * FROM recordings WHERE recording_id = ?", (rid,))
    assert fwd.central.count("POST", "/complete") == 0 and "quarantined" in rec["last_error"]


async def test_completion_sent_once_everything_is_confirmed(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store, status="completed", complete=True, expected=2)
    seed_chunk(store, media, s, rid, 1, state=ACKED)
    seed_chunk(store, media, s, rid, 2, state=ACKED)
    await fwd._finish_recordings()
    assert fwd.central.count("POST", "/complete") == 1
    assert store.one("SELECT central_completed FROM recordings WHERE recording_id = ?", (rid,))["central_completed"] == 1
    await fwd._finish_recordings()
    assert fwd.central.count("POST", "/complete") == 1, "idempotent: a completed recording is not completed again"


async def test_completion_failures_back_off_durably_and_do_not_busy_loop(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store, status="completed", complete=True, expected=1)
    seed_chunk(store, media, s, rid, 1, state=ACKED)
    fwd.central.complete_response = lambda req: httpx.Response(503, headers={"retry-after": "90"})
    await fwd._finish_recordings()
    for _ in range(5):  # the forwarding loop calls this every few seconds
        await fwd._finish_recordings()
    assert fwd.central.count("POST", "/complete") == 1, "no request until the stored retry time"
    reopened = Store(s.db_path)
    rec = reopened.one("SELECT complete_attempts, complete_next_at FROM recordings WHERE recording_id = ?", (rid,))
    reopened.close()
    assert rec["complete_attempts"] == 1 and 60 < rec["complete_next_at"] - time.time() <= 91


async def test_completion_unreachable_control_room(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store, status="completed", complete=True, expected=1)
    seed_chunk(store, media, s, rid, 1, state=ACKED)
    fwd.central.exception = httpx.ConnectError("down")
    await fwd._finish_recordings()
    rec = store.one("SELECT * FROM recordings WHERE recording_id = ?", (rid,))
    assert rec["central_completed"] == 0 and rec["complete_attempts"] == 1 and rec["complete_next_at"] > time.time()


# ------------------------------------------- heartbeat, commands, retention -------------------------------------------

async def test_heartbeat_applies_revocations_and_timestamps_are_not_invented(fwd):
    s, store, media = fwd.kit
    assert fwd.snapshot()["last_central_ack_at"] is None, "no confirmation yet: nothing is invented"
    g = str(uuid.uuid4())
    fwd.central.handler_orig = fwd.central.handler
    sent = {}

    def handler(request):
        if request.url.path.endswith("/heartbeat"):
            sent["body"] = request.read()
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path.endswith("/sync"):
            return httpx.Response(200, json={"revoked_grant_ids": [g], "commands": []})
        return httpx.Response(404)

    fwd._client = httpx.AsyncClient(base_url=s.central_url, transport=httpx.MockTransport(handler))
    await fwd._heartbeat_and_sync()
    assert store.is_revoked(g)
    assert b"last_central_ack_at" not in sent["body"]


async def test_operator_commands_requeue_quarantined_chunks(fwd):
    s, store, media = fwd.kit
    rid = seed_recording(store)
    q, _ = seed_chunk(store, media, s, rid, 1, state=QUARANTINED)
    await fwd._apply_command({"id": "c1", "type": "retry_quarantined"})
    assert chunk_row(store, q["chunk_id"])["state"] == PENDING
    assert "command_applied" in [e["event"] for e in store.recent_audit(10)]
    await fwd._apply_command({"id": "c1", "type": "retry_quarantined"})  # delivered twice: applied once
    assert [e["event"] for e in store.recent_audit(10)].count("command_applied") == 1


def _age_ack(store, cid, days):
    when = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat()
    store.execute("UPDATE chunks SET central_acked_at = ? WHERE chunk_id = ?", (when, cid))


async def test_retention_only_removes_centrally_confirmed_chunks(make_settings):
    from site_receiver.storage import MediaStorage
    import os

    s = make_settings(RECEIVER_CENTRAL_URL="https://central.test", RECEIVER_CENTRAL_TOKEN="x", RECEIVER_RETENTION_AFTER_SYNC_DAYS="7")
    os.makedirs(os.path.dirname(s.db_path), exist_ok=True)
    store, media = Store(s.db_path), MediaStorage(s.storage_root, s.site_id)
    f = Forwarder(s, store, media)
    rid = seed_recording(store)
    old, _ = seed_chunk(store, media, s, rid, 1, state=ACKED)
    recent, _ = seed_chunk(store, media, s, rid, 2, state=ACKED)
    pending, _ = seed_chunk(store, media, s, rid, 3, state=PENDING)
    quarantined, _ = seed_chunk(store, media, s, rid, 4, state=QUARANTINED)
    unsure, _ = seed_chunk(store, media, s, rid, 5, state="syncing")
    for row in (old, recent, pending, quarantined, unsure):
        _age_ack(store, row["chunk_id"], 30 if row is old else 1)
    assert f.purge_synced() == 1
    states = {r["chunk_number"]: r["state"] for r in store.query("SELECT chunk_number, state FROM chunks")}
    assert states == {1: PURGED, 2: ACKED, 3: PENDING, 4: QUARANTINED, 5: "syncing"}
    assert not os.path.exists(old["storage_path"]) and all(os.path.exists(r["storage_path"]) for r in (recent, pending, quarantined, unsure))
    purged = store.one("SELECT * FROM chunks WHERE chunk_number = 1")
    assert purged["sha256"] and purged["size_bytes"] and purged["purged_at"], "hash and size metadata survive purge"
    store.close()


async def test_low_space_purge_never_touches_unconfirmed_chunks(make_settings):
    from site_receiver.storage import MediaStorage
    import os

    s = make_settings(RECEIVER_CENTRAL_URL="https://central.test", RECEIVER_CENTRAL_TOKEN="x", RECEIVER_RETENTION_AFTER_SYNC_DAYS="365",
                      RECEIVER_PURGE_SYNCED_ON_LOW_SPACE="true", RECEIVER_MIN_FREE_MB="999999999")
    os.makedirs(os.path.dirname(s.db_path), exist_ok=True)
    store, media = Store(s.db_path), MediaStorage(s.storage_root, s.site_id)
    f = Forwarder(s, store, media)
    rid = seed_recording(store)
    acked, _ = seed_chunk(store, media, s, rid, 1, state=ACKED)
    others = [seed_chunk(store, media, s, rid, n, state=st)[0] for n, st in ((2, PENDING), (3, QUARANTINED), (4, FAILED_RETRY))]
    _age_ack(store, acked["chunk_id"], 0)
    assert f.purge_synced() == 1
    assert all(os.path.exists(r["storage_path"]) for r in others)
    store.close()


async def test_retention_zero_days_means_remove_once_confirmed(make_settings):
    """receiver.env.example documents RECEIVER_RETENTION_AFTER_SYNC_DAYS=0 as 'delete as soon as the control room confirmed'."""
    from site_receiver.storage import MediaStorage
    import os

    s = make_settings(RECEIVER_CENTRAL_URL="https://central.test", RECEIVER_CENTRAL_TOKEN="x", RECEIVER_RETENTION_AFTER_SYNC_DAYS="0")
    os.makedirs(os.path.dirname(s.db_path), exist_ok=True)
    store, media = Store(s.db_path), MediaStorage(s.storage_root, s.site_id)
    f = Forwarder(s, store, media)
    rid = seed_recording(store)
    acked, _ = seed_chunk(store, media, s, rid, 1, state=ACKED)
    pending, _ = seed_chunk(store, media, s, rid, 2, state=PENDING)
    _age_ack(store, acked["chunk_id"], 0)
    assert f.purge_synced() == 1 and os.path.exists(pending["storage_path"])
    store.close()


async def test_local_recording_summary_is_bounded_and_flags_unconfirmed(kit):
    s, store, media = kit
    done = seed_recording(store, status="completed", complete=True)
    seed_chunk(store, media, s, done, 1, state=ACKED)
    store.execute("UPDATE recordings SET central_completed = 1 WHERE recording_id = ?", (done,))
    open_rec = seed_recording(store)
    seed_chunk(store, media, s, open_rec, 1, state=ACKED)
    seed_chunk(store, media, s, open_rec, 2, state=QUARANTINED)
    for _ in range(60):
        seed_recording(store)
    summary = store.local_recordings_summary(limit=50)
    ids = [r["recording_id"] for r in summary]
    assert len(summary) == 50 and done not in ids
    row = store.local_recordings_summary(limit=500)
    mine = next(r for r in row if r["recording_id"] == open_rec)
    assert (mine["chunks_received"], mine["chunks_synced"], mine["chunks_quarantined"]) == (2, 1, 1)
