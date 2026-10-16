"""Configuration validation and the real forwarding loop (start, drain, back-pressure, pause, stop)."""
import asyncio
import time

import httpx
import pytest

from site_receiver.config import ConfigError, load
from site_receiver.forwarder import Forwarder
from site_receiver.store import ACKED, PENDING
from .conftest import seed_chunk, seed_recording


def test_required_settings_fail_clearly(env):
    env(RECEIVER_SITE_ID="not-a-uuid")
    with pytest.raises(ConfigError, match="RECEIVER_SITE_ID"):
        load()
    env(RECEIVER_SITE_CODE="")
    with pytest.raises(ConfigError):
        load()
    env(RECEIVER_GRANT_PUBLIC_KEY_PEM="")
    with pytest.raises(ConfigError, match="PUBLIC"):
        load()
    env(RECEIVER_MAX_CHUNK_MB="lots")
    with pytest.raises(ConfigError, match="integer"):
        load()


def test_plain_http_central_is_refused_unless_explicitly_allowed(env):
    env(RECEIVER_CENTRAL_URL="http://central.test")
    with pytest.raises(ConfigError, match="https"):
        load()
    env(RECEIVER_CENTRAL_URL="http://central.test", RECEIVER_ALLOW_INSECURE_CENTRAL="true")
    assert load().allow_insecure_central is True


def test_secrets_never_appear_in_settings_repr(env):
    env(RECEIVER_CENTRAL_URL="https://central.test", RECEIVER_CENTRAL_TOKEN="very-secret-token")
    text = repr(load())
    assert "very-secret-token" not in text and "unit-test-admin-key" not in text and "unit-test-session-secret" not in text and "BEGIN PUBLIC" not in text


def test_limits_are_clamped(env):
    s = (env(RECEIVER_UPLOAD_CONCURRENCY="9999", RECEIVER_MIN_FREE_MB="0"), load())[1]
    assert s.upload_concurrency == 64 and s.min_free_bytes == 1024 * 1024


def test_missing_access_secret_uses_a_random_per_process_one(env):
    env(RECEIVER_ACCESS_TOKEN_SECRET="")
    a, b = load(), load()
    assert a.ephemeral_access_secret and a.access_token_secret != b.access_token_secret and len(a.access_token_secret) >= 32


async def wait_for(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return False


async def test_the_real_loop_forwards_pending_chunks_and_completes_the_recording(kit):
    s, store, media = kit
    s.heartbeat_seconds = 5
    rid = seed_recording(store, status="completed", complete=True, expected=3)
    rows = [seed_chunk(store, media, s, rid, n)[0] for n in (1, 2, 3)]
    seen = []

    def central(req: httpx.Request):
        seen.append((req.method, req.url.path))
        if req.method == "PUT" and "/chunks/" in req.url.path:
            body = req.read()
            i = body.index(b'name="sha256"'); j = body.index(b"\r\n\r\n", i) + 4
            return httpx.Response(200, json={"original_hash": body[j:body.index(b"\r\n", j)].decode(), "duplicate": False})
        if req.url.path.endswith("/sync"):
            return httpx.Response(200, json={"revoked_grant_ids": [], "commands": []})
        return httpx.Response(200, json={"missing_chunk_numbers": [], "status": "ok"})

    f = Forwarder(s, store, media)
    f._client = httpx.AsyncClient(base_url=s.central_url, transport=httpx.MockTransport(central))
    task = asyncio.create_task(f.run())
    try:
        assert await wait_for(lambda: all(store.one("SELECT state FROM chunks WHERE chunk_id = ?", (r["chunk_id"],))["state"] == ACKED for r in rows))
        assert await wait_for(lambda: store.one("SELECT central_completed FROM recordings WHERE recording_id = ?", (rid,))["central_completed"] == 1)
    finally:
        f.stop()
        await asyncio.wait_for(task, timeout=5)
    assert ("POST", f"/receiver/v1/recordings/{rid}/complete") in seen and ("POST", "/receiver/v1/heartbeat") in seen
    assert task.done() and not task.cancelled(), "the loop stops cleanly when asked"


async def test_credential_rejection_pauses_instead_of_hammering_the_control_room(kit):
    s, store, media = kit
    rid = seed_recording(store)
    seed_chunk(store, media, s, rid, 1)
    calls = []

    def central(req):
        calls.append(req.url.path)
        return httpx.Response(401)

    f = Forwarder(s, store, media)
    f._client = httpx.AsyncClient(base_url=s.central_url, transport=httpx.MockTransport(central))
    task = asyncio.create_task(f.run())
    await asyncio.sleep(1.2)
    f.stop()
    await asyncio.wait_for(task, timeout=5)
    assert len(calls) <= 4, f"no tight retry loop while the credential is refused: {len(calls)} calls in 1.2 s"
    row = store.one("SELECT state, hard_errors FROM chunks")
    assert row["state"] in (PENDING, "failed_retry") and row["hard_errors"] == 0, "retryable, never quarantined, nothing consumed"


async def test_unconfigured_forwarding_stores_but_never_contacts_anyone(make_settings, tmp_path):
    from site_receiver.storage import MediaStorage
    from site_receiver.store import Store
    import os

    s = make_settings()  # no central URL / token
    os.makedirs(os.path.dirname(s.db_path), exist_ok=True)
    store, media = Store(s.db_path), MediaStorage(s.storage_root, s.site_id)
    f = Forwarder(s, store, media)
    assert f.configured is False
    task = asyncio.create_task(f.run())
    rid = seed_recording(store)
    seed_chunk(store, media, s, rid, 1)
    await asyncio.sleep(0.4)
    f.stop()
    await asyncio.wait_for(task, timeout=7)
    assert store.one("SELECT state FROM chunks")["state"] == PENDING
    store.close()
