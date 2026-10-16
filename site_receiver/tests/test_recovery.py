"""Crash recovery, orphan handling, single-instance protection and damaged-chunk healing."""
import hashlib
import os
import uuid

import pytest

from site_receiver.recovery import AlreadyRunning, InstanceLock, reconcile
from .conftest import make_chunk, seed_chunk, seed_recording



def test_syncing_rows_return_to_queue_after_restart(kit):
    s, store, media = kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1, state="syncing")
    assert store.recover_after_restart() == 1
    assert store.one("SELECT state FROM chunks WHERE chunk_id = ?", (row["chunk_id"],))["state"] == "pending_sync"
    assert store.recover_after_restart() == 0, "idempotent"


def test_missing_and_short_files_are_quarantined_not_lost(kit):
    s, store, media = kit
    rid = seed_recording(store)
    gone, _ = seed_chunk(store, media, s, rid, 1, write_file=False)
    short, _ = seed_chunk(store, media, s, rid, 2)
    with open(short["storage_path"], "ab") as fh:
        fh.write(b"extra")  # size no longer matches the recorded size
    report = reconcile(store, media)
    assert report["missing_quarantined"] == 1 and report["size_quarantined"] == 1
    assert store.one("SELECT state, last_error FROM chunks WHERE chunk_id = ?", (gone["chunk_id"],))["state"] == "quarantined"
    assert os.path.exists(short["storage_path"]), "the damaged file is kept for diagnosis"
    again = reconcile(store, media)
    assert again["missing_quarantined"] == 0 and again["size_quarantined"] == 0, "second run changes nothing"


def test_confirmed_chunk_with_missing_file_is_marked_purged(kit):
    s, store, media = kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1, state="central_acknowledged", write_file=False)
    assert reconcile(store, media)["marked_purged"] == 1
    assert store.one("SELECT state FROM chunks WHERE chunk_id = ?", (row["chunk_id"],))["state"] == "purged"


def test_orphan_file_is_moved_aside_never_adopted_or_deleted(kit):
    s, store, media = kit
    rid = str(uuid.uuid4())
    cid = str(uuid.uuid4())
    path = media.chunk_path(uuid.UUID(rid), uuid.UUID(cid))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data, _ = make_chunk(1)
    open(path, "wb").write(data)  # crash between rename and metadata commit: no row exists
    report = reconcile(store, media)
    assert report["orphans_moved"] == 1 and not os.path.exists(path)
    moved = [os.path.join(d, f) for d, _x, fs in os.walk(os.path.join(media.site_dir, ".orphans")) for f in fs]
    assert len(moved) == 1 and open(moved[0], "rb").read() == data, "bytes preserved"
    assert store.query("SELECT * FROM chunks") == []


def test_quarantined_rows_are_left_alone(kit):
    s, store, media = kit
    rid = seed_recording(store)
    row, _ = seed_chunk(store, media, s, rid, 1, state="quarantined", write_file=False)
    assert reconcile(store, media)["missing_quarantined"] == 0
    assert store.one("SELECT state FROM chunks WHERE chunk_id = ?", (row["chunk_id"],))["state"] == "quarantined"


def test_stale_tmp_uploads_are_cleaned(kit):
    s, store, media = kit
    staged = media.stage()
    staged.write(b"partial")
    staged._fh.flush()
    old = os.path.getmtime(staged.path) - 7200
    os.utime(staged.path, (old, old))
    staged._fh.close()
    assert media.clean_stale_tmp() == 1 and not os.path.exists(staged.path)


def test_second_process_cannot_use_same_database(tmp_path):
    a = InstanceLock(str(tmp_path / "db.lock"))
    b = InstanceLock(str(tmp_path / "db.lock"))
    a.acquire()
    with pytest.raises(AlreadyRunning):
        b.acquire()
    a.release()
    b.acquire()  # free again once the first owner is gone
    b.release()


async def test_create_app_refuses_a_second_instance(env, receiver):
    from site_receiver import main as m
    from site_receiver.config import ConfigError

    with pytest.raises(ConfigError):
        m.create_app()  # same environment => same database + lock as the running `receiver`


async def test_startup_recovery_runs_before_serving(env, tmp_path):
    from site_receiver import main as m
    from site_receiver.storage import MediaStorage
    from site_receiver.store import Store
    from site_receiver.config import load

    s = load()
    os.makedirs(os.path.dirname(s.db_path), exist_ok=True)
    store = Store(s.db_path)
    media = MediaStorage(s.storage_root, s.site_id)
    rid = seed_recording(store)
    syncing, _ = seed_chunk(store, media, s, rid, 1, state="syncing")
    lost, _ = seed_chunk(store, media, s, rid, 2, write_file=False)
    store.close()
    app = m.create_app()
    async with app.router.lifespan_context(app):
        st = app.state.store
        assert st.one("SELECT state FROM chunks WHERE chunk_id = ?", (syncing["chunk_id"],))["state"] == "pending_sync"
        assert st.one("SELECT state FROM chunks WHERE chunk_id = ?", (lost["chunk_id"],))["state"] == "quarantined"
        events = [r["event"] for r in st.recent_audit(20)]
        assert "recovery_finished" in events and "receiver_started" in events


# ------------------------------- healing through the HTTP API -------------------------------

async def _upload(receiver):
    h = await receiver.token()
    rid = await receiver.register(h)
    data, sha = make_chunk(1)
    cid = str(uuid.uuid4())
    assert (await receiver.put_chunk(h, rid, cid, 1, data)).status_code == 200
    return h, rid, cid, data, sha


async def test_lost_file_is_healed_by_identical_reupload(receiver):
    h, rid, cid, data, sha = await _upload(receiver)
    store = receiver.app.state.store
    path = store.one("SELECT storage_path FROM chunks WHERE chunk_id = ?", (cid,))["storage_path"]
    os.remove(path)
    r = await receiver.put_chunk(h, rid, cid, 1, data)
    assert r.status_code == 200 and r.json()["duplicate"] is False
    assert hashlib.sha256(open(path, "rb").read()).hexdigest() == sha
    assert store.one("SELECT state FROM chunks WHERE chunk_id = ?", (cid,))["state"] == "pending_sync"
    assert "chunk_healed" in [e["event"] for e in store.recent_audit(20)]


async def test_damaged_quarantined_file_is_replaced_and_old_bytes_kept(receiver):
    h, rid, cid, data, sha = await _upload(receiver)
    store = receiver.app.state.store
    path = store.one("SELECT storage_path FROM chunks WHERE chunk_id = ?", (cid,))["storage_path"]
    damaged = bytearray(data)
    damaged[100] ^= 0xFF
    open(path, "wb").write(bytes(damaged))  # bit rot: same size, different content
    store.execute("UPDATE chunks SET state = 'quarantined', last_error = 'local file no longer matches its SHA-256' WHERE chunk_id = ?", (cid,))
    r = await receiver.put_chunk(h, rid, cid, 1, data)
    assert r.status_code == 200
    assert hashlib.sha256(open(path, "rb").read()).hexdigest() == sha
    assert store.one("SELECT state FROM chunks WHERE chunk_id = ?", (cid,))["state"] == "pending_sync"
    kept = [os.path.join(d, f) for d, _x, fs in os.walk(os.path.join(receiver.app.state.media.site_dir, ".quarantine")) for f in fs]
    assert len(kept) == 1 and open(kept[0], "rb").read() == bytes(damaged), "the damaged copy is preserved, not deleted"


async def test_quarantined_for_policy_reasons_is_never_acknowledged(receiver):
    h, rid, cid, data, sha = await _upload(receiver)
    store = receiver.app.state.store
    store.execute("UPDATE chunks SET state = 'quarantined', last_error = 'control room refused the chunk (HTTP 409 hash_conflict)' WHERE chunk_id = ?", (cid,))
    r = await receiver.put_chunk(h, rid, cid, 1, data)  # file is intact: an upload cannot fix this
    assert r.status_code == 409 and r.json()["error"]["code"] == "chunk_quarantined"
    assert store.one("SELECT state FROM chunks WHERE chunk_id = ?", (cid,))["state"] == "quarantined"


async def test_orphan_then_reupload_after_restart(env, tmp_path):
    from site_receiver import main as m
    from site_receiver.storage import MediaStorage
    import httpx
    from .conftest import make_grant

    app = m.create_app()
    async with app.router.lifespan_context(app):
        media = app.state.media
    rid, cid = str(uuid.uuid4()), str(uuid.uuid4())
    path = media.chunk_path(uuid.UUID(rid), uuid.UUID(cid))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data, sha = make_chunk(1)
    open(path, "wb").write(data)  # a crash left this file without a row
    app2 = m.create_app()
    async with app2.router.lifespan_context(app2):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app2, client=("10.0.0.5", 1)), base_url="http://r")
        tok = (await c.post("/v1/auth/session", json={"grant": make_grant()})).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        await c.post("/v1/recordings", headers=h, json={"recording_id": rid, "started_at": "2026-01-01T00:00:00Z"})
        r = await c.put(f"/v1/recordings/{rid}/chunks/{cid}", headers=h, data={"chunk_number": "1", "sha256": sha}, files={"file": ("c.mp4", data, "video/mp4")})
        await c.aclose()
        assert r.status_code == 200 and r.json()["duplicate"] is False
        assert os.path.exists(path)
