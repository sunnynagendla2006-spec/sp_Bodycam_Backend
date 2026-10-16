"""Durable chunk receipt: what is on disk and in SQLite must agree with what was acknowledged."""
import asyncio
import errno
import hashlib
import os
import sqlite3
import uuid

import pytest

from .conftest import make_chunk

CRLF = bytes([13, 10])


def rows(receiver, sql="SELECT * FROM chunks", params=()):
    return receiver.app.state.store.query(sql, params)


def media_files(receiver):
    out = []
    for d, _dirs, files in os.walk(receiver.app.state.media.site_dir):
        if os.sep + ".tmp" in d or ".quarantine" in d or ".orphans" in d:
            continue
        out += [os.path.join(d, f) for f in files]
    return out


def tmp_files(receiver):
    d = os.path.join(receiver.app.state.media.site_dir, ".tmp")
    return os.listdir(d) if os.path.isdir(d) else []


async def setup(receiver):
    h = await receiver.token()
    return h, await receiver.register(h)


async def test_valid_upload_is_durable_before_ack(receiver):
    h, rid = await setup(receiver)
    data, sha = make_chunk(1)
    cid = str(uuid.uuid4())
    r = await receiver.put_chunk(h, rid, cid, 1, data)
    assert r.status_code == 200
    ack = r.json()
    assert ack["status"] == "locally_durable" and ack["ack"] == "local_received" and ack["central_acknowledged"] is False
    assert ack["sha256"] == sha and ack["duplicate"] is False and ack["sync_state"] == "pending_sync"
    row = rows(receiver)[0]
    assert row["chunk_id"] == cid and row["sha256"] == sha and row["size_bytes"] == len(data)
    # the acknowledged bytes really are on disk, byte-identical, at the documented layout
    path = row["storage_path"]
    assert path.endswith(os.path.join(rid, f"{cid}.mp4"))
    assert hashlib.sha256(open(path, "rb").read()).hexdigest() == sha
    assert tmp_files(receiver) == []


async def test_wrong_hash_rejected_and_nothing_stored(receiver):
    h, rid = await setup(receiver)
    data, _ = make_chunk(1)
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data, sha="0" * 64)
    assert r.status_code == 422 and r.json()["error"]["code"] == "hash_mismatch"
    assert rows(receiver) == [] and media_files(receiver) == [] and tmp_files(receiver) == []


async def test_declared_size_mismatch_and_malformed_sha(receiver):
    h, rid = await setup(receiver)
    data, sha = make_chunk(1)
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data, size=False, size_bytes=len(data) + 5)
    assert r.status_code == 422 and r.json()["error"]["code"] == "size_mismatch"
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data, sha="zz" * 32)
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_sha256"
    assert rows(receiver) == [] and media_files(receiver) == []


async def test_non_mp4_rejected(receiver):
    h, rid = await setup(receiver)
    data = b"this is definitely not an mp4 file" * 10
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 400 and r.json()["error"]["code"] == "unsupported_type"
    assert rows(receiver) == []


async def test_oversize_declared_and_actual(receiver):
    h, rid = await setup(receiver)  # max chunk is 2 MiB in the test configuration
    big, sha = make_chunk(1, size=3 * 1024 * 1024)
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, big)  # declared size_bytes exceeds the limit
    assert r.status_code == 413
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, big, size=False)  # no declared size: streamed cap
    assert r.status_code == 413
    assert rows(receiver) == [] and media_files(receiver) == [] and tmp_files(receiver) == []


async def test_body_limit_middleware_refuses_before_parsing(receiver):
    h, rid = await setup(receiver)
    # a lying Content-Length far beyond the limit is refused without reading the body
    r = await receiver.client.put(f"/v1/recordings/{rid}/chunks/{uuid.uuid4()}", headers={**h, "Content-Length": str(500 * 1024 * 1024), "Content-Type": "multipart/form-data; boundary=x"}, content=b"--x--")
    assert r.status_code == 413


async def test_body_limit_counts_undeclared_streams(receiver):
    h, rid = await setup(receiver)

    async def body():
        # a well-formed multipart start, then far more data than the limit, with no Content-Length (chunked transfer)
        yield b"--x" + CRLF + b'Content-Disposition: form-data; name="file"; filename="f.mp4"' + CRLF + b"Content-Type: video/mp4" + CRLF + CRLF
        for _ in range(8):
            yield b"a" * (1024 * 1024)

    r = await receiver.client.put(f"/v1/recordings/{rid}/chunks/{uuid.uuid4()}", headers={**h, "Content-Type": "multipart/form-data; boundary=x"}, content=body())
    assert r.status_code == 413


async def test_duplicate_identical_is_idempotent(receiver):
    h, rid = await setup(receiver)
    data, _ = make_chunk(1)
    cid = str(uuid.uuid4())
    first = await receiver.put_chunk(h, rid, cid, 1, data)
    second = await receiver.put_chunk(h, rid, cid, 1, data)
    assert first.status_code == second.status_code == 200 and second.json()["duplicate"] is True
    assert len(rows(receiver)) == 1 and len(media_files(receiver)) == 1


async def test_same_id_different_content_is_conflict_and_original_untouched(receiver):
    h, rid = await setup(receiver)
    data, sha = make_chunk(1)
    other, _ = make_chunk(2, seed=b"other")
    cid = str(uuid.uuid4())
    assert (await receiver.put_chunk(h, rid, cid, 1, data)).status_code == 200
    r = await receiver.put_chunk(h, rid, cid, 1, other)
    assert r.status_code == 409 and r.json()["error"]["code"] == "hash_conflict"
    path = rows(receiver)[0]["storage_path"]
    assert hashlib.sha256(open(path, "rb").read()).hexdigest() == sha, "existing evidence must never be overwritten"


async def test_same_number_different_chunk_id_is_conflict(receiver):
    h, rid = await setup(receiver)
    data, _ = make_chunk(1)
    other, _ = make_chunk(2, seed=b"other")
    assert (await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)).status_code == 200
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, other)
    assert r.status_code == 409
    same_bytes = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)
    assert same_bytes.status_code == 409 and same_bytes.json()["error"]["code"] == "identity_conflict"
    assert len(rows(receiver)) == 1


async def test_concurrent_identical_uploads_store_once(receiver):
    h, rid = await setup(receiver)
    data, _ = make_chunk(1)
    cid = str(uuid.uuid4())
    results = await asyncio.gather(*[receiver.put_chunk(h, rid, cid, 1, data) for _ in range(6)])
    assert [r.status_code for r in results] == [200] * 6
    assert sum(1 for r in results if r.json()["duplicate"] is False) == 1
    assert len(rows(receiver)) == 1 and len(media_files(receiver)) == 1 and tmp_files(receiver) == []


async def test_concurrent_conflicting_numbers_exactly_one_wins(receiver):
    h, rid = await setup(receiver)
    payloads = [make_chunk(1, seed=bytes([i])) for i in range(5)]
    results = await asyncio.gather(*[receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, d) for d, _ in payloads])
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) == 1 and codes.count(409) == 4, codes
    winner = rows(receiver)[0]
    assert len(rows(receiver)) == 1 and len(media_files(receiver)) == 1
    assert hashlib.sha256(open(winner["storage_path"], "rb").read()).hexdigest() == winner["sha256"]


async def test_concurrent_different_chunks_all_stored(receiver):
    h, rid = await setup(receiver)
    items = [(str(uuid.uuid4()), n, *make_chunk(n)) for n in range(1, 9)]
    results = await asyncio.gather(*[receiver.put_chunk(h, rid, cid, n, d) for cid, n, d, _ in items])
    assert all(r.status_code == 200 for r in results)
    assert len(rows(receiver)) == 8 and len(media_files(receiver)) == 8
    for row in rows(receiver):
        assert hashlib.sha256(open(row["storage_path"], "rb").read()).hexdigest() == row["sha256"]


async def test_other_devices_recording_is_not_found(receiver):
    h, rid = await setup(receiver)
    other = await receiver.token(dev=str(uuid.uuid4()), devid="other-phone")
    data, _ = make_chunk(1)
    r = await receiver.put_chunk(other, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 404 and r.json()["error"]["code"] == "recording_not_found"
    assert (await receiver.client.get(f"/v1/recordings/{rid}", headers=other)).status_code == 404


async def test_recording_id_conflict_for_other_device(receiver):
    h, rid = await setup(receiver)
    other = await receiver.token(dev=str(uuid.uuid4()), devid="other-phone")
    r = await receiver.client.post("/v1/recordings", headers=other, json={"recording_id": rid, "started_at": "2026-01-01T00:00:00Z"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "recording_id_conflict"


async def test_register_is_idempotent(receiver):
    h = await receiver.token()
    rid = str(uuid.uuid4())
    a = await receiver.client.post("/v1/recordings", headers=h, json={"recording_id": rid, "started_at": "2026-01-01T00:00:00Z"})
    b = await receiver.client.post("/v1/recordings", headers=h, json={"recording_id": rid, "started_at": "2026-01-01T00:00:00Z"})
    assert a.json()["created"] is True and b.json()["created"] is False
    assert len(rows(receiver, "SELECT * FROM recordings")) == 1


# ---------------- failure injection ----------------

async def test_disk_full_while_writing_returns_507_and_leaves_nothing(receiver, monkeypatch):
    from site_receiver import storage

    h, rid = await setup(receiver)
    orig = storage.StagedUpload.write

    def boom(self, data):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(storage.StagedUpload, "write", boom)
    data, _ = make_chunk(1)
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 507 and r.headers.get("retry-after") and r.json()["error"]["code"] == "storage_full"
    assert rows(receiver) == [] and media_files(receiver) == [] and tmp_files(receiver) == []
    monkeypatch.setattr(storage.StagedUpload, "write", orig)
    assert (await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)).status_code == 200, "the sender can simply retry"


async def test_admission_control_below_free_space_threshold(env, tmp_path):
    from site_receiver import main as m
    import httpx

    env(RECEIVER_MIN_FREE_MB="999999999")  # more free space than any disk has
    app = m.create_app()
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("10.0.0.5", 1)), base_url="http://r")
        from .conftest import make_grant

        tok = (await c.post("/v1/auth/session", json={"grant": make_grant()})).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        rid = str(uuid.uuid4())
        await c.post("/v1/recordings", headers=h, json={"recording_id": rid, "started_at": "2026-01-01T00:00:00Z"})
        data, sha = make_chunk(1)
        r = await c.put(f"/v1/recordings/{rid}/chunks/{uuid.uuid4()}", headers=h, data={"chunk_number": "1", "sha256": sha}, files={"file": ("c.mp4", data, "video/mp4")})
        health = await c.get("/v1/health")
        await c.aclose()
    assert r.status_code == 507 and r.headers.get("retry-after") == "120"
    assert health.json()["ready"] is False


async def test_permission_error_returns_503_not_200(receiver, monkeypatch):
    from site_receiver import storage

    h, rid = await setup(receiver)

    def deny(self, data):
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(storage.StagedUpload, "write", deny)
    data, _ = make_chunk(1)
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 503 and r.headers.get("retry-after") and rows(receiver) == [] and tmp_files(receiver) == []


async def test_fsync_failure_is_not_acknowledged(receiver, monkeypatch):
    from site_receiver import storage

    h, rid = await setup(receiver)

    def bad_fsync(fd):
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(storage.os, "fsync", bad_fsync)
    data, _ = make_chunk(1)
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 503, r.text
    assert rows(receiver) == [] and media_files(receiver) == [] and tmp_files(receiver) == []


async def test_rename_failure_is_not_acknowledged(receiver, monkeypatch):
    from site_receiver import storage

    h, rid = await setup(receiver)

    def bad_replace(src, dst):
        raise OSError(errno.EXDEV, "cross-device link")

    monkeypatch.setattr(storage.os, "replace", bad_replace)
    data, _ = make_chunk(1)
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 503 and rows(receiver) == [] and media_files(receiver) == [] and tmp_files(receiver) == []


async def test_sqlite_failure_after_rename_removes_unacknowledged_file(receiver, monkeypatch):
    h, rid = await setup(receiver)
    store = receiver.app.state.store
    real = store.execute

    def failing(sql, params=()):
        if sql.lstrip().upper().startswith("INSERT INTO CHUNKS"):
            raise sqlite3.OperationalError("database is locked")
        return real(sql, params)

    monkeypatch.setattr(store, "execute", failing)
    data, _ = make_chunk(1)
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 503 and r.headers.get("retry-after")
    monkeypatch.setattr(store, "execute", real)
    assert rows(receiver) == [] and media_files(receiver) == [], "a file that was never acknowledged must not be left behind as if it were stored"
    assert (await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)).status_code == 200


async def test_io_error_mid_stream_leaves_no_partial_file(receiver, monkeypatch):
    from site_receiver import storage

    h, rid = await setup(receiver)
    orig = storage.StagedUpload.write
    calls = {"n": 0}

    def flaky(self, data):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise OSError(errno.EIO, "I/O error")
        return orig(self, data)

    monkeypatch.setattr(storage.StagedUpload, "write", flaky)
    data, _ = make_chunk(1, size=3 * 1024 * 1024 // 2)  # more than one 1 MiB read
    r = await receiver.put_chunk(h, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 503 and rows(receiver) == [] and tmp_files(receiver) == [] and media_files(receiver) == []


async def test_path_traversal_ids_are_rejected(receiver):
    h, rid = await setup(receiver)
    data, sha = make_chunk(1)
    r = await receiver.client.put(f"/v1/recordings/{rid}/chunks/..%2F..%2Fevil", headers=h, data={"chunk_number": "1", "sha256": sha}, files={"file": ("c.mp4", data, "video/mp4")})
    assert r.status_code in (404, 422)
    r = await receiver.client.put(f"/v1/recordings/{rid}/chunks/{uuid.uuid4()}", headers=h, data={"chunk_number": "1", "sha256": sha}, files={"file": ("../../evil.mp4", data, "video/mp4")})
    assert r.status_code == 200
    root = os.path.abspath(receiver.app.state.media.root)
    assert all(os.path.abspath(p).startswith(root) for p in media_files(receiver)), "client file names never choose the path"
    assert not any(n.endswith("evil.mp4") for n in os.listdir(os.path.dirname(root)) if os.path.isfile(os.path.join(os.path.dirname(root), n)))


async def test_complete_reports_missing_chunks_and_is_idempotent(receiver):
    h, rid = await setup(receiver)
    for n in (1, 3):
        d, _ = make_chunk(n)
        assert (await receiver.put_chunk(h, rid, str(uuid.uuid4()), n, d)).status_code == 200
    body = {"chunk_count": 2}
    a = await receiver.client.post(f"/v1/recordings/{rid}/complete", headers=h, json=body)
    b = await receiver.client.post(f"/v1/recordings/{rid}/complete", headers=h, json=body)
    assert a.status_code == b.status_code == 200
    assert a.json()["missing_chunk_numbers"] == [2] and a.json()["central_received"] is False
    short = await receiver.client.post(f"/v1/recordings/{rid}/complete", headers=h, json={"chunk_count": 9})
    assert short.status_code == 409 and short.json()["error"]["code"] == "chunks_outstanding"
