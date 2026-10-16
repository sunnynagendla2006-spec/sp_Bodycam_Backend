"""
Control-room side of the bodycam offline transport: offline grants, receiver ingestion, evidence preservation, concurrency,
site isolation, recording-start idempotency and the health/body-limit contracts.

Needs the disposable MongoDB replica set the rest of the suite uses (TEST_MONGODB_URL). Uses throw-away keys and credentials.
"""
import asyncio
import datetime
import hashlib
import os
import tempfile
import uuid

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt

from app import models
from app.models import UserRole
from app.services import receiver_auth, site_grants
from tests.conftest import _asgi_client
from httpx_ws.transport import ASGIWebSocketTransport

KEY = ec.generate_private_key(ec.SECP256R1())
PRIV_PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
MP4 = lambda n=1, seed=b"s": b"\x00\x00\x00\x18ftypmp42" + hashlib.sha256(seed + str(n).encode()).digest() * 40  # noqa: E731
sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731


def now():
    return datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture(autouse=True)
def _grant_env(monkeypatch):
    monkeypatch.setenv("GRANT_SIGNING_PRIVATE_KEY_PEM", PRIV_PEM)
    monkeypatch.setenv("GRANT_SIGNING_KEY_ID", "test-key-1")
    monkeypatch.delenv("GRANT_LIFETIME_HOURS", raising=False)
    monkeypatch.delenv("PRESERVE_ORIGINAL_EVIDENCE", raising=False)
    monkeypatch.delenv("ALLOW_HTTP_RECEIVER_ENDPOINTS", raising=False)


@pytest_asyncio.fixture()
async def bc(mongo_db):
    from fastapi import FastAPI

    from app.routers import auth, constables, devices, media, mobile_nh, receiver_ingest, recordings, site_bodycam, sites

    media.UPLOAD_DIR = tempfile.mkdtemp(prefix="sp_bc_uploads_")
    app = FastAPI()
    for r in (auth.router, constables.router, devices.router, recordings.router, sites.router, site_bodycam.router, mobile_nh.router, receiver_ingest.router):
        app.include_router(r)
    async with _asgi_client(ASGIWebSocketTransport(app=app)) as c:
        c.upload_dir = media.UPLOAD_DIR
        yield c


def stored_files(c):
    out = []
    for d, _x, fs in os.walk(c.upload_dir):
        out += [os.path.join(d, f) for f in fs]
    return out


class World:
    """site + admin + officer + registered device + assignment + device authorization + receiver (with credential)."""

    def __init__(self):
        self.h = {}

    async def build(self, c, make_user, make_constable, *, phone="7770001111", authorize=True, assign=True, site_code="SITE-A", restricted=False):
        self.admin = await make_user(phone="7770009999", role=UserRole.admin)
        self.site = models.MonitoredSite(code=site_code, name="Site " + site_code, access_mode="restricted" if restricted else "all_control_room")
        await self.site.insert()
        self.user, self.constable = await make_constable(phone=phone)
        self.h_admin = await self.login(c, "7770009999")
        self.h_off = await self.login(c, phone)
        r = await c.post("/devices/register", json={"device_identifier": "phone-" + phone, "platform": "android"}, headers=self.h_off)
        assert r.status_code == 200, r.text
        self.device_id = uuid.UUID(r.json()["id"])
        self.device = await models.Device.get(self.device_id)
        self.device.enrolment_status = models.EnrolmentStatus.approved
        await self.device.save()
        if assign:
            self.assignment = models.SiteAssignment(site_id=self.site.id, constable_id=self.constable.id)
            await self.assignment.insert()
        if authorize:
            self.auth = models.DeviceSiteAuthorization(site_id=self.site.id, device_id=self.device_id, constable_id=self.constable.id)
            await self.auth.insert()
        self.receiver = models.SiteReceiver(site_id=self.site.id, code="R1", name="Receiver 1", endpoint_url="https://r.site.test:8443")
        token = receiver_auth.apply_new_token(self.receiver, keep_previous=False)
        await self.receiver.insert()
        self.h_rcv = {"Authorization": f"Bearer {token}"}
        return self

    async def login(self, c, phone):
        r = await c.post("/auth/login", json={"username": phone, "password": "correct-horse-battery"})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    async def config(self, c):
        r = await c.get("/mobile/v1/network-hopping/config", params={"device_identifier": self.device.device_identifier}, headers=self.h_off)
        assert r.status_code == 200, r.text
        return r.json()

    async def grant(self, c):
        cfg = await self.config(c)
        return cfg, cfg["sites"][0]

    def reg_body(self, grant_id, **over):
        b = {"site_id": str(self.site.id), "constable_id": str(self.constable.id), "device_id": str(self.device_id), "grant_id": str(grant_id), "trigger_type": "manual",
             "camera_lens_direction": "back", "started_at": now().isoformat(), "status": "recording"}
        b.update(over)
        return b

    async def register(self, c, grant_id=None, rid=None, **over):
        if grant_id is None:
            _, site = await self.grant(c)
            grant_id = site["grant_id"]
        rid = rid or str(uuid.uuid4())
        r = await c.put(f"/receiver/v1/recordings/{rid}", json=self.reg_body(grant_id, **over), headers=self.h_rcv)
        return rid, r

    async def put_chunk(self, c, rid, cid, n, data, headers=None, sha256=None, **form):
        fields = {"chunk_number": str(n), "sha256": sha256 or sha(data), "is_last_chunk": "false", **{k: str(v) for k, v in form.items()}}
        return await c.put(f"/receiver/v1/recordings/{rid}/chunks/{cid}", data=fields, files={"file": ("c.mp4", data, "video/mp4")}, headers=headers or self.h_rcv)


@pytest_asyncio.fixture()
async def world(bc, make_user, make_constable):
    return await World().build(bc, make_user, make_constable)


# ================================================================ grants ==============================================================

async def test_grant_claims_signature_kid_and_lifetime(bc, world):
    cfg, s = await world.grant(bc)
    assert s["eligible"] is True and s["grant"] and s["reason"] is None
    header = jwt.get_unverified_header(s["grant"])
    assert header["alg"] == "ES256" and header["kid"] == "test-key-1"
    pub = cfg["grant_public_keys"][0]["pem"]
    claims = jwt.decode(s["grant"], pub, algorithms=["ES256"], issuer=cfg["grant_issuer"])
    for k in ("iss", "sub", "jti", "site", "site_code", "org", "dev", "devid", "asg", "zone", "ops", "iat", "exp", "ver"):
        assert k in claims, k
    assert claims["site"] == str(world.site.id) and claims["sub"] == str(world.constable.id) and claims["dev"] == str(world.device_id)
    assert claims["devid"] == world.device.device_identifier and claims["asg"] == str(world.assignment.id) and set(claims["ops"]) >= {"session", "upload"}
    assert claims["exp"] - claims["iat"] == 8 * 3600
    assert cfg["constable_id"] == str(world.constable.id) and cfg["grant_public_keys"][0]["kid"] == "test-key-1"


async def test_response_never_contains_private_key_material(bc, world):
    cfg = await world.config(bc)
    assert "PRIVATE" not in str(cfg) and PRIV_PEM.strip().splitlines()[1] not in str(cfg)
    assert "BEGIN PUBLIC KEY" in cfg["grant_public_keys"][0]["pem"]


async def test_public_key_cannot_mint_a_grant(bc, world):
    cfg, s = await world.grant(bc)
    pub = cfg["grant_public_keys"][0]["pem"]
    claims = jwt.get_unverified_claims(s["grant"])
    with pytest.raises(Exception):
        jwt.encode(claims, pub, algorithm="ES256")  # not a private key: cannot sign
    other = ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    forged = jwt.encode(claims, other, algorithm="ES256")
    with pytest.raises(Exception):
        jwt.decode(forged, pub, algorithms=["ES256"], issuer=cfg["grant_issuer"])


@pytest.mark.parametrize("value,expected", [("1", 1), ("168", 168), ("0", 1), ("500", 168), ("-3", 1), ("abc", 8), ("", 8)])
def test_lifetime_boundaries(monkeypatch, value, expected):
    monkeypatch.setenv("GRANT_LIFETIME_HOURS", value)
    assert site_grants.lifetime_hours() == expected


async def test_refresh_reuses_the_grant_record_instead_of_creating_new_ones(bc, world):
    _, a = await world.grant(bc)
    _, b = await world.grant(bc)
    assert a["grant_id"] == b["grant_id"]
    assert jwt.get_unverified_claims(a["grant"])["exp"] == jwt.get_unverified_claims(b["grant"])["exp"], "same grant, same expiry"
    assert jwt.get_unverified_claims(a["grant"])["iat"] == jwt.get_unverified_claims(b["grant"])["iat"]
    assert a["grant_expires_at"].endswith("Z") and b["grant_expires_at"].endswith("Z"), "the phone parses this string: it must carry its UTC marker"
    assert await models.OfflineGrant.find({"site_id": world.site.id}).count() == 1
    issued = [l for l in await models.AuditLog.find_all().to_list() if l.action == "bodycam.grant_issued"]
    assert len(issued) == 1, "re-signing an existing grant is not a new issuance"


async def test_eligibility_requirements_each_block_a_grant(bc, make_user, make_constable):
    w = await World().build(bc, make_user, make_constable, phone="7770002222", authorize=False)
    _, s = await w.grant(bc)
    assert s["eligible"] is False and s["grant"] is None and s["reason"] == "device_not_authorized"
    w.auth = models.DeviceSiteAuthorization(site_id=w.site.id, device_id=w.device_id, constable_id=w.constable.id)
    await w.auth.insert()
    assert (await w.grant(bc))[1]["eligible"] is True
    w.assignment.status = "revoked"
    await w.assignment.save()
    cfg = await w.config(bc)
    assert cfg["sites"] == [], "an officer without an active assignment is not told about the site at all"


async def test_signing_not_configured_gives_no_grant(bc, world, monkeypatch):
    monkeypatch.delenv("GRANT_SIGNING_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.delenv("GRANT_SIGNING_PRIVATE_KEY_FILE", raising=False)
    cfg, s = await world.grant(bc)
    assert s["eligible"] is False and s["grant"] is None and s["reason"] == "signing_not_configured"
    assert cfg["grant_public_keys"] == []


async def test_expired_device_authorization_blocks_grant(bc, world):
    world.auth.valid_until = now() - datetime.timedelta(minutes=1)
    await world.auth.save()
    assert (await world.grant(bc))[1]["reason"] == "device_authorization_expired"


async def test_grant_never_outlives_its_assignment(bc, world):
    world.assignment.valid_until = now() + datetime.timedelta(hours=2)
    await world.assignment.save()
    _, s = await world.grant(bc)
    claims = jwt.get_unverified_claims(s["grant"])
    assert claims["exp"] - claims["iat"] <= 2 * 3600 + 5


async def test_revocation_paths_propagate_to_receiver_sync(bc, world):
    _, s = await world.grant(bc)
    gid = s["grant_id"]
    assert (await bc.get("/receiver/v1/sync", headers=world.h_rcv)).json()["revoked_grant_ids"] == []
    r = await bc.post(f"/sites/{world.site.id}/bodycam/grants/{gid}/revoke", json={"reason": "lost phone"}, headers=world.h_admin)
    assert r.status_code == 200 and r.json()["state"] == "revoked"
    assert (await bc.get("/receiver/v1/sync", headers=world.h_rcv)).json()["revoked_grant_ids"] == [gid]
    _, s2 = await world.grant(bc)
    assert s2["grant_id"] != gid, "a revoked grant is never re-signed"
    # revoking the device authorization / assignment revokes the newest grant too
    r = await bc.post(f"/sites/{world.site.id}/bodycam/device-authorizations/{world.auth.id}/revoke", json={"reason": "x"}, headers=world.h_admin)
    assert r.status_code == 200
    assert s2["grant_id"] in (await bc.get("/receiver/v1/sync", headers=world.h_rcv)).json()["revoked_grant_ids"]
    assert (await world.grant(bc))[1]["reason"] == "device_not_authorized"


async def test_assignment_revocation_revokes_grants(bc, world):
    _, s = await world.grant(bc)
    r = await bc.post(f"/sites/{world.site.id}/bodycam/assignments/{world.assignment.id}/revoke", json={"reason": "reassigned"}, headers=world.h_admin)
    assert r.status_code == 200
    assert s["grant_id"] in (await bc.get("/receiver/v1/sync", headers=world.h_rcv)).json()["revoked_grant_ids"]


async def test_only_admin_manages_grants(bc, world):
    r = await bc.post(f"/sites/{world.site.id}/bodycam/grants", json={"device_id": str(world.device_id)}, headers=world.h_off)
    assert r.status_code in (401, 403)
    r = await bc.get(f"/sites/{world.site.id}/bodycam/grants", headers=world.h_off)
    assert r.status_code in (401, 403)


async def test_purge_of_expired_records_is_dry_run_by_default_and_spares_valid_grants(bc, world, monkeypatch):
    monkeypatch.setenv("GRANT_RECORD_RETENTION_DAYS", "30")
    _, s = await world.grant(bc)
    old = models.OfflineGrant(site_id=world.site.id, constable_id=world.constable.id, device_id=world.device_id, expires_at=now() - datetime.timedelta(days=45), operations=["upload"])
    recent = models.OfflineGrant(site_id=world.site.id, constable_id=world.constable.id, device_id=world.device_id, expires_at=now() - datetime.timedelta(days=5), operations=["upload"])
    await old.insert()
    await recent.insert()
    assert await site_grants.purge_expired_records(dry_run=True) == 1
    assert await models.OfflineGrant.find({}).count() == 3, "dry run deletes nothing"
    assert await site_grants.purge_expired_records(dry_run=False) == 1
    left = {g.id for g in await models.OfflineGrant.find({}).to_list()}
    assert left == {recent.id, uuid.UUID(s["grant_id"])}


# ================================================== provisioning receivers ============================================================

async def test_unconfigured_receiver_is_listed_as_unconfigured_not_dropped_or_fatal(bc, world):
    await models.SiteReceiver(site_id=world.site.id, code="R0", name="No address").insert()
    s = (await world.config(bc))["sites"][0]
    by = {r["code"]: r for r in s["receivers"]}
    assert by["R0"]["configured"] is False and by["R0"]["endpoint_url"] is None
    assert by["R1"]["configured"] is True and by["R1"]["endpoint_url"].startswith("https://")


async def test_receiver_endpoint_must_be_https_unless_dev_flag(bc, world, monkeypatch):
    body = {"code": "R9", "name": "Plain", "endpoint_url": "http://10.0.0.5:8443"}
    r = await bc.post(f"/sites/{world.site.id}/bodycam/receivers", json=body, headers=world.h_admin)
    assert r.status_code == 422
    monkeypatch.setenv("ALLOW_HTTP_RECEIVER_ENDPOINTS", "true")
    r = await bc.post(f"/sites/{world.site.id}/bodycam/receivers", json=body, headers=world.h_admin)
    assert r.status_code == 201
    for bad in ("https://u:p@x.test", "https://x.test/path", "ftp://x.test", "https://x.test?q=1"):
        r = await bc.post(f"/sites/{world.site.id}/bodycam/receivers", json={"code": "RX" + str(abs(hash(bad)) % 999), "name": "n", "endpoint_url": bad}, headers=world.h_admin)
        assert r.status_code == 422, bad


# ================================================== receiver credentials ==============================================================

async def test_receiver_credential_lifecycle(bc, world):
    assert (await bc.get("/receiver/v1/sync", headers=world.h_rcv)).status_code == 200
    assert (await bc.get("/receiver/v1/sync")).status_code == 401
    assert (await bc.get("/receiver/v1/sync", headers={"Authorization": f"Bearer {world.receiver.id.hex}.wrong"})).status_code == 401
    old = world.h_rcv
    r = await bc.post(f"/sites/{world.site.id}/bodycam/receivers/{world.receiver.id}/rotate-token", headers=world.h_admin)
    new = {"Authorization": f"Bearer {r.json()['token']}"}
    assert (await bc.get("/receiver/v1/sync", headers=new)).status_code == 200
    assert (await bc.get("/receiver/v1/sync", headers=old)).status_code == 200, "old token works for the rotation grace period"
    await bc.post(f"/sites/{world.site.id}/bodycam/receivers/{world.receiver.id}/revoke", headers=world.h_admin)
    for h in (old, new):
        assert (await bc.get("/receiver/v1/sync", headers=h)).status_code == 401, "a revoked credential works nowhere"
        assert (await bc.post("/receiver/v1/heartbeat", json={}, headers=h)).status_code == 401


# ================================================== receiver ingestion ================================================================

async def test_registration_requires_a_matching_grant(bc, world):
    _, s = await world.grant(bc)
    rid, r = await world.register(bc, grant_id=None)
    assert r.status_code == 200 and r.json()["created"] is True
    rid2 = str(uuid.uuid4())
    body = world.reg_body(s["grant_id"])
    body.pop("grant_id")
    r = await bc.put(f"/receiver/v1/recordings/{rid2}", json=body, headers=world.h_rcv)
    assert r.status_code == 403 and r.headers["x-conflict-reason"] == "grant_required"
    r = await bc.put(f"/receiver/v1/recordings/{rid2}", json=world.reg_body(str(uuid.uuid4())), headers=world.h_rcv)
    assert r.status_code == 403 and r.headers["x-conflict-reason"] == "grant_mismatch"
    r = await bc.put(f"/receiver/v1/recordings/{rid2}", json=world.reg_body(s["grant_id"], started_at=(now() + datetime.timedelta(days=2)).isoformat()), headers=world.h_rcv)
    assert r.status_code == 403 and r.headers["x-conflict-reason"] == "grant_window"


async def test_grant_revoked_before_vs_after_capture(bc, world):
    _, s = await world.grant(bc)
    gid = uuid.UUID(s["grant_id"])
    grant = await models.OfflineGrant.get(gid)
    started = now() - datetime.timedelta(minutes=2)
    grant.revoked, grant.revoked_at = True, now() - datetime.timedelta(minutes=1)
    await grant.save()
    rid, r = await world.register(bc, grant_id=gid, started_at=started.isoformat())
    assert r.status_code == 200 and "grant_revoked_later" in r.json()["flags"], "captured while valid, revoked afterwards: accepted and flagged"
    grant.revoked_at = now() - datetime.timedelta(minutes=5)  # revoked BEFORE the recording started
    await grant.save()
    rid2, r2 = await world.register(bc, grant_id=gid, started_at=started.isoformat())
    assert r2.status_code == 403 and r2.headers["x-conflict-reason"] == "grant_revoked"


async def test_registration_is_idempotent_and_owner_bound(bc, world, make_constable):
    rid, r = await world.register(bc)
    again = await bc.put(f"/receiver/v1/recordings/{rid}", json=world.reg_body(uuid.uuid4()), headers=world.h_rcv)
    assert again.status_code == 200 and again.json()["created"] is False
    other_user, other = await make_constable(phone="7770003333")
    body = world.reg_body(uuid.uuid4(), constable_id=str(other.id))
    r = await bc.put(f"/receiver/v1/recordings/{rid}", json=body, headers=world.h_rcv)
    assert r.status_code in (409, 422)


async def test_valid_chunk_preserves_original_and_records_provenance(bc, world, monkeypatch):
    rid, _ = await world.register(bc)
    data = MP4(1)
    cid = str(uuid.uuid4())
    r = await world.put_chunk(bc, rid, cid, 1, data)
    assert r.status_code == 200 and r.json()["original_hash"] == sha(data) and r.json()["duplicate"] is False
    session = await models.RecordingSession.get(uuid.UUID(rid))
    c = session.chunks[0]
    assert str(c.id) == cid and c.original_hash == sha(data) and c.original_size == len(data) and c.received_via == "site_receiver"
    from app.routers import media

    storage = media._get_storage_backend()
    assert c.original_storage_key and c.original_storage_key != c.storage_key
    stored_original = b"".join(storage.read_range(c.original_storage_key, 0, len(data) - 1))
    assert stored_original == data, "the preserved original is byte-identical to what the phone sent"
    assert any(p["step"] == "received_via_site_receiver" for p in c.processing)


async def test_watermark_is_a_separate_derivative_with_its_own_hash(bc, world, monkeypatch):
    from app.routers import media, receiver_ingest

    async def fake_burn(*, storage, storage_key, **kw):
        derived = b"DERIVED-WATERMARKED-" + b"x" * 64
        with storage.open_write(storage_key) as fh:
            fh.write(derived)
        return len(derived), sha(derived)

    monkeypatch.setattr(receiver_ingest, "_burn_watermark_best_effort", fake_burn)
    rid, _ = await world.register(bc)
    data = MP4(2)
    assert (await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, data)).status_code == 200
    c = (await models.RecordingSession.get(uuid.UUID(rid))).chunks[0]
    storage = media._get_storage_backend()
    assert c.original_hash == sha(data) and c.derived_hash and c.derived_hash != c.original_hash and c.file_hash == c.derived_hash
    assert b"".join(storage.read_range(c.original_storage_key, 0, len(data) - 1)) == data, "watermarking never touches the original"
    step = [p for p in c.processing if p["step"] == "watermark"][0]
    assert step["input_hash"] == c.original_hash and step["output_hash"] == c.derived_hash


@pytest.mark.parametrize("mode", ["flag_off", "preservation_fails"])
async def test_without_a_preserved_original_nothing_is_watermarked(bc, world, monkeypatch, mode):
    from app.routers import media, receiver_ingest
    from app.services import evidence

    if mode == "flag_off":
        monkeypatch.setenv("PRESERVE_ORIGINAL_EVIDENCE", "false")
    else:
        monkeypatch.setattr(evidence, "preserve_original", lambda *a, **k: False)

    async def must_not_run(**kw):
        raise AssertionError("the watermark would overwrite the only copy of the evidence")

    monkeypatch.setattr(receiver_ingest, "_burn_watermark_best_effort", must_not_run)
    rid, _ = await world.register(bc)
    data = MP4(3)
    assert (await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, data)).status_code == 200
    c = (await models.RecordingSession.get(uuid.UUID(rid))).chunks[0]
    storage = media._get_storage_backend()
    assert c.original_storage_key is None and c.derived_hash is None
    assert b"".join(storage.read_range(c.storage_key, 0, len(data) - 1)) == data and c.file_hash == sha(data)
    assert any(p["step"] == "watermark_skipped" for p in c.processing)


async def test_hash_mismatch_leaves_no_object_and_no_chunk(bc, world):
    rid, _ = await world.register(bc)
    r = await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, MP4(1), sha256="0" * 64)
    assert r.status_code == 422 and r.headers["x-conflict-reason"] == "hash_mismatch"
    assert stored_files(bc) == [] and (await models.RecordingSession.get(uuid.UUID(rid))).chunks == []


async def test_bad_inputs_are_rejected(bc, world):
    rid, _ = await world.register(bc)
    assert (await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, b"not a video at all" * 10)).status_code == 400
    r = await bc.put(f"/receiver/v1/recordings/{rid}/chunks/{uuid.uuid4()}", data={"chunk_number": "1", "sha256": "zz"}, files={"file": ("c.mp4", MP4(1), "video/mp4")}, headers=world.h_rcv)
    assert r.status_code == 422
    r = await bc.put(f"/receiver/v1/recordings/{rid}/chunks/{uuid.uuid4()}", data={"sha256": sha(MP4(1))}, files={"file": ("c.mp4", MP4(1), "video/mp4")}, headers=world.h_rcv)
    assert r.status_code == 422, "chunk_number is required"
    r = await bc.put(f"/receiver/v1/recordings/{rid}/chunks/{uuid.uuid4()}", data={"chunk_number": "0", "sha256": sha(MP4(1))}, files={"file": ("c.mp4", MP4(1), "video/mp4")}, headers=world.h_rcv)
    assert r.status_code == 422
    assert stored_files(bc) == []


async def test_duplicates_and_conflicts(bc, world):
    rid, _ = await world.register(bc)
    data, other = MP4(1), MP4(1, seed=b"other")
    cid = str(uuid.uuid4())
    assert (await world.put_chunk(bc, rid, cid, 1, data)).json()["duplicate"] is False
    dup = await world.put_chunk(bc, rid, cid, 1, data)
    assert dup.status_code == 200 and dup.json()["duplicate"] is True
    for chunk_id in (cid, str(uuid.uuid4())):
        r = await world.put_chunk(bc, rid, chunk_id, 1, other)
        assert r.status_code == 409 and r.headers["x-conflict-reason"] == "hash_conflict"
    r = await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, data)
    assert r.status_code == 409, "same bytes under a different chunk id is an identity conflict, not a duplicate"
    session = await models.RecordingSession.get(uuid.UUID(rid))
    assert len(session.chunks) == 1 and session.chunks[0].original_hash == sha(data)


async def test_concurrent_identical_uploads_store_exactly_one_chunk_and_leave_no_orphans(bc, world):
    rid, _ = await world.register(bc)
    data, cid = MP4(1), str(uuid.uuid4())
    results = await asyncio.gather(*[world.put_chunk(bc, rid, cid, 1, data) for _ in range(6)])
    assert all(r.status_code == 200 for r in results), [r.status_code for r in results]
    session = await models.RecordingSession.get(uuid.UUID(rid))
    assert len(session.chunks) == 1
    c = session.chunks[0]
    from app.routers import media

    storage = media._get_storage_backend()
    assert b"".join(storage.read_range(c.original_storage_key, 0, len(data) - 1)) == data
    assert len(stored_files(bc)) == 2, f"only the winner's two objects remain (stored + original): {stored_files(bc)}"


async def test_losing_racers_never_delete_the_winners_objects(bc, world):
    rid, _ = await world.register(bc)
    payloads = [MP4(1, seed=bytes([i])) for i in range(5)]
    results = await asyncio.gather(*[world.put_chunk(bc, rid, str(uuid.uuid4()), 1, p) for p in payloads])
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) == 1 and all(c in (200, 409) for c in codes), codes
    session = await models.RecordingSession.get(uuid.UUID(rid))
    assert len(session.chunks) == 1
    c = session.chunks[0]
    from app.routers import media

    storage = media._get_storage_backend()
    assert storage.get_size(c.storage_key) == len(payloads[0]) and storage.get_size(c.original_storage_key) == len(payloads[0])
    assert sha(b"".join(storage.read_range(c.original_storage_key, 0, len(payloads[0]) - 1))) == c.original_hash
    assert len(stored_files(bc)) == 2


async def test_direct_upload_racing_receiver_forwarding_of_the_same_chunk(bc, world):
    """The Network Hopping fallback case: the phone sends chunk N straight to the control room while the receiver forwards it."""
    rid, _ = await world.register(bc)
    data = MP4(1)
    direct = await bc.post(f"/recordings/{rid}/chunks", data={"chunk_number": "1", "sha256": sha(data), "chunk_id": str(uuid.uuid4())}, files={"file": ("c.mp4", data, "video/mp4")}, headers=world.h_off)
    cid = str(uuid.uuid4())
    results = await asyncio.gather(
        bc.post(f"/recordings/{rid}/chunks", data={"chunk_number": "2", "sha256": sha(MP4(2)), "chunk_id": str(uuid.uuid4())}, files={"file": ("c.mp4", MP4(2), "video/mp4")}, headers=world.h_off),
        world.put_chunk(bc, rid, cid, 2, MP4(2)),
    )
    assert direct.status_code == 200 and sorted(r.status_code for r in results).count(200) >= 1
    session = await models.RecordingSession.get(uuid.UUID(rid))
    from app.routers import media

    storage = media._get_storage_backend()
    for c in session.chunks:
        size = storage.get_size(c.storage_key)
        assert size and size > 0, "every stored chunk's object must exist"
        assert c.original_storage_key and storage.get_size(c.original_storage_key)
    assert sorted(c.chunk_number for c in session.chunks) == [1, 2]


async def test_database_failure_removes_only_this_requests_objects(bc, world, monkeypatch):
    rid, _ = await world.register(bc)
    first = MP4(1)
    assert (await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, first)).status_code == 200
    before = set(stored_files(bc))

    real_coll = models.RecordingSession.get_motor_collection()

    class Boom:
        def __getattr__(self, name):  # everything else (reads) works normally
            return getattr(real_coll, name)

        async def find_one_and_update(self, *a, **k):
            raise RuntimeError("database write failed")

    from app.routers import receiver_ingest

    real = models.RecordingSession.get_motor_collection
    monkeypatch.setattr(receiver_ingest.models.RecordingSession, "get_motor_collection", classmethod(lambda cls: Boom()))
    with pytest.raises(RuntimeError):
        await world.put_chunk(bc, rid, str(uuid.uuid4()), 2, MP4(2))
    monkeypatch.setattr(receiver_ingest.models.RecordingSession, "get_motor_collection", real)
    assert set(stored_files(bc)) == before, "the failed request cleaned up its own objects and nobody else's"


async def test_cancelled_recording_refuses_chunks(bc, world):
    rid, _ = await world.register(bc)
    s = await models.RecordingSession.get(uuid.UUID(rid))
    s.status = models.RecordingStatus.cancelled
    await s.save()
    r = await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, MP4(1))
    assert r.status_code == 409 and r.headers["x-conflict-reason"] == "recording_cancelled"


async def test_completion_is_idempotent_reports_missing_and_waits_for_declared_chunks(bc, world):
    rid, _ = await world.register(bc)
    for n in (1, 3):
        assert (await world.put_chunk(bc, rid, str(uuid.uuid4()), n, MP4(n))).status_code == 200
    short = await bc.post(f"/receiver/v1/recordings/{rid}/complete", json={"chunk_count": 5}, headers=world.h_rcv)
    assert short.status_code == 409 and short.headers["x-conflict-reason"] == "chunks_outstanding"
    a = await bc.post(f"/receiver/v1/recordings/{rid}/complete", json={"chunk_count": 2}, headers=world.h_rcv)
    b = await bc.post(f"/receiver/v1/recordings/{rid}/complete", json={"chunk_count": 2}, headers=world.h_rcv)
    assert a.status_code == b.status_code == 200 and a.json()["missing_chunk_numbers"] == [2]
    detail = await bc.get(f"/sites/{world.site.id}/bodycam/recordings/{rid}", headers=world.h_admin)
    assert detail.json()["sync_state"] == "incomplete", "a recording with a gap is never reported as fully synchronized"
    assert detail.json()["missing_chunk_numbers"] == [2]


async def test_manifest_exposes_original_hashes_for_the_phone_gate(bc, world):
    rid, _ = await world.register(bc)
    data = MP4(1)
    await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, data)
    m = (await bc.get(f"/recordings/{rid}/chunks", headers=world.h_off)).json()
    assert m["chunks"][0]["original_hash"] == sha(data) and m["chunks"][0]["upload_status"] == "uploaded"
    rm = (await bc.get(f"/receiver/v1/recordings/{rid}/manifest", headers=world.h_rcv)).json()
    assert rm["chunks"][0]["original_hash"] == sha(data)


async def test_a_receiver_cannot_touch_another_sites_recordings(bc, world, make_user, make_constable):
    rid, _ = await world.register(bc)
    other = models.MonitoredSite(code="SITE-B", name="B")
    await other.insert()
    rcv = models.SiteReceiver(site_id=other.id, code="RB", name="B receiver", endpoint_url="https://b.test")
    token = receiver_auth.apply_new_token(rcv, keep_previous=False)
    await rcv.insert()
    hb = {"Authorization": f"Bearer {token}"}
    for r in (
        await world.put_chunk(bc, rid, str(uuid.uuid4()), 1, MP4(1), headers=hb),
        await bc.get(f"/receiver/v1/recordings/{rid}/manifest", headers=hb),
        await bc.post(f"/receiver/v1/recordings/{rid}/complete", json={}, headers=hb),
    ):
        assert r.status_code == 404, "another site's recording does not exist as far as this credential can tell"
    r = await bc.put(f"/receiver/v1/recordings/{uuid.uuid4()}", json=world.reg_body(uuid.uuid4(), site_id=str(world.site.id)), headers=hb)
    assert r.status_code == 403, "a credential cannot name a site other than its own"


async def test_heartbeat_does_not_invent_confirmations_and_bounds_local_summaries(bc, world):
    r = await bc.post("/receiver/v1/heartbeat", json={"pending_chunks": 3, "site_code": world.site.code}, headers=world.h_rcv)
    assert r.status_code == 200
    stored = await models.SiteReceiver.get(world.receiver.id)
    assert stored.last_central_ack_at is None and stored.pending_chunks == 3
    too_many = [{"recording_id": str(uuid.uuid4())} for _ in range(51)]
    assert (await bc.post("/receiver/v1/heartbeat", json={"local_recordings": too_many}, headers=world.h_rcv)).status_code == 422
    ok = [{"recording_id": str(uuid.uuid4()), "status": "completed", "chunks_received": 4, "chunks_synced": 1, "chunks_quarantined": 0, "secret": "dropped"} for _ in range(3)]
    assert (await bc.post("/receiver/v1/heartbeat", json={"local_recordings": ok}, headers=world.h_rcv)).status_code == 200
    out = (await bc.get(f"/sites/{world.site.id}/bodycam/receivers/{world.receiver.id}/local-recordings", headers=world.h_admin)).json()
    assert len(out["items"]) == 3 and out["stale"] is False and out["items"][0]["expected_chunks"] is None and out["items"][0]["registered_centrally"] is False
    assert "secret" not in str(out)
    wrong = await bc.post("/receiver/v1/heartbeat", json={"site_code": "SOMEONE-ELSE"}, headers=world.h_rcv)
    assert wrong.status_code == 403


# ================================================== recording start / listing / isolation =============================================

async def test_client_recording_id_start_is_idempotent_even_when_concurrent(bc, world):
    rid = str(uuid.uuid4())
    body = {"device_identifier": world.device.device_identifier, "trigger_type": "manual", "recording_id": rid, "site_id": str(world.site.id)}
    results = await asyncio.gather(*[bc.post("/recordings/start", json=body, headers=world.h_off) for _ in range(6)])
    assert [r.status_code for r in results] == [200] * 6, [r.text for r in results if r.status_code != 200]
    assert {r.json()["id"] for r in results} == {rid}
    assert await models.RecordingSession.find({"_id": uuid.UUID(rid)}).count() == 1


async def test_client_recording_id_owned_by_someone_else_is_a_conflict(bc, world, make_constable):
    rid = str(uuid.uuid4())
    body = {"device_identifier": world.device.device_identifier, "trigger_type": "manual", "recording_id": rid}
    assert (await bc.post("/recordings/start", json=body, headers=world.h_off)).status_code == 200
    user2, c2 = await make_constable(phone="7770004444")
    h2 = await world.login(bc, "7770004444")
    await bc.post("/devices/register", json={"device_identifier": "phone-2", "platform": "android"}, headers=h2)
    r = await bc.post("/recordings/start", json={**body, "device_identifier": "phone-2"}, headers=h2)
    assert r.status_code == 409 and r.headers["x-conflict-reason"] == "recording_id_conflict"


async def test_start_needs_an_active_assignment_for_a_site(bc, world):
    other = models.MonitoredSite(code="SITE-C", name="C")
    await other.insert()
    r = await bc.post("/recordings/start", json={"device_identifier": world.device.device_identifier, "trigger_type": "manual", "site_id": str(other.id)}, headers=world.h_off)
    assert r.status_code == 403


async def test_late_registration_does_not_make_the_device_look_live_but_the_legacy_start_does(bc, world):
    dev = lambda: models.Device.get(world.device_id)  # noqa: E731
    before = (await dev()).status
    await bc.post("/recordings/start", json={"device_identifier": world.device.device_identifier, "trigger_type": "manual", "recording_id": str(uuid.uuid4())}, headers=world.h_off)
    assert (await dev()).status == before
    await bc.post("/recordings/start", json={"device_identifier": world.device.device_identifier, "trigger_type": "manual"}, headers=world.h_off)
    assert (await dev()).status == models.DeviceStatus.recording


async def test_legacy_online_flow_is_unchanged(bc, world):
    r = await bc.post("/recordings/start", json={"device_identifier": world.device.device_identifier, "trigger_type": "manual"}, headers=world.h_off)
    assert r.status_code == 200
    rid = r.json()["id"]
    data = MP4(1)
    up = await bc.post(f"/recordings/{rid}/chunks", data={"chunk_number": "1", "is_last_chunk": "true"}, files={"file": ("c.mp4", data, "video/mp4")}, headers=world.h_off)
    assert up.status_code == 200 and up.json()["upload_status"] == "uploaded"
    dup = await bc.post(f"/recordings/{rid}/chunks", data={"chunk_number": "1"}, files={"file": ("c.mp4", data, "video/mp4")}, headers=world.h_off)
    assert dup.status_code == 409 and dup.headers["x-conflict-reason"] == "duplicate_chunk"
    assert (await bc.post(f"/recordings/{rid}/complete", headers=world.h_off)).status_code == 200


async def test_chunk_hash_is_verified_on_the_direct_path_too(bc, world):
    r = await bc.post("/recordings/start", json={"device_identifier": world.device.device_identifier, "trigger_type": "manual"}, headers=world.h_off)
    rid = r.json()["id"]
    bad = await bc.post(f"/recordings/{rid}/chunks", data={"chunk_number": "1", "sha256": "0" * 64}, files={"file": ("c.mp4", MP4(1), "video/mp4")}, headers=world.h_off)
    assert bad.status_code == 422 and bad.headers["x-conflict-reason"] == "hash_mismatch" and stored_files(bc) == []
    ok = await bc.post(f"/recordings/{rid}/chunks", data={"chunk_number": "1", "sha256": sha(MP4(1))}, files={"file": ("c.mp4", MP4(1), "video/mp4")}, headers=world.h_off)
    assert ok.status_code == 200
    conflict = await bc.post(f"/recordings/{rid}/chunks", data={"chunk_number": "1", "sha256": sha(MP4(1, b'x'))}, files={"file": ("c.mp4", MP4(1, b"x"), "video/mp4")}, headers=world.h_off)
    assert conflict.status_code == 409 and conflict.headers["x-conflict-reason"] == "hash_conflict"


async def _mk_recordings(world, site, n):
    ids = []
    for i in range(n):
        s = models.RecordingSession(trigger_type=models.RecordingTriggerType.manual, constable_id=world.constable.id, device_id=world.device_id, site_id=site.id if site else None, status=models.RecordingStatus.completed,
                                    created_at=now() - datetime.timedelta(minutes=i))
        await s.insert()
        ids.append(str(s.id))
    return ids


async def test_restricted_site_recordings_are_filtered_before_paging(bc, make_user, make_constable):
    w = await World().build(bc, make_user, make_constable, restricted=True)
    cr_allowed = await make_user(phone="7770005555", role=UserRole.control_room)
    cr_denied = await make_user(phone="7770006666", role=UserRole.control_room)
    w.site.viewer_user_ids = [cr_allowed.id]
    await w.site.save()
    public = models.MonitoredSite(code="PUB", name="Public")
    await public.insert()
    hidden_ids = await _mk_recordings(w, w.site, 2)
    visible_ids = await _mk_recordings(w, public, 1)
    h_allowed, h_denied = await w.login(bc, "7770005555"), await w.login(bc, "7770006666")
    seen_denied = (await bc.get("/recordings/", headers=h_denied)).json()
    assert {r["id"] for r in seen_denied} == set(visible_ids), "restricted rows never appear in the list"
    page = (await bc.get("/recordings/", params={"limit": 2, "offset": 0}, headers=h_denied)).json()
    assert len(page) == 1 and page[0]["id"] == visible_ids[0], "paging is applied to authorized rows only"
    assert {r["id"] for r in (await bc.get("/recordings/", headers=h_allowed)).json()} == set(hidden_ids + visible_ids)
    assert {r["id"] for r in (await bc.get("/recordings/", headers=w.h_admin)).json()} == set(hidden_ids + visible_ids)
    for rid in hidden_ids:
        assert (await bc.get(f"/recordings/{rid}", headers=h_denied)).status_code == 403
        assert (await bc.get(f"/recordings/{rid}/chunks", headers=h_denied)).status_code == 403
        assert (await bc.get(f"/recordings/{rid}", headers=h_allowed)).status_code == 200
    sb = f"/sites/{w.site.id}/bodycam/recordings"
    assert (await bc.get(sb, headers=h_denied)).status_code in (403, 404)
    assert (await bc.get(sb, headers=h_allowed)).json()["total"] == 2


# ================================================== health + body limits ==============================================================

async def test_healthz_contract_and_middleware_registration():
    import httpx

    from app import main
    from app.services.body_limit import BodyLimitMiddleware

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://t") as c:
        r = await c.get("/healthz")
        assert r.status_code == 200 and r.json() == {"status": "ok", "service": "sp-bodycam-central"}
        assert (await c.get("/does-not-exist")).status_code == 404
    assert any(m.cls is BodyLimitMiddleware for m in main.app.user_middleware)


async def test_body_limit_middleware_declared_and_undeclared_sizes():
    import httpx
    from fastapi import FastAPI, Request

    from app.services.body_limit import BodyLimitMiddleware

    app = FastAPI()
    seen = {"n": 0}

    @app.put("/recordings/{rid}/chunks")
    async def sink(rid: str, request: Request):
        seen["n"] += 1
        async for _ in request.stream():
            pass
        return {"ok": True}

    app.add_middleware(BodyLimitMiddleware, limit_bytes=1000, matches=lambda m, p: m == "PUT" and p.endswith("/chunks"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.put("/recordings/x/chunks", content=b"a" * 900)).status_code == 200
        assert (await c.put("/recordings/x/chunks", content=b"a" * 1200)).status_code == 413
        assert seen["n"] == 1, "a declared oversize body never reaches the handler"
        assert (await c.put("/recordings/x/chunks", headers={"Content-Length": "5000"}, content=b"a")).status_code in (413, 400)

        async def stream():
            for _ in range(5):
                yield b"a" * 500

        assert (await c.put("/recordings/x/chunks", content=stream())).status_code == 413
        assert (await c.put("/other", content=b"a" * 5000)).status_code in (404, 405), "unmatched paths are not limited by this middleware"
