"""
Fixtures for the site-receiver tests. Everything is isolated: a temporary SQLite database and storage root per test, a
freshly generated throw-away EC key pair for grants, fake credentials, and a mock control room. No network, no MongoDB.
"""
import hashlib
import os
import tempfile
import time
import uuid

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt

SITE_ID = str(uuid.uuid4())
OFFICER_ID = str(uuid.uuid4())
DEVICE_ID = str(uuid.uuid4())
DEVICE_IDENT = "test-device-0001"
ISSUER = "sp-bodycam-control-room"


def _keypair():
    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


PRIV, PUB = _keypair()
OTHER_PRIV, OTHER_PUB = _keypair()


def _apply_env(root, extra=None):
    env = {
        "RECEIVER_SITE_ID": SITE_ID, "RECEIVER_SITE_CODE": "SITE-T", "RECEIVER_NAME": "test-receiver",
        "RECEIVER_GRANT_PUBLIC_KEY_PEM": PUB, "RECEIVER_GRANT_ISSUER": ISSUER,
        "RECEIVER_STORAGE_ROOT": os.path.join(root, "media"), "RECEIVER_DB_PATH": os.path.join(root, "data", "receiver.sqlite3"),
        "RECEIVER_ACCESS_TOKEN_SECRET": "unit-test-session-secret-not-for-production", "RECEIVER_ADMIN_KEY": "unit-test-admin-key",
        "RECEIVER_MIN_FREE_MB": "1", "RECEIVER_MAX_CHUNK_MB": "2", "RECEIVER_RATE_LIMIT_PER_MINUTE": "600",
    }
    env.update(extra or {})
    for k in [k for k in os.environ if k.startswith("RECEIVER_")]:
        del os.environ[k]
    os.environ.update(env)
    return env


# The module builds an app at import time, so a valid environment must exist before the first import.
_import_root = tempfile.mkdtemp(prefix="receiver-import-")
_apply_env(_import_root)
from site_receiver import main as receiver_main  # noqa: E402


def make_chunk(n=1, size=4096, seed=b"x"):
    """Deterministic MP4-looking bytes (ftyp box first) and their SHA-256."""
    body = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + hashlib.sha256(seed + str(n).encode()).digest() * (size // 32)
    return body, hashlib.sha256(body).hexdigest()


def make_grant(priv=None, *, site=SITE_ID, exp_in=3600, iat_offset=0, ops=("session", "upload", "live"), issuer=ISSUER, dev=DEVICE_ID, devid=DEVICE_IDENT,
                sub=OFFICER_ID, alg="ES256", kid=None, jti=None, extra=None):
    now = int(time.time())
    claims = {"iss": issuer, "sub": sub, "jti": jti or str(uuid.uuid4()), "site": site, "site_code": "SITE-T", "org": None, "dev": dev, "devid": devid,
              "asg": str(uuid.uuid4()), "zone": None, "ops": list(ops), "iat": now + iat_offset, "exp": now + exp_in, "ver": 1}
    claims.update(extra or {})
    headers = {"kid": kid} if kid else None
    return jwt.encode(claims, priv or PRIV, algorithm=alg, headers=headers)


class Harness:
    def __init__(self, app, root, base="http://receiver", ip="10.0.0.5"):
        self.app, self.root = app, root
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 5555)), base_url=base)

    def other_client(self, ip):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app, client=(ip, 5555)), base_url="http://receiver")

    async def session(self, grant=None, device=DEVICE_IDENT):
        r = await self.client.post("/v1/auth/session", json={"grant": grant or make_grant(), "device_identifier": device})
        return r

    async def token(self, **kw):
        r = await self.session(make_grant(**kw) if kw else None, device=kw.get("devid", DEVICE_IDENT))
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    async def register(self, headers, rid=None):
        rid = rid or str(uuid.uuid4())
        r = await self.client.post("/v1/recordings", headers=headers, json={"recording_id": rid, "started_at": "2026-01-01T00:00:00Z", "trigger_type": "manual", "camera_lens_direction": "back"})
        assert r.status_code == 200, r.text
        return rid

    async def put_chunk(self, headers, rid, cid, n, data, sha=None, size=True, **form):
        fields = {"chunk_number": str(n), "sha256": sha or hashlib.sha256(data).hexdigest(), "is_last_chunk": "false"}
        if size:
            fields["size_bytes"] = str(len(data))
        fields.update({k: str(v) for k, v in form.items()})
        return await self.client.put(f"/v1/recordings/{rid}/chunks/{cid}", headers=headers, data=fields, files={"file": ("c.mp4", data, "video/mp4")})

    def db(self):
        return receiver_main  # placeholder to keep the name free


@pytest.fixture
def env(tmp_path, monkeypatch):
    def apply(**extra):
        return _apply_env(str(tmp_path), extra)
    apply()
    return apply


@pytest_asyncio.fixture
async def receiver(tmp_path, env):
    app = receiver_main.create_app()
    async with app.router.lifespan_context(app):
        h = Harness(app, str(tmp_path))
        yield h
        await h.client.aclose()


@pytest.fixture
def settings(tmp_path, env):
    from site_receiver.config import load
    return load()


# ---------------------------------------------------------------------------------------------------------------------
# Direct (non-HTTP) helpers for forwarder / recovery tests
# ---------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def make_settings(env):
    from site_receiver.config import load

    def build(**extra):
        env(**extra)
        return load()

    return build


@pytest.fixture
def kit(make_settings):
    """(settings, store, media) on a fresh temporary database + storage root."""
    from site_receiver.storage import MediaStorage
    from site_receiver.store import Store

    s = make_settings(RECEIVER_CENTRAL_URL="https://central.test", RECEIVER_CENTRAL_TOKEN="test-receiver-token", RECEIVER_MAX_HARD_ERRORS="2")
    os.makedirs(os.path.dirname(s.db_path), exist_ok=True)
    store = Store(s.db_path)
    media = MediaStorage(s.storage_root, s.site_id)
    yield s, store, media
    store.close()


def seed_recording(store, rid=None, *, status="recording", complete=False, expected=None):
    from site_receiver.store import now_iso

    rid = rid or str(uuid.uuid4())
    store.execute(
        "INSERT INTO recordings (recording_id, site_id, constable_id, device_id, device_identifier, grant_id, trigger_type, camera, started_at, status, complete_requested, expected_chunks, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'manual', 'back', ?, ?, ?, ?, ?, ?)",
        (rid, SITE_ID, OFFICER_ID, DEVICE_ID, DEVICE_IDENT, str(uuid.uuid4()), now_iso(), status, 1 if complete else 0, expected, now_iso(), now_iso()))
    return rid


def seed_chunk(store, media, settings, rid, n=1, *, state="pending_sync", data=None, write_file=True, cid=None):
    """Writes a chunk file at the receiver's documented path and the matching SQLite row. Returns (row dict, bytes)."""
    from site_receiver.store import now_iso

    cid = cid or str(uuid.uuid4())
    data = data or make_chunk(n)[0]
    path = media.chunk_path(uuid.UUID(rid), uuid.UUID(cid))
    if write_file:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
    store.execute(
        "INSERT INTO chunks (chunk_id, recording_id, chunk_number, sha256, size_bytes, mime, storage_path, received_at, state, is_last) VALUES (?, ?, ?, ?, ?, 'video/mp4', ?, ?, ?, 0)",
        (cid, rid, n, hashlib.sha256(data).hexdigest(), len(data), path, now_iso(), state))
    return store.one("SELECT * FROM chunks WHERE chunk_id = ?", (cid,)), data
