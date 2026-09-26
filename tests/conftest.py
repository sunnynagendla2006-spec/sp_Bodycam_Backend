"""
Shared test fixtures for the MongoDB/Beanie-backed backend.

Every test needs a real, reachable MongoDB **replica set** -- Beanie/Motor's
partial-unique-index dedup (`DuplicateKeyError` retries) and the
multi-document transactions used for atomic audit-log writes both need a
real server; there is no lightweight in-process fallback the way SQLite
used to stand in for Postgres for most of this suite. Point tests at a
non-default instance via `TEST_MONGODB_URL`; otherwise this assumes the
docker-compose `mongo` service is reachable at
mongodb://localhost:27017/?replicaSet=rs0.

Each test gets its own uniquely-named, disposable database (dropped on
teardown) -- the same strategy the old Postgres concurrency/migration
tests already used for themselves, just applied to every test now instead
of a special-cased few.

Route handlers no longer take a `db: Session = Depends(get_db)` parameter
(Beanie documents are queried as classmethods against whatever database
`init_beanie` last registered them against), so there's no dependency to
override the way the old SQLAlchemy-based fixtures did -- the `mongo_db`
fixture below re-runs `init_beanie` against a fresh database before each
test, and that's the only wiring needed.

Tests are async (`pytest-asyncio`, `asyncio_mode = auto` in pytest.ini) and
use `httpx.AsyncClient(transport=ASGIWebSocketTransport(app=app))` (from
the `httpx-ws` package) rather than Starlette's `TestClient`: this
transport runs the app in-process on the calling coroutine's own event
loop -- required here since Motor clients are bound to the loop they're
created on -- while ALSO supporting WebSocket upgrades (plain
`httpx.ASGITransport` is HTTP-only). The older sync `TestClient` spins up
a separate thread/loop per request, which would break Beanie the moment
any route or fixture touched the database. WebSocket tests connect via
`httpx_ws.aconnect_ws(url, client)` instead of `client.websocket_connect`.
"""
import os
import uuid

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "60")

import pytest
import pytest_asyncio
from httpx import AsyncClient
from httpx_ws.transport import ASGIWebSocketTransport
from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app import models
from app.auth.security import hash_password

TEST_MONGODB_URL = os.getenv("TEST_MONGODB_URL", "mongodb://localhost:27017/?replicaSet=rs0")


def _mongo_reachable() -> bool:
    try:
        MongoClient(TEST_MONGODB_URL, serverSelectionTimeoutMS=500, uuidRepresentation="standard").admin.command("ping")
        return True
    except PyMongoError:
        return False


_MONGO_AVAILABLE = _mongo_reachable()

requires_mongo = pytest.mark.skipif(
    not _MONGO_AVAILABLE,
    reason=f"No reachable MongoDB replica set at {TEST_MONGODB_URL} (set TEST_MONGODB_URL to override)",
)


@pytest_asyncio.fixture()
async def mongo_db():
    """Beanie freshly registered against a uniquely-named, disposable test database."""
    if not _MONGO_AVAILABLE:
        pytest.skip(f"No reachable MongoDB replica set at {TEST_MONGODB_URL}")

    from beanie import init_beanie
    from motor.motor_asyncio import AsyncIOMotorClient

    db_name = f"sp_test_{uuid.uuid4().hex[:16]}"
    motor_client = AsyncIOMotorClient(TEST_MONGODB_URL, uuidRepresentation="standard")
    database = motor_client[db_name]
    await init_beanie(database=database, document_models=models.DOCUMENT_MODELS)
    try:
        yield database
    finally:
        await motor_client.drop_database(db_name)
        motor_client.close()


@pytest_asyncio.fixture()
async def client(mongo_db):
    """AsyncClient for a minimal app containing only the auth router."""
    from fastapi import Depends, FastAPI

    from app.auth.deps import require_role
    from app.routers import auth as auth_router_module

    app = FastAPI()
    app.include_router(auth_router_module.router)

    # Test-only routes to exercise require_role() in isolation -- not part
    # of the real application.
    @app.get("/__test__/admin-only")
    async def _admin_only(user: models.User = Depends(require_role("admin"))):
        return {"ok": True}

    @app.get("/__test__/constable-only")
    async def _constable_only(user: models.User = Depends(require_role("constable"))):
        return {"ok": True}

    transport = ASGIWebSocketTransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture()
async def full_client(mongo_db):
    """
    AsyncClient wired up with every real router (imported unmodified from
    app/routers/*). Media file uploads write into a temporary directory
    instead of the real /app/uploads path.
    """
    import tempfile

    from fastapi import FastAPI

    from app.routers import alerts as alerts_router_module
    from app.routers import audit_logs as audit_logs_router_module
    from app.routers import auth as auth_router_module
    from app.routers import commands as commands_router_module
    from app.routers import constables as constables_router_module
    from app.routers import devices as devices_router_module
    from app.routers import incidents as incidents_router_module
    from app.routers import live_stream as live_stream_router_module
    from app.routers import media as media_router_module
    from app.routers import police_stations as police_stations_router_module
    from app.routers import recordings as recordings_router_module
    from app.routers import settings as settings_router_module
    from app.routers import websocket as websocket_router_module

    tmp_upload_dir = tempfile.mkdtemp(prefix="sp_test_uploads_")
    media_router_module.UPLOAD_DIR = tmp_upload_dir

    app = FastAPI()
    app.include_router(auth_router_module.router)
    app.include_router(incidents_router_module.router)
    app.include_router(constables_router_module.router)
    app.include_router(media_router_module.router)
    app.include_router(settings_router_module.router)
    app.include_router(police_stations_router_module.router)
    app.include_router(audit_logs_router_module.router)
    app.include_router(devices_router_module.router)
    app.include_router(recordings_router_module.router)
    app.include_router(commands_router_module.router)
    app.include_router(alerts_router_module.router)
    app.include_router(websocket_router_module.router)
    app.include_router(live_stream_router_module.router)

    transport = ASGIWebSocketTransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def _reset_login_rate_limiter():
    yield
    from app.auth import rate_limit
    rate_limit._attempts.clear()


@pytest.fixture(autouse=True)
def _reset_ws_manager():
    """
    app.routers.websocket.manager is a module-level singleton, so it's
    shared across every test's freshly-built FastAPI app in this process.
    """
    yield
    from app.routers.websocket import manager
    manager.control_room_connections.clear()
    manager.station_connections.clear()
    manager.constable_connections.clear()


@pytest_asyncio.fixture()
async def make_station(mongo_db):
    """Factory fixture: creates a PoliceStation document at a given lon/lat."""

    async def _make_station(name: str = "Test Station", longitude: float = 78.90, latitude: float = 20.50):
        station = models.PoliceStation(
            name=name,
            location=models.GeoPoint(coordinates=[longitude, latitude]),
            contact="000-0000",
        )
        await station.insert()
        return station

    return _make_station


@pytest_asyncio.fixture()
async def make_user(mongo_db):
    """Factory fixture to create a User document with a real bcrypt hash."""

    async def _make_user(
        phone: str = "9990001111",
        password: str = "correct-horse-battery",
        role: models.UserRole = models.UserRole.admin,
        status: models.UserStatus = models.UserStatus.active,
        station_id=None,
    ) -> models.User:
        user = models.User(
            phone=phone,
            role=role,
            status=status,
            station_id=station_id,
            hashed_password=hash_password(password),
        )
        await user.insert()
        return user

    return _make_user


@pytest_asyncio.fixture()
async def make_constable(mongo_db, make_user):
    """Factory fixture: creates a User(role=constable) + linked Constable document, returns (user, constable)."""

    async def _make_constable(
        phone: str = "8880001111",
        password: str = "correct-horse-battery",
        badge_number: str = None,
        status: models.ConstableStatus = models.ConstableStatus.available,
        station_id=None,
        user_status: models.UserStatus = models.UserStatus.active,
    ):
        user = await make_user(phone=phone, password=password, role=models.UserRole.constable, status=user_status)
        constable = models.Constable(
            user_id=user.id,
            badge_number=badge_number or f"BADGE-{phone}",
            status=status,
            battery_level=100,
            station_id=station_id,
        )
        await constable.insert()
        return user, constable

    return _make_constable


@pytest_asyncio.fixture()
async def make_location(mongo_db):
    """Factory fixture: creates a ConstableLocation reading, optionally backdated (for freshness tests)."""
    import datetime as _dt

    async def _make_location(constable_id, longitude: float = 78.90, latitude: float = 20.50, age_seconds: int = 0):
        ts = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=age_seconds)
        loc = models.ConstableLocation(
            constable_id=constable_id,
            location=models.GeoPoint(coordinates=[longitude, latitude]),
            timestamp=ts,
        )
        await loc.insert()
        return loc

    return _make_location


@pytest_asyncio.fixture()
async def make_incident(mongo_db):
    """Factory fixture: creates an Incident document, optionally owned by a citizen."""

    async def _make_incident(
        citizen_id=None,
        description: str = "test incident",
        status_=models.IncidentStatus.new,
        longitude: float = 78.90,
        latitude: float = 20.50,
        station_id=None,
    ):
        incident = models.Incident(
            citizen_id=citizen_id,
            location=models.GeoPoint(coordinates=[longitude, latitude]),
            description=description,
            status=status_,
            station_id=station_id,
        )
        await incident.insert()
        return incident

    return _make_incident


@pytest_asyncio.fixture()
async def make_assignment():
    """
    Factory fixture: appends an Assignment onto an incident's embedded
    `assignments` list and marks it active, via a single atomic
    find_one_and_update -- mirrors what routers/incidents.py::dispatch_incident
    does, for tests that need an existing assignment without going through
    the dispatch endpoint itself.
    """

    async def _make_assignment(constable_id, incident_id):
        assignment = models.Assignment(constable_id=constable_id)
        await models.Incident.find_one(models.Incident.id == incident_id).update(
            {
                "$push": {"assignments": assignment.model_dump()},
                "$set": {"active_assignment_id": assignment.id},
            }
        )
        return assignment

    return _make_assignment


@pytest_asyncio.fixture()
async def make_evidence(mongo_db):
    """Factory fixture: creates an Evidence document directly (bypassing the upload endpoint) for download/list tests."""
    import tempfile

    async def _make_evidence(incident_id, constable_id=None, content: bytes = b"fake evidence bytes", mime_type: str = None):
        tmp_dir = tempfile.mkdtemp(prefix="sp_test_evidence_")
        file_path = os.path.join(tmp_dir, "evidence.jpg")
        with open(file_path, "wb") as f:
            f.write(content)
        evidence = models.Evidence(
            incident_id=incident_id,
            constable_id=constable_id,
            type=models.MediaType.photo,
            file_path=file_path,
            file_hash="deadbeef",
            mime_type=mime_type,
        )
        await evidence.insert()
        return evidence

    return _make_evidence


@pytest_asyncio.fixture()
async def auth_header(full_client):
    """Helper fixture: logs in and returns an {'Authorization': 'Bearer ...'} header dict."""

    async def _auth_header(phone: str, password: str) -> dict:
        resp = await full_client.post("/auth/login", json={"username": phone, "password": password})
        assert resp.status_code == 200, resp.text
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _auth_header
