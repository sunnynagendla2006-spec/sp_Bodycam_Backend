"""
Test fixtures for the authentication foundation.

Design note: app/main.py runs `models.Base.metadata.create_all(bind=engine)`
at import time against whatever DATABASE_URL is configured (normally the
real Postgres+PostGIS instance from docker-compose). That's fine for local
dev, but it means importing app.main directly in a unit test would require a
live PostGIS-capable Postgres connection just to test auth.

Since the User table (the only table auth touches) has no Geometry columns,
these tests instead build a minimal FastAPI app containing ONLY the auth
router, backed by an isolated in-memory SQLite database, with only the
`users` table created. This tests the real auth code paths (security.py,
deps.py, routers/auth.py) without requiring Postgres/PostGIS to be running.

Full end-to-end testing against the real Postgres+PostGIS stack (via
docker-compose) is still recommended before deployment -- see the "Exact
commands" section of the phase summary.
"""
import os
import sys

# Ensure a JWT secret is present before app.auth.security is imported, so
# tests don't depend on (or warn about) the insecure dev fallback.
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "60")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import get_db
from app.routers import auth as auth_router_module
from app.auth.security import hash_password
from app.auth.deps import require_role

# ---------------------------------------------------------------------------
# Geometry-column monkeypatch for SQLite-based test isolation.
#
# The real schema uses GeoAlchemy2 `Geometry` columns (PostGIS). GeoAlchemy2's
# SQLite dialect assumes a SpatiaLite-loaded SQLite (it emits
# AddGeometryColumn/RecoverGeometryColumn DDL on table creation), which isn't
# available in this environment and isn't installable via pip. Since these
# authorization tests only need "some column exists to hold a WKT-ish
# string" (none of the authorization logic under test depends on real
# spatial indexing/queries), the Geometry-typed columns are swapped for
# plain String columns -- but ONLY for the duration of the `db_session`
# fixture below, NOT at module-import time.
#
# IMPORTANT: this used to be applied unconditionally at module import time,
# which meant it silently and PERMANENTLY mutated the shared `models` module
# for the rest of the pytest process -- including polluting any real-
# PostgreSQL integration test (see tests/test_evidence_verification_concurrency.py)
# collected in the same session, since pytest always auto-loads this
# conftest.py regardless of which specific test file is targeted. That was
# a genuine bug, discovered while actually running the Postgres concurrency
# tests against a real database for the first time: inserting a WKT string
# into what should have been a native `geometry` column failed with a type
# mismatch, because this monkeypatch had already silently downgraded the
# column to `String` before the Postgres test even started. Scoping the
# monkeypatch to the fixture's own setup/teardown (restoring the original
# Geometry type afterward) fixes this while leaving every SQLite-based test
# working exactly as before.
_GEOMETRY_COLUMNS = [
    (models.PoliceStation, "location"),
    (models.PoliceStation, "jurisdiction"),
    (models.ConstableLocation, "location"),
    (models.Incident, "location"),
    (models.Evidence, "location"),
]

_ALL_TEST_TABLES = [
    models.User.__table__,
    models.PoliceStation.__table__,
    models.Constable.__table__,
    models.ConstableLocation.__table__,
    models.Incident.__table__,
    models.IncidentAssignment.__table__,
    models.Evidence.__table__,
    models.AuditLog.__table__,
    models.Device.__table__,
    models.BatteryReading.__table__,
    models.Alert.__table__,
    models.RecordingSession.__table__,
    models.VideoChunk.__table__,
    models.RemoteCommand.__table__,
]


@pytest.fixture()
def db_session():
    """A fresh in-memory SQLite session with the full authorization-relevant schema created."""
    original_types = {}
    for _model_cls, _colname in _GEOMETRY_COLUMNS:
        col = _model_cls.__table__.c[_colname]
        original_types[(_model_cls, _colname)] = col.type
        col.type = String()

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _register_geo_shims(dbapi_conn, conn_record):
        import re
        import math

        dbapi_conn.create_function("ST_GeomFromEWKT", 1, lambda wkt: wkt)
        dbapi_conn.create_function("ST_AsText", 1, lambda geom: geom)

        def _parse_point(wkt):
            if wkt is None:
                return None
            m = re.match(r"POINT\(([-0-9.eE]+)\s+([-0-9.eE]+)\)", wkt)
            if not m:
                return None
            return float(m.group(1)), float(m.group(2))

        def st_distance(wkt_a, wkt_b):
            """
            Test-only ST_Distance shim: real Haversine distance in meters,
            computed directly from two WKT "POINT(lon lat)" strings. See
            app/routers/police_stations.py::distance_expr for why this
            deliberately does NOT rely on any SQL-level CAST(... AS
            GEOGRAPHY) -- SQLite has no such type, and empirically mangles
            the value if you try.
            """
            a = _parse_point(wkt_a)
            b = _parse_point(wkt_b)
            if not a or not b:
                return None
            lon1, lat1 = a
            lon2, lat2 = b
            R = 6371000.0
            phi1, phi2 = math.radians(lat1), math.radians(lat2)
            dphi = math.radians(lat2 - lat1)
            dlambda = math.radians(lon2 - lon1)
            h = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
            return R * 2 * math.asin(math.sqrt(h))

        def st_x(wkt):
            point = _parse_point(wkt)
            return point[0] if point else None

        def st_y(wkt):
            point = _parse_point(wkt)
            return point[1] if point else None

        dbapi_conn.create_function("ST_Distance", 2, st_distance)
        dbapi_conn.create_function("ST_X", 1, st_x)
        dbapi_conn.create_function("ST_Y", 1, st_y)

    models.Base.metadata.create_all(bind=engine, tables=_ALL_TEST_TABLES)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        for (_model_cls, _colname), _original_type in original_types.items():
            _model_cls.__table__.c[_colname].type = _original_type


@pytest.fixture()
def client(db_session):
    """TestClient for a minimal app containing only the auth router."""
    app = FastAPI()
    app.include_router(auth_router_module.router)

    # Test-only routes to exercise require_role() in isolation. These are
    # NOT part of the real application -- no production router is modified
    # in this phase.
    @app.get("/__test__/admin-only")
    def _admin_only(user: models.User = Depends(require_role("admin"))):
        return {"ok": True}

    @app.get("/__test__/constable-only")
    def _constable_only(user: models.User = Depends(require_role("constable"))):
        return {"ok": True}

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app) as c:
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
    Each websocket test is expected to cleanly exit its
    `with client.websocket_connect(...) as ws:` block (which triggers the
    server-side disconnect/cleanup on its own), but this is a safety net
    against any leftover connections from a test that errors out mid-block.
    """
    yield
    from app.routers.websocket import manager
    manager.control_room_connections.clear()
    manager.station_connections.clear()
    manager.constable_connections.clear()


@pytest.fixture()
def full_client(db_session):
    """
    TestClient wired up with the REAL auth, incidents, constables, media, and
    settings routers (imported unmodified from app/routers/*) -- used for the
    phase-2 authorization tests. Media file uploads write into a temporary
    directory instead of the real /app/uploads path.
    """
    import tempfile
    from app.routers import incidents as incidents_router_module
    from app.routers import constables as constables_router_module
    from app.routers import media as media_router_module
    from app.routers import settings as settings_router_module
    from app.routers import police_stations as police_stations_router_module
    from app.routers import audit_logs as audit_logs_router_module
    from app.routers import devices as devices_router_module
    from app.routers import recordings as recordings_router_module
    from app.routers import commands as commands_router_module
    from app.routers import alerts as alerts_router_module
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

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def make_station(db_session):
    """Factory fixture: creates a PoliceStation row at a given lon/lat."""

    def _make_station(name: str = "Test Station", longitude: float = 78.90, latitude: float = 20.50):
        station = models.PoliceStation(
            name=name,
            location=f"POINT({longitude} {latitude})",
            contact="000-0000",
        )
        db_session.add(station)
        db_session.commit()
        db_session.refresh(station)
        return station

    return _make_station


@pytest.fixture()
def make_constable(db_session, make_user):
    """Factory fixture: creates a User(role=constable) + linked Constable row, returns (user, constable)."""

    def _make_constable(
        phone: str = "8880001111",
        password: str = "correct-horse-battery",
        badge_number: str = None,
        status: models.ConstableStatus = models.ConstableStatus.available,
        station_id=None,
        user_status: models.UserStatus = models.UserStatus.active,
    ):
        user = make_user(phone=phone, password=password, role=models.UserRole.constable, status=user_status)
        constable = models.Constable(
            user_id=user.id,
            badge_number=badge_number or f"BADGE-{phone}",
            status=status,
            battery_level=100,
            station_id=station_id,
        )
        db_session.add(constable)
        db_session.commit()
        db_session.refresh(constable)
        return user, constable

    return _make_constable


@pytest.fixture()
def make_location(db_session):
    """Factory fixture: creates a ConstableLocation row, optionally backdated (for freshness tests)."""
    import datetime as _dt

    def _make_location(constable_id, longitude: float = 78.90, latitude: float = 20.50, age_seconds: int = 0):
        ts = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=age_seconds)
        loc = models.ConstableLocation(
            constable_id=constable_id,
            location=f"POINT({longitude} {latitude})",
            timestamp=ts,
        )
        db_session.add(loc)
        db_session.commit()
        db_session.refresh(loc)
        return loc

    return _make_location


@pytest.fixture()
def make_incident(db_session):
    """Factory fixture: creates an Incident row, optionally owned by a citizen."""

    def _make_incident(
        citizen_id=None,
        description: str = "test incident",
        status_=models.IncidentStatus.new,
        longitude: float = 78.90,
        latitude: float = 20.50,
        station_id=None,
    ):
        incident = models.Incident(
            citizen_id=citizen_id,
            location=f"POINT({longitude} {latitude})",
            description=description,
            status=status_,
            station_id=station_id,
        )
        db_session.add(incident)
        db_session.commit()
        db_session.refresh(incident)
        return incident

    return _make_incident


@pytest.fixture()
def make_assignment(db_session):
    """Factory fixture: creates an IncidentAssignment linking a constable to an incident."""

    def _make_assignment(constable_id, incident_id):
        assignment = models.IncidentAssignment(constable_id=constable_id, incident_id=incident_id)
        db_session.add(assignment)
        db_session.commit()
        db_session.refresh(assignment)
        return assignment

    return _make_assignment


@pytest.fixture()
def make_evidence(db_session):
    """Factory fixture: creates an Evidence row directly (bypassing the upload endpoint) for download/list tests."""
    import tempfile

    def _make_evidence(incident_id, constable_id=None, content: bytes = b"fake evidence bytes", mime_type: str = None):
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
        db_session.add(evidence)
        db_session.commit()
        db_session.refresh(evidence)
        return evidence

    return _make_evidence


@pytest.fixture()
def auth_header(full_client):
    """Helper fixture: logs in and returns an {'Authorization': 'Bearer ...'} header dict."""

    def _auth_header(phone: str, password: str) -> dict:
        resp = full_client.post("/auth/login", json={"username": phone, "password": password})
        assert resp.status_code == 200, resp.text
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _auth_header


@pytest.fixture()
def make_user(db_session):
    """Factory fixture to create a User row with a real bcrypt hash."""

    def _make_user(
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
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    return _make_user
