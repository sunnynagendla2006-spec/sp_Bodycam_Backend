import os
import sys
import warnings

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Police Emergency Response API")

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# Previously: allow_origins=["*"] combined with allow_credentials=True.
# That combination is invalid per the CORS spec (browsers reject a wildcard
# origin paired with credentialed requests) and was flagged as a security
# gap as far back as the very first audit of this codebase, but never
# actually fixed. It is fixed here:
#   - allow_credentials=False: nothing in this application uses
#     cookie-based sessions -- authentication is exclusively via a
#     client-supplied `Authorization: Bearer <JWT>` header, which does not
#     require (or benefit from) `credentials: include`/cookie support at
#     all. There is therefore no functional reason to ever set this True.
#   - allow_origins is now configurable via CORS_ALLOWED_ORIGINS (a
#     comma-separated list), defaulting to "*" only for local development
#     convenience -- since allow_credentials is False, a wildcard origin
#     here is spec-valid (unlike the previous combination) and merely
#     permissive, not internally contradictory. Production deployments
#     should set CORS_ALLOWED_ORIGINS explicitly (e.g. to the real
#     web_dashboard origin) rather than relying on the wildcard default.
_cors_origins_env = os.getenv("CORS_ALLOWED_ORIGINS", "*")
_cors_allowed_origins = [o.strip() for o in _cors_origins_env.split(",") if o.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

from .routers import auth, incidents, constables, media, settings, websocket, police_stations, audit_logs, devices, recordings, commands, alerts, live_stream
app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(constables.router)
app.include_router(media.router)
app.include_router(settings.router)
app.include_router(websocket.router)
app.include_router(police_stations.router)
app.include_router(audit_logs.router)
app.include_router(devices.router)
app.include_router(recordings.router)
app.include_router(commands.router)
app.include_router(alerts.router)
app.include_router(live_stream.router)


# ---------------------------------------------------------------------------
# Database schema initialization
# ---------------------------------------------------------------------------
# Previously: `models.Base.metadata.create_all(bind=engine)` ran
# unconditionally at import time. That directly undermines the entire
# Alembic migration chain this project now relies on (see the migration-
# repair phase reports): `create_all()` silently creates any table that
# doesn't exist yet using whatever `models.py` currently says, with no
# awareness of migration history at all -- so a deployment that never ran
# `alembic upgrade head` would still appear to "work", masking exactly the
# kind of schema drift that caused real bugs in earlier phases
# (`incidents.display_id`, `evidence.comment` were both missing from the
# migration chain for a long time and this call is *why nobody noticed*).
#
# The correct production initialization path is `alembic upgrade head`,
# run as an explicit deploy/startup step (see Dockerfile). This module no
# longer creates or alters any schema itself. Instead, it performs a
# read-only check that the connected database is actually at the expected
# migration head, and fails loudly (production) or warns loudly
# (development) if not -- consistent with the same fail-safe pattern
# already used for JWT_SECRET_KEY in app/auth/security.py.
def _verify_database_at_expected_migration_head() -> None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from sqlalchemy import text
    from .database import engine

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    alembic_ini_path = os.path.join(backend_dir, "alembic.ini")

    try:
        cfg = Config(alembic_ini_path)
        cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
        script = ScriptDirectory.from_config(cfg)
        expected_heads = set(script.get_heads())
    except Exception as exc:
        # Can't even determine the expected head (e.g. alembic.ini missing) --
        # this is a packaging/deployment problem, not a schema-drift one;
        # don't block startup over it, just make it visible.
        warnings.warn(f"Could not resolve expected Alembic head: {exc}", RuntimeWarning)
        return

    try:
        with engine.connect() as conn:
            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
        actual_head = row[0] if row else None
    except Exception as exc:
        actual_head = None
        connect_error = str(exc)
    else:
        connect_error = None

    if actual_head in expected_heads:
        return  # database is exactly where the code expects it to be

    environment = os.getenv("ENVIRONMENT", "development").lower()
    message = (
        f"Database is NOT at the expected Alembic migration head. "
        f"Expected one of {expected_heads}, found {actual_head!r}"
        + (f" (connection/query error: {connect_error})" if connect_error else "")
        + ". Run `alembic upgrade head` before starting the application."
    )
    if environment == "production":
        raise RuntimeError(message)
    warnings.warn(message, RuntimeWarning)
    print(f"WARNING: {message}", file=sys.stderr)


_verify_database_at_expected_migration_head()


@app.get("/")
def root():
    return {"message": "Police Emergency Response System API is running."}
