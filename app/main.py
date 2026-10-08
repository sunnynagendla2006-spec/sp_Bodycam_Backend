import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------
# Mongo/Beanie has no separate migration-tool step: `init_db()` registers
# every Document model and idempotently creates any collection/index that
# doesn't exist yet (including the partial-unique and 2dsphere indexes
# declared on each Document's Settings). Safe to run on every startup.
@asynccontextmanager
async def lifespan(_app: FastAPI):
    from .database import init_db

    await init_db()
    yield


app = FastAPI(title="Police Emergency Response API", lifespan=lifespan)

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

from .routers import auth, incidents, constables, media, settings, websocket, police_stations, audit_logs, devices, recordings, commands, alerts, live_stream, cctv, access_points, presence, deployments
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
app.include_router(access_points.router)
app.include_router(presence.router)
app.include_router(deployments.router)

# Authorized CCTV monitoring is an optional subsystem (see
# app/services/cctv_security.py::CCTV_ENABLED) -- disabling it removes the
# routes entirely (404) rather than leaving them mounted but non-functional.
from .services.cctv_security import CCTV_ENABLED
if CCTV_ENABLED:
    app.include_router(cctv.router)


@app.get("/")
def root():
    return {"message": "Police Emergency Response System API is running."}
