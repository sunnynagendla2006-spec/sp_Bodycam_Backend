# Emergency Smart Recording and Intelligent Police Response System — Backend

FastAPI + MongoDB (Motor/Beanie) backend. No README existed in this
repository before this document; it currently covers the two subsystems
added in this phase (Authorized CCTV Monitoring, AP-Based Police
Presence) rather than re-documenting the entire pre-existing backend
(auth, body-camera devices/recordings, incidents, LiveKit live-stream,
etc.) — see the inline module docstrings throughout `app/` for that.

Every claim below is tagged:

- **IMPLEMENTED** — the code exists and does what's described.
- **UNIT TESTED** — covered by a test in `tests/`, not yet run in this environment (see Verification status).
- **RUNTIME VERIFIED** — actually exercised against a live MongoDB/LiveKit/RTSP source in this environment. Nothing below carries this tag.
- **CONFIGURATION REQUIRED** — needs an environment variable or external service before it does anything.
- **NOT IMPLEMENTED** — a named extension point only; calling it raises `NotImplementedError` or returns an honest failure, never a fabricated success.

## Verification status

Tests for both subsystems were written but **not executed** in this
environment: there is no reachable MongoDB replica set and the test
dependencies (`requirements-dev.txt`) were not installed here (by
explicit choice — see the implementation report for why). Every
`[UNIT TESTED]` tag below means "a test exists for this," not "this test
has been run and passed." Run `pytest` yourself against a real MongoDB
replica set to get real pass/fail results.

---

## 1. Authorized CCTV Monitoring

Router: `app/routers/cctv.py`. Models: `app/models.py::CCTVCamera`,
`CCTVStreamSession`. Services: `app/services/cctv_security.py` (SSRF +
secret encryption), `app/services/cctv_providers.py` (provider
abstraction).

### Architecture

```
AUTHORIZED CAMERA (admin-registered only)
        |
        | RTSP (SSRF-validated host:port)
        v
   RTSPProvider.validate_connection()        [IMPLEMENTED] [UNIT TESTED]
        |
        v
  CCTVCamera.status (online/offline/degraded/unknown/disabled)

Browser-viewable streaming (WebRTC/HLS bridge): [NOT IMPLEMENTED]
  -- see "Streaming" below.
```

This system never discovers, scans, or connects to a camera an admin
has not explicitly registered. There is no "all city CCTV" capability
anywhere in this code.

### Camera management

- `POST /cctv/cameras` (admin) — register a camera. Rejects a
  stream target outside `CCTV_ALLOWED_NETWORKS` **before** storing it.
- `GET /cctv/cameras` (admin, control_room) — list, with filters
  (`station_id`, `zone`, `enabled`, `status`, `provider_type`,
  `camera_code`, `name`).
- `GET /cctv/cameras/{id}`, `PATCH /cctv/cameras/{id}` (admin),
  `DELETE /cctv/cameras/{id}` (admin).
- `POST /cctv/cameras/{id}/enable` / `/disable` (admin) — `enabled`
  (administrative) and `status` (observed) are deliberately different
  fields; disabling sets `status=disabled` explicitly, never `offline`.
- `POST /cctv/cameras/{id}/test` (admin, control_room) — a real RTSP
  `OPTIONS` probe (see Providers below). Always returns the live
  result honestly; a disabled camera's *persisted* status stays
  `disabled` regardless of what the probe finds.
- `GET /cctv/cameras/{id}/status` (admin, control_room) — last
  persisted status, no new probe.

[IMPLEMENTED] [UNIT TESTED] — `tests/test_cctv_cameras.py`.

### RBAC

Enforced at the dependency level (`require_cctv_viewer` =
admin+control_room, `require_cctv_admin` = admin-only), never left to
the frontend:

| Action | admin | control_room | station | constable | citizen |
|---|---|---|---|---|---|
| View / list / status | ✅ | ✅ | 403 | 403 | 403 |
| Test connectivity | ✅ | ✅ | 403 | 403 | 403 |
| Request/stop stream | ✅ | ✅ | 403 | 403 | 403 |
| Create/update/delete/enable/disable | ✅ | 403 | 403 | 403 | 403 |

[IMPLEMENTED] [UNIT TESTED] — `tests/test_cctv_cameras.py` parametrized
RBAC tests exercise every endpoint against every denied role.

### Credential security

`CCTVCamera.encrypted_secret` (Fernet-encrypted, key from
`CCTV_SECRET_KEY`) is **never** returned by any endpoint — only
`credentials_configured: bool`. Verified by an explicit test asserting
the plaintext secret never appears anywhere in a create/list response
body. [IMPLEMENTED] [UNIT TESTED]

### SSRF protection

`app/services/cctv_security.py::validate_stream_target` resolves the
camera's hostname and checks the **resolved** IP (not just the string
typed) against:
- an unconditional block list (cloud metadata endpoints, multicast,
  unspecified/broadcast), and
- an explicit, deployer-configured allowlist (`CCTV_ALLOWED_NETWORKS`,
  comma-separated CIDRs).

No allowlist configured ⇒ no camera target can ever validate
(fail-closed). This is deliberately **not** a blanket private-IP block
— authorized CCTV commonly lives on private networks; you must list
them explicitly. Enforced both at camera creation/update time and at
every connectivity test. [IMPLEMENTED] [UNIT TESTED] —
`tests/test_cctv_providers.py`.

Also closing a whole class of scheme-confusion SSRF bugs: the API never
accepts a raw URL from the client — `stream_protocol` is a closed enum
(`rtsp`/`rtsps`), and `stream_host`/`stream_port`/`stream_path` are
separate fields, so there's no `file://`/`gopher://` scheme for a client
to smuggle in the first place.

### Geo / nearby camera

`CCTVCamera.location` carries a 2dsphere index. `GET
/cctv/cameras/nearby` and `GET
/cctv/incidents/{incident_id}/nearby-cameras` both use MongoDB's
`$geoNear` aggregation — no Python-side Haversine distance calculation
anywhere in this subsystem. The incident-anchored endpoint is read-only:
it identifies nearby *already-registered, authorized* cameras for
Control Room; it does not itself start a stream or modify the incident.
[IMPLEMENTED] [UNIT TESTED] — `tests/test_cctv_streams_geo.py`.

### CCTV provider architecture

`app/services/cctv_providers.py::CCTVProvider` is the abstraction;
`get_provider(provider_type)` returns the right implementation.

| Provider | validate_connection | start_stream (media bridge) |
|---|---|---|
| RTSP | [IMPLEMENTED] [UNIT TESTED] — real TCP connect + RTSP `OPTIONS`, against a local fake server in tests. [RUNTIME VERIFIED: NO] [PHYSICAL CAMERA VERIFIED: NO] | [NOT IMPLEMENTED] — see Streaming below |
| ONVIF | [NOT IMPLEMENTED] — raises `NotImplementedError` | [NOT IMPLEMENTED] |
| NVR | [NOT IMPLEMENTED] | [NOT IMPLEMENTED] |
| VMS | [NOT IMPLEMENTED] | [NOT IMPLEMENTED] |

### Streaming (browser-viewable video)

`CCTVStreamSession` lifecycle (`requested → active|failed → stopped`),
RBAC, audit logging, and WebSocket events are fully implemented and
real. The actual WebRTC/HLS media bridge is **not implemented**: this
repository's existing LiveKit integration
(`app/routers/live_stream.py`) is a WebRTC *publish* path driven by a
device's own LiveKit client SDK, with no existing code path for pulling
an RTSP source into a room, and I could not verify the exact
`livekit-api` Ingress-service call shape against a real LiveKit
deployment in this environment. Rather than guess at an SDK surface I
couldn't confirm, every stream request today completes honestly as
`status=failed` with a clear error — the session bookkeeping is real,
the video bridge is a documented extension point
(`CCTVProvider.start_stream`). [IMPLEMENTED: session lifecycle only]
[NOT IMPLEMENTED: media bridge] [CONFIGURATION REQUIRED: a confirmed
LiveKit Ingress integration or a separate gateway like MediaMTX, before
this can ever return a playable stream].

### Audit logging

Every mutation is audited via the existing `log_action` helper:
`camera_created`, `camera_updated`, `camera_enabled`, `camera_disabled`,
`camera_deleted`, `camera_tested`, `camera_status_changed`,
`camera_stream_requested`, `camera_stream_started`,
`camera_stream_stopped`, `camera_stream_failed`. Never logs a camera
secret. [IMPLEMENTED]

### WebSocket events

`cctv.registered`, `cctv.updated`, `cctv.deleted`, `cctv.enabled`,
`cctv.disabled`, `cctv.online`/`cctv.offline`/`cctv.status_changed`,
`cctv.stream_requested`, `cctv.stream_started`, `cctv.stream_ended`,
`cctv.stream_failed`. Published **only** to the `control_room` WebSocket
room — `app/routers/websocket.py` never places a station/constable
connection into that room in the first place, so this is enforced
structurally, not just by convention. [IMPLEMENTED] [UNIT TESTED] —
`tests/test_cctv_streams_geo.py`.

### Demo mode

Every test fixture camera created via `tests/conftest.py::make_cctv_camera`
sets `is_demo=True`. No demo-seeding script is included for CCTV (unlike
AP-presence below) since a CCTV camera needs a real RTSP source to be
useful even as a demo — register one against a local test RTSP server
(e.g. `ffmpeg`'s RTSP output, or any RTSP test stream) and mark it
`is_demo: true` in the create request.

### Environment variables

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `CCTV_ENABLED` | optional | `true` | Set `false` to remove `/cctv/*` routes entirely |
| `CCTV_ALLOWED_NETWORKS` | **required** for any camera to validate | empty (fail-closed) | SSRF allowlist, comma-separated CIDRs |
| `CCTV_SECRET_KEY` | required in production (when enabled) | insecure dev fallback + warning | Fernet key for camera secrets |
| `CCTV_RTSP_CONNECT_TIMEOUT_SECONDS` | optional | `5` | RTSP probe timeout |

---

## 2. AP-Based Police Presence

Routers: `app/routers/access_points.py` (AP management),
`app/routers/presence.py` (association reporting + current state +
history). Models: `app/models.py::AccessPoint`, `PolicePresence`,
`PresenceHandoff`. Service: `app/services/presence.py::PresenceService`.

**This phase built the backend only.** No frontend/simulation portal
exists in this repository — see the implementation report for why that
was explicitly descoped.

### Architecture

```
Constable's own device (JWT-authenticated, same ownership check as
device heartbeat/battery reporting)
        |
        | POST /presence/association
        v
PresenceService.process_association()   [IMPLEMENTED] [UNIT TESTED]
        |
   same-AP repeat?  --yes--> update last_seen_at only, no handoff row
        |no
        v
  PresenceHandoff row inserted + PolicePresence updated
        |
        v
  WebSocket: presence.connected (first-ever) or presence.handoff
        |
        v
  control_room + the constable's own station room
```

### Why three separate models

- `AccessPoint` — the fixed infrastructure asset (like `PoliceStation`).
- `PolicePresence` — one row per device, current state (like
  `Device.status`/`last_seen_at`).
- `PresenceHandoff` — append-only movement history (like `AuditLog`).

`PresenceHandoff` is a regular `Document`, **not** a time-series
collection (unlike `ConstableLocation`/`BatteryReading` elsewhere in
this codebase) — MongoDB does not support unique indexes on time-series
collections, and a genuine unique index on `event_id` is exactly what
makes a retried association request idempotent.

### Business logic: one path, reused

`PresenceService.process_association()` is the single entry point every
caller must go through — today that's only the authenticated
constable-device endpoint below. A future edge server or a dev-only
simulator endpoint (**neither exists yet**) would call this exact same
function, never a second, divergent write path.

Handles:
- **Duplicate same-AP heartbeat** → no handoff row, `handoff_count`
  unchanged. [IMPLEMENTED] [UNIT TESTED]
- **AP-to-AP handoff** → one `PresenceHandoff` row, `handoff_count`
  incremented, `presence.handoff` published. [IMPLEMENTED] [UNIT TESTED]
- **Retried request with the same `event_id`** → idempotent, via a
  sparse unique index on `PresenceHandoff.event_id` +
  `DuplicateKeyError` handling (same pattern as `Alert`/`Chunk`
  elsewhere in this codebase). [IMPLEMENTED] [UNIT TESTED]
- **Disabled access point** → `409`, no state change. [IMPLEMENTED]
  [UNIT TESTED]
- **Unknown access point code** → `404`. [IMPLEMENTED] [UNIT TESTED]
- **Device not registered / owned by another constable** → `404`/`403`
  (reuses `devices.py`'s existing ownership check verbatim).
  [IMPLEMENTED] [UNIT TESTED]
- **Stale/offline detection** — lazy, computed on read
  (`compute_effective_presence_status`), same "no background
  scheduler" design as `Device.status`. Thresholds
  (`presence_stale_seconds`/`presence_offline_seconds`) are
  runtime-configurable via `POST /settings/` (admin), not environment
  variables. [IMPLEMENTED] [UNIT TESTED]

`source` on every handoff/presence row is `REAL` or `SIMULATOR`
(`PresenceEventSource`) — but the only endpoint that exists today
(`POST /presence/association`) **always** writes `REAL`; it has no
field for a client to claim otherwise. A `SIMULATOR`-tagged path would
require a separate, clearly-marked, dev-only endpoint that does not
exist in this phase.

### API

- `POST /presence/association` — constable's own device only. Body:
  `device_identifier`, `access_point_code`, optional `event_id`,
  optional `occurred_at`.
- `GET /presence/me` — the authenticated constable's own device(s).
- `GET /presence/` — role-scoped list (admin/control_room: all;
  station: own station's constables; constable: own only; citizen:
  403).
- `GET /presence/devices/{device_id}` — single device, same
  authorization as the equivalent `GET /devices/{id}`.
- `GET /presence/devices/{device_id}/history` — paginated movement
  history, most-recent-first.

Access point management mirrors `PoliceStation`'s exact RBAC:
`POST/PATCH/DELETE /access-points/*` and enable/disable (admin only);
`GET /access-points/*` (admin/control_room: all; station: own only;
constable/citizen: denied).

[IMPLEMENTED] [UNIT TESTED] — `tests/test_presence.py`,
`tests/test_access_points.py`, `tests/test_presence_websocket.py`.

### WebSocket events

`presence.connected`, `presence.handoff`, `presence.stale`,
`presence.offline`, `presence.online` (recovery). Routed exactly like
the existing `constable.location_updated` event: control_room + the
constable's own station — never back to the constable themselves, never
to any other constable. [IMPLEMENTED] [UNIT TESTED] —
`tests/test_presence_websocket.py`.

### Demo data

`scripts/seed_ap_presence_demo.py` — idempotent, `--reset`-capable,
creates the "DEMO JATARA ZONE" deployment: four `AccessPoint`s
(`AP-01` Main Gate, `AP-02` Temple Area, `AP-03` Parking Area, `AP-04`
Food Area, all `is_demo=True`) plus one demo constable/device (badge
`POL-023`, device `DEV-023`, phone `9990003023`, password
`Demo@12345`). Coordinates are synthetic and do not correspond to a
real location. Safe to run repeatedly; matched by natural key
(`AccessPoint.code` / `User.phone` / `Device.device_identifier`), never
duplicated, and never collides with `seed_demo.py` or
`scripts/seed_test_data.py`'s own phone ranges.

```bash
python scripts/seed_ap_presence_demo.py          # create/verify
python scripts/seed_ap_presence_demo.py --reset   # remove only this demo data
```

### What this phase explicitly did NOT build

- The simulation/validation portal (frontend) described in the original
  request — no frontend project exists in this repository at all.
- A dev-only `SIMULATOR`-source endpoint.
- An edge-server integration.
- Multi-officer/replay/export UI — all frontend concerns, out of scope
  for a backend-only phase.

See the implementation report delivered alongside this phase for the
full reasoning.

### Environment variables

None added. `presence_stale_seconds`/`presence_offline_seconds` are
configured via `POST /settings/` (admin), the same mechanism as the
existing `device_stale_seconds`/`device_offline_seconds`.
