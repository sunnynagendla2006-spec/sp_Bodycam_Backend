# CCTV Buildings, Media Gateway and Control-Room Wall

Status legend used below: **IMPLEMENTED** = code exists; **NOT RUNTIME VERIFIED** = nothing here has been
executed against a real MongoDB, MediaMTX, NVR or camera; **OPERATOR TASK** = needs infrastructure or
credentials that the code cannot provide.

## 1. What this adds

* **Buildings** (`models.Building`, collection `cctv_buildings`): one control-room slot each, many cameras.
  Owner, zone, address, latitude/longitude, optional public/static IP, connection method, secure-access
  mode, per-building authorized networks. Camera counts are always derived from camera rows.
* **Cameras** (`models.CCTVCamera`) gain optional `building_id`, `channel`, `sort_order` (+ health
  bookkeeping). Existing cameras are untouched and keep working as unassigned cameras.
* **Two connection methods** per building: **NVR/DVR** (default; one recorder endpoint, cameras are
  channels) and **direct IP** (each camera has its own endpoint).
* **Media gateway** (MediaMTX): RTSP/RTSPS in, WebRTC (WHEP) out, started on demand per viewed camera.
* **Playback authorization**: short-lived signed token per camera, checked by MediaMTX through the
  backend (`POST /cctv/gateway/auth`).
* **CCTV Wall** (`/cctv/wall`): one slot per enabled building, independent 5-second rotation, zone filter,
  search, pagination, manual selection, pause/resume, per-slot error/offline/reconnect states.
* **Admin** (`/cctv/buildings`): create/edit buildings and cameras, test, enable/disable, delete,
  assign legacy cameras.
* **Health monitoring** with back-off and a per-building roll-up.

## 2. Architecture

```
Building NVR / IP camera
   | RTSP(S)   <-- over site-to-site VPN or an outbound tunnel (preferred; no public camera ports needed)
   v
MediaMTX (on-demand path per camera: cctv-<camera id>)
   | WebRTC (WHEP, video only)           ^ control API (internal network only)
   v                                      |
Browser (CCTV Wall slot) ---- token ---> FastAPI backend --(auth callback from MediaMTX)--> verifies token
```

* Only the camera **currently on screen** in a slot streams (default). `CCTV_PREFETCH_NEXT=true` also keeps
  the next camera warm (bounded by the stream cap). Slots off screen, in a hidden tab, or on another page
  hold no stream.
* MediaMTX connects to the camera only while someone watches (`sourceOnDemand`); the backend removes the
  path when a camera/building changes or is disabled.
* The credential-bearing RTSP URL exists only inside the backend process and the call to MediaMTX's
  internal API. Browsers receive a WHEP URL plus a token, never a source URL or camera credentials.
* Destination IPs are re-validated at playback time and the validated address is handed to MediaMTX
  (pinned) so DNS cannot change between check and connect. (`rtsps` keeps the hostname for certificate
  validation; its destination is still validated.)

## 3. Why a 5-second rotation uses ONE stream per slot

Registered cameras can be hundreds; bandwidth and gateway CPU scale with *simultaneous streams*, not with
registered cameras. Each slot opens one stream and switches camera each dwell period. WebRTC startup is
typically 1 to 3 seconds, so a strict 5 s dwell can include noticeable "connecting" time. The dwell time is
**not** shortened silently. Options if this is unacceptable in practice: set `CCTV_PREFETCH_NEXT=true`
(warm the next camera; raises concurrent streams up to 2 per slot, still capped by
`CCTV_MAX_CONCURRENT_STREAMS`), or raise `CCTV_ROTATION_SECONDS`.

No capacity figure is claimed: measure with your cameras' bitrate and your gateway host.

## 4. Connectivity model (per building)

| Mode | Use when | Needs from the building owner |
|---|---|---|
| `vpn` | Preferred. Site-to-site VPN to the police network | VPN endpoint; recorder reachable on its private IP (e.g. `10.20.5.2`) |
| `tunnel` | Owner cannot host a VPN | An on-site gateway that initiates an authenticated outbound tunnel to your network |
| `lan` | Gateway runs on the same private network | Nothing extra |
| `public_direct` | Last resort, explicitly approved | A static public IP with the RTSP port forwarded to the recorder, firewall limited to the gateway's address, strong recorder password. Requires `public_ip` on the building |

The **building public IP is the router/firewall address**. It is not the recorder or camera address
(those are normally private and sit behind it) and is never assumed to be.

### Authorizing a building's network (SSRF policy)

The global `CCTV_ALLOWED_NETWORKS` stays the baseline and is never widened. An **admin** authorizes the
networks for one building on its record (`authorized_networks`, CIDRs such as the VPN subnet). The
building's `public_ip` authorizes exactly that address. Rules enforced in code
(`services/cctv_security.py`):

* the authorization applies only to that building's cameras (context-scoped, not global);
* networks wider than /16 (IPv6: /48) are rejected;
* cloud-metadata, multicast and unspecified ranges stay blocked regardless of any allowlist;
* resolved addresses (not just typed names) are checked on registration, test, health probe and playback.

### Recorder requirements to give building owners

* A **read-only/viewer** recorder account for this system (never an admin account).
* RTSP enabled. Streams must be **H.264** (browsers cannot decode H.265 over WebRTC; this system does not transcode).
* Preferably a sub-stream or moderate bitrate for wall viewing.
* Correct time (NTP) on the recorder.

## 5. Vendor channel paths (explicit, not guessed)

NVR mode builds the stream path from the building's setting plus the camera's channel number:

* `hikvision`: `/Streaming/Channels/{channel}01` (channel 3 gives `/Streaming/Channels/301`)
* `dahua`: `/cam/realmonitor?channel={channel}&subtype=0`
* `custom`: an admin-written template containing `{channel}`, e.g. `/stream/{channel}`

Only `{channel}` may appear as a placeholder; unusual characters are rejected. Confirm the exact path of
each recorder model with its documentation before relying on a preset.

## 6. API summary (all under `/cctv`, admin and control_room unless noted)

| Method and path | Who | Purpose |
|---|---|---|
| `POST /buildings` | admin | Create building (+ initial cameras) |
| `GET /buildings` | viewer | Paginated list with embedded cameras; `zone`, `enabled`, `q`, `limit`, `offset` |
| `GET /buildings/zones` | viewer | Zone names for the filter |
| `GET /buildings/{id}` | viewer | One building (infrastructure fields shown to admins only) |
| `PATCH /buildings/{id}` | admin | Update; connection mode cannot change while cameras exist |
| `POST /buildings/{id}/enable` / `disable` | admin | Toggle (disable closes gateway paths) |
| `DELETE /buildings/{id}?cameras=reject|detach|delete` | admin | Safe delete |
| `GET/POST /buildings/{id}/cameras`, `PATCH .../{camera_id}`, `POST .../reorder` | viewer / admin | Cameras inside a building |
| `POST /buildings/{id}/test` | viewer | Probe recorder/cameras now |
| `GET /buildings/unassigned-cameras` | admin | Legacy/detached cameras |
| `PUT /cameras/{id}/building` | admin | Assign/detach a camera |
| `POST /buildings/health/run` | admin | Run one health cycle (for external schedulers) |
| `GET /streaming/config` | viewer | Rotation seconds, stream cap, gateway state |
| `POST /cameras/{id}/playback` | viewer | Token + WHEP URL for one camera |
| `POST /cameras/{id}/playback/report` | viewer | Report playback failure/recovery |
| `POST /cameras/{id}/stream`, `/stream/stop` | viewer | Audited session variant (camera detail dialog) |
| `POST /gateway/auth` | MediaMTX only | External-auth callback (shared key) |

Playback error codes are returned in the `X-CCTV-Error` response header (for example
`gateway_not_configured`, `camera_disabled`, `building_disabled`, `target_not_authorized`,
`stream_capacity`, `gateway_unreachable`).

WebSocket events (control_room room, no hosts/credentials): `cctv.building_created|updated|enabled|disabled|deleted`,
`cctv.building_health`, plus the existing camera events (now including `building_id`).

## 7. Environment variables

See `.env.example` (section "CCTV media gateway and building dashboard"). Required for live video:
`CCTV_GATEWAY_API_URL`, `CCTV_GATEWAY_PUBLIC_URL`, `CCTV_GATEWAY_AUTH_KEY`. Also `CCTV_SECRET_KEY` (Fernet)
and `JWT_SECRET_KEY` must be real values in production. The dashboard env var `VITE_CCTV_ICE_SERVERS`
(optional JSON array) supplies STUN/TURN for browsers that cannot reach the gateway's UDP port directly.

## 8. Deploying the gateway (OPERATOR TASK)

Files: `deploy/docker-compose.cctv.yml`, `deploy/mediamtx/mediamtx.yml` (pinned image `bluenviron/mediamtx:1.9.3`).

1. Join MediaMTX to the docker network of the backend (`BACKEND_NETWORK`).
2. Set `CCTV_GATEWAY_AUTH_URL` to `http://backend:8000/cctv/gateway/auth?key=<CCTV_GATEWAY_AUTH_KEY>` and
   `CCTV_GATEWAY_PUBLIC_HOST` to the address browsers use for media.
3. Put a TLS reverse proxy in front of port 8889 and open UDP 8189 in the firewall. Set
   `CCTV_GATEWAY_PUBLIC_URL` to the proxy's https URL.
4. Do **not** publish port 9997 (control API). Restrict the `authInternalUsers` CIDR in `mediamtx.yml` to the backend's network.
5. Establish VPN/tunnel connectivity to each building and add its subnet to the building's authorized networks.

Verify the MediaMTX option names against the pinned release (some changed in later versions).
**None of this has been started or tested.**

## 9. Health monitoring

* `CCTV_HEALTH_ENABLED=true` starts an in-process loop (one cycle per `CCTV_HEALTH_INTERVAL_SECONDS`)
  guarded by a short Mongo lease so only one backend replica probes at a time.
* Or leave it off and call `POST /cctv/buildings/health/run` (admin token) from cron/a Kubernetes CronJob.
* All channels of one NVR share **one** probe. Failures back off exponentially (`CCTV_HEALTH_MAX_BACKOFF_SECONDS`).
* A reachable recorder does not prove a channel has video; channel failures reported by the dashboard
  (`/playback/report`) mark that camera `degraded`.

## 10. Deployment, migration and backfill

* **No data migration is required.** New camera fields default (`building_id=null`, `channel=null`,
  `sort_order=0`, `consecutive_failures=0`). Beanie creates the `cctv_buildings` collection and the new
  indexes (`cctv_cameras(building_id, sort_order)`; building unique `code`, zone, enabled, name, 2dsphere)
  at startup (`init_db`), like every other collection. Allow the first start after upgrading to build indexes.
* **Backfill is a manual, admin-driven step:** create buildings, then assign existing cameras with
  *CCTV Buildings → Cameras not in a building → Assign* (or `PUT /cctv/cameras/{id}/building`). NVR buildings
  need a channel number per camera. Nothing is changed automatically.
* Rollback: the new fields are ignored by older code; dropping `cctv_buildings` and unsetting the camera
  fields fully reverts the data.

## 11. Known limitations

* Building access control is role-based (admin / control_room). There is no per-operator building scoping.
* Video only, WebRTC only: no HLS fallback and no audio. H.265 cameras need to be set to H.264.
* WebRTC token expiry is checked when a viewer connects, not mid-session.
* In-process health loop assumes one MongoDB; the stream cap is a soft limit (fails open if the gateway cannot report viewers).
* The rotation timer, stream budget and playback code have unit tests that have **not been run**.
