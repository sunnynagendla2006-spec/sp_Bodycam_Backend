# Bodycam offline video transport (Network Hopping)

**Status: implemented but not run.** Nothing described here has been tested, built, started or exercised against real
phones, receivers or a control room. Treat every statement as design intent until you have validated it (see
"Validation you must do").

## 1. Purpose

At a site with no (or unreliable) internet, an officer's bodycam phone must still hand its video to something that keeps
it safely, and that video must reach the control room when the site's internet link ("backhaul") returns.

```
 phone (Flutter) --Wi-Fi/LAN--> site receiver --(backhaul returns)--> control room (FastAPI + MongoDB)
   keeps every chunk             SQLite + files                         authoritative evidence store
   until the control room        verifies, fsyncs, acknowledges,        verifies hash again, preserves the
   confirms it                   forwards with retry                    original, watermarks a derivative
```

Online mode (phone straight to the control room) is unchanged and remains the default. Network Hopping is an explicit,
per-phone mode switch.

## 2. Components

| Part | Where | Role |
|---|---|---|
| Control room | `backend/app` | Authoritative store; issues offline grants; owns receivers, assignments, device authorizations; ingests from receivers (`/receiver/v1/*`) |
| Site receiver | `backend/site_receiver` | Runs on the site LAN. Accepts chunks from phones, stores them durably, forwards to the control room |
| Phone app | `mobile` | Records 20 s MP4 chunks, hashes them, chooses a route, keeps each chunk until the control room confirms it |
| Dashboard | `frontend` (Site > "Video transfer") | Receiver health, recordings and chunks, assignments, devices, grants, audit |
| Collector | `backend/collector` | Unchanged. Network monitoring telemetry; independent of video transport |

## 3. Chunk lifecycle

Receiver (column `state`):

```
RECEIVING            upload in flight; nothing stored, nothing acknowledged
LOCALLY_DURABLE ---> bytes verified (size + SHA-256), fsynced, atomically renamed, metadata committed; ONLY NOW acknowledged
PENDING_SYNC         waiting to be forwarded                    (pending_sync)
SYNCING              a forward attempt is in progress           (syncing)
failed_retry         retryable failure; next attempt scheduled with exponential back-off and jitter
CENTRAL_ACKNOWLEDGED the control room confirmed identical content (central_acknowledged)
quarantined          never retried automatically: hash/id conflict, permanent rejection, or local corruption; needs a person
purged               file deleted under the retention policy after central acknowledgement (metadata kept)
```

Phone (`chunk_queue.upload_state`): `pending` -> `uploading` -> `local_acked` (receiver holds it durably; **file kept**) ->
`uploaded` (control room confirmed; **file deleted**). `failed` means a definitive refusal of the content (file kept).
Network or server problems never mark a chunk failed: they are retried indefinitely with persisted exponential back-off
(5 s doubling to 5 min, +/-25 % jitter). The former "8 retries then failed" rule is gone.

## 4. Offline grants

A grant is an ES256 JWS signed **only** by the control room (private key from `GRANT_SIGNING_PRIVATE_KEY_FILE`/`_PEM`).
Receivers hold only the **public** key, so a compromised receiver cannot mint grants.

Claims: `iss`, `sub` (officer), `jti` (grant id), `site`, `site_code`, `org`, `dev` (device id), `devid` (device
identifier), `asg` (assignment), `zone`, `ops` (`session`, `upload`, `live`), `iat`, `exp`, `ver`; header `kid`.

Lifecycle:

1. **Eligibility.** An officer has an *active site assignment* and the phone has an *authorized device record* for the site;
   the site is active; the signing key is configured.
2. **Issue.** The phone calls `GET /mobile/v1/network-hopping/config` while it can reach the control room. It receives the
   site's receivers and a fresh grant for each eligible site. Administrators can also issue one by hand.
3. **Use.** At the site the phone sends the grant to the receiver (`POST /v1/auth/session`). The receiver verifies signature,
   algorithm (ES256 only), expiry, issuer, key id (if pinned), site, and its revocation list, then hands back a short-lived
   HS256 session token bound to the same officer/device/site/grant and never valid past the grant's expiry. Every request
   re-checks the revocation list.
4. **Renew.** While online the phone renews it automatically (it refreshes when stale or within 2 h of expiry). Default
   lifetime 8 h (`GRANT_LIFETIME_HOURS`, 1-168).
5. **Revoke.** Revoking a grant, an assignment, a device authorization, or the officer marks grants revoked at the control
   room; receivers learn of it at their next sync and stop accepting it.

**Unavoidable limitation.** A receiver that cannot reach the control room cannot learn of a revocation. A revoked grant
remains usable at that receiver until it expires or the receiver next syncs. Keep the lifetime as short as your operations
allow, and revoke the *receiver* credential if a receiver itself is compromised. Receiver and phone clocks must be right
(NTP); expiry is checked locally.

## 5. Provisioning checklist (for the operator, later)

1. Generate the grant key pair offline; install the private key on the control room only (`.env.example`).
2. Create/identify the site; add zones as needed.
3. Site > Video transfer > **Receivers** > Add receiver. Copy the one-time token into the receiver's secret store.
4. Install the receiver on the site LAN (section 9), give it the site id/code, the control-room URL, the token, and the grant **public** key.
5. **Assignments**: assign the officers. **Devices**: authorize their phones for the site.
6. Each officer opens the app while online > Network Hopping > Network Hopping mode > *Refresh from control room*.
7. Check the receiver shows **online** and "Test connection" on the phone succeeds on the site Wi-Fi.

## 6. Control-room API additions

| Endpoint | Who | Purpose |
|---|---|---|
| `/sites/{id}/bodycam/receivers` (CRUD, `rotate-token`, `revoke`, `commands`) | admin manage / control_room view | Receiver registry and operator commands (`resync`, `retry_quarantined`, `retry_recording`) |
| `/sites/{id}/bodycam/assignments` | admin / view | Officer-to-site assignments |
| `/sites/{id}/bodycam/device-authorizations` | admin / view | Phone-to-site authorization |
| `/sites/{id}/bodycam/grants` | admin / view | Issue / list / revoke grants |
| `/sites/{id}/bodycam/recordings`, `/recordings/{rid}` | view | Recordings with `sync_state` and per-chunk original/derived hashes |
| `/sites/{id}/bodycam/overview`, `/audit` | view / admin | Health summary and audit trail |
| `GET /mobile/v1/network-hopping/config` | constable | Phone provisioning and grant renewal |
| `/receiver/v1/heartbeat`, `/sync`, `/recordings/{rid}`, `/recordings/{rid}/chunks/{cid}`, `/recordings/{rid}/complete`, `/recordings/{rid}/manifest` | receiver credential | Ingestion; the site comes **only** from the credential |
| `POST /recordings/start` (+`recording_id`, `site_id`), `POST /recordings/{id}/chunks` (+`chunk_id`, `sha256`) | constable | Existing endpoints, backward compatible; a client recording id makes start idempotent |

Data models added: `SiteAssignment`, `DeviceSiteAuthorization`, `OfflineGrant`, `SiteReceiver`; extended `RecordingSession`
(`site_id`, `receiver_id`, `origin`, `grant_id`, `flags`) and `Chunk` (`original_storage_key`, `original_hash`, `original_size`,
`derived_hash`, `processing`, `received_via`, `receiver_id`, `captured_start/end`, `site_received_at`).

Conflict handling at the control room: same chunk id + same hash = duplicate acknowledgement (idempotent); same number or id
with a different hash = `409 hash_conflict` (never overwritten; the receiver quarantines it); recording id owned by another
officer/device = `409 recording_id_conflict`; grant problems are `grant_required / grant_mismatch / grant_window /
grant_revoked`. A recording whose grant was revoked *after* the footage was captured is accepted and flagged
`grant_revoked_later` rather than dropped.

## 7. Evidence integrity and watermark policy

* The phone computes a SHA-256 over each chunk the moment the segment is finalized. The receiver and the control room each
  recompute it over the received bytes and reject a mismatch (`hash_mismatch`; the sender resends).
* The receiver acknowledges only after the file is fsynced and renamed into place **and** its row is committed.
* The control room keeps the **original bytes exactly as received** (`original_storage_key`, `original_hash`). The
  watermarked file is a separate **derivative** with its own `derived_hash` and a `processing` provenance record
  (`PRESERVE_ORIGINAL_EVIDENCE=true`, default). The watermark never replaces the original.
* Recordings made before this upgrade have no preserved original (they were watermarked in place); the dashboard shows
  "no original" for them and the migration deliberately does not pretend otherwise.
* The phone deletes a local chunk only after the control room's own manifest shows the same chunk with the same SHA-256. A
  mismatch there marks the chunk failed and keeps the file.
* A site receiver is untrusted for identity: it cannot widen its site, and everything it forwards is re-verified.

## 8. Storage sizing

Receiver disk holds every phone's video for the longest outage you must survive, plus retention of already-synced video.

`bytes = bitrate/8 x 3600 x hours_per_device_per_day x devices x outage_days x 1.10`

Use `python -m site_receiver.capacity --devices N --hours H --outage-days D --bitrate-kbps B`, or the receiver's
`GET /v1/admin/capacity-estimate`. The 4000 kbps default is a **planning figure, not a measurement**; measure the real
median chunk size from your phones. Example: 40 phones x 8 h x 3 days at 4 Mbps is about 1.4 TiB. Set
`RECEIVER_MIN_FREE_MB` so the receiver stops accepting (HTTP 507, `Retry-After`) before the disk is full; phones then keep
their copies, or use the control room if it is reachable. Use a UPS and a journaling filesystem on a dedicated volume;
keep the SQLite database on the same durable disk. Phone storage: in this mode a phone may hold hours of unconfirmed video,
so the app warns below 1 GiB free and again below 300 MiB.

## 9. Install and startup (for later; not done here)

Receiver host (Linux, Python 3.11+):

```
python -m venv /opt/bodycam-receiver/venv && /opt/bodycam-receiver/venv/bin/pip install -r backend/site_receiver/requirements.txt
set -a; . /etc/bodycam-receiver/receiver.env; set +a            # see site_receiver/receiver.env.example
/opt/bodycam-receiver/venv/bin/uvicorn site_receiver.main:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile /etc/bodycam-receiver/tls.key --ssl-certfile /etc/bodycam-receiver/tls.crt --workers 1
```

Run under systemd with `Restart=always`, a dedicated user, and file permissions 0600 on secrets. **One worker only**: rate
limits and chunk locks are in-process. On start it recovers `syncing` rows, removes stale `.tmp` uploads, and resumes
forwarding. Control room: apply `.env.example` additions, restart, run the migration (section 11).
Mobile: `flutter pub get` (adds `crypto`), then build as usual. Frontend: no new dependencies.

## 10. TLS and VPN

* Phones validate TLS normally; the app never disables certificate validation. Give the receiver a certificate the phones
  trust: a public CA name resolving to the LAN address (split-horizon DNS), or a private CA installed on managed phones
  (Android network security config / MDM). A receiver with an untrusted certificate is simply unusable until fixed.
* The receiver verifies the control room's certificate (`RECEIVER_CENTRAL_CA_FILE` for a private CA). Plain `http://` to
  the control room is refused unless `RECEIVER_ALLOW_INSECURE_CENTRAL=true` (trusted private link or development only).
* A site-to-control-room VPN (WireGuard/IPsec) is recommended for the receiver's backhaul; it protects the link but does not
  replace token authentication or hash verification. Do not expose the receiver to the internet. Plain-http receivers
  are for isolated labs only (the app's manifest still allows cleartext for development).

## 11. Migrations (created, not executed)

`python -m scripts.migrate_bodycam_site_transport [--dry-run]` backfills `origin`/`flags` on recordings and `received_via`
on chunks. Beanie creates the new collections and indexes at start-up. The script is idempotent and deletes nothing.
Phone: the local queue upgrades from schema v2 to v3 automatically on first launch (additive columns only).

## 12. Environment variables

Control room (`.env.example`): `GRANT_SIGNING_PRIVATE_KEY_FILE` / `_PEM`, `GRANT_SIGNING_KEY_ID`, `GRANT_ISSUER`,
`GRANT_LIFETIME_HOURS`, `PRESERVE_ORIGINAL_EVIDENCE`, `RECEIVER_RATE_LIMIT_PER_MINUTE`.
Receiver (`site_receiver/receiver.env.example`): `RECEIVER_SITE_ID`, `_SITE_CODE`, `_NAME`, `_CENTRAL_URL`,
`_CENTRAL_TOKEN(_FILE)`, `_CENTRAL_CA_FILE`, `_ALLOW_INSECURE_CENTRAL`, `_GRANT_PUBLIC_KEY_PEM/_FILE`, `_GRANT_ISSUER`,
`_GRANT_KEY_ID`, `_ACCESS_TOKEN_SECRET(_FILE)`, `_ACCESS_TOKEN_MINUTES`, `_ADMIN_KEY(_FILE)`, `_STORAGE_ROOT`, `_DB_PATH`,
`_MAX_CHUNK_MB`, `_MIN_FREE_MB`, `_UPLOAD_CONCURRENCY`, `_FORWARD_CONCURRENCY`, `_BACKOFF_BASE_SECONDS`,
`_BACKOFF_MAX_SECONDS`, `_MAX_HARD_ERRORS`, `_RETENTION_AFTER_SYNC_DAYS`, `_PURGE_SYNCED_ON_LOW_SPACE`,
`_RATE_LIMIT_PER_MINUTE`, `_HEARTBEAT_SECONDS`, `_LOCAL_LIVEKIT_URL`, `_LOCAL_LIVEKIT_API_KEY(_FILE)`,
`_LOCAL_LIVEKIT_API_SECRET(_FILE)`, `_LOG_LEVEL`. Dependency manifests: backend `requirements.txt` already carries
python-jose, cryptography, httpx, python-multipart (nothing new); `site_receiver/requirements.txt` lists the receiver's;
`mobile/pubspec.yaml` adds `crypto`.

## 13. Retention

Receiver: video the control room confirmed is kept `RECEIVER_RETENTION_AFTER_SYNC_DAYS` (default 7; 0 = remove at once),
then the file is deleted and the row marked `purged` (hashes and timestamps stay). With
`RECEIVER_PURGE_SYNCED_ON_LOW_SPACE=true` confirmed video may be removed earlier when space is short. The receiver **never**
deletes a chunk the control room has not confirmed. Phone: a chunk file is deleted only after control-room confirmation.
The optional low-storage exception (off by default, Network Hopping screen): when phone storage is critical, the oldest
chunks a receiver already holds may be deleted from the phone first; that evidence then exists only on the receiver until
it syncs.

## 14. Mobile behavior

* Mode toggle (default **Online**) on the Network Hopping screen; the home screen shows a banner while the mode is on.
* Provisioned receivers and the grant are stored in secure storage. A runtime receiver-address override can be typed in.
* Routing per upload pass: receiver (if reachable, right site, accepting uploads, valid grant) else control room directly
  (if reachable) else wait. Connectivity is detected by probing; no extra permissions are needed.
* A Network Hopping recording starts with a client-generated UUID and needs no control-room call to start. If the app
  starts with no connectivity it falls back to the last device registration so recording is still possible.
* A central 401 does not force logout while Network Hopping is on and the grant is valid; the officer re-authenticates
  next time online. When the grant expires the officer must go online and sign in again to renew it.
* Live view in this mode uses the site-local LiveKit through the receiver when configured; otherwise the app says live
  view is unavailable (recording and upload continue).

## 15. Known limitations

* Nothing has been executed or verified (no tests, builds, servers, phones, receivers).
* Revocation cannot reach an offline receiver (section 4). Cancelling a recording in this mode does not recall chunks a
  receiver already holds.
* Receiver "live" is only as good as the site LAN and needs a LiveKit server on site; the delayed chunk playback endpoint
  is near-live at best and is labelled as such.
* One receiver process per site (no clustering); a receiver disk failure loses what it alone holds (the phone retains
  copies until central confirmation unless the low-storage exception was used).
* Phone-side hashing/uploading of long recordings adds CPU and battery use; unmeasured.
* The grant is a bearer credential on the phone (secure storage); a stolen unlocked phone can use it until it expires or is revoked.
* Recordings captured before the upgrade have no preserved original.
* The central health probe assumes the control room answers HTTP on its base URL; any HTTP response counts as reachable.

## 16. Validation you must do

Unit and integration tests for grant verification, idempotency/conflict handling, crash recovery (kill during upload,
during fsync, during forwarding), disk-full behavior, clock skew, grant revoke/renew, Android upgrade of the v2 queue,
large queues, TLS with a private CA, and a full outage drill with real phones, before relying on this for evidence.

## 17. Hardening revision (source-inspection pass; still unexecuted)

These changes supersede any earlier wording above that disagrees.

**Acknowledgement levels.** A receiver reply to a phone carries `ack`: `local_received` (durably stored at the receiver only) or
`central_received` (the control room confirmed identical content). `status: locally_durable` is kept for older callers and never
means archived. The phone deletes a file only when the control room's own manifest (`GET /recordings/{id}/chunks`, field
`original_hash`) matches its SHA-256; a receiver reply, a completion call or a recording status never counts. Receiver
`complete` now reports `missing_chunk_numbers` and `central_received: false`; "completed" only means the phone has finished sending.

**Watermark and originals.** The watermark rewrites the stored file in place, so it is now applied **only when a pristine copy of the
original was preserved** (both `POST /recordings/{id}/chunks` and `/receiver/v1/...`). If preservation is disabled
(`PRESERVE_ORIGINAL_EVIDENCE=false`) or fails, the stored file stays byte-identical to what the phone sent, no watermark is burned, and
`processing` records `watermark_skipped`. This replaces the old "flag false = watermark in place" behaviour.

**Receiver crash recovery** (`site_receiver/recovery.py`, run at every start before forwarding resumes):
* Rows whose file is missing or the wrong size (not yet confirmed centrally) are quarantined with a reason; a phone that still holds the
  chunk heals the row by re-uploading identical bytes (state returns to pending, audit `chunk_healed`).
* Rows confirmed centrally whose file is gone become `purged`.
* Files with no row (crash between rename and metadata commit; never acknowledged) are moved to `.orphans/`, never deleted or adopted.
* A lock file `<RECEIVER_DB_PATH>.lock` prevents two receiver processes sharing one database/storage root; the second refuses to start.
* Disk-full during upload returns 507 + `Retry-After`; other I/O or SQLite failures return 503 + `Retry-After`. Nothing is acknowledged in these cases.
* Heartbeat `last_central_ack_at`/`last_local_upload_at` are derived from stored data; the control room no longer invents a confirmation time.

**Phone routing and authorization.**
* Only Network Hopping chunks (those carrying a site id) may go to a receiver, and only to a receiver of the same site. Online-mode chunks always go to the control room.
* A receiver refusing the grant (revoked, expired, wrong device, operation not permitted) pauses receiver uploads for 10 minutes (lifted by
  "Sync now" or a provisioning refresh), keeps every chunk queued, and shows the reason. It is not retried as a network error. Short session
  expiry / receiver-restart (`session_*` 401) just opens a new session.
* A central 401 under a valid offline grant no longer forces logout; the screens say the control-room sign-in expired and must be renewed online.
* Fallback policy (`Fallback policy` switch, default on): with no usable receiver, site chunks may go directly to the control room.
* Receiver address overrides must be `https://host[:port]` (plain `http` only for loopback/private addresses); certificates are always validated.

**Known remaining gaps** (not fixed here): no automatic receiver-side detection of a corrupted file until it is next forwarded;
multi-file SQLite backup is the operator's job; grant revocation latency for offline receivers is unchanged; the optional low-storage purge
on the phone still exists (off by default) and, if enabled, removes local copies before central confirmation by explicit operator choice.

## 18. Audit-closure revision (source changes only; nothing executed)

This section supersedes any earlier text that disagrees. Status of every change: written, never run.

**Concurrent ingestion (DATA-001).** Every ingest request writes its chunk (and its preserved original) under keys that contain a
per-request random token (`chunk_000007_<token>.mp4`, `original/chunk_000007_<token>.mp4`). The database row references only the keys of the
request that won the atomic push; a request that loses, or whose database write fails, deletes only the keys it wrote itself. Nothing ever
deletes or overwrites another request's object. Limitation: a request that crashes between writing the file and the database push leaves an
unreferenced object (storage waste, no evidence loss); the object store has no conditional-write primitive here, so none is used.
Recordings stored before this change keep their old number-only keys and are unaffected.

**Recording start (DATA-003).** A client-supplied recording id is idempotent even under concurrent identical requests (a duplicate-key
collision returns the existing session for the same officer/device, 409 otherwise). A start carrying a client id no longer marks the device
as `recording` (it may be a late registration); the legacy flow without an id is unchanged.

**Provisioning (MOB-001).** Receivers without an address are returned with `configured: false` and no address; the phone skips them, shows
how many were skipped, and keeps all other receivers. Receiver addresses must be https (`ALLOW_HTTP_RECEIVER_ENDPOINTS=true` only for a
development lab). Parse failures after a successful reply are reported as `provisioning_response_invalid`, not as "control room unreachable".

**Endpoint trust (SEC-001).** The phone validates every receiver address each time it is used (https only; no credentials, query, fragment or
path); a debug build made with `--dart-define=ALLOW_INSECURE_RECEIVER=true` may use plain http to a loopback/private host, nothing else. A private
network address is never treated as proof of trust. Receiver identity rests on TLS: the certificate must validate for the provisioned host name
(for a private site CA, install that CA on the managed phones; the app never bypasses certificate checks). `/v1/health` is a readiness probe only
(`status`, `service`, `api`, `ready`) and is never used as identity. After the receiver accepts the grant, the session reply names the site it serves
and the phone discards the session on a mismatch. **Not implemented:** certificate/public-key pinning. It needs a decision on how pins are provisioned,
rotated and revoked; until then identity is exactly as strong as the CA that issued the receiver certificate. Android: `usesCleartextTraffic` is
now `false` in the main manifest and `true` only in the debug manifest.

**Phone-side grant verification (SEC-002).** `lib/services/grant_verifier.dart` verifies the ES256 signature (header algorithm must be `ES256`),
issuer, site, device, officer, `upload`+`session` operations, `iat`/`exp` with a 2-minute skew allowance. It runs when provisioning arrives and again
immediately before the grant would be sent to a receiver; a failing grant is dropped and never presented. Trusted keys: the public key the control
room returns at provisioning (`grant_public_keys`), or, if the build defines `GRANT_PUBLIC_KEY_PEM`, only that pinned key. The receiver still verifies
independently. Key rotation: the control room serves its current key id and key; pinned builds need a new build. New dependency in
`mobile/pubspec.yaml`: `dart_jsonwebtoken` (`pubspec.lock` was NOT regenerated).

**Quarantined chunks (REC-001).** A re-upload of a chunk that exists on the receiver now behaves by state: intact file and healthy state = duplicate acknowledgement;
missing file, or a quarantined chunk whose file no longer matches its recorded size/hash = the damaged file is moved to `.quarantine/` (never deleted),
the verified upload is stored in its place and the chunk returns to the forwarding queue; quarantined for another reason (for example the control room refused it)
= `409 chunk_quarantined`, no acknowledgement. The phone treats a quarantined acknowledgement or `chunk_quarantined` as a failure that keeps the original and lists it
under "Needs attention". A reused chunk number with a different chunk id is `409 identity_conflict`.

**Forwarding classes (REC-002, REC-003).** See the table at the top of `site_receiver/forwarder.py`. Every 5xx and 408/425/429 is retried forever with durable
back-off and `Retry-After`; quarantine is reserved for integrity and policy failures. Recording completion has its own durable schedule
(`recordings.complete_next_at`, `complete_attempts`) and a visible reason; it is never requested while any chunk is unconfirmed or quarantined.
Operator intervention is needed only for quarantined chunks and for a rejected receiver credential.

**Request size (SEC-005).** `BodyLimitMiddleware` (central: `app/services/body_limit.py`, receiver: `site_receiver/limits.py`) refuses chunk-upload bodies larger than
the limit (+1 MiB for form fields) using the declared Content-Length and by counting received bytes, before multipart parsing. It cannot help once a body has been
read by a proxy or by the server's own socket layer, so a reverse proxy must enforce the same limit, for example nginx: `client_max_body_size 101m;` on the
chunk-upload locations (and `client_body_temp_path` on a volume with room). Spooled parts use the system temp directory: set `TMPDIR` to the evidence volume.

**Site isolation of lists (SEC-003).** `GET /recordings/` removes recordings of restricted sites the control-room user may not view before paging.
Detail, manifest and the site-scoped Bodycam APIs already used the same policy.

**Receiver endpoints (SEC-004).** `/v1/health` no longer discloses the site id, site code, version or time. Unauthenticated session attempts are rate-limited per client address in their own
bucket, failed admin-key attempts per address in another; correct credentials are never throttled by failures. Behind a proxy all clients share the proxy address, so limit at the proxy too.

**Grant records (MOB-006).** A provisioning refresh re-signs an existing valid grant (same id, same expiry) when more than half its lifetime remains, instead of creating a record each time;
the token is never stored. `scripts/purge_expired_offline_grants.py` (dry run by default, not scheduled) removes records expired longer than `GRANT_RECORD_RETENTION_DAYS`; the audit log is untouched.

**Health contracts (ENV-001/002).** Central: `GET /healthz` returns `{status: ok, service: sp-bodycam-central}`; the phone requires exactly that, so a 404 from an older server counts as "health_missing", not as reachable
(redeploy the backend before relying on Network Hopping fallback). Receiver: `GET /v1/health` as above. `RECEIVER_ALLOW_INSECURE_CENTRAL`, `TMPDIR`, `ALLOW_HTTP_RECEIVER_ENDPOINTS` and `GRANT_RECORD_RETENTION_DAYS` are in the example files.

**Receiver-local recordings (UI-001).** Each heartbeat carries a bounded summary (at most 50) of recordings the receiver still holds that are not fully confirmed centrally.
`GET /sites/{id}/bodycam/receivers/{rid}/local-recordings` returns it with `stale` and `registered_centrally`. The dashboard lists recordings the control room does not know yet in their own table
("Held at the site receiver, not yet at the control room"), annotates central rows with the receiver's own count, shows expected chunks as "unknown" unless the phone declared them at completion,
and flags old reports. It is the receiver's statement and is labelled so.

**Mobile queue.** Routing is per chunk (Online-mode chunks always go to the control room; site chunks follow the receiver/fallback policy and wait without blocking the others). Before every upload the file is
checked against its recorded size and SHA-256; a mismatch parks the chunk as `failed` (`local_file_corrupt`), keeps the file, never recomputes the expected hash, and leaves the recording incomplete.
On upgrade to queue schema v3, rows `failed` with `retry_count >= 8` (the old retry cap, never a server decision) return to pending; other failures stay failed and can be re-queued from the Network Hopping
screen, except corrupt/missing files. The recording card never says "all uploaded" while any chunk is only at a receiver.

**Still open / needs a decision or infrastructure:** certificate or key pinning for receivers; a site-local LiveKit server; real vendor collectors; multi-key grant rotation without a rebuild for pinned
builds; a reverse proxy with body limits; regenerated `pubspec.lock`; every runtime behaviour in this document.
