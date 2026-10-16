# Bodycam + Network Hopping integration: requirement checklist

Status words: **Implemented in source** (written, never executed), **Partial**, **Blocked** (external prerequisite), **Not implemented**.
Nothing here was tested, built or run. Paths are relative to `E:\SP_BODY_CAM`.

| Requirement | Status | Where |
|---|---|---|
| Stable recording UUID from phone through receiver to control room | Implemented in source | `mobile/lib/services/recording_service.dart` (local session id), `backend/site_receiver/main.py`, `backend/app/routers/receiver_ingest.py`, `backend/app/routers/recordings.py` (`recording_id` on start) |
| Legacy/online recordings unaffected; no mapping needed | Implemented in source | Online mode still lets the backend generate the id; Network Hopping chunks are tagged with a site id so they never mix (`chunk_uploader.dart`) |
| Idempotent recording + chunk ingest (duplicates, conflicts, races) | Implemented in source | receiver `main.py` (per-chunk lock, UNIQUE keys), central `receiver_ingest.py` (`find_one_and_update` guard, `hash_conflict`) |
| Out-of-order chunks / missing chunks / repeated completion | Implemented in source | chunks keyed by number; `complete` is idempotent and reports `missing_chunk_numbers`; recordings with gaps show `incomplete`, never `central` (`site_bodycam._sync_state`) |
| Recording status vs chunk delivery status kept separate | Implemented in source | receiver `recordings.status` vs `chunks.state` (`store.py`); phone `recording_sessions.lifecycle_state` vs `chunk_queue.upload_state` |
| Site-local receiver, durable store, ack after fsync + commit | Implemented in source | `backend/site_receiver/{main,storage,store}.py` |
| Crash recovery, orphan/missing-file reconciliation, single instance | Implemented in source | `site_receiver/recovery.py` |
| Storage admission, thresholds, retention, 507 + Retry-After | Implemented in source | `config.py` (`RECEIVER_MIN_FREE_MB`, retention vars), `main.py`, `forwarder.purge_synced` |
| Authenticated health/storage/backlog endpoints | Implemented in source | receiver `/v1/admin/status`, `/v1/admin/recordings`; central heartbeat to `/sites/{id}/bodycam/receivers` |
| Forwarding with backoff + jitter, restart-safe, verified central ack | Implemented in source | `site_receiver/forwarder.py`, `receiver_ingest.py` (ack carries `original_hash`, compared) |
| Local vs central state distinguishable | Implemented in source | receiver `ack` field (`local_received`/`central_received`), phone `local_acked` vs `uploaded`, dashboard labels |
| SHA-256 on phone, verified at receiver and control room | Implemented in source | `recording_service.dart`, `chunk_uploader.dart`, receiver `main.py`, `recordings.py`, `receiver_ingest.py` |
| Original preserved; watermark is a separate derivative | Implemented in source | `app/services/evidence.py`; watermark only runs when a pristine original exists |
| Central-signed, site-scoped, expiring offline grants (default 8 h) | Implemented in source | `app/services/site_grants.py`, `site_receiver/auth.py`, `app/routers/mobile_nh.py` |
| Phone verifies grant signature locally | **Not implemented** | The phone treats the grant as an opaque bearer credential and relies on the receiver to verify it; it checks only the expiry the control room reports. Verifying the signature on the phone would need the public key and a JWS library (a new dependency) |
| Revocation while a receiver is offline | Partial (inherent) | Propagates at the receiver's next sync only; documented |
| Runtime endpoint selection, validation, persistence, fallback policy | Implemented in source | `network_hopping_service.dart` |
| Phone queue: persistent backoff, no retry cap, per-target state | Implemented in source | `offline_queue_service.dart` (schema v3), `chunk_uploader.dart` |
| Phone keeps copies until central confirmation | Implemented in source | `chunk_uploader._reconcileWithCentral`; optional low-storage purge is off by default |
| Offline recording with a valid grant | Implemented in source | `recording_service.start` (no central call), `home_screen.dart` offline start-up |
| UI for destination, grant, storage, pending, errors | Partial | `network_hopping_screen.dart`, home banner. The active destination is shown as receiver status only, not per recording |
| Android permissions | Implemented in source | None added: reachability is probed over HTTP. Wi-Fi SSID/AP identity is deliberately not read |
| Receiver separate from telemetry collector | Implemented in source | `backend/site_receiver` vs `backend/collector`; collector files untouched |
| Receiver/device/officer/recording tied to a site | Implemented in source | `SiteAssignment`, `DeviceSiteAuthorization`, `RecordingSession.site_id/receiver_id`, `SiteReceiver.recent_devices` |
| AP association / "phone changed AP" | Not implemented | Not claimed: no trusted source exists; existing Network Hopping data is unchanged |
| Real vendor collector integration | Blocked | Needs vendor credentials/hardware; the existing adapter boundary is untouched |
| Frontend receiver + synchronization views | Partial | `VideoTransferTab.jsx`. Shows central-side data only: a recording the receiver holds but has not yet registered centrally is not visible, and "expected chunk count" is not stored centrally |
| Operator actions (retry/re-sync, grants) | Implemented in source | receiver commands via `/sites/{id}/bodycam/receivers/{rid}/commands`. No evidence-deletion action exists, deliberately |
| Site-local live view | Partial / Blocked | Token issuing in `site_receiver/main.py` (`/v1/live/start`), phone wiring in `live_stream_service.dart`. Needs a LiveKit server on site (not deployed). Central live path unchanged |
| Documentation | Implemented in source | `docs/BODYCAM_OFFLINE_TRANSPORT.md`, `site_receiver/README.md`, `receiver.env.example`, this file |
| Tests / builds / validation | **Not done** (forbidden) | see the transport doc, section 16 |

## What the system does when something is down

* **Internet down, site network up.** Phones record normally. Chunks go to the site receiver, which stores them durably and acknowledges
  `local_received`. The phone keeps its copy. When the internet returns the receiver forwards; once the control room confirms, the phone frees its copy.
* **Receiver down or unreachable, internet up.** The phone sends site chunks directly to the control room if the fallback policy is on (default); otherwise they wait. Nothing is lost.
* **Both down.** The phone keeps recording and queueing locally; storage warnings appear as space shrinks. Uploads resume automatically, with backoff, when either returns.
* **Control room down, receiver up.** The receiver keeps accepting and queueing; the forwarder retries with backoff. The dashboard shows a growing backlog and an old "last confirmation" time.
* **Grant expired.** Existing footage stays queued and nothing is deleted; receiver uploads stop until the officer goes online and renews it.

## Update after the audit-closure pass

Rows changed: "Phone verifies grant signature" is now **Implemented in source** (`mobile/lib/services/grant_verifier.dart`, unverified; new dependency not locked). Endpoint trust is **Partial**
(TLS-based, https enforced; pinning not implemented). Receiver-held recordings are visible on the dashboard as the receiver's own report (**Implemented in source**, expected chunk count shown only when known).
Concurrent-ingest key collisions, quarantined-chunk acknowledgement, central-outage quarantine, list/WebSocket site isolation, false "all uploaded", local-file corruption detection, legacy failed-row recovery and
the health contracts are **Implemented in source**. See `BODYCAM_OFFLINE_TRANSPORT.md` section 18 and `BODYCAM_NETWORK_HOPPING_IMPLEMENTATION_REPORT.md` section 11. All unverified at runtime.
