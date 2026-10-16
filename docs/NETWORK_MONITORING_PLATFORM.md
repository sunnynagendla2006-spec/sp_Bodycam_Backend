# Network Monitoring Platform (Sites, Collectors, Occupancy)

Status legend: **IMPLEMENTED (not runtime-verified)** = code exists and has been read, never executed;
**SIMULATED** = artificial data, always labelled; **AWAITING HARDWARE** = needs a real vendor adapter;
**AWAITING CONFIGURATION** = needs keys, floor plans or coordinates from an operator.

Nothing in this document has been run. No real access point, controller, switch or collector has been connected.

## 1. What it is

A generic, real-time network occupancy and movement monitor. A **site** is any monitored area: campus,
building, mall, hospital, station, airport, stadium, convention centre, festival ground, outdoor square,
industrial campus or a custom area. Buildings are one possible deployment, not the root of the model.

```
Site ──┬── Zone ──┬── Access points (management IP, BSSID/radios, placement)
       │          └── (optional) geographic boundary and/or polygon on a floor plan
       ├── (optional) Building ── Floor (plan image) ── zones/APs positioned on it
       ├── Switches (ports mapped to APs), Controllers (optional)
       └── Collectors (LAN service, own credential)  →  telemetry  →  backend
```

* Buildings and floors are **optional**. An open ground uses zones only; zones need neither floors nor coordinates.
* `SiteBuilding.cctv_building_id` can reference a CCTV building without copying its data.
* The older police-presence feature (`/presence`, `/telemetry`, `PolicePresence`) is unchanged apart from an
  ordering guard (section 5).

## 2. Data model (`app/models.py`)

| Document | Purpose |
|---|---|
| `MonitoredSite` | site, type, timezone, boundary, visibility (`access_mode`, `viewer_user_ids`), `policy` (scope, retention, raw-identifier option), AP load thresholds |
| `SiteBuilding`, `SiteFloor` | optional; floor holds the plan image key, size and scale |
| `SiteZone` | any area; optional `boundary` (GeoJSON), optional `plan_polygon` (fractions of a floor plan), capacity, warning/critical thresholds, free-text `zone_type` |
| `AccessPoint` (extended) | adds `site_id`, `site_zone_id`, building/floor, `controller_id`, `switch_id`/`switch_port`, `radios[]`, `ssids[]`, `environment`, plan position, `client_capacity`. Old fields untouched |
| `NetworkSwitch`, `NetworkController` | optional inventory; switch ports map to APs; link status/health only from real telemetry |
| `Collector` | per-site LAN collector with its own hashed credential, capabilities, health, `is_simulated` |
| `ClientAssociation` | CURRENT state, one row per (site, client pseudonym) |
| `NetworkEvent` | append-only history with outcome and ordering confidence |
| `OccupancySample` | time series of active associations per site/zone/AP/floor |
| `ThresholdBreach`, `AvailabilityEvent` | breach and stale/offline history |

Identifiers are never conflated: AP **management IP** (distinct per AP, enforced per site), radio **BSSIDs**
(unique across APs), and **client** identifiers (pseudonymized, section 6).

## 3. Telemetry architecture

```
network equipment ──(adapter)── collector ──(SQLite buffer)── HTTPS ── POST /collector/* ── backend
```

* `backend/collector/` is a standalone, standard-library-only service (see `collector/README.md`).
* **Adapters** (`collector/adapters`): `synthetic` (SIMULATED, development only) and `example_skeleton`
  (template, refuses to run). **There is no production vendor adapter.** Writing one needs the chosen
  hardware's documented API, credentials and equipment to verify against. Do not assume APs expose clients
  through their own management IPs; many only expose them through a central controller, cloud API, SNMP,
  syslog, RADIUS accounting or streaming telemetry. Declared **capabilities** tell the dashboard what a
  collector can really supply.
* **Buffering/retry**: events are persisted before upload and removed only after the backend acknowledged
  them; exponential back-off with jitter; credential errors pause upload but keep buffering; permanently
  invalid items are quarantined; buffer overflow drops the oldest and reports the count in heartbeats.
* **Ingest API** (collector credential only): `POST /collector/heartbeat`, `/collector/ingest/events`
  (≤200), `/collector/ingest/snapshot`, `/collector/ingest/health`.

### Collector security

* Own token per collector: `<collector id>.<secret>`; only SHA-256 of the secret is stored; shown once on
  create/rotate. **Rotation** keeps the old token valid 10 minutes; **revocation** is immediate.
* The site always comes from the credential. A `site_code` in the body must match or the request is refused (403).
  APs are resolved only among that site's APs; nothing is auto-created.
* Rate limit per collector (`COLLECTOR_RATE_LIMIT_PER_MINUTE`), bounded batches, timezone-aware source
  timestamps, future skew and maximum age checks (buffered replay after an outage is accepted up to
  `COLLECTOR_MAX_EVENT_AGE_HOURS`).
* The collector refuses `http://` unless explicitly allowed. TLS termination and certificates are a deployment task.

## 4. Counting semantics (`services/site_counts.py`)

The authoritative metric is **active client associations**: `ClientAssociation` rows with `state == active`.

* A roaming client is one row, so it is never counted twice; closed (disassociated) clients are never counted;
  stale or duplicate events cannot inflate counts because they never change state.
* It is **not** a head count of people. Several devices per person, devices not associated, and rotating
  (randomized) MACs all break any such inference. Every API/UI surface says so.
* "Unique device pseudonyms in a window" (roaming summary) is a different, history-based metric.
* Breakdowns: per AP, per radio (backend), per zone, per floor, per site; plus `last_updated`, `quality`
  (live / simulated / mixed / snapshot / none) and `stale` (no collector heard from recently), and capacity
  utilization where a capacity is configured.

## 5. Event ordering (`services/site_events.py`)

1. **Idempotency**: `(collector, event_id)` unique. A repeat is `duplicate`; an event stored but never finished is finished.
2. **Order**: same sequence stream → higher sequence wins; otherwise **source timestamps** decide (server
   receive time is stored, never used for ordering). Equal timestamps/sequence → deterministic tie-break
   (snapshot-derived facts lose to real events, then greater `<collector>:<event id>` wins) and the outcome
   is marked `tie_break`, i.e. not trustworthy.
3. **Stale** events are kept in history (`outcome=stale`) and never change state.
4. **State machine**: association/roam makes the client active on the AP (a roam, not a second connection);
   disassociation closes only if it names the AP the client is currently on (a disassociation from an AP
   already left is `ap_mismatch`, ignored); a disassociation arriving first leaves a closed tombstone so an
   older association arriving late is stale.
5. Updates are compare-and-set on a version; a lost race re-reads and re-decides (≤5 tries, else `uncertain`).
6. **Snapshots** are processed as events at the snapshot time; a **complete** snapshot also closes active
   associations in its scope it does not list (`snapshot_absent`), never ones newer than the snapshot.

The older presence path (`services/presence.py`) gained a minimal guard: an event older than the held state
for a different AP is ignored (`stale_ignored`) and the freshness marker never moves backwards. It is not the
full engine above.

## 6. Privacy

* Client identifiers become **keyed per-site pseudonyms** (HMAC-SHA256, `CLIENT_ID_HMAC_KEY`) on arrival;
  raw values are not stored or logged. In production the key is mandatory: ingest answers 503 without it.
* **Monitoring scope** (`policy.scope_mode`): default `allowlist` (only authorized devices are tracked; others
  are dropped without storing anything). `all_clients_pseudonymized` requires an authorization reference.
* Raw identifiers can be kept encrypted only if the site policy enables it **and** `CLIENT_RAW_ID_KEY` is set;
  the only way to read one is `POST /sites/{id}/privacy/reveal` (admin, reason required, audited).
* Dashboards and APIs show **masked** pseudonyms (8 characters). WebSocket events are **aggregate only**
  (counts, AP ids) and are delivered only to users allowed to view that site.
* **Retention**: per-site `retention_days` (default 30, max 365), applied daily (`SITE_RETENTION_LOOP`) and on
  demand. Active associations are state, not history.
* Pseudonymization is **not** anonymization and does not by itself make tracking lawful. Obtain local legal
  advice before monitoring visitors.

## 7. Roles and visibility

`admin`: manage everything. `control_room`: read sites it may see; restricted sites need the user in
`viewer_user_ids`. All other roles: 403. A site you cannot see answers 404. Audit entries are written for
every configuration change, credential action, export and reveal.

## 8. API summary

| Area | Routes |
|---|---|
| Sites | `GET/POST /sites`, `GET/PATCH/DELETE /sites/{id}`, `GET /sites/adapters`, `GET /sites/site-types`, `POST /sites/{id}/allowlist`, `DELETE /sites/{id}/allowlist/{pseudonym}` |
| Structure | `/sites/{id}/buildings`, `/floors` (+ `POST/GET /floors/{fid}/plan`), `/zones` (create, list, patch, delete) |
| Infrastructure | `/sites/{id}/access-points` (register, list, patch, adopt), `/switches`, `/controllers`, `/collectors` (+ `rotate-token`, `revoke`) |
| Monitoring | `GET /sites/{id}/summary`, `/associations`, `/events`, `/analytics/{occupancy,peaks,roaming,breaches,availability,export.csv}`, `POST /monitor/run`, `/retention/run`, `/privacy/reveal` |
| Collector ingest | `POST /collector/heartbeat`, `/collector/ingest/{events,snapshot,health}` |
| WebSocket | `network.counts`, `network.roam`, `network.breach`, `network.health` (site-scoped, aggregate) |

## 9. Dashboard

`/sites` (list with live counts) and `/sites/:id` with tabs: Overview, Map (outdoor, Leaflet; boundaries, zones
coloured by threshold, AP markers), Floor plan (image with zones and APs), Layers, Events, Analytics, Health,
and (admin) Configure. Loading, error, empty, disconnected, stale and permission states are explicit and
simulated data is labelled everywhere.

**3D**: the *Layers* view is a schematic stacked-floor view built from the same plan coordinates. It is **not a
surveyed 3D model** and no geometry is invented. A full 3D viewer would need a 3D library (none is installed)
and real building geometry; the floor plan and map remain fully functional without it.

## 10. Operating it

Backend variables are listed in `.env.example` (section "Network monitoring platform"). Required for real use:
`CLIENT_ID_HMAC_KEY`. Optional: `CLIENT_RAW_ID_KEY`, collector thresholds, `SITE_MONITOR_*`, `SAMPLE_BUCKET_SECONDS`,
`SITE_RETENTION_LOOP`, `FLOOR_PLAN_MAX_MB`.

1. Create the site; set its monitoring scope (allowlist is the default).
2. Define zones (and optionally buildings/floors, upload plans, draw zones, position APs).
3. Register APs with management IP and BSSID(s); optionally switches/ports and controllers.
4. Add a collector; copy the token once into the collector's secret store.
5. On the LAN computer run `python -m collector` with the `COLLECTOR_*` variables (see `collector/README.md`).
   For development use the `synthetic` adapter with `COLLECTOR_ALLOW_SYNTHETIC=true`; its data is labelled SIMULATED.
6. Keep `SITE_MONITOR_ENABLED=true` (or call `POST /sites/{id}/monitor/run` from a scheduler) so stale/offline
   transitions are recorded when no telemetry arrives.

### Credential rotation
Rotate in the dashboard (Configure → Collectors), update the collector's token file, restart it within ten
minutes. Revoke immediately if a token may have leaked.

## 11. Known limitations

* No production vendor adapter; real telemetry availability depends on the equipment (see the checklist in
  `NETWORK_HOPPING_IMPLEMENTATION_REPORT.md`).
* A client has one active association per site; clients genuinely holding several simultaneous associations are
  represented by the latest event.
* Counts are associations, not people; unique-device figures overstate with randomized MACs.
* No true 3D viewer; indoor positioning is AP-level only (no RTT/RSSI trilateration).
* Rate limiting is in-process per worker; the monitor lease assumes one MongoDB.
* Collector TLS/CA, firewalling and VPN to the control room are deployment tasks not provided here.
* Nothing has been run: expect first-run fixes.
