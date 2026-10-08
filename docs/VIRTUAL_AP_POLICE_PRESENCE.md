# Virtual AP Police Presence, Zones & Movement

## 1. Problem

During a Jatara, festival, or temporary deployment, there is usually no
physical Wi-Fi AP infrastructure and unreliable mobile/internet
connectivity. Control Room still needs to know, in real time: which
officer is near which part of the event area, when they move, and who
is currently near an emergency.

## 2. Event deployment

A `Deployment` (`app/models.py`) is lightweight metadata for a named
operation — e.g. `JATARA-DEMO-001` — with a status (`active`/`ended`)
and an optional start/end time. It is **not** the same concept as
`Incident` (a single citizen-reported event) and does not duplicate it.
The actual link between a deployment and its access points is the
existing `AccessPoint.deployment` string field (already present before
this feature) — a `Deployment` row just adds admin-configurable
name/status/time-window metadata on top of that string.

## 3. Four zones (and why there's no `Zone` collection)

A zone is a **derived view** over the distinct `AccessPoint.zone`
values within a deployment — never a separate stored row. Every fact a
zone dashboard needs (which APs are in it, is it enabled, how many
officers are currently there, how many are moving toward it) is already
fully computable from `AccessPoint` + `PolicePresence` + the in-memory
moving-state tracker. See `app/routers/access_points.py::list_zones`.
"Enabling/disabling a zone" bulk-toggles every `AccessPoint` in it
(`POST /access-points/zones/{zone}/enable|disable`).

The demo configuration (not a permanent limit) is four zones:

| Zone | AP | Name |
|---|---|---|
| ZONE-01 | AP-01 | Main Gate |
| ZONE-02 | AP-02 | Main Temple |
| ZONE-03 | AP-03 | Parking Area |
| ZONE-04 | AP-04 | Food / Market Area |

## 4. Access Points

`AccessPoint` (added in an earlier phase of this same feature) already
carries `code`, `name`, `zone`, `deployment`, `location` (GeoJSON,
2dsphere-indexed), `enabled`, `status`. Nothing about this model changed
for virtual AP mode — it already supported everything needed.

## 5. Police device IDs

Identity is always the existing authenticated `Device` → `Constable`
relationship (`_require_own_device_for_constable`, reused verbatim from
`app/routers/devices.py`). No endpoint in this feature accepts a
client-claimed officer/device identity — ownership is derived from the
JWT every time, exactly like device heartbeat/battery reporting already
works.

## 6. Virtual AP concept

**Virtual AP mode simulates AP association for development and
demonstration. It does not represent a physical Wi-Fi association.**
No packet capture, no router APIs, no special hardware. A police user
explicitly selects a destination AP and the app calls
`POST /presence/association/virtual`, which runs through the exact same
`PresenceService.process_association` as a real AP would
(`app/services/presence.py`) — only the `source` tag differs
(`SIMULATOR` vs `REAL`). See `app/services/ap_association.py` for the
`APAssociationProvider` abstraction: `VirtualAPAssociationProvider` and
`RealAPAssociationProvider` are both ~5-line wrappers around the same
function. A future `PhysicalAPAssociationProvider` (fed by a real edge
server) would be exactly as short.

**AP association provides approximate operational presence within the
configured AP coverage zone and does not provide exact GPS-level
positioning.**

## 7. Police movement flow

1. Police app calls `GET /presence/virtual/map` (constable-safe: code,
   name, zone, location — no station_id, no counts) to show available
   destinations.
2. Officer selects a destination AP, presses GO.
3. App animates the transition **client-side only** — see §11,
   "do not store every animation frame." Optionally calls
   `POST /presence/virtual/moving-ping` at a controlled interval during
   the animation (pure WebSocket passthrough, zero persistence — see
   below).
4. On arrival, app calls `POST /presence/association/virtual` with the
   real destination AP code. This is the only call that actually
   changes backend state.
5. Backend detects same-AP (no-op) vs a genuine handoff exactly like the
   real endpoint, creates a `PresenceHandoff` row, updates
   `PolicePresence`, publishes `presence.connected` or `presence.handoff`.
6. Admin's live view updates from the real WebSocket event — never from
   the police app's own local animation state.

## 8. Admin movement monitoring

Admin/control_room sees, via `GET /presence/` (existing) and
`GET /access-points/zones` (new): current AP/zone per officer, zone
police counts, zone moving counts, and movement history
(`GET /presence/devices/{id}/history`, existing). An officer is never
"lost" mid-transition: their last known `PolicePresence` row is
unchanged until the real association lands, and the `presence.moving`
WebSocket event (if the police app sends moving-pings) shows live
progress without ever touching the officer's actual recorded state.

## 9. Handoff detection

Unchanged from the base AP-presence feature
(`services/presence.py::process_association`): a repeated association
to the same AP is a no-op (no handoff row, no event); a different AP
creates exactly one `PresenceHandoff` row, increments
`PolicePresence.handoff_count`, and is idempotent on a retried
`event_id` via the existing partial-unique index.

## 10. Emergency zone targeting

`POST /presence/zones/{zone}/alert` (admin/control_room only) finds
every `PolicePresence` row with `status=connected` whose current AP is
in that zone, and pushes a `zone.emergency_alert` WebSocket event
**directly to each targeted constable's own room** via the existing
`manager.send_to_constable` transport (`app/services/events.py`) — the
same transport every other role-scoped event in this codebase already
uses. This does **not** create a new notification system, a new
`RemoteCommandType`, or touch the existing `Alert`/`RemoteCommand`
models. A constable moving into the zone becomes eligible for a
*future* alert the moment their real association lands (step 4 above);
a constable who has only sent moving-pings (not yet arrived) is not
yet targeted.

## 11. WebSocket flow

New events (`app/services/events.py`), routed exactly like every other
presence event (control_room + the constable's own station):

- `presence.moving` — pure passthrough, **never persisted**, published
  by `POST /presence/virtual/moving-ping`. Carries `device_id`,
  `constable_id`, `from_access_point_code`, `target_access_point_code`,
  `from_zone`, `target_zone`, `progress` (0–100), `source: "SIMULATOR"`.
- `presence.connected` / `presence.handoff` — unchanged, already existed.
- `zone.emergency_alert` — sent to control_room (awareness) and
  individually to each targeted constable's room.

No JWT or other secret is ever included in any WebSocket payload.

## 12. Real AP future integration

A `PhysicalAPAssociationProvider` would be added to
`app/services/ap_association.py` alongside `VirtualAPAssociationProvider`
— same `source`-tagged call into `PresenceService.process_association`,
fed by a real edge server's own credential instead of a constable's JWT.
No change to `PresenceService`, `PolicePresence`, `PresenceHandoff`, or
any WebSocket event would be needed.

## 13. Limitations

- **No frontend project exists in this repository** (confirmed
  repeatedly this session — no React/Vite, no Flutter app). Everything
  above is backend + the existing lightweight HTML admin console
  (`admin_console.html`); there is no native police mobile app screen.
- "Moving" state is in-memory, single-process, TTL-bound (see
  `app/services/movement_state.py`) — not shared across horizontally
  scaled replicas, same documented limitation as the existing login
  rate limiter (`app/auth/rate_limit.py`).
- Zone enable/disable is bulk-AP-toggle, not an independent stored
  entity — see §3.
- Virtual AP mode is gated by `VIRTUAL_AP_MODE_ENABLED` (default
  `true`) but defaults to **on** — a production deployment that must
  prevent any simulated movement should explicitly set it to `false`.
- No nearest-AP auto-connect UI flow was built (only the backend
  endpoint, `GET /presence/virtual/nearest-ap`) — the described demo
  flow uses explicit AP selection, not automatic nearest-AP detection.
