"""
Association event processing: ordering, de-duplication and current state.

TWO SEPARATE THINGS
  * NetworkEvent       -- append-only history of every accepted event (with the outcome).
  * ClientAssociation  -- the CURRENT state, one row per (site, client pseudonym),
                          changed only here, only by a version-guarded compare-and-set.
Only `ClientAssociation.state == "active"` rows are ever counted as connected.

ORDERING POLICY (applied identically to every event, in this order)
 1. Idempotency. (collector, event_id) is unique. A repeat of an already-processed
    event returns outcome `duplicate` and changes nothing. A repeat of an event
    that was stored but never finished (crash between history insert and state
    update) is processed again, so replay repairs it.
 2. Compare with the state's last applied event:
      a. If BOTH carry a source sequence number from the SAME sequence stream:
         higher wins; lower is stale. (confidence "sequence")
      b. Otherwise SOURCE timestamps decide: later wins, earlier is stale.
         (confidence "timestamp"). Server receive time is stored but never used for ordering.
      c. Equal timestamps (or equal sequence from different events) are broken
         deterministically: a snapshot-derived fact loses to a real event, then the
         lexicographically greater "<collector>:<event id>" wins. This is recorded as
         confidence "tie_break" -- the ordering is NOT trustworthy there, and says so.
 3. Stale events are kept in history (outcome `stale`) but never change state.
 4. State machine:
      association / roam  -> client becomes ACTIVE on the named AP (a client has at most
                             one active association per site: moving AP-to-AP is a roam,
                             not a second connection).
      disassociation      -> closes the association ONLY if it names the AP the client is
                             currently on (or names none). A disassociation from an AP the
                             client has already left is a normal side effect of roaming and is
                             ignored (outcome `ap_mismatch`).
      A disassociation that arrives before any association leaves a closed "tombstone"
      carrying its timestamp, so an older association arriving late is correctly stale.
 5. Writes are compare-and-set on `version`; a lost race re-reads and re-decides (max 5 tries).

SNAPSHOTS are processed as association events with source SNAPSHOT at the snapshot
time. A COMPLETE snapshot additionally closes active associations in its scope that it
does not list (reason `snapshot_absent`), but never ones newer than the snapshot.

Unknown APs: an event naming an AP that is not registered at THIS site is recorded as
`unknown_ap` and changes nothing; APs are never auto-created from telemetry.
"""
import dataclasses
import datetime
import logging
import uuid
from typing import Dict, List, Optional, Tuple

from pymongo.errors import DuplicateKeyError

from .. import models, schemas_network as sn
from . import site_privacy

logger = logging.getLogger("site_events")

MAX_CAS_ATTEMPTS = 5
SNAPSHOT_GRACE = datetime.timedelta(seconds=60)

APPLIED = "applied"
STALE = "stale"
DUPLICATE = "duplicate"
DUPLICATE_STATE = "duplicate_state"
AP_MISMATCH = "ap_mismatch"
NO_ACTIVE = "no_active"
UNKNOWN_AP = "unknown_ap"
OUT_OF_SCOPE = "out_of_scope"
UNCERTAIN = "uncertain"


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt: datetime.datetime) -> datetime.datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


@dataclasses.dataclass
class EventResult:
    outcome: str
    detail: Optional[str] = None
    changed: bool = False  # current state changed (affects counts)
    roamed: bool = False
    ap_id: Optional[uuid.UUID] = None
    from_ap_id: Optional[uuid.UUID] = None
    confidence: Optional[str] = None  # sequence | timestamp | tie_break | snapshot


# ---------------------------------------------------------------------------
# Scope (authorized monitoring)
# ---------------------------------------------------------------------------

def in_scope(policy: models.SitePolicy, pseudonym: str) -> bool:
    if policy.scope_mode == models.SiteMonitoringScope.all_clients:
        return bool(policy.authorization_reference)  # monitoring everyone needs a recorded authorization
    return pseudonym in set(policy.allowlist or [])


# ---------------------------------------------------------------------------
# AP resolution (site-scoped)
# ---------------------------------------------------------------------------

class APResolver:
    """Resolves source AP references to registered APs of ONE site, with a per-instance cache."""

    def __init__(self, site_id: uuid.UUID):
        self.site_id = site_id
        self._cache: Dict[Tuple, Optional[models.AccessPoint]] = {}

    async def resolve(self, ref: Optional[sn.APRef]) -> Optional[models.AccessPoint]:
        if ref is None:
            return None
        key = (ref.bssid, ref.ap_code, ref.management_ip, ref.serial_number)
        if key in self._cache:
            return self._cache[key]
        ap = None
        # Most specific identifier first. Always restricted to this site: a collector can never address another site's APs.
        if ref.bssid:
            ap = await models.AccessPoint.find_one({"site_id": self.site_id, "$or": [{"bssid": ref.bssid}, {"radios.bssid": ref.bssid}]})
        if ap is None and ref.serial_number:
            ap = await models.AccessPoint.find_one({"site_id": self.site_id, "serial_number": ref.serial_number})
        if ap is None and ref.management_ip:
            ap = await models.AccessPoint.find_one({"site_id": self.site_id, "management_ip": ref.management_ip})
        if ap is None and ref.ap_code:
            ap = await models.AccessPoint.find_one({"site_id": self.site_id, "code": ref.ap_code})
        self._cache[key] = ap
        return ap


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------

def compare_order(
    cur: Optional[models.ClientAssociation], *, ts: datetime.datetime, seq: Optional[int], seq_stream: Optional[str], key: str, source: str
) -> Tuple[int, str]:
    """Returns (1 newer | 0 same event | -1 stale, confidence). See the module docstring."""
    if cur is None or cur.last_event_at is None:
        return 1, "timestamp"
    if seq is not None and cur.last_seq is not None and seq_stream == cur.seq_stream:
        if seq > cur.last_seq:
            return 1, "sequence"
        if seq < cur.last_seq:
            return -1, "sequence"
        if key == cur.last_event_key:
            return 0, "sequence"
        return (1 if key > (cur.last_event_key or "") else -1), "tie_break"
    t_new, t_cur = _aware(ts), _aware(cur.last_event_at)
    if t_new > t_cur:
        return 1, "timestamp"
    if t_new < t_cur:
        return -1, "timestamp"
    if key == cur.last_event_key:
        return 0, "timestamp"
    if source == "SNAPSHOT" and cur.source != "SNAPSHOT":
        return -1, "tie_break"
    if cur.source == "SNAPSHOT" and source != "SNAPSHOT":
        return 1, "tie_break"
    return (1 if key > (cur.last_event_key or "") else -1), "tie_break"


def _placement(ap: Optional[models.AccessPoint]) -> dict:
    if ap is None:
        return {"ap_id": None, "zone_id": None, "floor_id": None, "building_id": None}
    return {"ap_id": ap.id, "zone_id": ap.site_zone_id, "floor_id": ap.site_floor_id, "building_id": ap.site_building_id}


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

async def process_event(
    site: models.MonitoredSite,
    collector: models.Collector,
    ev: sn.CollectorEvent,
    resolver: APResolver,
    *,
    now: Optional[datetime.datetime] = None,
    source_override: Optional[str] = None,
) -> EventResult:
    now = now or _utcnow()
    pseudonym = site_privacy.pseudonymize(site.id, ev.client_id)
    if not in_scope(site.policy, pseudonym):
        # Nothing is stored for a device the site has not authorized (data minimization).
        return EventResult(OUT_OF_SCOPE, "client is outside the site's monitoring scope")

    source = source_override or ("SYNTHETIC" if collector.is_simulated else ev.source)
    ap = await resolver.resolve(ev.ap)
    from_ap = await resolver.resolve(ev.from_ap)

    doc = models.NetworkEvent(
        site_id=site.id, collector_id=collector.id, event_id=ev.event_id, event_type=ev.event_type,
        client_pseudonym=pseudonym, ap_id=ap.id if ap else None, ap_ref=_ref_text(ev.ap), from_ap_id=from_ap.id if from_ap else None,
        radio_bssid=ev.radio_bssid, zone_id=ap.site_zone_id if ap else None, source_timestamp=_aware(ev.source_timestamp),
        received_at=now, source_seq=ev.source_seq, seq_stream=ev.seq_stream, session_id=ev.session_id, source=source,
    )
    try:
        await doc.insert()
    except DuplicateKeyError:
        existing = await models.NetworkEvent.find_one({"collector_id": collector.id, "event_id": ev.event_id})
        if existing is None or existing.outcome != "received":
            return EventResult(DUPLICATE, "event already processed")
        doc = existing  # stored but never finished: finish it now

    result = await _apply(site, collector, ev, pseudonym, ap, source, doc.id)
    await models.NetworkEvent.get_motor_collection().update_one(
        {"_id": doc.id},
        {"$set": {"outcome": result.outcome, "outcome_detail": result.detail, "ordering_confidence": result.confidence,
                  **({"from_ap_id": result.from_ap_id} if result.from_ap_id else {})}},
    )
    return result


def _ref_text(ref: Optional[sn.APRef]) -> Optional[str]:
    if ref is None:
        return None
    return ref.bssid or ref.ap_code or ref.management_ip or ref.serial_number


async def _apply(
    site: models.MonitoredSite, collector: models.Collector, ev: sn.CollectorEvent, pseudonym: str,
    ap: Optional[models.AccessPoint], source: str, _event_doc_id: uuid.UUID,
) -> EventResult:
    coll = models.ClientAssociation.get_motor_collection()
    key = f"{collector.id}:{ev.event_id}"
    ts = _aware(ev.source_timestamp)
    is_disassoc = ev.event_type == "disassociation"

    if not is_disassoc and ap is None:
        return EventResult(UNKNOWN_AP, "access point is not registered at this site")
    if is_disassoc and ap is None and ev.ap is not None:
        return EventResult(UNKNOWN_AP, "access point is not registered at this site")

    raw_enc = None
    if site.policy.store_raw_identifiers and site_privacy.raw_storage_available():
        raw_enc = site_privacy.encrypt_raw(ev.client_id)

    for _attempt in range(MAX_CAS_ATTEMPTS):
        cur = await models.ClientAssociation.find_one({"site_id": site.id, "client_pseudonym": pseudonym})
        cmp, conf = compare_order(cur, ts=ts, seq=ev.source_seq, seq_stream=ev.seq_stream, key=key, source=source)

        def done(outcome: str, detail: Optional[str] = None, **kw) -> EventResult:
            r = EventResult(outcome, detail, confidence=conf, **kw)
            if conf == "tie_break" and outcome == APPLIED:
                r.detail = (detail or "") + " ordering decided by tie-break (equal timestamps/sequence); treat as uncertain"
            return r

        common = {
            "last_event_at": ts, "last_event_key": key, "last_seq": ev.source_seq, "seq_stream": ev.seq_stream,
            "ordering_confidence": conf, "source": source, "updated_at": _utcnow(),
        }

        if not is_disassoc:
            placement = _placement(ap)
            if cur is None:
                fresh = models.ClientAssociation(
                    site_id=site.id, client_pseudonym=pseudonym, state="active", radio_bssid=ev.radio_bssid, ap_ref=_ref_text(ev.ap),
                    associated_at=ts, raw_identifier_encrypted=raw_enc, version=0, **placement, **common,
                )
                try:
                    await fresh.insert()
                except DuplicateKeyError:
                    continue
                return done(APPLIED, "new association", changed=True, ap_id=ap.id)
            if cmp == 0:
                return done(DUPLICATE_STATE, "same event already applied")
            if cmp < 0:
                return done(STALE, "a newer association event has already been applied")
            was_active = cur.state == "active"
            same_ap = was_active and cur.ap_id == ap.id
            update = {**common, **placement, "state": "active", "radio_bssid": ev.radio_bssid, "ap_ref": _ref_text(ev.ap),
                      "closed_at": None, "close_reason": None}
            if not same_ap:
                update["associated_at"] = ts
                update["previous_ap_id"] = cur.ap_id if was_active else None
            if raw_enc:
                update["raw_identifier_encrypted"] = raw_enc
            res = await coll.update_one({"_id": cur.id, "version": cur.version}, {"$set": update, "$inc": {"version": 1}})
            if res.matched_count == 0:
                continue
            if same_ap:
                return done(APPLIED, "refresh of the current association", changed=False, ap_id=ap.id)
            roamed = was_active
            return done(APPLIED, "roam" if roamed else "reassociation", changed=True, roamed=roamed, ap_id=ap.id, from_ap_id=cur.ap_id if was_active else None)

        # ---- disassociation ----
        if cur is None:
            tomb = models.ClientAssociation(
                site_id=site.id, client_pseudonym=pseudonym, state="closed", closed_at=ts, close_reason="disassociated_first",
                version=0, **{**common, "ap_id": ap.id if ap else None},
            )
            try:
                await tomb.insert()
            except DuplicateKeyError:
                continue
            return done(NO_ACTIVE, "no active association; recorded so an older association arriving late is treated as stale")
        if cmp == 0:
            return done(DUPLICATE_STATE, "same event already applied")
        if cmp < 0:
            return done(STALE, "a newer event has already been applied")
        if cur.state != "active":
            # newer than the closed marker: just advance the marker
            res = await coll.update_one({"_id": cur.id, "version": cur.version}, {"$set": common, "$inc": {"version": 1}})
            if res.matched_count == 0:
                continue
            return done(NO_ACTIVE, "client was not associated")
        if ap is not None and cur.ap_id != ap.id:
            return done(AP_MISMATCH, "disassociation from an access point the client has already left")
        close = {**common, "state": "closed", "closed_at": ts, "close_reason": "disassociated"}
        res = await coll.update_one({"_id": cur.id, "version": cur.version}, {"$set": close, "$inc": {"version": 1}})
        if res.matched_count == 0:
            continue
        return done(APPLIED, "disassociated", changed=True, ap_id=cur.ap_id)

    return EventResult(UNCERTAIN, "state kept changing concurrently; event recorded but not applied", confidence="tie_break")


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

async def process_snapshot(
    site: models.MonitoredSite, collector: models.Collector, snap: sn.SnapshotRequest, resolver: APResolver, *, now: Optional[datetime.datetime] = None
) -> sn.SnapshotResponse:
    now = now or _utcnow()
    ts = _aware(snap.source_timestamp)
    source = "SYNTHETIC" if collector.is_simulated else "SNAPSHOT"

    # Idempotent: the same snapshot id is never processed twice.
    marker_id = f"snapshot:{snap.snapshot_id}"
    marker = models.NetworkEvent(
        site_id=site.id, collector_id=collector.id, event_id=marker_id, event_type="snapshot", client_pseudonym="-",
        source_timestamp=ts, received_at=now, source=source, outcome="received",
    )
    try:
        await marker.insert()
    except DuplicateKeyError:
        return sn.SnapshotResponse(snapshot_id=snap.snapshot_id, clients_processed=0, applied=0, closed_absent=0, out_of_scope=0, duplicate=True)

    applied = out_of_scope = 0
    seen = set()
    for idx, c in enumerate(snap.clients):
        ev = sn.CollectorEvent(
            event_id=f"snap:{snap.snapshot_id}:{idx}", event_type="association", source_timestamp=ts, client_id=c.client_id,
            ap=c.ap, radio_bssid=c.radio_bssid, source="SNAPSHOT",
        )
        res = await process_event(site, collector, ev, resolver, now=now, source_override=source)
        if res.outcome == OUT_OF_SCOPE:
            out_of_scope += 1
            continue
        seen.add(site_privacy.pseudonymize(site.id, c.client_id))
        if res.outcome == APPLIED:
            applied += 1

    closed = 0
    if snap.complete:
        if snap.scope == "site":
            query: dict = {"site_id": site.id, "state": "active"}
        else:
            covered = [a for a in [await resolver.resolve(r) for r in snap.covered_aps] if a is not None]
            query = {"site_id": site.id, "state": "active", "ap_id": {"$in": [a.id for a in covered]}}
        cutoff = ts - SNAPSHOT_GRACE
        coll = models.ClientAssociation.get_motor_collection()
        async for row in coll.find({**query, "last_event_at": {"$lt": cutoff}}).limit(20000):
            if row["client_pseudonym"] in seen:
                continue
            res = await coll.update_one(
                {"_id": row["_id"], "version": row["version"], "state": "active"},
                {"$set": {"state": "closed", "closed_at": ts, "close_reason": "snapshot_absent", "last_event_at": ts,
                          "last_event_key": f"{collector.id}:{marker_id}", "ordering_confidence": "snapshot", "source": source,
                          "updated_at": _utcnow()}, "$inc": {"version": 1}},
            )
            if res.matched_count:
                closed += 1
                await models.NetworkEvent(
                    site_id=site.id, collector_id=collector.id, event_id=f"{marker_id}:close:{row['client_pseudonym']}",
                    event_type="disassociation", client_pseudonym=row["client_pseudonym"], ap_id=row.get("ap_id"),
                    zone_id=row.get("zone_id"), source_timestamp=ts, received_at=now, source=source, outcome=APPLIED,
                    outcome_detail="snapshot_absent", ordering_confidence="snapshot",
                ).insert()

    await models.NetworkEvent.get_motor_collection().update_one(
        {"_id": marker.id}, {"$set": {"outcome": APPLIED, "outcome_detail": f"processed={len(snap.clients)} closed_absent={closed}"}}
    )
    return sn.SnapshotResponse(
        snapshot_id=snap.snapshot_id, clients_processed=len(snap.clients) - out_of_scope, applied=applied, closed_absent=closed, out_of_scope=out_of_scope,
    )
