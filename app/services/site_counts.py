"""
Counting semantics (the single place that defines them).

Authoritative network metric = ACTIVE CLIENT ASSOCIATIONS: `ClientAssociation`
rows with state "active". Consequences, all intentional:
  * a roaming client is ONE row, so moving AP-to-AP never counts it twice;
  * disassociated ("closed") clients are never counted;
  * stale or duplicate events cannot inflate a count (they never change state);
  * a person with two devices counts twice; a device with a rotating MAC may count once
    per MAC; a person with no associated device counts zero. This is a NETWORK metric,
    not a head count, and every API/UI surface says so.
  * "unique devices in a window" is a different metric (see routers/site_monitoring.py,
    roaming summary) and is not equal to this one.

Data quality: `live` (real telemetry), `simulated` (every active association came from
a simulated collector), `mixed`, `snapshot` (only snapshot-derived), `none`. `stale`
is separate: true when no collector of the site has been heard from recently, in which
case the numbers describe the last known state, not necessarily the present.
"""
import datetime
import os
import uuid
from typing import Dict, List, Optional

from .. import models, schemas_network as sn

_ACTIVE = {"state": "active"}


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default)).strip()))
    except ValueError:
        return default


def collector_stale_seconds() -> int:
    return _int_env("COLLECTOR_STALE_SECONDS", 180)


def collector_offline_seconds() -> int:
    return _int_env("COLLECTOR_OFFLINE_SECONDS", 600)


def freshness_state(
    last_seen: Optional[datetime.datetime], now: datetime.datetime, stale_after: Optional[int] = None, offline_after: Optional[int] = None
) -> str:
    """online | stale | offline | unknown, from the age of the last real contact (collector thresholds unless given)."""
    if last_seen is None:
        return "unknown"
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=datetime.timezone.utc)
    age = (now - last_seen).total_seconds()
    if age <= (stale_after or collector_stale_seconds()):
        return "online"
    if age <= (offline_after or collector_offline_seconds()):
        return "stale"
    return "offline"


def quality_from_sources(sources: set) -> str:
    if not sources:
        return "none"
    real = {s for s in sources if s in ("REAL",)}
    snap = "SNAPSHOT" in sources
    sim = "SYNTHETIC" in sources
    if sim and (real or snap):
        return "mixed"
    if sim:
        return "simulated"
    if real:
        return "live"
    return "snapshot"


def level_for(count: int, warning: Optional[int], critical: Optional[int]) -> Optional[str]:
    if critical and count >= critical:
        return "critical"
    if warning and count >= warning:
        return "warning"
    return None


def ap_thresholds(site: models.MonitoredSite, ap: models.AccessPoint) -> tuple:
    """(warning, critical) active clients for an AP: its own capacity if set, else the site defaults."""
    if ap.client_capacity:
        return max(1, int(ap.client_capacity * 0.8)), ap.client_capacity
    return site.ap_warning_clients, site.ap_critical_clients


async def raw_counts(site_id: uuid.UUID) -> dict:
    """One bounded aggregation over the site's ACTIVE associations."""
    pipeline = [
        {"$match": {"site_id": site_id, **_ACTIVE}},
        {"$group": {"_id": {"ap": "$ap_id", "zone": "$zone_id", "floor": "$floor_id", "radio": "$radio_bssid", "source": "$source"}, "n": {"$sum": 1}}},
    ]
    by_ap: Dict[uuid.UUID, int] = {}
    by_zone: Dict[uuid.UUID, int] = {}
    by_floor: Dict[uuid.UUID, int] = {}
    by_radio: Dict[str, int] = {}
    sources = set()
    unassigned = 0
    total = 0
    async for row in models.ClientAssociation.get_motor_collection().aggregate(pipeline):
        key, n = row["_id"], row["n"]
        total += n
        sources.add(key.get("source") or "REAL")
        if key.get("ap"):
            by_ap[key["ap"]] = by_ap.get(key["ap"], 0) + n
        if key.get("zone"):
            by_zone[key["zone"]] = by_zone.get(key["zone"], 0) + n
        else:
            unassigned += n
        if key.get("floor"):
            by_floor[key["floor"]] = by_floor.get(key["floor"], 0) + n
        if key.get("radio"):
            by_radio[key["radio"]] = by_radio.get(key["radio"], 0) + n
    return {"total": total, "by_ap": by_ap, "by_zone": by_zone, "by_floor": by_floor, "by_radio": by_radio, "sources": sources, "unassigned": unassigned}


def collector_out(c: models.Collector, now: datetime.datetime) -> sn.CollectorOut:
    return sn.CollectorOut(
        id=c.id, site_id=c.site_id, code=c.code, name=c.name, adapter_kind=c.adapter_kind, is_simulated=c.is_simulated,
        active=c.active, revoked=c.revoked, token_hint=c.token_hint, token_version=c.token_version, capabilities=c.capabilities,
        adapter_health=c.adapter_health, version=c.version, buffer_depth=c.buffer_depth, dropped_events=c.dropped_events,
        state="offline" if (c.revoked or not c.active) else freshness_state(c.last_seen_at, datetime.datetime.now(datetime.timezone.utc) if now is None else now),
        last_seen_at=c.last_seen_at, last_ingest_at=c.last_ingest_at, config=c.config,
    )


async def summarize(site: models.MonitoredSite, now: Optional[datetime.datetime] = None) -> sn.SiteSummary:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    counts = await raw_counts(site.id)
    zones = await models.SiteZone.find({"site_id": site.id, "active": True}).sort("display_order", "code").to_list()
    floors = await models.SiteFloor.find({"site_id": site.id}).sort("display_order", "code").to_list()
    aps = await models.AccessPoint.find({"site_id": site.id}).sort("code").to_list()
    collectors = await models.Collector.find({"site_id": site.id}).sort("code").to_list()

    by_zone: List[sn.CountItem] = []
    for z in zones:
        n = counts["by_zone"].get(z.id, 0)
        by_zone.append(sn.CountItem(
            id=z.id, code=z.code, name=z.name, active_clients=n, capacity=z.capacity,
            utilization_pct=round(100.0 * n / z.capacity, 1) if z.capacity else None,
            level=level_for(n, z.warning_threshold, z.critical_threshold),
        ))
    by_ap: List[sn.CountItem] = []
    ap_states = {"online": 0, "stale": 0, "offline": 0, "unknown": 0}
    for a in aps:
        n = counts["by_ap"].get(a.id, 0)
        w, c = ap_thresholds(site, a)
        cap = a.client_capacity
        by_ap.append(sn.CountItem(
            id=a.id, code=a.code, name=a.name, active_clients=n, capacity=cap,
            utilization_pct=round(100.0 * n / cap, 1) if cap else None, level=level_for(n, w, c),
        ))
        ap_states[ap_state(a, now)] += 1
    by_floor = [sn.CountItem(id=f.id, code=f.code, name=f.name, active_clients=counts["by_floor"].get(f.id, 0)) for f in floors]

    out_collectors = [collector_out(c, now) for c in collectors]
    live_collectors = [c for c in out_collectors if c.state == "online"]
    stale = not live_collectors
    open_breaches = await models.ThresholdBreach.find({"site_id": site.id, "active": True}).count()
    last_updated = max([c.last_ingest_at for c in collectors if c.last_ingest_at], default=None)
    return sn.SiteSummary(
        site_id=site.id, site_code=site.code, total_active_clients=counts["total"], quality=quality_from_sources(counts["sources"]),
        stale=stale, last_updated=last_updated, by_zone=by_zone, by_ap=by_ap, by_floor=by_floor, unassigned_clients=counts["unassigned"],
        collectors=out_collectors, open_breaches=open_breaches, ap_states=ap_states,
    )


def ap_state(ap: models.AccessPoint, now: datetime.datetime) -> str:
    """AP availability from the age of its last REAL telemetry only; an AP that never reported is 'unknown', never 'online'."""
    if not ap.enabled:
        return "offline"
    from . import ap_integration  # existing AP_TELEMETRY_STALE_SECONDS knob

    stale_after = ap_integration.telemetry_stale_seconds()
    return freshness_state(ap.last_seen_at, now, stale_after, stale_after * 3)
