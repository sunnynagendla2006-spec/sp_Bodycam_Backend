"""
Periodic per-site evaluation: occupancy samples, threshold breaches,
availability history, and live count broadcasts.

Runs (a) throttled after telemetry ingest, (b) from an optional in-process loop
guarded by a short MongoDB lease (only one backend replica evaluates at a
time; SITE_MONITOR_ENABLED, default true) and (c) on demand from
POST /sites/{id}/monitor/run. Stale detection is time-based, so (b) or an
external scheduler calling (c) is required for "collector went silent"
transitions to be recorded when no telemetry arrives at all.

Samples describe ACTIVE CLIENT ASSOCIATIONS, bucketed by SAMPLE_BUCKET_SECONDS
(default 60). Nothing is interpolated for periods with no evaluation.
"""
import asyncio
import datetime
import logging
import os
import time
import uuid
from typing import Dict, Optional

from pymongo import ReturnDocument, UpdateOne
from pymongo.errors import DuplicateKeyError

from .. import database as db_module
from .. import models
from . import events, site_counts

logger = logging.getLogger("site_monitor")

_LEASE_ID = "site_monitor"
_last_cycle: Dict[uuid.UUID, float] = {}
INGEST_CYCLE_MIN_INTERVAL = 10.0


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default)).strip()))
    except ValueError:
        return default


def enabled() -> bool:
    return os.getenv("SITE_MONITOR_ENABLED", "true").strip().lower() in ("1", "true", "yes")


def interval_seconds() -> int:
    return _env_int("SITE_MONITOR_INTERVAL_SECONDS", 30, 5)


def bucket_seconds() -> int:
    return _env_int("SAMPLE_BUCKET_SECONDS", 60, 10)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def bucket_start(now: datetime.datetime) -> datetime.datetime:
    size = bucket_seconds()
    epoch = int(now.timestamp())
    return datetime.datetime.fromtimestamp(epoch - epoch % size, tz=datetime.timezone.utc)


async def run_site_cycle(site: models.MonitoredSite, now: Optional[datetime.datetime] = None, publish: bool = True) -> dict:
    now = now or _utcnow()
    summary = await site_counts.summarize(site, now)
    quality = "stale" if (summary.stale and summary.total_active_clients > 0) else summary.quality
    simulated = summary.quality == "simulated"
    bucket = bucket_start(now)

    rows = [("site", None, summary.total_active_clients)]
    rows += [("zone", z.id, z.active_clients) for z in summary.by_zone]
    rows += [("ap", a.id, a.active_clients) for a in summary.by_ap]
    rows += [("floor", f.id, f.active_clients) for f in summary.by_floor]
    ops = [
        UpdateOne(
            {"site_id": site.id, "scope": scope, "scope_id": scope_id, "bucket_start": bucket},
            {"$set": {"active_clients": n, "quality": quality, "simulated": simulated}, "$max": {"peak_clients": n}, "$inc": {"samples": 1},
             "$setOnInsert": {"_id": uuid.uuid4()}},
            upsert=True,
        )
        for scope, scope_id, n in rows
    ]
    if ops:
        await models.OccupancySample.get_motor_collection().bulk_write(ops, ordered=False)

    breaches_open = await _evaluate_breaches(site, summary, now, publish)
    changes = await _evaluate_availability(site, now, publish)
    if publish:
        await events.publish_network_counts(site, {
            "total_active_clients": summary.total_active_clients, "quality": summary.quality, "stale": summary.stale,
            "by_zone": {str(z.id): z.active_clients for z in summary.by_zone},
            "by_ap": {str(a.id): a.active_clients for a in summary.by_ap},
            "by_floor": {str(f.id): f.active_clients for f in summary.by_floor},
            "zone_levels": {str(z.id): z.level for z in summary.by_zone if z.level},
            "ap_levels": {str(a.id): a.level for a in summary.by_ap if a.level},
            "open_breaches": breaches_open, "at": now.isoformat(),
        })
    _last_cycle[site.id] = time.monotonic()
    return {"samples_written": len(ops), "breaches_open": breaches_open, "availability_changes": changes}


async def maybe_cycle_after_ingest(site: models.MonitoredSite) -> None:
    """Throttled: a burst of ingest batches triggers at most one evaluation per INGEST_CYCLE_MIN_INTERVAL."""
    if time.monotonic() - _last_cycle.get(site.id, 0.0) < INGEST_CYCLE_MIN_INTERVAL:
        return
    _last_cycle[site.id] = time.monotonic()
    try:
        await run_site_cycle(site)
    except Exception:
        logger.exception("site cycle after ingest failed for %s", site.code)


async def _evaluate_breaches(site: models.MonitoredSite, summary, now: datetime.datetime, publish: bool) -> int:
    coll = models.ThresholdBreach.get_motor_collection()
    zones = {z.id: z for z in await models.SiteZone.find({"site_id": site.id, "active": True}).to_list()}
    aps = {a.id: a for a in await models.AccessPoint.find({"site_id": site.id}).to_list()}
    active = {(b["scope"], b["scope_id"]): b async for b in coll.find({"site_id": site.id, "active": True})}

    current = {}  # (scope, id) -> (level, threshold, count)
    for item in summary.by_zone:
        z = zones.get(item.id)
        if z and item.level:
            current[("zone", z.id)] = (item.level, z.critical_threshold if item.level == "critical" else z.warning_threshold, item.active_clients)
    for item in summary.by_ap:
        a = aps.get(item.id)
        if a and item.level:
            w, c = site_counts.ap_thresholds(site, a)
            current[("ap", a.id)] = (item.level, c if item.level == "critical" else w, item.active_clients)

    for key, row in active.items():
        if key not in current:
            await coll.update_one({"_id": row["_id"]}, {"$set": {"active": False, "ended_at": now}})
            if publish:
                await events.publish_network_breach(site, {"scope": key[0], "scope_id": str(key[1]), "level": None, "ended": True})
    for key, (level, threshold, count) in current.items():
        row = active.get(key)
        if row is None:
            try:
                await models.ThresholdBreach(
                    site_id=site.id, scope=key[0], scope_id=key[1], level=level, threshold=threshold or 0, peak_clients=count, started_at=now, last_seen_at=now,
                ).insert()
            except DuplicateKeyError:
                continue
            if publish:
                await events.publish_network_breach(site, {"scope": key[0], "scope_id": str(key[1]), "level": level, "count": count, "threshold": threshold})
        else:
            await coll.update_one(
                {"_id": row["_id"]},
                {"$set": {"level": level, "threshold": threshold or 0, "last_seen_at": now}, "$max": {"peak_clients": count}},
            )
            if publish and row.get("level") != level:
                await events.publish_network_breach(site, {"scope": key[0], "scope_id": str(key[1]), "level": level, "count": count, "threshold": threshold})
    return len(current)


async def _evaluate_availability(site: models.MonitoredSite, now: datetime.datetime, publish: bool) -> int:
    changes = 0
    for c in await models.Collector.find({"site_id": site.id}).to_list():
        state = "offline" if (c.revoked or not c.active) else site_counts.freshness_state(c.last_seen_at, now)
        if state == "unknown" or state == c.last_state:
            continue
        await models.Collector.get_motor_collection().update_one({"_id": c.id}, {"$set": {"last_state": state}})
        await models.AvailabilityEvent(site_id=site.id, entity_type="collector", entity_id=c.id, state=state, at=now).insert()
        changes += 1
        if publish:
            await events.publish_network_health(site, {"entity_type": "collector", "entity_id": str(c.id), "state": state})
    for a in await models.AccessPoint.find({"site_id": site.id, "last_seen_at": {"$ne": None}}).to_list():
        state = site_counts.ap_state(a, now)
        if state == "unknown" or state == a.last_telemetry_state:
            continue
        await models.AccessPoint.get_motor_collection().update_one({"_id": a.id}, {"$set": {"last_telemetry_state": state}})
        await models.AvailabilityEvent(site_id=site.id, entity_type="ap", entity_id=a.id, state=state, at=now).insert()
        changes += 1
        if publish:
            await events.publish_network_health(site, {"entity_type": "ap", "entity_id": str(a.id), "state": state})
    return changes


async def run_all_sites() -> int:
    n = 0
    async for site in models.MonitoredSite.find({"active": True}):
        try:
            await run_site_cycle(site)
            n += 1
        except Exception:
            logger.exception("site cycle failed for %s", site.code)
    return n


# ---------------------------------------------------------------------------
# Optional in-process loop with a Mongo lease
# ---------------------------------------------------------------------------

async def _acquire_lease(owner: str, ttl_seconds: int) -> bool:
    coll = db_module.database["network_monitor_lease"]
    now = _utcnow()
    try:
        await coll.find_one_and_update(
            {"_id": _LEASE_ID, "$or": [{"expires_at": {"$lt": now}}, {"owner": owner}]},
            {"$set": {"owner": owner, "expires_at": now + datetime.timedelta(seconds=ttl_seconds)}},
            upsert=True, return_document=ReturnDocument.AFTER,
        )
        return True
    except DuplicateKeyError:
        return False


async def monitor_loop(stop: asyncio.Event) -> None:
    owner = uuid.uuid4().hex
    interval = interval_seconds()
    logger.info("site monitor started (interval=%ss)", interval)
    while not stop.is_set():
        try:
            if await _acquire_lease(owner, interval * 2 + 30):
                await run_all_sites()
        except Exception:
            logger.exception("site monitor cycle failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("site monitor stopped")
