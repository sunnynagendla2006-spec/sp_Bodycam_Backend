"""
Retention for network monitoring data.

Each site's policy.retention_days (1..365, default 30) bounds how long its event
history, occupancy samples, availability history, closed association rows and
ended breaches are kept. Active associations are current state, not history, and
are never purged here (a client that disappears is closed by a disassociation,
a complete snapshot, or manually).

Run daily from the application lifespan (SITE_RETENTION_LOOP, default true) and
on demand via POST /sites/{id}/retention/run. Deletions are bounded to one site
and one cutoff each; nothing here touches other collections.
"""
import asyncio
import datetime
import logging
import os

from .. import models

logger = logging.getLogger("site_retention")


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def loop_enabled() -> bool:
    return os.getenv("SITE_RETENTION_LOOP", "true").strip().lower() in ("1", "true", "yes")


async def purge_site(site: models.MonitoredSite, now: datetime.datetime = None) -> dict:
    now = now or _utcnow()
    cutoff = now - datetime.timedelta(days=site.policy.retention_days)
    events = await models.NetworkEvent.get_motor_collection().delete_many({"site_id": site.id, "received_at": {"$lt": cutoff}})
    samples = await models.OccupancySample.get_motor_collection().delete_many({"site_id": site.id, "bucket_start": {"$lt": cutoff}})
    avail = await models.AvailabilityEvent.get_motor_collection().delete_many({"site_id": site.id, "at": {"$lt": cutoff}})
    assoc = await models.ClientAssociation.get_motor_collection().delete_many({"site_id": site.id, "state": "closed", "updated_at": {"$lt": cutoff}})
    breaches = await models.ThresholdBreach.get_motor_collection().delete_many({"site_id": site.id, "active": False, "ended_at": {"$lt": cutoff}})
    return {
        "events_deleted": events.deleted_count, "samples_deleted": samples.deleted_count, "availability_deleted": avail.deleted_count,
        "associations_deleted": assoc.deleted_count, "breaches_deleted": breaches.deleted_count,
    }


async def purge_all() -> int:
    total = 0
    async for site in models.MonitoredSite.find({}):
        try:
            result = await purge_site(site)
            total += sum(result.values())
        except Exception:
            logger.exception("retention purge failed for site %s", site.code)
    return total


async def retention_loop() -> None:
    while True:
        try:
            removed = await purge_all()
            if removed:
                logger.info("network retention: removed %d expired rows", removed)
        except Exception:
            logger.exception("network retention loop failed")
        await asyncio.sleep(24 * 3600)
