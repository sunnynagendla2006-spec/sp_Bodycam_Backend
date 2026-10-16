"""
Idempotent, NON-DESTRUCTIVE data migration for the bodycam offline-transport upgrade.

Run once after deploying (safe to re-run):
    python -m scripts.migrate_bodycam_site_transport            # apply
    python -m scripts.migrate_bodycam_site_transport --dry-run  # report only

It never deletes anything. It only fills fields that older documents lack, so that queries which filter on them
(for example "recordings uploaded directly") also match recordings made before this upgrade:
  1. recording_sessions: sets origin="central" and flags=[] where absent.
  2. chunks: sets received_via="central" where absent. Existing chunks have NO preserved original (original_storage_key
     stays unset): the bytes they were stored from were watermarked in place before this upgrade, so claiming an
     original would be false. The control room reports them as "no original".
New collections (site_assignments, device_site_authorizations, offline_grants, site_receivers) and their indexes are created
by the application at start-up (Beanie); nothing is needed for them here.
This script has NOT been executed as part of the change that added it.
"""
import asyncio
import sys

from app import database, models


async def run(dry_run: bool) -> dict:
    await database.init_db()
    report = {"recording_sessions": 0, "chunks": 0}

    rs = models.RecordingSession.get_motor_collection()
    query = {"$or": [{"origin": {"$exists": False}}, {"flags": {"$exists": False}}]}
    report["recording_sessions"] = await rs.count_documents(query)
    if not dry_run and report["recording_sessions"]:
        await rs.update_many({"origin": {"$exists": False}}, {"$set": {"origin": "central"}})
        await rs.update_many({"flags": {"$exists": False}}, {"$set": {"flags": []}})

    ch = models.Chunk.get_motor_collection()
    report["chunks"] = await ch.count_documents({"received_via": {"$exists": False}})
    if not dry_run and report["chunks"]:
        await ch.update_many({"received_via": {"$exists": False}}, {"$set": {"received_via": "central"}})
    return report


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    result = asyncio.run(run(dry))
    print(("DRY RUN: would update " if dry else "Updated ") + ", ".join(f"{k}={v}" for k, v in result.items()))
