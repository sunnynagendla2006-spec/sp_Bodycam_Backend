"""
Idempotent, NON-DESTRUCTIVE data migration for the tracking / AP-inventory upgrade.

Run once after deploying (safe to re-run):
    python -m scripts.migrate_tracking_schema            # apply
    python -m scripts.migrate_tracking_schema --dry-run  # report only

It never deletes anything. It only:
  1. access_points: backfills the new inventory fields, and withdraws any
     stored `status: online|offline` that was set by an administrator click
     rather than by real telemetry (sets `unknown` unless the AP is already
     verified). Sets verification_status `configured`/`registered` for rows
     that were never verified, and lifecycle_status from `enabled`.
  2. constables: backfills last_location_recorded_at from the latest stored
     fix so existing positions age correctly instead of looking brand new.
  3. devices: leaves enrolment_status absent (reads as `approved`, as those
     devices were already in service) -- revoke any you do not trust.
"""
import asyncio
import sys

from app import database, models


async def run(dry_run: bool) -> dict:
    await database.init_db()
    report = {"access_points": 0, "constables": 0}

    ap_coll = models.AccessPoint.get_motor_collection()
    async for doc in ap_coll.find({}):
        updates = {}
        verified = doc.get("verification_status") == "verified"
        if "verification_status" not in doc:
            has_ident = bool(doc.get("bssid") or doc.get("serial_number") or doc.get("management_ip"))
            updates["verification_status"] = "configured" if has_ident else "registered"
        if "lifecycle_status" not in doc:
            updates["lifecycle_status"] = "active" if doc.get("enabled", True) else "disabled"
        if not verified and doc.get("status") in ("online", "offline"):
            updates["status"] = "unknown"
        if "integration_health" not in doc:
            updates["integration_health"] = "unconfigured"
        if "event_zone_codes" not in doc:
            updates["event_zone_codes"] = []
        if "config_history" not in doc:
            updates["config_history"] = []
        if updates:
            report["access_points"] += 1
            if not dry_run:
                await ap_coll.update_one({"_id": doc["_id"]}, {"$set": updates})

    c_coll = models.Constable.get_motor_collection()
    loc_coll = models.ConstableLocation.get_motor_collection()
    async for c in c_coll.find({"last_location_recorded_at": None, "last_location_point": {"$ne": None}}):
        last = await loc_coll.find_one({"constable_id": c["_id"]}, sort=[("timestamp", -1)])
        recorded = (last or {}).get("recorded_at") or (last or {}).get("timestamp") or c.get("last_location_at")
        if recorded:
            report["constables"] += 1
            if not dry_run:
                await c_coll.update_one({"_id": c["_id"]}, {"$set": {"last_location_recorded_at": recorded}})
    return report


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    print(("DRY RUN: " if dry else "") + str(asyncio.run(run(dry))))
