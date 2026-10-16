"""
Removes OfflineGrant RECORDS that expired more than GRANT_RECORD_RETENTION_DAYS ago (default 90, minimum 7).

    python -m scripts.purge_expired_offline_grants            # dry run: only counts
    python -m scripts.purge_expired_offline_grants --apply    # actually deletes

Valid grants and recently expired ones are never touched. Grant issue/revoke events live in the audit log, which this
script does not touch, so past authorization stays explainable after the records are gone. Nothing schedules this script;
an operator runs it. It has NOT been executed as part of the change that added it.
"""
import asyncio
import sys

from app import database
from app.services import site_grants


async def run(apply: bool) -> int:
    await database.init_db()
    return await site_grants.purge_expired_records(dry_run=not apply)


if __name__ == "__main__":
    apply = "--apply" in sys.argv
    n = asyncio.run(run(apply))
    print(f"{'Deleted' if apply else 'Would delete'} {n} expired grant record(s) older than {site_grants.record_retention_days()} days")
