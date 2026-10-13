"""Delete location history older than LOCATION_RETENTION_DAYS (for cron when LOCATION_RETENTION_LOOP=false)."""
import asyncio

from app import database
from app.services import retention


async def main():
    await database.init_db()
    print(f"removed {await retention.purge_location_history()} expired location rows")


if __name__ == "__main__":
    asyncio.run(main())
