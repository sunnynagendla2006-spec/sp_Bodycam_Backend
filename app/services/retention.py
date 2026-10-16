"""Location-history retention. LOCATION_RETENTION_DAYS (default 30) is the single policy knob."""
import datetime

from .. import models


async def purge_location_history(now: datetime.datetime = None) -> int:
    """Deletes ConstableLocation rows older than the retention window. Returns the number removed."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=models.location_retention_days())
    result = await models.ConstableLocation.get_motor_collection().delete_many({"timestamp": {"$lt": cutoff}})
    return result.deleted_count
