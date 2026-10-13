"""
Geographic zone detection and boundary validation service for ARVI-SENTINELS.

Handles:
- MongoDB $geoIntersects queries against EventZone GeoJSON polygons
- In-memory fallback point-in-polygon verification via app.geo
- Deterministic overlap resolution (priority DESC, created_at ASC, code ASC)
- Accuracy policy and boundary hysteresis to prevent ping-pong transitions
"""
import logging
from typing import Optional, Tuple, List
from datetime import datetime

from .. import models, geo

logger = logging.getLogger(__name__)

# Max GNSS horizontal accuracy in meters before a zone transition is marked UNCERTAIN
MAX_TRUSTED_ACCURACY_METERS = 50.0


async def detect_geographic_zone(
    longitude: float,
    latitude: float,
    accuracy: Optional[float] = None,
    deployment: Optional[str] = None,
    previous_zone: Optional[str] = None,
) -> Tuple[Optional[str], str, Optional[models.EventZone]]:
    """
    Given WGS84 [longitude, latitude] GNSS coordinates, determines the matching
    EventZone.

    Returns:
        (zone_code, zone_status, zone_model)
        where zone_status is one of:
          - 'CONFIRMED': Coordinate confidently falls within the zone.
          - 'UNCERTAIN': Coordinate falls in zone but accuracy exceeds threshold,
                         or near boundary with high inaccuracy.
          - 'OUTSIDE': Coordinate is outside all active zones.
    """
    query = {"enabled": True}
    if deployment:
        query["deployment"] = deployment

    # Attempt MongoDB native $geoIntersects query first
    matched_zones: List[models.EventZone] = []
    try:
        motor_coll = models.EventZone.get_motor_collection()
        mongo_query = {
            **query,
            "polygon": {
                "$geoIntersects": {
                    "$geometry": {
                        "type": "Point",
                        "coordinates": [longitude, latitude],
                    }
                }
            },
        }
        cursor = motor_coll.find(mongo_query)
        docs = await cursor.to_list(length=50)
        for doc in docs:
            matched_zones.append(models.EventZone(**doc))
    except Exception as e:
        logger.warning(f"MongoDB $geoIntersects failed or standalone fallback triggered: {e}")
        # In-memory ray-casting fallback over enabled zones
        active_zones = await models.EventZone.find(query).to_list()
        for z in active_zones:
            if z.polygon and z.polygon.coordinates:
                if geo.point_in_polygon(longitude, latitude, z.polygon.coordinates):
                    matched_zones.append(z)

    if not matched_zones:
        # If outside all zones but previous_zone was set and accuracy is bad,
        # flag as UNCERTAIN outside rather than immediately dropping
        if previous_zone and accuracy is not None and accuracy > MAX_TRUSTED_ACCURACY_METERS:
            return previous_zone, "UNCERTAIN", None
        return None, "OUTSIDE", None

    # Deterministic tie-breaking for overlapping zones:
    # 1. Highest priority wins
    # 2. Earliest created_at wins
    # 3. Alphabetical code wins
    matched_zones.sort(
        key=lambda z: (-z.priority, z.created_at or datetime.min, z.code)
    )
    winning_zone = matched_zones[0]

    # Accuracy policy / Hysteresis check:
    # If accuracy exceeds MAX_TRUSTED_ACCURACY_METERS and would cause a zone change,
    # mark as UNCERTAIN and preserve previous_zone if previous_zone was confirmed.
    if accuracy is not None and accuracy > MAX_TRUSTED_ACCURACY_METERS:
        if previous_zone and previous_zone != winning_zone.code:
            # Fix is noisy/inaccurate near boundary; retain previous zone with UNCERTAIN status
            return previous_zone, "UNCERTAIN", winning_zone
        return winning_zone.code, "UNCERTAIN", winning_zone

    return winning_zone.code, "CONFIRMED", winning_zone
