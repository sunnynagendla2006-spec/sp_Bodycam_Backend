"""
Geographic zone detection and transition policy for ARVI-SENTINELS.

Two layers, deliberately separate:

1. `find_matching_zones` / `detect_geographic_zone` -- RAW geometry: which
   enabled EventZones contain this coordinate (MongoDB $geoIntersects with an
   in-memory ray-casting fallback), overlaps resolved deterministically by
   priority DESC, created_at ASC, code ASC.

2. `resolve_zone_transition` -- POLICY: whether an officer's *recorded*
   (detected) zone may change because of one more fix. A single noisy fix
   must never flip the zone, so a change requires ALL of:
     - a trusted fix (horizontal accuracy known and <= MAX_TRUSTED_ACCURACY_METERS);
     - the fix lies clearly past the boundary: further than
       min(max(accuracy, ZONE_BOUNDARY_MARGIN_METERS), ZONE_BOUNDARY_MAX_MARGIN_METERS)
       from the boundary of the zone being left and of the zone being entered;
     - the same candidate zone seen on ZONE_TRANSITION_CONFIRMATIONS
       consecutive qualifying fixes.
   The first ever evaluation for an officer is accepted immediately (there is
   no prior belief to protect). Anything else is reported as UNCERTAIN /
   PENDING and leaves the recorded zone unchanged.

The detected zone is never the officer's *assigned* duty zone; that lives on
Constable.assigned_zone_code and is only ever set administratively.
"""
import dataclasses
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .. import models, geo

logger = logging.getLogger(__name__)

# Stored as Constable.zone_candidate while an officer appears to be leaving every zone.
OUTSIDE_CANDIDATE = "__outside__"

# Max GNSS horizontal accuracy in meters for a fix to be allowed to change a zone
MAX_TRUSTED_ACCURACY_METERS = 50.0


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def zone_transition_confirmations() -> int:
    try:
        return max(1, int(os.getenv("ZONE_TRANSITION_CONFIRMATIONS", "2")))
    except ValueError:
        return 2


def boundary_margin_meters() -> float:
    return _float_env("ZONE_BOUNDARY_MARGIN_METERS", 10.0)


def boundary_max_margin_meters() -> float:
    return _float_env("ZONE_BOUNDARY_MAX_MARGIN_METERS", 30.0)


async def find_matching_zones(
    longitude: float,
    latitude: float,
    deployment: Optional[str] = None,
) -> List[models.EventZone]:
    """All enabled zones containing the point, best match first."""
    query = {"enabled": True}
    if deployment:
        query["deployment"] = deployment

    matched_zones: List[models.EventZone] = []
    try:
        motor_coll = models.EventZone.get_motor_collection()
        mongo_query = {
            **query,
            "polygon": {
                "$geoIntersects": {
                    "$geometry": {"type": "Point", "coordinates": [longitude, latitude]}
                }
            },
        }
        docs = await motor_coll.find(mongo_query).to_list(length=50)
        for doc in docs:
            matched_zones.append(models.EventZone(**doc))
    except Exception as e:  # pragma: no cover - exercised only when the geo index/query is unavailable
        logger.warning("MongoDB $geoIntersects failed, using in-memory fallback: %s", e)
        matched_zones = []
        for z in await models.EventZone.find(query).to_list():
            if z.polygon and z.polygon.coordinates and geo.point_in_polygon(longitude, latitude, z.polygon.coordinates):
                matched_zones.append(z)

    matched_zones.sort(key=lambda z: (-z.priority, z.created_at or datetime.min, z.code))
    return matched_zones


async def detect_geographic_zone(
    longitude: float,
    latitude: float,
    accuracy: Optional[float] = None,
    deployment: Optional[str] = None,
    previous_zone: Optional[str] = None,
) -> Tuple[Optional[str], str, Optional[models.EventZone]]:
    """
    Stateless detection (no hysteresis) -- returns (zone_code, zone_status, zone_model)
    with zone_status one of CONFIRMED / UNCERTAIN / OUTSIDE. Ingestion uses
    `resolve_zone_transition`; this remains for callers that only need a
    point-in-zone answer.
    """
    matched = await find_matching_zones(longitude, latitude, deployment)
    if not matched:
        if previous_zone and accuracy is not None and accuracy > MAX_TRUSTED_ACCURACY_METERS:
            return previous_zone, "UNCERTAIN", None
        return None, "OUTSIDE", None

    winning_zone = matched[0]
    if accuracy is not None and accuracy > MAX_TRUSTED_ACCURACY_METERS:
        if previous_zone and previous_zone != winning_zone.code:
            return previous_zone, "UNCERTAIN", winning_zone
        return winning_zone.code, "UNCERTAIN", winning_zone
    return winning_zone.code, "CONFIRMED", winning_zone


@dataclasses.dataclass
class ZoneResolution:
    zone_code: Optional[str]  # the recorded (detected) zone AFTER this fix
    status: str  # CONFIRMED | OUTSIDE | UNCERTAIN | PENDING
    changed: bool
    candidate: Optional[str]
    candidate_count: int
    raw_zone_code: Optional[str]  # what the geometry alone said for this single fix


def _boundary_distance(zone: Optional[models.EventZone], longitude: float, latitude: float) -> Optional[float]:
    if zone is None or not zone.polygon or not zone.polygon.coordinates:
        return None
    return geo.distance_to_polygon_boundary_meters(longitude, latitude, zone.polygon.coordinates)


def resolve_zone_transition(
    *,
    current_zone: Optional[str],
    evaluated_before: bool,
    candidate: Optional[str],
    candidate_count: int,
    matched: List[models.EventZone],
    zones_by_code: Dict[str, models.EventZone],
    longitude: float,
    latitude: float,
    accuracy: Optional[float],
) -> ZoneResolution:
    """Pure policy function -- see the module docstring. `matched` must be priority-sorted (find_matching_zones)."""
    best = matched[0] if matched else None
    best_code = best.code if best else None
    current_status = "CONFIRMED" if current_zone else "OUTSIDE"
    if not evaluated_before:
        current_status = "UNCERTAIN"

    # 1. Untrusted fix: never allowed to change the zone.
    if accuracy is None or accuracy > MAX_TRUSTED_ACCURACY_METERS:
        return ZoneResolution(current_zone, "UNCERTAIN", False, candidate, candidate_count, best_code)

    # 2. Same as what we already believe: confirm and clear any pending candidate.
    if best_code == current_zone and evaluated_before:
        return ZoneResolution(current_zone, current_status, False, None, 0, best_code)

    # 3. Different zone. Require the fix to be clearly past the relevant boundaries.
    margin = min(max(accuracy, boundary_margin_meters()), boundary_max_margin_meters())
    current_zone_doc = zones_by_code.get(current_zone) if current_zone else None
    still_inside_current = current_zone is not None and any(z.code == current_zone for z in matched)
    distances: List[Optional[float]] = [_boundary_distance(best, longitude, latitude)]
    if not still_inside_current:
        distances.append(_boundary_distance(current_zone_doc, longitude, latitude))
    if any(d is not None and d < margin for d in distances):
        return ZoneResolution(current_zone, "PENDING", False, candidate, candidate_count, best_code)

    # 4. First ever evaluation: nothing to protect, accept immediately.
    if not evaluated_before:
        return ZoneResolution(best_code, "CONFIRMED" if best_code else "OUTSIDE", best_code != current_zone, None, 0, best_code)

    # 5. Count consecutive confirmations of the same candidate ("leaving every zone" is a candidate too).
    candidate_key = best_code or OUTSIDE_CANDIDATE
    count = candidate_count + 1 if candidate == candidate_key else 1
    if count >= zone_transition_confirmations():
        return ZoneResolution(best_code, "CONFIRMED" if best_code else "OUTSIDE", True, None, 0, best_code)
    return ZoneResolution(current_zone, "PENDING", False, candidate_key, count, best_code)
