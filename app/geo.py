"""
GeoJSON helpers -- replaces the PostGIS ST_*/WKT-string plumbing that used
to live inline in each router. `models.GeoPoint`/`GeoPolygon` are the
storage representation (see app/models.py); `to_wkt()` renders the same
"POINT(lon lat)" text the API has always returned in `location` fields, so
existing clients (mobile app, web dashboard) see no change in shape even
though storage moved from PostGIS geometry to native GeoJSON + a 2dsphere
index.
"""
from typing import List, Optional, Tuple

from . import models


def point(longitude: float, latitude: float) -> models.GeoPoint:
    return models.GeoPoint(coordinates=[longitude, latitude])


def polygon(rings: List[List[List[float]]]) -> models.GeoPolygon:
    return models.GeoPolygon(coordinates=rings)


def lon_lat(geo_point: Optional[models.GeoPoint]) -> Tuple[Optional[float], Optional[float]]:
    if geo_point is None:
        return None, None
    lon, lat = geo_point.coordinates
    return lon, lat


def to_wkt(geo_point: Optional[models.GeoPoint]) -> Optional[str]:
    if geo_point is None:
        return None
    lon, lat = geo_point.coordinates
    return f"POINT({lon} {lat})"


def haversine_meters(a: Optional[models.GeoPoint], b: Optional[models.GeoPoint]) -> Optional[float]:
    """
    Great-circle distance in meters -- used where the old code relied on
    Postgres's `ST_Distance(geography, geography)`. For queries against the
    database (rather than two already-loaded points), prefer Mongo's native
    `$geoNear`/`$near` aggregation stages instead (see
    routers/police_stations.py::find_nearest_stations) -- this helper is
    for the handful of spots that just need to compare two in-memory points.
    """
    import math

    if a is None or b is None:
        return None
    lon1, lat1 = a.coordinates
    lon2, lat2 = b.coordinates
    r = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    h = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return r * 2 * math.asin(math.sqrt(h))
