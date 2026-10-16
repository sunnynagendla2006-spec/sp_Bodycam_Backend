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


def validate_geojson_polygon(rings: List[List[List[float]]]) -> Tuple[bool, Optional[str]]:
    """
    Validates GeoJSON Polygon structure per RFC 7946 & MongoDB 2dsphere requirements:
    1. Must be a non-empty list of rings.
    2. Outer ring must have at least 4 coordinates (3 distinct vertices + closing vertex).
    3. The first and last coordinate of each ring must be identical (ring closure).
    4. Each coordinate must be [longitude, latitude] with -180 <= lon <= 180 and -90 <= lat <= 90.
    5. Non-degenerate: Outer ring must contain at least 3 distinct points.
    """
    if not isinstance(rings, list) or len(rings) == 0:
        return False, "Polygon coordinates must be a non-empty list of linear rings"

    for r_idx, ring in enumerate(rings):
        if not isinstance(ring, list) or len(ring) < 4:
            return False, f"Ring {r_idx} must contain at least 4 coordinates (closed linear ring)"

        first, last = ring[0], ring[-1]
        if not isinstance(first, (list, tuple)) or not isinstance(last, (list, tuple)) or len(first) < 2 or len(last) < 2:
            return False, f"Ring {r_idx} contains invalid coordinate tuples"

        if first[0] != last[0] or first[1] != last[1]:
            return False, f"Ring {r_idx} is not closed: first coordinate {first} != last coordinate {last}"

        distinct_points = set()
        for c_idx, coord in enumerate(ring):
            if not isinstance(coord, (list, tuple)) or len(coord) != 2:
                return False, f"Coordinate {c_idx} in ring {r_idx} must be a 2-element [longitude, latitude] list"
            lon, lat = coord[0], coord[1]
            if not isinstance(lon, (int, float)) or not isinstance(lat, (int, float)):
                return False, f"Coordinate {c_idx} in ring {r_idx} must contain numeric values"
            if not (-180.0 <= lon <= 180.0):
                return False, f"Longitude {lon} in ring {r_idx} must be between -180 and 180"
            if not (-90.0 <= lat <= 90.0):
                return False, f"Latitude {lat} in ring {r_idx} must be between -90 and 90"
            distinct_points.add((round(float(lon), 7), round(float(lat), 7)))

        if len(distinct_points) < 3:
            return False, f"Ring {r_idx} must contain at least 3 distinct vertices"

    return True, None


def point_in_ring(lon: float, lat: float, ring: List[List[float]]) -> bool:
    """
    Standard ray casting algorithm for point-in-polygon on a 2D ring.
    Returns True if (lon, lat) is strictly inside the ring.
    """
    n = len(ring)
    inside = False
    p1x, p1y = ring[0][0], ring[0][1]
    for i in range(1, n + 1):
        p2x, p2y = ring[i % n][0], ring[i % n][1]
        if lat > min(p1y, p2y):
            if lat <= max(p1y, p2y):
                if lon <= max(p1x, p2x):
                    if p1y != p2y:
                        xinters = (lat - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                    if p1x == p2x or lon <= xinters:
                        inside = not inside
        p1x, p1y = p2x, p2y
    return inside


def point_in_polygon(lon: float, lat: float, rings: List[List[List[float]]]) -> bool:
    """
    Determines whether (lon, lat) is inside a GeoJSON Polygon:
    - Inside outer ring (rings[0])
    - NOT inside any interior hole rings (rings[1:])
    """
    if not rings or not point_in_ring(lon, lat, rings[0]):
        return False
    for hole in rings[1:]:
        if point_in_ring(lon, lat, hole):
            return False
    return True



# ---------------------------------------------------------------------------
# Boundary distance (used for zone-transition hysteresis)
# ---------------------------------------------------------------------------

def _to_local_xy(lon: float, lat: float, lon0: float, lat0: float) -> Tuple[float, float]:
    """Equirectangular projection around (lon0, lat0), in meters. Accurate to well under a metre over a festival-sized area."""
    import math

    x = math.radians(lon - lon0) * 6371000.0 * math.cos(math.radians(lat0))
    y = math.radians(lat - lat0) * 6371000.0
    return x, y


def distance_to_ring_meters(lon: float, lat: float, ring: List[List[float]]) -> float:
    """Shortest distance in meters from a point to a ring's edges (0 if it lies on an edge)."""
    px, py = 0.0, 0.0  # the query point is the projection origin
    best = float("inf")
    n = len(ring)
    for i in range(n - 1):
        ax, ay = _to_local_xy(ring[i][0], ring[i][1], lon, lat)
        bx, by = _to_local_xy(ring[i + 1][0], ring[i + 1][1], lon, lat)
        dx, dy = bx - ax, by - ay
        seg_len_sq = dx * dx + dy * dy
        if seg_len_sq == 0:
            t = 0.0
        else:
            t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / seg_len_sq))
        cx, cy = ax + t * dx, ay + t * dy
        dist = (cx * cx + cy * cy) ** 0.5
        if dist < best:
            best = dist
    return best


def distance_to_polygon_boundary_meters(lon: float, lat: float, rings: List[List[List[float]]]) -> float:
    """Distance to the nearest edge of ANY ring (outer boundary or hole) -- the distance a fix must travel to change inside/outside."""
    return min(distance_to_ring_meters(lon, lat, ring) for ring in rings if ring)
