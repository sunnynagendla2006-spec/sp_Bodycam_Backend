from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from sqlalchemy.orm import Session
from sqlalchemy import func
from geoalchemy2 import Geography
import uuid

from .. import database, models, schemas
from ..auth.deps import require_role
from ..services.audit import log_action
from ..services import events

router = APIRouter(prefix="/police-stations", tags=["Police Stations"])


def distance_expr(db: Session, expr_a, expr_b):
    """
    Dialect-aware distance expression, in meters where possible.

    On real Postgres/PostGIS, casts both sides to `geography` so
    ST_Distance returns a true great-circle distance in meters (a plain
    geometry-to-geometry ST_Distance on SRID 4326 would return a
    meaningless planar *degree* distance instead).

    In the SQLite test environment, `PoliceStation.location` /
    `ConstableLocation.location` are monkeypatched to plain TEXT columns
    (see tests/conftest.py) storing raw WKT strings -- SQLite has no
    `geography` type, and empirically `CAST(text AS GEOGRAPHY)` silently
    mangles the value (confirmed while building this). So under any
    non-Postgres dialect, this skips the cast entirely and calls
    ST_Distance directly; the test suite registers an ST_Distance shim
    that parses the two WKT strings itself and computes real Haversine
    meters in Python. This is a deliberate, documented test-only fallback,
    not a claim that SQLite provides equivalent PostGIS semantics.
    """
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        return func.ST_Distance(func.cast(expr_a, Geography), func.cast(expr_b, Geography))
    return func.ST_Distance(expr_a, expr_b)


def find_nearest_stations(db: Session, longitude: float, latitude: float, limit: int = 2):
    """
    Returns up to `limit` (PoliceStation, distance_meters) pairs nearest to
    the given point, ordered nearest first. See distance_expr() above for
    the dialect-aware distance computation. Used by both this router's
    /nearest endpoint and incidents.py's verify/dispatch flow (primary/
    backup station lookup).
    """
    point_wkt = f"POINT({longitude} {latitude})"
    dist = distance_expr(db, models.PoliceStation.location, point_wkt).label("distance_meters")
    rows = (
        db.query(models.PoliceStation, dist)
        .filter(models.PoliceStation.location.isnot(None))
        .order_by("distance_meters")
        .limit(limit)
        .all()
    )
    return rows


@router.get("/nearest", response_model=schemas.NearestStationsResponse)
def get_nearest_stations(
    latitude: float = Query(..., ge=-90.0, le=90.0),
    longitude: float = Query(..., ge=-180.0, le=180.0),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """
    Returns the two nearest police stations to a point -- used by Control
    Room to see primary/backup station for an incident. Restricted to
    admin/control_room since station identity + distance is operational
    dispatch information, not public data.
    """
    rows = find_nearest_stations(db, longitude, latitude, limit=2)
    primary = None
    backup = None
    if len(rows) >= 1:
        station, distance = rows[0]
        primary = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)
    if len(rows) >= 2:
        station, distance = rows[1]
        backup = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)
    return schemas.NearestStationsResponse(primary_station=primary, backup_station=backup)


def _station_location_to_lonlat(db: Session, station: models.PoliceStation):
    """Returns (longitude, latitude) parsed from the station's WKT location, or (None, None) if unset."""
    loc_wkt = db.query(func.ST_AsText(models.PoliceStation.location)).filter(models.PoliceStation.id == station.id).scalar()
    if not loc_wkt:
        return None, None
    lon_str, lat_str = loc_wkt.replace("POINT(", "").replace(")", "").split(" ")
    return float(lon_str), float(lat_str)


def _station_to_response(db: Session, station: models.PoliceStation) -> schemas.PoliceStationResponse:
    lon, lat = _station_location_to_lonlat(db, station)
    return schemas.PoliceStationResponse(
        id=station.id, name=station.name, contact=station.contact, latitude=lat, longitude=lon
    )


@router.get("/", response_model=list[schemas.PoliceStationResponse])
def list_police_stations(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """
    admin/control_room: every station.
    station: only their own station (a single-item list, or empty if their
    station_id isn't set) -- "GET only its own station" applies to both the
    list and detail views for consistency.
    """
    query = db.query(models.PoliceStation)
    if current_user.role == models.UserRole.station:
        if not current_user.station_id:
            return []
        query = query.filter(models.PoliceStation.id == current_user.station_id)

    stations = query.all()
    return [_station_to_response(db, s) for s in stations]


@router.get("/{station_id}", response_model=schemas.PoliceStationResponse)
def get_police_station(
    station_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """admin/control_room: any station. station: ONLY their own (403 for any other station_id, even a real one -- never confirms/denies existence of stations they can't see beyond that)."""
    station = db.query(models.PoliceStation).filter(models.PoliceStation.id == station_id).first()
    if not station:
        raise HTTPException(status_code=404, detail="Police station not found")

    if current_user.role == models.UserRole.station and current_user.station_id != station_id:
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to view this station")

    return _station_to_response(db, station)


@router.post("/", response_model=schemas.PoliceStationResponse)
async def create_police_station(
    payload: schemas.PoliceStationCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin")),
):
    """admin only -- control_room/station/constable/citizen may never create a station."""
    station = models.PoliceStation(
        name=payload.name,
        contact=payload.contact,
        location=f"POINT({payload.longitude} {payload.latitude})",
    )
    db.add(station)
    db.flush()

    log_action(db, user_id=current_user.id, action="police_station.created", details={"station_id": str(station.id), "name": payload.name})

    db.commit()
    db.refresh(station)

    await events.publish_police_station_event("created", station.id, station.name)

    return _station_to_response(db, station)


@router.put("/{station_id}", response_model=schemas.PoliceStationResponse)
async def update_police_station(
    station_id: uuid.UUID,
    payload: schemas.PoliceStationUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin")),
):
    """admin only. Only the fields provided in the request are changed."""
    station = db.query(models.PoliceStation).filter(models.PoliceStation.id == station_id).first()
    if not station:
        raise HTTPException(status_code=404, detail="Police station not found")

    if payload.name is not None:
        station.name = payload.name
    if payload.contact is not None:
        station.contact = payload.contact
    if payload.latitude is not None or payload.longitude is not None:
        lon, lat = _station_location_to_lonlat(db, station)
        new_lat = payload.latitude if payload.latitude is not None else lat
        new_lon = payload.longitude if payload.longitude is not None else lon
        if new_lat is not None and new_lon is not None:
            station.location = f"POINT({new_lon} {new_lat})"

    log_action(db, user_id=current_user.id, action="police_station.updated", details={"station_id": str(station_id)})

    db.commit()
    db.refresh(station)

    await events.publish_police_station_event("updated", station.id, station.name)

    return _station_to_response(db, station)


@router.delete("/{station_id}")
async def delete_police_station(
    station_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin")),
):
    """admin only."""
    station = db.query(models.PoliceStation).filter(models.PoliceStation.id == station_id).first()
    if not station:
        raise HTTPException(status_code=404, detail="Police station not found")

    db.delete(station)
    log_action(db, user_id=current_user.id, action="police_station.deleted", details={"station_id": str(station_id)})
    db.commit()

    await events.publish_police_station_event("deleted", station_id)

    return {"status": "deleted"}
