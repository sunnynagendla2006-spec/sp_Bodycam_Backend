import uuid
from typing import List, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status

from .. import geo, models, schemas
from ..auth.deps import require_role
from ..services.audit import log_action
from ..services import events

router = APIRouter(prefix="/police-stations", tags=["Police Stations"])


async def find_nearest_stations(longitude: float, latitude: float, limit: int = 2) -> List[Tuple[models.PoliceStation, float]]:
    """
    Returns up to `limit` (PoliceStation, distance_meters) pairs nearest to
    the given point, ordered nearest first, via Mongo's `$geoNear`
    aggregation stage (needs the 2dsphere index declared on
    PoliceStation.location) -- the direct equivalent of the old
    `ST_Distance(geography, geography)` ORDER BY. Used by both this
    router's /nearest endpoint and incidents.py's verify/dispatch flow
    (primary/backup station lookup).
    """
    pipeline = [
        {
            "$geoNear": {
                "near": {"type": "Point", "coordinates": [longitude, latitude]},
                "distanceField": "distance_meters",
                "spherical": True,
                "key": "location",
                "query": {"location": {"$ne": None}},
            }
        },
        {"$limit": limit},
    ]
    results: List[Tuple[models.PoliceStation, float]] = []
    async for doc in models.PoliceStation.get_motor_collection().aggregate(pipeline):
        station = models.PoliceStation(
            id=doc["_id"],
            name=doc.get("name"),
            location=doc.get("location"),
            jurisdiction=doc.get("jurisdiction"),
            contact=doc.get("contact"),
        )
        results.append((station, doc["distance_meters"]))
    return results


@router.get("/nearest", response_model=schemas.NearestStationsResponse)
async def get_nearest_stations(
    latitude: float = Query(..., ge=-90.0, le=90.0),
    longitude: float = Query(..., ge=-180.0, le=180.0),
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """
    Returns the two nearest police stations to a point -- used by Control
    Room to see primary/backup station for an incident. Restricted to
    admin/control_room since station identity + distance is operational
    dispatch information, not public data.
    """
    rows = await find_nearest_stations(longitude, latitude, limit=2)
    primary = None
    backup = None
    if len(rows) >= 1:
        station, distance = rows[0]
        primary = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)
    if len(rows) >= 2:
        station, distance = rows[1]
        backup = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)
    return schemas.NearestStationsResponse(primary_station=primary, backup_station=backup)


def _station_to_response(station: models.PoliceStation) -> schemas.PoliceStationResponse:
    lon, lat = geo.lon_lat(station.location)
    return schemas.PoliceStationResponse(
        id=station.id, name=station.name, contact=station.contact, latitude=lat, longitude=lon
    )


@router.get("/", response_model=list[schemas.PoliceStationResponse])
async def list_police_stations(
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """
    admin/control_room: every station.
    station: only their own station (a single-item list, or empty if their
    station_id isn't set) -- "GET only its own station" applies to both the
    list and detail views for consistency.
    """
    if current_user.role == models.UserRole.station:
        if not current_user.station_id:
            return []
        stations = await models.PoliceStation.find(models.PoliceStation.id == current_user.station_id).to_list()
    else:
        stations = await models.PoliceStation.find_all().to_list()

    return [_station_to_response(s) for s in stations]


@router.get("/{station_id}", response_model=schemas.PoliceStationResponse)
async def get_police_station(
    station_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """admin/control_room: any station. station: ONLY their own (403 for any other station_id, even a real one -- never confirms/denies existence of stations they can't see beyond that)."""
    station = await models.PoliceStation.get(station_id)
    if not station:
        raise HTTPException(status_code=404, detail="Police station not found")

    if current_user.role == models.UserRole.station and current_user.station_id != station_id:
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to view this station")

    return _station_to_response(station)


@router.post("/", response_model=schemas.PoliceStationResponse)
async def create_police_station(
    payload: schemas.PoliceStationCreate,
    current_user: models.User = Depends(require_role("admin")),
):
    """admin only -- control_room/station/constable/citizen may never create a station."""
    station = models.PoliceStation(
        name=payload.name,
        contact=payload.contact,
        location=geo.point(payload.longitude, payload.latitude),
    )
    await station.insert()

    await log_action(user_id=current_user.id, action="police_station.created", details={"station_id": str(station.id), "name": payload.name})

    await events.publish_police_station_event("created", station.id, station.name)

    return _station_to_response(station)


@router.put("/{station_id}", response_model=schemas.PoliceStationResponse)
async def update_police_station(
    station_id: uuid.UUID,
    payload: schemas.PoliceStationUpdate,
    current_user: models.User = Depends(require_role("admin")),
):
    """admin only. Only the fields provided in the request are changed."""
    station = await models.PoliceStation.get(station_id)
    if not station:
        raise HTTPException(status_code=404, detail="Police station not found")

    if payload.name is not None:
        station.name = payload.name
    if payload.contact is not None:
        station.contact = payload.contact
    if payload.latitude is not None or payload.longitude is not None:
        lon, lat = geo.lon_lat(station.location)
        new_lat = payload.latitude if payload.latitude is not None else lat
        new_lon = payload.longitude if payload.longitude is not None else lon
        if new_lat is not None and new_lon is not None:
            station.location = geo.point(new_lon, new_lat)

    await station.save()

    await log_action(user_id=current_user.id, action="police_station.updated", details={"station_id": str(station_id)})

    await events.publish_police_station_event("updated", station.id, station.name)

    return _station_to_response(station)


@router.delete("/{station_id}")
async def delete_police_station(
    station_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin")),
):
    """admin only."""
    station = await models.PoliceStation.get(station_id)
    if not station:
        raise HTTPException(status_code=404, detail="Police station not found")

    await station.delete()
    await log_action(user_id=current_user.id, action="police_station.deleted", details={"station_id": str(station_id)})

    await events.publish_police_station_event("deleted", station_id)

    return {"status": "deleted"}
