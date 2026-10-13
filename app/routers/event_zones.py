import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import geo, models, schemas
from ..auth.deps import get_current_user
from ..services.audit import log_action

router = APIRouter(prefix="/event-zones", tags=["Event Zones"])


def _require_admin(user: models.User):
    if user.role != models.UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators may manage event zones",
        )


def _require_authorized_viewer(user: models.User):
    if user.role not in [
        models.UserRole.admin,
        models.UserRole.control_room,
        models.UserRole.station,
        models.UserRole.constable,
    ]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view event zones",
        )


def _to_zone_response(zone: models.EventZone) -> schemas.EventZoneResponse:
    return schemas.EventZoneResponse(
        id=zone.id,
        code=zone.code,
        name=zone.name,
        description=zone.description,
        deployment=zone.deployment,
        zone_type=zone.zone_type,
        coordinates=zone.polygon.coordinates if zone.polygon else [],
        priority=zone.priority,
        color=zone.color,
        enabled=zone.enabled,
        created_at=zone.created_at,
        updated_at=zone.updated_at,
    )


@router.post("/", response_model=schemas.EventZoneResponse, status_code=status.HTTP_201_CREATED)
async def create_event_zone(
    payload: schemas.EventZoneCreateRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Creates an event-specific geographic operational zone with a validated
    GeoJSON polygon boundary in WGS84 coordinates.
    """
    _require_admin(current_user)

    # Validate GeoJSON polygon structure and coordinate ranges
    valid, err_msg = geo.validate_geojson_polygon(payload.coordinates)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid GeoJSON polygon coordinates: {err_msg}",
        )

    # Check natural key uniqueness
    existing = await models.EventZone.find_one(models.EventZone.code == payload.code)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Event zone with code '{payload.code}' already exists",
        )

    polygon_model = geo.polygon(payload.coordinates)
    zone = models.EventZone(
        code=payload.code,
        name=payload.name,
        description=payload.description,
        deployment=payload.deployment,
        zone_type=payload.zone_type,
        polygon=polygon_model,
        priority=payload.priority,
        color=payload.color or "#3B82F6",
        enabled=payload.enabled,
        created_by=current_user.id,
        updated_by=current_user.id,
    )
    await zone.insert()

    await log_action(
        user_id=current_user.id,
        action="event_zone.created",
        details={"zone_id": str(zone.id), "code": zone.code, "name": zone.name},
    )

    return _to_zone_response(zone)


@router.get("/", response_model=List[schemas.EventZoneResponse])
async def list_event_zones(
    deployment: Optional[str] = Query(default=None),
    enabled: Optional[bool] = Query(default=None),
    current_user: models.User = Depends(get_current_user),
):
    """
    Lists event zones, optionally filtered by deployment or enabled status.
    """
    _require_authorized_viewer(current_user)

    query = {}
    if deployment:
        query["deployment"] = deployment
    if enabled is not None:
        query["enabled"] = enabled

    zones = await models.EventZone.find(query).sort("-priority", "+created_at").to_list()
    return [_to_zone_response(z) for z in zones]


@router.get("/{zone_id}", response_model=schemas.EventZoneResponse)
async def get_event_zone(
    zone_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """
    Retrieves details for a specific event zone.
    """
    _require_authorized_viewer(current_user)

    zone = await models.EventZone.get(zone_id)
    if not zone:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event zone not found")

    return _to_zone_response(zone)


@router.patch("/{zone_id}", response_model=schemas.EventZoneResponse)
async def update_event_zone(
    zone_id: uuid.UUID,
    payload: schemas.EventZoneUpdateRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Updates an event zone's metadata or boundary polygon geometry.
    """
    _require_admin(current_user)

    zone = await models.EventZone.get(zone_id)
    if not zone:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event zone not found")

    if payload.coordinates is not None:
        valid, err_msg = geo.validate_geojson_polygon(payload.coordinates)
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid GeoJSON polygon coordinates: {err_msg}",
            )
        zone.polygon = geo.polygon(payload.coordinates)

    if payload.name is not None:
        zone.name = payload.name
    if payload.description is not None:
        zone.description = payload.description
    if payload.deployment is not None:
        zone.deployment = payload.deployment
    if payload.zone_type is not None:
        zone.zone_type = payload.zone_type
    if payload.priority is not None:
        zone.priority = payload.priority
    if payload.color is not None:
        zone.color = payload.color
    if payload.enabled is not None:
        zone.enabled = payload.enabled

    zone.updated_at = datetime.now(timezone.utc)
    zone.updated_by = current_user.id
    await zone.save()

    await log_action(
        user_id=current_user.id,
        action="event_zone.updated",
        details={"zone_id": str(zone.id), "code": zone.code},
    )

    return _to_zone_response(zone)


@router.post("/{zone_id}/disable", response_model=schemas.EventZoneResponse)
async def disable_event_zone(
    zone_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """
    Disables an active event zone.
    """
    _require_admin(current_user)

    zone = await models.EventZone.get(zone_id)
    if not zone:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event zone not found")

    zone.enabled = False
    zone.updated_at = datetime.now(timezone.utc)
    zone.updated_by = current_user.id
    await zone.save()

    await log_action(
        user_id=current_user.id,
        action="event_zone.disabled",
        details={"zone_id": str(zone.id), "code": zone.code},
    )

    return _to_zone_response(zone)
