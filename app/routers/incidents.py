import datetime
import uuid

from beanie.operators import In
from fastapi import APIRouter, Depends, HTTPException
from fastapi import status as http_status
from pymongo import ReturnDocument

from .. import database, geo, models, schemas
from ..auth.deps import get_current_user, require_role
from .constables import get_own_constable, CONSTABLE_LOCATION_MAX_AGE_SECONDS, ACTIVE_ASSIGNMENT_STATUSES
from .police_stations import find_nearest_stations
from ..services.audit import log_action
from ..services import events

router = APIRouter(prefix="/incidents", tags=["Incidents"])

# Statuses a constable is allowed to set on an incident THEY are assigned to,
# through the LEGACY generic PUT /incidents/{id}/status endpoint (kept for
# backward compatibility -- see that endpoint's docstring below).
_CONSTABLE_ALLOWED_STATUS_TRANSITIONS = {
    models.IncidentStatus.en_route,
    models.IncidentStatus.arrived,
    models.IncidentStatus.resolved,
}

# Roles allowed to create an incident directly. Constables are intentionally
# excluded -- nothing in the current spec requires a constable to be able to
# create an incident report on a citizen's behalf, and allowing it would
# let a constable manufacture incidents. Citizens create their own; admin/
# control_room may create operationally (e.g. phone-in reports).
_INCIDENT_CREATE_ROLES = {models.UserRole.citizen, models.UserRole.admin, models.UserRole.control_room}

# Incident statuses from which a dispatch is meaningful. Only a verified
# incident (or one re-opened back to verified after a constable rejected
# their assignment -- see constables.py::reject_assignment) may be
# dispatched. Rejected/resolved/closed incidents may never be dispatched.
_DISPATCHABLE_INCIDENT_STATUSES = {models.IncidentStatus.verified}


def _to_incident_out(incident: models.Incident) -> schemas.IncidentOut:
    return schemas.IncidentOut(
        id=incident.id,
        display_id=incident.display_id,
        citizen_id=incident.citizen_id,
        description=incident.description,
        status=incident.status,
        station_id=incident.station_id,
        location=geo.to_wkt(incident.location),
        created_at=incident.created_at,
    )


@router.post("/", response_model=schemas.IncidentOut)
async def create_incident(
    incident: schemas.IncidentCreate,
    current_user: models.User = Depends(get_current_user),
):
    if current_user.role not in _INCIDENT_CREATE_ROLES:
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to create incidents")

    now = datetime.datetime.now()
    display_id = f"INC-{now.strftime('%Y%m%d-%H%M%S')}-{int(abs(incident.location_lat))}-{int(abs(incident.location_lon))}"

    # Never trust a client-supplied citizen_id: derive it from the
    # authenticated user when they are a citizen, otherwise leave it null
    # (a control-room/admin-created incident has no citizen owner yet).
    citizen_id = current_user.id if current_user.role == models.UserRole.citizen else None

    # Auto-assign the responsible station at creation time (nearest
    # PoliceStation to the incident's coordinates), so a station user can
    # see/verify/reject incidents in their own jurisdiction from the moment
    # they're reported.
    nearest_station_id = None
    station_rows = await find_nearest_stations(incident.location_lon, incident.location_lat, limit=1)
    if station_rows:
        nearest_station_id = station_rows[0][0].id

    new_incident = models.Incident(
        display_id=display_id,
        citizen_id=citizen_id,
        location=geo.point(incident.location_lon, incident.location_lat),
        description=incident.description,
        status=models.IncidentStatus.new,
        station_id=nearest_station_id,
    )
    await new_incident.insert()

    await log_action(
        user_id=current_user.id,
        action="incident.created",
        incident_id=new_incident.id,
        details={"display_id": display_id},
    )
    return _to_incident_out(new_incident)


@router.get("/", response_model=list[schemas.IncidentOut])
async def list_incidents(
    current_user: models.User = Depends(get_current_user),
):
    """
    Role-scoped incident listing:
      - admin / control_room: all incidents
      - citizen: only incidents they created
      - constable: only incidents currently (or previously) assigned to them
      - station: incidents whose `station_id` matches the authenticated
        user's `station_id`. A station user with no station_id set gets an
        empty list rather than an error.
    """
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        incidents = await models.Incident.find_all().to_list()
    elif role == models.UserRole.citizen:
        incidents = await models.Incident.find(models.Incident.citizen_id == current_user.id).to_list()
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            return []
        incidents = await models.Incident.find({"assignments.constable_id": own_constable.id}).to_list()
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        incidents = await models.Incident.find(models.Incident.station_id == current_user.station_id).to_list()
    else:
        return []

    return [_to_incident_out(inc) for inc in incidents]


@router.put("/{incident_id}/status", response_model=schemas.IncidentOut)
async def update_incident_status(
    incident_id: uuid.UUID,
    status: models.IncidentStatus,
    current_user: models.User = Depends(get_current_user),
):
    """
    LEGACY generic status setter, kept for backward compatibility. New
    workflow-specific actions (verify/reject/needs-review, and constable
    response-progress) should use the dedicated endpoints below / PUT
    /constables/me/incidents/{id}/status, which enforce proper
    state-machine transitions.

      - admin / control_room: any transition
      - station: any transition, but ONLY for incidents belonging to their
        own station
      - constable: ONLY for incidents they are assigned to, ONLY to
        en_route/arrived/resolved
      - citizen: never
    """
    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    role = current_user.role

    if role == models.UserRole.admin:
        pass
    elif role == models.UserRole.control_room:
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id or incident.station_id != current_user.station_id:
            raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to update this incident")
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        assigned = own_constable and any(a.constable_id == own_constable.id for a in incident.assignments)
        if not own_constable or not assigned:
            raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to update this incident")
        if status not in _CONSTABLE_ALLOWED_STATUS_TRANSITIONS:
            raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to set this status")
    else:
        # citizen, or any other/unknown role
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to update this incident")

    old_status = incident.status.value if incident.status else None
    incident.status = status
    await incident.save()

    await log_action(
        user_id=current_user.id,
        action="incident.status_changed",
        incident_id=incident.id,
        details={"old_status": old_status, "new_status": status.value},
    )

    if status == models.IncidentStatus.closed:
        # Logic to clear evidence files from S3/MinIO goes here if they don't need review
        pass

    return _to_incident_out(incident)


# ---------------------------------------------------------------------------
# Dedicated verification workflow. Explicit actions, not a generic status
# setter. admin/control_room: any incident. station: only incidents
# belonging to their own station. constable/citizen: never.
# ---------------------------------------------------------------------------

def _check_verification_authority(incident: models.Incident, current_user: models.User):
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        return
    if role == models.UserRole.station:
        if not current_user.station_id or incident.station_id != current_user.station_id:
            raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to act on this incident")
        return
    raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to act on this incident")


async def _set_incident_verification_status(
    incident_id: uuid.UUID,
    new_status: models.IncidentStatus,
    current_user: models.User,
    action: str,
    reason: str = None,
) -> models.Incident:
    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    _check_verification_authority(incident, current_user)

    old_status = incident.status.value if incident.status else None
    incident.status = new_status
    await incident.save()

    details = {"old_status": old_status, "new_status": new_status.value}
    if reason:
        details["reason"] = reason
    await log_action(user_id=current_user.id, action=action, incident_id=incident.id, details=details)

    return incident


@router.post("/{incident_id}/verify", response_model=schemas.IncidentOut)
async def verify_incident(
    incident_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """Explicit verification action. admin/control_room: any incident. station: only their own station's incidents -- see _check_verification_authority."""
    incident = await _set_incident_verification_status(incident_id, models.IncidentStatus.verified, current_user, "incident.verified")
    await events.publish_incident_verified(incident)
    return _to_incident_out(incident)


@router.post("/{incident_id}/reject", response_model=schemas.IncidentOut)
async def reject_incident(
    incident_id: uuid.UUID,
    payload: schemas.IncidentActionReason = schemas.IncidentActionReason(),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """Explicit rejection. A rejected incident can never be dispatched (see dispatch_incident). Station-scoped per _check_verification_authority."""
    incident = await _set_incident_verification_status(
        incident_id, models.IncidentStatus.rejected, current_user, "incident.rejected", reason=payload.reason
    )
    await events.publish_incident_rejected(incident)
    return _to_incident_out(incident)


@router.post("/{incident_id}/needs-review", response_model=schemas.IncidentOut)
async def flag_incident_needs_review(
    incident_id: uuid.UUID,
    payload: schemas.IncidentActionReason = schemas.IncidentActionReason(),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """Explicit 'needs more information before we can verify/reject' flag. Station-scoped per _check_verification_authority."""
    incident = await _set_incident_verification_status(
        incident_id, models.IncidentStatus.needs_review, current_user, "incident.needs_review", reason=payload.reason
    )
    await events.publish_incident_needs_review(incident)
    return _to_incident_out(incident)


# ---------------------------------------------------------------------------
# Responsible station lookup (primary/backup nearest PoliceStation)
# ---------------------------------------------------------------------------

@router.get("/{incident_id}/responsible-stations", response_model=schemas.NearestStationsResponse)
async def get_responsible_stations(
    incident_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """
    Primary (nearest) and backup (second-nearest) PoliceStation for this
    incident's location, using the same $geoNear-based helper as
    /police-stations/nearest. Does not itself assign incident.station_id --
    that happens as a side effect of dispatch (see dispatch_incident) once
    a station is actually being acted on, not merely queried.
    """
    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not incident.location:
        raise HTTPException(status_code=422, detail="Incident has no location to route from")

    lon, lat = geo.lon_lat(incident.location)
    rows = await find_nearest_stations(lon, lat, limit=2)

    primary = None
    backup = None
    if len(rows) >= 1:
        station, distance = rows[0]
        primary = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)
    if len(rows) >= 2:
        station, distance = rows[1]
        backup = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)
    return schemas.NearestStationsResponse(primary_station=primary, backup_station=backup)


# ---------------------------------------------------------------------------
# Dispatch: find nearest ELIGIBLE constable, create the assignment, and do
# so safely under concurrent dispatch requests.
# ---------------------------------------------------------------------------

class _ConstableRaceLost(Exception):
    """Raised inside a database.transaction() block: this candidate was grabbed by a concurrent dispatch first -- abort and try the next candidate."""


class _IncidentRaceLost(Exception):
    """Raised inside a database.transaction() block: this incident was dispatched by a concurrent request first -- abort and stop entirely."""


async def _busy_constable_ids() -> set:
    pipeline = [
        {"$unwind": "$assignments"},
        {"$match": {"assignments.status": {"$in": [s.value for s in ACTIVE_ASSIGNMENT_STATUSES]}}},
        {"$group": {"_id": "$assignments.constable_id"}},
    ]
    return {doc["_id"] async for doc in models.Incident.get_motor_collection().aggregate(pipeline)}


@router.post("/{incident_id}/dispatch", response_model=schemas.DispatchResponse)
async def dispatch_incident(
    incident_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """
    admin/control_room: any dispatchable incident. station: only incidents
    belonging to their own station -- a constable can never dispatch
    themselves or anyone else, and a station user can never dispatch
    another station's incident.

    Preconditions enforced (all return an explicit error, never a silent 200):
      - incident exists (404)
      - caller is authorized for this specific incident (403) -- station
        role only, see above
      - incident.status == verified (409) -- rejected/resolved/closed/new/
        needs_review incidents can never be dispatched
      - incident does not already have an active assignment (409) -- avoids
        double-dispatching the same incident

    Nearest-eligible-constable selection considers ONLY constables who are:
      - Constable.status == available
      - their User.status == active
      - have a ConstableLocation reading no older than
        CONSTABLE_LOCATION_MAX_AGE_SECONDS -- a stale GPS fix is not
        treated as "reliably available"
      - have no other active assignment (pending/accepted/en_route/arrived)

    Concurrency: the top-5 nearest eligible candidates are pre-fetched, then
    tried in distance order. Each attempt runs inside a
    `database.transaction()` (needs the replica-set deployment) and uses
    `find_one_and_update` compare-and-swap on BOTH the candidate Constable
    (status must still be "available") and the Incident (must still have no
    active_assignment_id) -- if either condition no longer holds by the
    time the update runs, the transaction is aborted (via
    `_DispatchRaceLost`, so nothing partial persists) and the next
    candidate is tried. This is the direct Mongo equivalent of the old
    `SELECT ... FOR UPDATE SKIP LOCKED` row-locking approach: two concurrent
    dispatch requests can never both win the same constable.

    "No eligible constable found" deliberately stays a 200 with a
    machine-readable `status: "no_available_constable"` body (NOT a 404/409)
    -- an established, already-tested API contract, not an error: the
    request was entirely valid, there just isn't capacity right now.
    """
    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if current_user.role == models.UserRole.station:
        if not current_user.station_id or incident.station_id != current_user.station_id:
            raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to dispatch this incident")

    if incident.status not in _DISPATCHABLE_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail=f"Incident is not in a dispatchable state (current status: {incident.status.value})",
        )

    if incident.active_assignment_id is not None:
        raise HTTPException(status_code=http_status.HTTP_409_CONFLICT, detail="Incident already has an active assignment")

    # --- Determine primary/backup station (reporting + best-effort station_id assignment) ---
    primary_summary = None
    backup_summary = None
    if incident.location:
        lon, lat = geo.lon_lat(incident.location)
        station_rows = await find_nearest_stations(lon, lat, limit=2)
        if len(station_rows) >= 1:
            station, distance = station_rows[0]
            primary_summary = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)
            if not incident.station_id:
                incident.station_id = station.id
                await incident.save()
        if len(station_rows) >= 2:
            station, distance = station_rows[1]
            backup_summary = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)

    # --- Nearest eligible constable candidates ----------------------------
    freshness_cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=CONSTABLE_LOCATION_MAX_AGE_SECONDS
    )

    candidate_query = models.Constable.find(models.Constable.status == models.ConstableStatus.available)
    if incident.station_id:
        candidate_query = candidate_query.find(models.Constable.station_id == incident.station_id)
    candidates = await candidate_query.to_list()

    if candidates:
        active_user_ids = {
            u.id for u in await models.User.find(
                In(models.User.id, [c.user_id for c in candidates if c.user_id]),
                models.User.status == models.UserStatus.active,
            ).to_list()
        }
        candidates = [c for c in candidates if c.user_id in active_user_ids]

    busy_ids = await _busy_constable_ids()
    candidates = [c for c in candidates if c.id not in busy_ids]

    latest_locations = {}
    if candidates:
        pipeline = [
            {"$match": {
                "constable_id": {"$in": [c.id for c in candidates]},
                "timestamp": {"$gte": freshness_cutoff},
            }},
            {"$sort": {"timestamp": -1}},
            {"$group": {"_id": "$constable_id", "location": {"$first": "$location"}}},
        ]
        async for doc in models.ConstableLocation.get_motor_collection().aggregate(pipeline):
            latest_locations[doc["_id"]] = models.GeoPoint(**doc["location"])

    ranked = []
    for c in candidates:
        loc = latest_locations.get(c.id)
        if loc is None:
            continue
        distance = geo.haversine_meters(loc, incident.location) if incident.location else 0.0
        ranked.append((distance or 0.0, c))
    ranked.sort(key=lambda pair: pair[0])
    top_candidates = [c for _dist, c in ranked[:5]]

    won_constable = None
    won_assignment = None
    for candidate in top_candidates:
        new_display_id = (
            f"{incident.display_id}-{candidate.badge_number}"
            if incident.display_id and candidate.badge_number
            else incident.display_id
        )
        assignment = models.Assignment(constable_id=candidate.id, status=models.AssignmentStatus.pending)
        try:
            async with database.transaction() as session:
                constable_doc = await models.Constable.get_motor_collection().find_one_and_update(
                    {"_id": candidate.id, "status": models.ConstableStatus.available.value},
                    {"$set": {"status": models.ConstableStatus.busy.value}},
                    session=session,
                    return_document=ReturnDocument.AFTER,
                )
                if not constable_doc:
                    raise _ConstableRaceLost()  # lost this candidate -- try the next one

                incident_doc = await models.Incident.get_motor_collection().find_one_and_update(
                    {"_id": incident.id, "active_assignment_id": None},
                    {
                        "$push": {"assignments": assignment.model_dump()},
                        "$set": {
                            "active_assignment_id": assignment.id,
                            "status": models.IncidentStatus.assigned.value,
                            "display_id": new_display_id,
                        },
                    },
                    session=session,
                    return_document=ReturnDocument.AFTER,
                )
                if not incident_doc:
                    # Someone else already dispatched this exact incident
                    # concurrently -- stop entirely, not just this candidate.
                    raise _IncidentRaceLost()
        except _ConstableRaceLost:
            continue
        except _IncidentRaceLost:
            break

        won_constable = candidate
        won_assignment = assignment
        incident.assignments.append(assignment)
        incident.active_assignment_id = assignment.id
        incident.status = models.IncidentStatus.assigned
        incident.display_id = new_display_id
        break

    if won_constable is None:
        return schemas.DispatchResponse(
            status="no_available_constable",
            incident_id=incident.id,
            primary_station=primary_summary,
            backup_station=backup_summary,
        )

    await log_action(
        user_id=current_user.id,
        action="incident.dispatched",
        incident_id=incident.id,
        details={"constable_id": str(won_constable.id), "assignment_id": str(won_assignment.id)},
    )

    await events.publish_incident_dispatched(incident, won_constable.id, won_assignment.id)

    return schemas.DispatchResponse(
        status="dispatched",
        incident_id=incident.id,
        constable_id=won_constable.id,
        assignment_id=won_assignment.id,
        primary_station=primary_summary,
        backup_station=backup_summary,
    )
