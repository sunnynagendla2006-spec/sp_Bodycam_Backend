import os
import re
import uuid
import datetime
from typing import Optional

from beanie.operators import In
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from .. import geo, models, schemas
from ..auth.deps import get_current_user, require_role
from ..auth.security import hash_password
from ..services.audit import log_action
from ..services import events

router = APIRouter(prefix="/constables", tags=["Constables"])

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# A constable whose last GPS ping is older than this is not considered
# reliably available for emergency dispatch (see incidents.py::dispatch_incident).
CONSTABLE_LOCATION_MAX_AGE_SECONDS = int(os.getenv("CONSTABLE_LOCATION_MAX_AGE_SECONDS", "120"))

ACTIVE_ASSIGNMENT_STATUSES = models.ACTIVE_ASSIGNMENT_STATUSES

# Legal constable-driven assignment transitions for PUT /constables/me/incidents/{id}/status.
# accept/reject (pending -> accepted/rejected) are handled by their own dedicated endpoints,
# not through this table.
_ASSIGNMENT_ALLOWED_NEXT = {
    models.AssignmentStatus.accepted: {models.AssignmentStatus.en_route},
    models.AssignmentStatus.en_route: {models.AssignmentStatus.arrived},
    models.AssignmentStatus.arrived: {models.AssignmentStatus.completed},
}

# Mirrors an assignment-level status onto the shared Incident.status field
# (which existing/Phase-2 control-room-facing code already reads), since
# IncidentStatus and AssignmentStatus are separate enums with only partial
# overlap ("completed" on the assignment side maps to "resolved" on the
# incident side -- IncidentStatus has no "completed" value).
_ASSIGNMENT_TO_INCIDENT_STATUS = {
    models.AssignmentStatus.en_route: models.IncidentStatus.en_route,
    models.AssignmentStatus.arrived: models.IncidentStatus.arrived,
    models.AssignmentStatus.completed: models.IncidentStatus.resolved,
}


async def get_own_constable(user: models.User) -> Optional[models.Constable]:
    """
    Resolve the Constable document that belongs to the given authenticated
    User. Shared by constables.py, incidents.py, and media.py so that
    "which constable is this?" is always derived from the authenticated
    identity, never from a client-supplied constable_id.
    """
    return await models.Constable.find_one(models.Constable.user_id == user.id)


async def _require_own_constable(current_user: models.User) -> models.Constable:
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Constable role required")
    constable = await get_own_constable(current_user)
    if not constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")
    return constable


def _find_assignment(incident: models.Incident, constable_id: uuid.UUID) -> Optional[models.Assignment]:
    """Most recent assignment belonging to this constable on this incident (mirrors the old per-incident FK-scoped lookup)."""
    matches = [a for a in incident.assignments if a.constable_id == constable_id]
    return max(matches, key=lambda a: a.assigned_at) if matches else None


def _clear_active_if_matches(incident: models.Incident, assignment_id: uuid.UUID) -> None:
    if incident.active_assignment_id == assignment_id:
        incident.active_assignment_id = None


# ===========================================================================
# Constable self-service ("/me") endpoints.
#
# IMPORTANT ROUTING NOTE: these are registered BEFORE the "/{constable_id}/..."
# routes further down in this file -- see original module docstring for why
# (literal "/me" must be matched before the "/{constable_id}" pattern).
# ===========================================================================

@router.get("/me", response_model=schemas.ConstableMeResponse)
async def get_my_constable_profile(
    current_user: models.User = Depends(get_current_user),
):
    """Authenticated constable's own profile. 403 if the caller isn't a constable."""
    constable = await _require_own_constable(current_user)
    last_location = await models.ConstableLocation.find(
        models.ConstableLocation.constable_id == constable.id
    ).sort(-models.ConstableLocation.timestamp).first_or_none()
    return schemas.ConstableMeResponse(
        id=constable.id,
        user_id=constable.user_id,
        badge_number=constable.badge_number,
        phone=current_user.phone,
        status=constable.status,
        station_id=constable.station_id,
        battery_level=constable.battery_level,
        last_location_at=last_location.timestamp if last_location else None,
        is_active=(current_user.status == models.UserStatus.active),
    )


@router.get("/me/incidents", response_model=list[schemas.ConstableIncidentResponse])
async def list_my_incidents(
    incident_status: Optional[str] = None,
    assignment_status: Optional[str] = None,
    current_user: models.User = Depends(get_current_user),
):
    """
    Incidents currently (or previously) assigned to the authenticated
    constable -- never another constable's. Optional filters by incident
    status and/or assignment status; no pagination, matching the rest of
    this API's current (unpaginated) style.
    """
    constable = await _require_own_constable(current_user)

    match: dict = {"assignments.constable_id": constable.id}
    if incident_status:
        try:
            match["status"] = models.IncidentStatus(incident_status).value
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid incident_status: {incident_status}")

    element_match: dict = {"assignments.constable_id": constable.id}
    if assignment_status:
        try:
            element_match["assignments.status"] = models.AssignmentStatus(assignment_status).value
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid assignment_status: {assignment_status}")

    pipeline = [
        {"$match": match},
        {"$unwind": "$assignments"},
        {"$match": element_match},
        {"$sort": {"assignments.assigned_at": -1}},
    ]

    results = []
    async for doc in models.Incident.get_motor_collection().aggregate(pipeline):
        a = doc["assignments"]
        location = models.GeoPoint(**doc["location"]) if doc.get("location") else None
        results.append(schemas.ConstableIncidentResponse(
            incident_id=doc["_id"],
            display_id=doc.get("display_id"),
            incident_status=doc["status"],
            location=geo.to_wkt(location),
            created_at=doc["created_at"],
            assignment_id=a["id"],
            assignment_status=a["status"],
            assigned_at=a["assigned_at"],
        ))
    return results


@router.get("/me/assignments", response_model=list[schemas.AssignmentResponse])
async def list_my_assignments(
    current_user: models.User = Depends(get_current_user),
):
    """Raw assignment records for the authenticated constable (assignment-centric view; see /me/incidents for the incident-enriched view)."""
    constable = await _require_own_constable(current_user)
    pipeline = [
        {"$match": {"assignments.constable_id": constable.id}},
        {"$unwind": "$assignments"},
        {"$match": {"assignments.constable_id": constable.id}},
        {"$sort": {"assignments.assigned_at": -1}},
    ]
    results = []
    async for doc in models.Incident.get_motor_collection().aggregate(pipeline):
        a = doc["assignments"]
        results.append(schemas.AssignmentResponse(
            id=a["id"],
            incident_id=doc["_id"],
            constable_id=a["constable_id"],
            status=a["status"],
            assigned_at=a["assigned_at"],
            responded_at=a.get("responded_at"),
            closed_at=a.get("closed_at"),
        ))
    return results


@router.post("/me/incidents/{incident_id}/accept", response_model=schemas.AssignmentActionResponse)
async def accept_assignment(
    incident_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """
    Accept the authenticated constable's OWN pending assignment for this
    incident. Cannot accept another constable's assignment (there simply
    isn't one to find, since the lookup is scoped to constable.id), and
    cannot accept anything already accepted/rejected/en_route/etc.
    """
    constable = await _require_own_constable(current_user)
    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Assignment not found")

    assignment = _find_assignment(incident, constable.id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    if assignment.status != models.AssignmentStatus.pending:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Assignment is not pending")
    if incident.status != models.IncidentStatus.assigned:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Incident is no longer in a dispatchable state")

    assignment.status = models.AssignmentStatus.accepted
    assignment.responded_at = datetime.datetime.now(datetime.timezone.utc)
    await incident.save()

    await log_action(
        user_id=current_user.id,
        action="assignment.accepted",
        incident_id=incident.id,
        details={"assignment_id": str(assignment.id), "constable_id": str(constable.id)},
    )

    await events.publish_assignment_accepted(assignment, incident)
    return schemas.AssignmentActionResponse(status="accepted", assignment_id=assignment.id, assignment_status=assignment.status)


@router.post("/me/incidents/{incident_id}/reject", response_model=schemas.AssignmentActionResponse)
async def reject_assignment(
    incident_id: uuid.UUID,
    payload: schemas.IncidentActionReason = schemas.IncidentActionReason(),
    current_user: models.User = Depends(get_current_user),
):
    """
    Reject the authenticated constable's OWN pending assignment. Frees the
    constable back to `available` and reopens the incident (back to
    `verified`) for Control Room to dispatch to someone else -- this phase
    does NOT auto-reassign.
    """
    constable = await _require_own_constable(current_user)
    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Assignment not found")

    assignment = _find_assignment(incident, constable.id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    if assignment.status != models.AssignmentStatus.pending:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Assignment is not pending")

    assignment.status = models.AssignmentStatus.rejected
    assignment.responded_at = datetime.datetime.now(datetime.timezone.utc)
    _clear_active_if_matches(incident, assignment.id)

    constable.status = models.ConstableStatus.available
    await constable.save()

    if incident.status == models.IncidentStatus.assigned:
        incident.status = models.IncidentStatus.verified  # reopen for reassignment
    await incident.save()

    await log_action(
        user_id=current_user.id,
        action="assignment.rejected",
        incident_id=incident_id,
        details={"assignment_id": str(assignment.id), "constable_id": str(constable.id), "reason": payload.reason},
    )

    await events.publish_assignment_rejected(assignment, incident)
    return schemas.AssignmentActionResponse(status="rejected", assignment_id=assignment.id, assignment_status=assignment.status)


@router.put("/me/incidents/{incident_id}/status", response_model=schemas.AssignmentActionResponse)
async def update_my_assignment_status(
    incident_id: uuid.UUID,
    payload: schemas.ConstableStatusUpdateRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Constable-driven response-progress update: en_route -> arrived -> completed.
    A constable can NEVER reach verified/rejected/needs_review through this
    endpoint (those aren't even valid AssignmentStatus values) -- those
    remain exclusively Control-Room actions via POST /incidents/{id}/verify|reject.
    """
    constable = await _require_own_constable(current_user)

    try:
        requested = models.AssignmentStatus(payload.status)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid status: {payload.status}")

    if requested not in (models.AssignmentStatus.en_route, models.AssignmentStatus.arrived, models.AssignmentStatus.completed):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to set this status")

    incident = await models.Incident.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Assignment not found")
    assignment = _find_assignment(incident, constable.id)
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    allowed_next = _ASSIGNMENT_ALLOWED_NEXT.get(assignment.status, set())
    if requested not in allowed_next:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot transition assignment from {assignment.status.value} to {requested.value}",
        )

    old_assignment_status = assignment.status.value
    assignment.status = requested

    if requested == models.AssignmentStatus.completed:
        assignment.closed_at = datetime.datetime.now(datetime.timezone.utc)
        _clear_active_if_matches(incident, assignment.id)
        constable.status = models.ConstableStatus.available  # restore availability
        await constable.save()
    if requested in _ASSIGNMENT_TO_INCIDENT_STATUS:
        incident.status = _ASSIGNMENT_TO_INCIDENT_STATUS[requested]
    await incident.save()

    await log_action(
        user_id=current_user.id,
        action="assignment.status_changed",
        incident_id=incident_id,
        details={
            "assignment_id": str(assignment.id),
            "constable_id": str(constable.id),
            "old_status": old_assignment_status,
            "new_status": requested.value,
        },
    )

    await events.publish_assignment_status_changed(assignment, incident)
    return schemas.AssignmentActionResponse(status="updated", assignment_id=assignment.id, assignment_status=assignment.status)


@router.post("/me/location", response_model=schemas.ConstableLocationResponse)
async def update_my_location(
    payload: schemas.ConstableMeLocationUpdate,
    current_user: models.User = Depends(get_current_user),
):
    """
    Flutter-facing location endpoint: constable identity comes ENTIRELY
    from the JWT via _require_own_constable -- there is no constable_id in
    the request at all, so there is nothing to spoof. Uses the server
    timestamp as the authoritative received time -- no client timestamp is
    accepted here. Does NOT touch User.last_login (an authentication
    concept, not a location concept).
    """
    constable = await _require_own_constable(current_user)

    new_location = models.ConstableLocation(
        constable_id=constable.id,
        location=geo.point(payload.longitude, payload.latitude),
        accuracy=payload.accuracy,
    )
    await new_location.insert()

    await log_action(
        user_id=current_user.id,
        action="constable.location_updated",
        details={"constable_id": str(constable.id), "accuracy": payload.accuracy},
    )

    await events.publish_constable_location_updated(
        constable.id, constable.station_id, payload.latitude, payload.longitude, payload.accuracy
    )

    return schemas.ConstableLocationResponse(
        status="Location updated successfully",
        constable_id=constable.id,
        latitude=payload.latitude,
        longitude=payload.longitude,
        accuracy=payload.accuracy,
        timestamp=new_location.timestamp,
    )


# ===========================================================================
# Existing administrative / parameterized-path endpoints.
# ===========================================================================

@router.post("/{constable_id}/location")
async def update_location(
    constable_id: uuid.UUID,
    location_data: schemas.ConstableLocationUpdate,
    current_user: models.User = Depends(get_current_user),
):
    """
    Legacy/administrative location endpoint. Kept for backward
    compatibility; Flutter should use POST /constables/me/location instead
    so identity always comes from the JWT.

    Critical ownership check: a constable may only update THEIR OWN
    location -- the path's constable_id is only used to verify it matches
    their own derived constable id, never trusted as proof of identity.
    admin/control_room may submit an administrative override for any
    constable.
    """
    target_constable = await models.Constable.get(constable_id)
    if not target_constable:
        raise HTTPException(status_code=404, detail="Constable not found")

    role = current_user.role
    if role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable or own_constable.id != constable_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot update another constable's location",
            )
    elif role in (models.UserRole.admin, models.UserRole.control_room):
        pass  # administrative override, explicitly role-gated
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update constable location")

    new_location = models.ConstableLocation(
        constable_id=constable_id,
        location=geo.point(location_data.location_lon, location_data.location_lat),
    )
    await new_location.insert()

    if location_data.battery_level is not None:
        target_constable.battery_level = location_data.battery_level
        await target_constable.save()

    await log_action(
        user_id=current_user.id,
        action="constable.location_updated",
        details={"constable_id": str(constable_id), "battery_level": location_data.battery_level, "via": "admin_endpoint"},
    )

    await events.publish_constable_location_updated(
        constable_id, target_constable.station_id, location_data.location_lat, location_data.location_lon, None
    )

    return {"status": "Location updated successfully"}


class ConstableCreate(BaseModel):
    phone: str
    badge_number: str
    # REQUIRED -- previously absent here entirely, which created a User
    # with hashed_password left at its default None. /auth/login's
    # verify_password(creds.password, user.hashed_password or "") then has
    # no real hash to check against, so that constable could never log
    # into the mobile app at all. The admin sets this when creating the
    # account (same phone+password contract every other login already
    # uses -- see seed_demo.py/seed_test_data.py for the same pattern).
    password: str

@router.post("/")
async def create_constable(
    req: ConstableCreate,
    current_user: models.User = Depends(require_role("admin")),
):
    if len(req.password) < 8:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Password must be at least 8 characters")
    existing = await models.User.find_one(models.User.phone == req.phone)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this phone number already exists")
    new_user = models.User(phone=req.phone, role=models.UserRole.constable, hashed_password=hash_password(req.password))
    await new_user.insert()
    new_constable = models.Constable(user_id=new_user.id, badge_number=req.badge_number, status=models.ConstableStatus.available, battery_level=100)
    await new_constable.insert()
    return {"id": str(new_constable.id)}

@router.delete("/{constable_id}")
async def delete_constable(
    constable_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin")),
):
    constable = await models.Constable.get(constable_id)
    if not constable:
        raise HTTPException(status_code=404)
    await constable.delete()
    return {"status": "deleted"}

@router.get("/")
async def list_constables(
    current_user: models.User = Depends(get_current_user),
):
    """
    admin/control_room: full roster.
    station: scoped to constables at their own station (via the
    User.station_id -> Constable.station_id linkage). A station user with
    no station_id set gets an empty list (safe default), not an error.
    Any other role: 403.
    """
    role = current_user.role

    if role in (models.UserRole.admin, models.UserRole.control_room):
        constables = await models.Constable.find_all().to_list()
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        constables = await models.Constable.find(models.Constable.station_id == current_user.station_id).to_list()
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to list constables")

    # Batch-fetched (not one query per constable) so the Live Map's roster
    # call stays O(1) queries for station names/users/active-assignments
    # regardless of roster size.
    station_ids = {c.station_id for c in constables if c.station_id}
    stations_by_id = {}
    if station_ids:
        for s in await models.PoliceStation.find(In(models.PoliceStation.id, list(station_ids))).to_list():
            stations_by_id[s.id] = s.name

    user_ids = [c.user_id for c in constables if c.user_id]
    users_by_id = {}
    if user_ids:
        for u in await models.User.find(In(models.User.id, user_ids)).to_list():
            users_by_id[u.id] = u

    active_pipeline = [
        {"$unwind": "$assignments"},
        {"$match": {"assignments.status": {"$in": [s.value for s in ACTIVE_ASSIGNMENT_STATUSES]}}},
        {"$group": {"_id": "$assignments.constable_id", "incident_id": {"$first": "$_id"}}},
    ]
    active_incident_by_constable = {}
    async for doc in models.Incident.get_motor_collection().aggregate(active_pipeline):
        active_incident_by_constable[doc["_id"]] = doc["incident_id"]

    results = []
    for c in constables:
        user = users_by_id.get(c.user_id)
        task_incident_id = active_incident_by_constable.get(c.id)
        results.append({
            "id": str(c.id),
            "user_id": str(c.user_id),
            "status": c.status.value,
            "badge_number": c.badge_number,
            "phone": user.phone if user else None,
            "last_login": c.last_login.isoformat() if c.last_login else None,
            "battery_level": c.battery_level,
            "assigned_task": str(task_incident_id) if task_incident_id else None,
            "station_id": str(c.station_id) if c.station_id else None,
            "station_name": stations_by_id.get(c.station_id),
        })
    return results

class AssignTaskRequest(BaseModel):
    incident_id: str

@router.post("/{constable_id}/tasks")
async def assign_task(
    constable_id: uuid.UUID,
    req: AssignTaskRequest,
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """Only admin/control_room may assign tasks -- a constable can never assign themselves or another constable."""
    incident = None
    try:
        inc_uuid = uuid.UUID(req.incident_id)
        incident = await models.Incident.get(inc_uuid)
    except ValueError:
        incident = await models.Incident.find_one(models.Incident.display_id == req.incident_id)

    if not incident:
        # If still not found, check if they passed just the first part (e.g., 123 from INC-123)
        incident = await models.Incident.find_one({"display_id": {"$regex": f"^{re.escape(req.incident_id)}"}})

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    assignment = models.Assignment(constable_id=constable_id)
    incident.assignments.append(assignment)
    incident.active_assignment_id = assignment.id
    await incident.save()

    constable = await models.Constable.get(constable_id)
    if constable:
        constable.status = models.ConstableStatus.busy
        await constable.save()

    return {"status": "assigned"}

@router.delete("/{constable_id}/tasks/{incident_id}")
async def unassign_task(
    constable_id: uuid.UUID,
    incident_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """Only admin/control_room may unassign tasks -- same rationale as assign_task above."""
    incident = await models.Incident.get(incident_id)
    if incident:
        removed_ids = {a.id for a in incident.assignments if a.constable_id == constable_id}
        incident.assignments = [a for a in incident.assignments if a.constable_id != constable_id]
        if incident.active_assignment_id in removed_ids:
            incident.active_assignment_id = None
        await incident.save()

    constable = await models.Constable.get(constable_id)
    if constable:
        constable.status = models.ConstableStatus.available
        await constable.save()

    return {"status": "unassigned"}

@router.get("/locations")
async def list_constable_locations(
    current_user: models.User = Depends(get_current_user),
):
    """
    admin/control_room: every constable's latest location.
    station: scoped to their own station's constables.
    Any other role: 403.
    """
    role = current_user.role
    if role == models.UserRole.station and not current_user.station_id:
        return []
    if role not in (models.UserRole.admin, models.UserRole.control_room, models.UserRole.station):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view constable locations")

    # "Latest location per constable" via $sort + $group ($first) -- the
    # Mongo equivalent of the old GROUP BY + MAX(timestamp) join-back.
    pipeline = [
        {"$sort": {"timestamp": -1}},
        {"$group": {"_id": "$constable_id", "location": {"$first": "$location"}}},
    ]
    latest_by_constable = {}
    async for doc in models.ConstableLocation.get_motor_collection().aggregate(pipeline):
        latest_by_constable[doc["_id"]] = doc["location"]

    if role == models.UserRole.station:
        constables = await models.Constable.find(models.Constable.station_id == current_user.station_id).to_list()
    else:
        constables = await models.Constable.find_all().to_list()

    results = []
    for c in constables:
        loc = latest_by_constable.get(c.id)
        if not loc:
            continue
        lon, lat = loc["coordinates"]
        results.append({
            "constable_id": c.badge_number,
            "lon": lon,
            "lat": lat,
            "battery_level": c.battery_level,
        })
    return results
