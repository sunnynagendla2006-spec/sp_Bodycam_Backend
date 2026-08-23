import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from typing import Optional
from .. import database, models, schemas
from ..auth.deps import get_current_user, require_role
from ..services.audit import log_action
from ..services import events
import uuid
import datetime

router = APIRouter(prefix="/constables", tags=["Constables"])

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# A constable whose last GPS ping is older than this is not considered
# reliably available for emergency dispatch (see incidents.py::dispatch_incident).
CONSTABLE_LOCATION_MAX_AGE_SECONDS = int(os.getenv("CONSTABLE_LOCATION_MAX_AGE_SECONDS", "120"))

# Assignment states that count as "this constable is already busy with
# something" -- used both to block dispatching an already-committed
# constable and to block a constable from having two active assignments.
ACTIVE_ASSIGNMENT_STATUSES = (
    models.AssignmentStatus.pending,
    models.AssignmentStatus.accepted,
    models.AssignmentStatus.en_route,
    models.AssignmentStatus.arrived,
)

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


def get_own_constable(db: Session, user: models.User):
    """
    Resolve the Constable row that belongs to the given authenticated User.
    Shared by constables.py, incidents.py, and media.py so that "which
    constable is this?" is always derived from the authenticated identity,
    never from a client-supplied constable_id.
    """
    return db.query(models.Constable).filter(models.Constable.user_id == user.id).first()


def _require_own_constable(db: Session, current_user: models.User) -> models.Constable:
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Constable role required")
    constable = get_own_constable(db, current_user)
    if not constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")
    return constable


# ===========================================================================
# Constable self-service ("/me") endpoints.
#
# IMPORTANT ROUTING NOTE: these are registered BEFORE the "/{constable_id}/..."
# routes further down in this file. FastAPI/Starlette match path templates by
# registration order using plain string segments (the uuid.UUID conversion
# only happens during parameter binding, AFTER a route already matched) --
# so if "/{constable_id}/location" were registered first, a request to
# "/constables/me/location" would match THAT route with constable_id="me"
# and fail UUID validation with a 422, never reaching the real /me handler.
# Keeping literal "/me" routes first avoids that entirely.
# ===========================================================================

@router.get("/me", response_model=schemas.ConstableMeResponse)
def get_my_constable_profile(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Authenticated constable's own profile. 403 if the caller isn't a constable."""
    constable = _require_own_constable(db, current_user)
    last_location = (
        db.query(models.ConstableLocation)
        .filter(models.ConstableLocation.constable_id == constable.id)
        .order_by(models.ConstableLocation.timestamp.desc())
        .first()
    )
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
def list_my_incidents(
    incident_status: Optional[str] = None,
    assignment_status: Optional[str] = None,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Incidents currently (or previously) assigned to the authenticated
    constable -- never another constable's. Optional filters by incident
    status and/or assignment status; no pagination, matching the rest of
    this API's current (unpaginated) style.
    """
    constable = _require_own_constable(db, current_user)

    query = (
        db.query(models.Incident, models.IncidentAssignment)
        .join(models.IncidentAssignment, models.IncidentAssignment.incident_id == models.Incident.id)
        .filter(models.IncidentAssignment.constable_id == constable.id)
    )

    if incident_status:
        try:
            query = query.filter(models.Incident.status == models.IncidentStatus(incident_status))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid incident_status: {incident_status}")

    if assignment_status:
        try:
            query = query.filter(models.IncidentAssignment.status == models.AssignmentStatus(assignment_status))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid assignment_status: {assignment_status}")

    rows = query.order_by(models.IncidentAssignment.assigned_at.desc()).all()

    results = []
    for incident, assignment in rows:
        loc_str = None
        try:
            loc_str = db.query(func.ST_AsText(models.Incident.location)).filter(models.Incident.id == incident.id).scalar()
        except Exception:
            loc_str = None
        results.append(schemas.ConstableIncidentResponse(
            incident_id=incident.id,
            display_id=incident.display_id,
            incident_status=incident.status,
            location=loc_str,
            created_at=incident.created_at,
            assignment_id=assignment.id,
            assignment_status=assignment.status,
            assigned_at=assignment.assigned_at,
        ))
    return results


@router.get("/me/assignments", response_model=list[schemas.AssignmentResponse])
def list_my_assignments(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Raw assignment records for the authenticated constable (assignment-centric view; see /me/incidents for the incident-enriched view)."""
    constable = _require_own_constable(db, current_user)
    assignments = (
        db.query(models.IncidentAssignment)
        .filter(models.IncidentAssignment.constable_id == constable.id)
        .order_by(models.IncidentAssignment.assigned_at.desc())
        .all()
    )
    return assignments


@router.post("/me/incidents/{incident_id}/accept", response_model=schemas.AssignmentActionResponse)
async def accept_assignment(
    incident_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Accept the authenticated constable's OWN pending assignment for this
    incident. Cannot accept another constable's assignment (there simply
    isn't one to find, since the lookup is scoped to constable.id), and
    cannot accept anything already accepted/rejected/en_route/etc.
    """
    constable = _require_own_constable(db, current_user)
    assignment = (
        db.query(models.IncidentAssignment)
        .filter(
            models.IncidentAssignment.incident_id == incident_id,
            models.IncidentAssignment.constable_id == constable.id,
        )
        .first()
    )
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    if assignment.status != models.AssignmentStatus.pending:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Assignment is not pending")

    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident or incident.status != models.IncidentStatus.assigned:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Incident is no longer in a dispatchable state")

    assignment.status = models.AssignmentStatus.accepted
    assignment.responded_at = datetime.datetime.now(datetime.timezone.utc)

    log_action(
        db,
        user_id=current_user.id,
        action="assignment.accepted",
        incident_id=incident.id,
        details={"assignment_id": str(assignment.id), "constable_id": str(constable.id)},
    )

    db.commit()
    db.refresh(assignment)
    await events.publish_assignment_accepted(assignment, incident)
    return schemas.AssignmentActionResponse(status="accepted", assignment_id=assignment.id, assignment_status=assignment.status)


@router.post("/me/incidents/{incident_id}/reject", response_model=schemas.AssignmentActionResponse)
async def reject_assignment(
    incident_id: uuid.UUID,
    payload: schemas.IncidentActionReason = schemas.IncidentActionReason(),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Reject the authenticated constable's OWN pending assignment. Frees the
    constable back to `available` and reopens the incident (back to
    `verified`) for Control Room to dispatch to someone else -- this phase
    does NOT auto-reassign.
    """
    constable = _require_own_constable(db, current_user)
    assignment = (
        db.query(models.IncidentAssignment)
        .filter(
            models.IncidentAssignment.incident_id == incident_id,
            models.IncidentAssignment.constable_id == constable.id,
        )
        .first()
    )
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    if assignment.status != models.AssignmentStatus.pending:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Assignment is not pending")

    assignment.status = models.AssignmentStatus.rejected
    assignment.responded_at = datetime.datetime.now(datetime.timezone.utc)

    constable.status = models.ConstableStatus.available

    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if incident and incident.status == models.IncidentStatus.assigned:
        incident.status = models.IncidentStatus.verified  # reopen for reassignment

    log_action(
        db,
        user_id=current_user.id,
        action="assignment.rejected",
        incident_id=incident_id,
        details={"assignment_id": str(assignment.id), "constable_id": str(constable.id), "reason": payload.reason},
    )

    db.commit()
    db.refresh(assignment)
    if incident:
        await events.publish_assignment_rejected(assignment, incident)
    return schemas.AssignmentActionResponse(status="rejected", assignment_id=assignment.id, assignment_status=assignment.status)


@router.put("/me/incidents/{incident_id}/status", response_model=schemas.AssignmentActionResponse)
async def update_my_assignment_status(
    incident_id: uuid.UUID,
    payload: schemas.ConstableStatusUpdateRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Constable-driven response-progress update: en_route -> arrived -> completed.
    A constable can NEVER reach verified/rejected/needs_review through this
    endpoint (those aren't even valid AssignmentStatus values) -- those
    remain exclusively Control-Room actions via POST /incidents/{id}/verify|reject.
    """
    constable = _require_own_constable(db, current_user)

    try:
        requested = models.AssignmentStatus(payload.status)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid status: {payload.status}")

    if requested not in (models.AssignmentStatus.en_route, models.AssignmentStatus.arrived, models.AssignmentStatus.completed):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to set this status")

    assignment = (
        db.query(models.IncidentAssignment)
        .filter(
            models.IncidentAssignment.incident_id == incident_id,
            models.IncidentAssignment.constable_id == constable.id,
        )
        .first()
    )
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
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()

    if requested == models.AssignmentStatus.completed:
        assignment.closed_at = datetime.datetime.now(datetime.timezone.utc)
        constable.status = models.ConstableStatus.available  # restore availability
    if incident and requested in _ASSIGNMENT_TO_INCIDENT_STATUS:
        incident.status = _ASSIGNMENT_TO_INCIDENT_STATUS[requested]

    log_action(
        db,
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

    db.commit()
    db.refresh(assignment)
    if incident:
        await events.publish_assignment_status_changed(assignment, incident)
    return schemas.AssignmentActionResponse(status="updated", assignment_id=assignment.id, assignment_status=assignment.status)


@router.post("/me/location", response_model=schemas.ConstableLocationResponse)
async def update_my_location(
    payload: schemas.ConstableMeLocationUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Flutter-facing location endpoint: constable identity comes ENTIRELY
    from the JWT via _require_own_constable -- there is no constable_id in
    the request at all, so there is nothing to spoof. Coordinate range
    validation happens declaratively on schemas.ConstableMeLocationUpdate
    (returns 422 automatically for out-of-range values). Uses the server
    timestamp as the authoritative received time -- no client timestamp is
    accepted here. Does NOT touch User.last_login (see module docstring /
    phase report: last_login is an authentication concept, not a location
    concept, and the older admin-facing endpoint's coupling of the two was
    a bug, fixed below).
    """
    constable = _require_own_constable(db, current_user)

    location_str = f"POINT({payload.longitude} {payload.latitude})"
    new_location = models.ConstableLocation(
        constable_id=constable.id,
        location=location_str,
        accuracy=payload.accuracy,
    )
    db.add(new_location)

    log_action(
        db,
        user_id=current_user.id,
        action="constable.location_updated",
        details={"constable_id": str(constable.id), "accuracy": payload.accuracy},
    )

    db.commit()
    db.refresh(new_location)

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
# Existing administrative / parameterized-path endpoints (unchanged
# authorization model from Phase 2, with station-scoping added where the
# new User.station_id linkage now makes it possible -- see Phase 4 report).
# ===========================================================================

@router.post("/{constable_id}/location")
async def update_location(
    constable_id: uuid.UUID,
    location_data: schemas.ConstableLocationUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Legacy/administrative location endpoint. Kept for backward
    compatibility; Flutter should use POST /constables/me/location instead
    (see module docstring above) so identity always comes from the JWT.

    Critical ownership check: a constable may only update THEIR OWN
    location -- the path's constable_id is only used to verify it matches
    their own derived constable id, never trusted as proof of identity.
    admin/control_room may submit an administrative override for any
    constable.

    NOTE (Phase 4 fix): this endpoint previously updated User-adjacent
    `last_login` on every GPS ping, incorrectly conflating "last time we
    heard a location ping" with "last time this user authenticated". That
    coupling has been removed -- `Constable.last_login` is no longer
    touched here at all; `ConstableLocation.timestamp` is the correct
    "last seen" signal (see get_own_constable/list endpoints and
    incidents.py's freshness check).

    NOTE (Phase 5 fix): this endpoint previously fired its WebSocket
    broadcast via `asyncio.create_task(manager.broadcast(...))` inside what
    was then a sync `def` handler -- with no running event loop in that
    context, `create_task` would raise, and the bare `except Exception:
    pass` around it silently swallowed that every time, so the broadcast
    never actually happened. This is now a proper `async def` that awaits
    the same role-scoped event-publishing helper used by
    POST /constables/me/location.
    """
    target_constable = db.query(models.Constable).filter(models.Constable.id == constable_id).first()
    if not target_constable:
        raise HTTPException(status_code=404, detail="Constable not found")

    role = current_user.role
    if role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable or own_constable.id != constable_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot update another constable's location",
            )
    elif role in (models.UserRole.admin, models.UserRole.control_room):
        pass  # administrative override, explicitly role-gated
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update constable location")

    location_str = f"POINT({location_data.location_lon} {location_data.location_lat})"
    new_location = models.ConstableLocation(
        constable_id=constable_id,
        location=location_str
    )
    db.add(new_location)

    if location_data.battery_level is not None:
        db.query(models.Constable).filter(models.Constable.id == constable_id).update(
            {"battery_level": location_data.battery_level}
        )

    log_action(
        db,
        user_id=current_user.id,
        action="constable.location_updated",
        details={"constable_id": str(constable_id), "battery_level": location_data.battery_level, "via": "admin_endpoint"},
    )

    db.commit()

    await events.publish_constable_location_updated(
        constable_id, target_constable.station_id, location_data.location_lat, location_data.location_lon, None
    )

    return {"status": "Location updated successfully"}


class ConstableCreate(BaseModel):
    phone: str
    badge_number: str

@router.post("/")
def create_constable(
    req: ConstableCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin")),
):
    new_user = models.User(phone=req.phone, role=models.UserRole.constable)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    new_constable = models.Constable(user_id=new_user.id, badge_number=req.badge_number, status=models.ConstableStatus.available, battery_level=100)
    db.add(new_constable)
    db.commit()
    db.refresh(new_constable)
    return {"id": str(new_constable.id)}

@router.delete("/{constable_id}")
def delete_constable(
    constable_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin")),
):
    constable = db.query(models.Constable).filter(models.Constable.id == constable_id).first()
    if not constable: raise HTTPException(status_code=404)
    db.delete(constable)
    db.commit()
    return {"status": "deleted"}

@router.get("/")
def list_constables(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    admin/control_room: full roster.
    station: scoped to constables at their own station (via the new
    User.station_id -> Constable.station_id linkage). A station user with
    no station_id set gets an empty list (safe default), not an error.
    Any other role: 403.
    """
    role = current_user.role
    query = db.query(models.Constable)

    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        query = query.filter(models.Constable.station_id == current_user.station_id)
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to list constables")

    constables = query.all()
    results = []
    for c in constables:
        user = db.query(models.User).filter(models.User.id == c.user_id).first()
        task = db.query(models.IncidentAssignment).filter(
            models.IncidentAssignment.constable_id == c.id,
            models.IncidentAssignment.status.in_(ACTIVE_ASSIGNMENT_STATUSES),
        ).first()
        results.append({
            "id": str(c.id), 
            "user_id": str(c.user_id), 
            "status": c.status.value,
            "badge_number": c.badge_number,
            "phone": user.phone if user else None,
            "last_login": c.last_login.isoformat() if c.last_login else None,
            "battery_level": c.battery_level,
            "assigned_task": str(task.incident_id) if task else None
        })
    return results

class AssignTaskRequest(BaseModel):
    incident_id: str

@router.post("/{constable_id}/tasks")
def assign_task(
    constable_id: uuid.UUID,
    req: AssignTaskRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """Only admin/control_room may assign tasks -- a constable can never assign themselves or another constable."""
    incident = None
    try:
        inc_uuid = uuid.UUID(req.incident_id)
        incident = db.query(models.Incident).filter(models.Incident.id == inc_uuid).first()
    except ValueError:
        incident = db.query(models.Incident).filter(models.Incident.display_id == req.incident_id).first()
        
    if not incident:
        # If still not found, check if they passed just the first part (e.g., 123 from INC-123)
        # For prototype flexibility, we can just create a dummy assignment or let it fail
        # Or search by prefix
        incident = db.query(models.Incident).filter(models.Incident.display_id.startswith(req.incident_id)).first()
        
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    assignment = models.IncidentAssignment(constable_id=constable_id, incident_id=incident.id)
    db.add(assignment)
    db.query(models.Constable).filter(models.Constable.id == constable_id).update({"status": models.ConstableStatus.busy})
    db.commit()
    return {"status": "assigned"}

@router.delete("/{constable_id}/tasks/{incident_id}")
def unassign_task(
    constable_id: uuid.UUID,
    incident_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """Only admin/control_room may unassign tasks -- same rationale as assign_task above."""
    db.query(models.IncidentAssignment).filter(
        models.IncidentAssignment.constable_id == constable_id,
        models.IncidentAssignment.incident_id == incident_id
    ).delete()
    db.query(models.Constable).filter(models.Constable.id == constable_id).update({"status": models.ConstableStatus.available})
    db.commit()
    return {"status": "unassigned"}

@router.get("/locations")
def list_constable_locations(
    db: Session = Depends(database.get_db),
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

    # "Latest location per constable" via GROUP BY + MAX(timestamp) +
    # join-back, matching incidents.py::dispatch_incident's approach --
    # NOT the previous `.order_by(...).distinct(constable_id)` (Postgres
    # DISTINCT ON), which SQLAlchemy silently ignores on non-Postgres
    # dialects (flagged as deprecated, will become a hard CompileError in a
    # future SQLAlchemy version) and would silently return duplicate/wrong
    # rows for any constable with more than one location row under SQLite.
    latest_ts_subq = (
        db.query(
            models.ConstableLocation.constable_id.label("constable_id"),
            func.max(models.ConstableLocation.timestamp).label("max_ts"),
        )
        .group_by(models.ConstableLocation.constable_id)
        .subquery()
    )

    query = (
        db.query(
            models.Constable.badge_number,
            models.Constable.battery_level,
            func.ST_X(models.ConstableLocation.location).label("lon"),
            func.ST_Y(models.ConstableLocation.location).label("lat"),
        )
        .join(models.Constable, models.ConstableLocation.constable_id == models.Constable.id)
        .join(
            latest_ts_subq,
            (models.ConstableLocation.constable_id == latest_ts_subq.c.constable_id)
            & (models.ConstableLocation.timestamp == latest_ts_subq.c.max_ts),
        )
    )

    if role == models.UserRole.station:
        query = query.filter(models.Constable.station_id == current_user.station_id)

    locations = query.all()

    return [
        {
            "constable_id": loc.badge_number,
            "lon": loc.lon,
            "lat": loc.lat,
            "battery_level": loc.battery_level
        }
        for loc in locations if loc.lon is not None and loc.lat is not None
    ]
