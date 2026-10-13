import os
import re
import uuid
import datetime
from typing import Optional

from beanie.operators import In
from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.errors import DuplicateKeyError
from pydantic import BaseModel

from .. import geo, models, schemas
from ..auth.deps import get_current_user, require_role
from ..auth.security import hash_password
from ..auth import request_limiter
from ..services.audit import log_action
from ..services import events, location_ingest

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


def _location_rate_limit_per_minute() -> int:
    try:
        return max(1, int(os.getenv("LOCATION_RATE_LIMIT_PER_MINUTE", "120")))
    except ValueError:
        return 120


def _ingest_http_error(exc: location_ingest.IngestError) -> HTTPException:
    return HTTPException(status_code=exc.http_status, detail={"code": exc.code, "message": exc.message, "retryable": exc.retryable})


def _location_response(constable, payload, outcome) -> schemas.ConstableLocationResponse:
    return schemas.ConstableLocationResponse(
        status="Location updated successfully" if outcome.result != "duplicate" else "Duplicate fix ignored",
        result=outcome.result,
        constable_id=constable.id,
        duty_session_id=outcome.session.id,
        latitude=payload.latitude,
        longitude=payload.longitude,
        accuracy=payload.accuracy,
        timestamp=outcome.recorded_at,
        recorded_at=outcome.recorded_at,
        server_received_at=outcome.server_received_at,
        sequence_number=payload.sequence_number,
        geographic_zone=outcome.zone_code,
        zone_status=outcome.zone_status,
        zone_changed=outcome.zone_changed,
        projection_advanced=outcome.projection_advanced,
        buffered=outcome.buffered,
        source=payload.source,
    )


@router.post("/me/location", response_model=schemas.ConstableLocationResponse)
async def update_my_location(
    payload: schemas.ConstableMeLocationUpdate,
    current_user: models.User = Depends(get_current_user),
):
    """
    Officer location fix. Constable identity comes ENTIRELY from the JWT --
    there is no constable_id in the request, so there is nothing to spoof.

    Requires an active duty session on an approved, enrolled device and a
    fully specified fix (coordinates, accuracy, recorded_at, sequence_number).
    Idempotent per (duty session, sequence_number): a retry returns
    `result: "duplicate"` with HTTP 200 and changes nothing, so the client may
    safely drop the queued item. See services/location_ingest.py for the full
    contract and docs/MOBILE_INTEGRATION_CONTRACT.md for client behaviour.
    """
    constable = await _require_own_constable(current_user)
    if not request_limiter.allow(f"loc:{current_user.id}", _location_rate_limit_per_minute()):
        raise HTTPException(status_code=429, detail={"code": "rate_limited", "message": "Too many location updates", "retryable": True})
    try:
        outcome = await location_ingest.ingest_fix(constable=constable, user=current_user, payload=payload)
    except location_ingest.IngestError as exc:
        raise _ingest_http_error(exc)
    return _location_response(constable, payload, outcome)


@router.post("/me/location/batch", response_model=schemas.ConstableLocationBatchResponse)
async def update_my_location_batch(
    payload: schemas.ConstableLocationBatchRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Flush of fixes queued while the officer had no route to the server.
    Each fix is judged independently (a bad one never blocks the rest) and
    reported back so the client knows exactly which to drop and which to
    retry (`rejected` + a code the client treats as non-retryable means
    drop). Older fixes become history; they never move the live marker.
    Limited to 100 fixes per call and rate-limited separately from the
    single-fix endpoint, so bulk uploads cannot crowd out live updates.
    """
    constable = await _require_own_constable(current_user)
    if not request_limiter.allow(f"locbatch:{current_user.id}", 20):
        raise HTTPException(status_code=429, detail={"code": "rate_limited", "message": "Too many batch uploads", "retryable": True})
    # Oldest first, so the projection advances through history in order.
    ordered = sorted(payload.fixes, key=lambda f: (f.recorded_at if f.recorded_at.tzinfo else f.recorded_at.replace(tzinfo=datetime.timezone.utc), f.sequence_number))
    results = []
    accepted = duplicate = rejected = 0
    for fix in ordered:
        try:
            outcome = await location_ingest.ingest_fix(constable=constable, user=current_user, payload=fix)
        except location_ingest.IngestError as exc:
            rejected += 1
            results.append(schemas.ConstableLocationBatchItemResult(sequence_number=fix.sequence_number, result="rejected", code=exc.code, detail=exc.message))
            continue
        if outcome.result == "duplicate":
            duplicate += 1
        else:
            accepted += 1
        results.append(schemas.ConstableLocationBatchItemResult(sequence_number=fix.sequence_number, result=outcome.result))
    return schemas.ConstableLocationBatchResponse(total=len(ordered), accepted=accepted, duplicate=duplicate, rejected=rejected, results=results)


# ---------------------------------------------------------------------------
# Duty sessions: the explicit authorisation for location tracking.
# ---------------------------------------------------------------------------

def _session_response(session: models.DutySession) -> schemas.DutySessionResponse:
    return schemas.DutySessionResponse(
        id=session.id, constable_id=session.constable_id, device_identifier=session.device_identifier,
        status=session.status.value, started_at=session.started_at, ended_at=session.ended_at,
        end_reason=session.end_reason, assigned_zone_code=session.assigned_zone_code, fix_count=session.fix_count,
    )


async def end_duty_session(
    session: models.DutySession, constable: models.Constable, *, reason: str, ended_by: Optional[uuid.UUID]
) -> models.DutySession:
    """Shared by officer stop, admin force-end and device revocation. Idempotent."""
    if session.status == models.DutySessionStatus.ended:
        return session
    session.status = models.DutySessionStatus.ended
    session.ended_at = datetime.datetime.now(datetime.timezone.utc)
    session.end_reason = reason
    session.ended_by = ended_by
    await session.save()
    await models.Constable.get_motor_collection().update_one(
        {"_id": constable.id, "active_duty_session_id": session.id}, {"$set": {"active_duty_session_id": None}}
    )
    await events.publish_constable_duty_changed(constable.id, constable.station_id, False, session.id, reason)
    await log_action(
        user_id=ended_by, action="duty.ended",
        details={"constable_id": str(constable.id), "duty_session_id": str(session.id), "reason": reason},
    )
    return session


@router.get("/me/duty-session", response_model=schemas.DutyStatusResponse)
async def get_my_duty_session(current_user: models.User = Depends(get_current_user)):
    """The client may collect and send location ONLY while `tracking_enabled` is true."""
    constable = await _require_own_constable(current_user)
    session = await models.DutySession.find_one(
        models.DutySession.constable_id == constable.id, models.DutySession.status == models.DutySessionStatus.active
    )
    if session is None:
        return schemas.DutyStatusResponse(on_duty=False, session=None, tracking_enabled=False)
    device = await models.Device.get(session.device_id)
    approved = device is not None and device.enrolment_status == models.EnrolmentStatus.approved
    return schemas.DutyStatusResponse(on_duty=True, session=_session_response(session), tracking_enabled=approved)


@router.post("/me/duty-session/start", response_model=schemas.DutyStatusResponse)
async def start_my_duty_session(
    payload: schemas.DutyStartRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Starts location-tracking authorisation for the calling officer on ONE of
    their own approved devices. Idempotent for the same device; 409 if the
    officer is already on duty on a different device. Starting duty does not
    start any audio/video recording.
    """
    constable = await _require_own_constable(current_user)
    device = await models.Device.find_one(models.Device.device_identifier == payload.device_identifier)
    if device is None or device.constable_id != constable.id:
        raise HTTPException(status_code=404, detail={"code": "device_not_enrolled", "message": "This device is not enrolled for your account"})
    if device.enrolment_status != models.EnrolmentStatus.approved:
        raise HTTPException(status_code=403, detail={"code": "device_not_approved", "message": f"Device enrolment is {device.enrolment_status.value}; an administrator must approve it before duty can start"})

    existing = await models.DutySession.find_one(
        models.DutySession.constable_id == constable.id, models.DutySession.status == models.DutySessionStatus.active
    )
    if existing is not None:
        if existing.device_id == device.id:
            return schemas.DutyStatusResponse(on_duty=True, session=_session_response(existing), tracking_enabled=True)
        raise HTTPException(status_code=409, detail={"code": "already_on_duty_other_device", "message": "You are already on duty on another device; stop that duty session first"})

    session = models.DutySession(
        constable_id=constable.id, device_id=device.id, device_identifier=device.device_identifier,
        assigned_zone_code=constable.assigned_zone_code,
    )
    try:
        await session.insert()
    except DuplicateKeyError:
        existing = await models.DutySession.find_one(
            models.DutySession.constable_id == constable.id, models.DutySession.status == models.DutySessionStatus.active
        )
        if existing is not None and existing.device_id == device.id:
            return schemas.DutyStatusResponse(on_duty=True, session=_session_response(existing), tracking_enabled=True)
        raise HTTPException(status_code=409, detail={"code": "already_on_duty_other_device", "message": "You are already on duty"})

    # A new duty period starts with a clean zone state so the first fix is
    # accepted immediately instead of being held against a stale zone.
    await models.Constable.get_motor_collection().update_one(
        {"_id": constable.id},
        {"$set": {
            "active_duty_session_id": session.id, "current_geographic_zone": None, "zone_status": None,
            "zone_candidate": None, "zone_candidate_count": 0,
        }},
    )
    await events.publish_constable_duty_changed(constable.id, constable.station_id, True, session.id)
    await log_action(
        user_id=current_user.id, action="duty.started",
        details={"constable_id": str(constable.id), "duty_session_id": str(session.id), "device_identifier": device.device_identifier},
    )
    return schemas.DutyStatusResponse(on_duty=True, session=_session_response(session), tracking_enabled=True)


@router.post("/me/duty-session/stop", response_model=schemas.DutyStatusResponse)
async def stop_my_duty_session(current_user: models.User = Depends(get_current_user)):
    """Ends tracking authorisation. Idempotent. Queued fixes recorded before this moment are still accepted for a short grace period."""
    constable = await _require_own_constable(current_user)
    session = await models.DutySession.find_one(
        models.DutySession.constable_id == constable.id, models.DutySession.status == models.DutySessionStatus.active
    )
    if session is not None:
        await end_duty_session(session, constable, reason="officer_stopped", ended_by=current_user.id)
    return schemas.DutyStatusResponse(on_duty=False, session=None, tracking_enabled=False)


@router.post("/{constable_id}/duty-session/end", response_model=schemas.DutyStatusResponse)
async def force_end_duty_session(
    constable_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin")),
):
    """Administrative override: end an officer's duty (and therefore tracking). Audited."""
    constable = await models.Constable.get(constable_id)
    if constable is None:
        raise HTTPException(status_code=404, detail="Constable not found")
    session = await models.DutySession.find_one(
        models.DutySession.constable_id == constable.id, models.DutySession.status == models.DutySessionStatus.active
    )
    if session is not None:
        await end_duty_session(session, constable, reason="admin_ended", ended_by=current_user.id)
    return schemas.DutyStatusResponse(on_duty=False, session=None, tracking_enabled=False)


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
    RETIRED. This endpoint accepted a bare coordinate for any constable id
    (including an administrative override), with no duty session, no
    timestamp/sequence and no accuracy -- i.e. positions that could be
    injected rather than genuinely reported. Positions now arrive only
    through POST /constables/me/location (or /me/location/batch).
    """
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="This endpoint has been retired. Report location with POST /constables/me/location during an active duty session.",
    )


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
    Latest server-held position of every officer who is ON DUTY, with the
    fix's own recorded_at so callers can judge freshness. Off-duty officers
    are not listed (their positions are not exposed). Prefer
    GET /tracking/officers, which adds tracking state and zones.
    admin/control_room: all. station: own station only. Others: 403.
    """
    role = current_user.role
    if role == models.UserRole.station and not current_user.station_id:
        return []
    if role not in (models.UserRole.admin, models.UserRole.control_room, models.UserRole.station):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view constable locations")

    query = {"active_duty_session_id": {"$ne": None}, "last_location_point": {"$ne": None}}
    if role == models.UserRole.station:
        query["station_id"] = current_user.station_id
    results = []
    for c in await models.Constable.find(query).to_list():
        lon, lat = c.last_location_point.coordinates
        results.append({
            "constable_id": c.badge_number,
            "lon": lon,
            "lat": lat,
            "accuracy": c.last_location_accuracy,
            "recorded_at": c.last_location_recorded_at.isoformat() if c.last_location_recorded_at else None,
            "battery_level": c.battery_level,
        })
    return results
