from fastapi import APIRouter, Depends, HTTPException
from fastapi import status as http_status
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from .. import database, models, schemas
from ..auth.deps import get_current_user, require_role
from .constables import get_own_constable, CONSTABLE_LOCATION_MAX_AGE_SECONDS, ACTIVE_ASSIGNMENT_STATUSES
from .police_stations import find_nearest_stations, distance_expr
from ..services.audit import log_action
from ..services import events
import uuid
import datetime

router = APIRouter(prefix="/incidents", tags=["Incidents"])

# Statuses a constable is allowed to set on an incident THEY are assigned to,
# through the LEGACY generic PUT /incidents/{id}/status endpoint (kept for
# backward compatibility -- see module docstring on that endpoint below).
# The Flutter app should prefer PUT /constables/me/incidents/{id}/status
# (constables.py), which additionally validates legal state-machine order.
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


@router.post("/", response_model=schemas.IncidentOut)
def create_incident(
    incident: schemas.IncidentCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    if current_user.role not in _INCIDENT_CREATE_ROLES:
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to create incidents")

    # Map coordinates to PostGIS format in real implementation
    location_str = f"POINT({incident.location_lon} {incident.location_lat})"

    now = datetime.datetime.now()
    display_id = f"INC-{now.strftime('%Y%m%d-%H%M%S')}-{int(abs(incident.location_lat))}-{int(abs(incident.location_lon))}"

    # Never trust a client-supplied citizen_id: derive it from the
    # authenticated user when they are a citizen, otherwise leave it null
    # (a control-room/admin-created incident has no citizen owner yet).
    citizen_id = current_user.id if current_user.role == models.UserRole.citizen else None

    # Auto-assign the responsible station at creation time (nearest
    # PoliceStation to the incident's coordinates), so a station user can
    # see/verify/reject incidents in their own jurisdiction from the moment
    # they're reported -- not only after admin/control_room dispatches them
    # (dispatch_incident still sets this too, defensively, if it's somehow
    # still null by then -- e.g. no PoliceStation rows existed at creation
    # time but one was added since).
    nearest_station_id = None
    station_rows = find_nearest_stations(db, incident.location_lon, incident.location_lat, limit=1)
    if station_rows:
        nearest_station_id = station_rows[0][0].id

    new_incident = models.Incident(
        display_id=display_id,
        citizen_id=citizen_id,
        location=location_str,
        description=incident.description,
        status=models.IncidentStatus.new,
        station_id=nearest_station_id,
    )
    db.add(new_incident)
    db.flush()  # obtain new_incident.id before the audit row references it

    log_action(
        db,
        user_id=current_user.id,
        action="incident.created",
        incident_id=new_incident.id,
        details={"display_id": display_id},
    )
    db.commit()
    db.refresh(new_incident)
    return new_incident


@router.get("/", response_model=list[schemas.IncidentOut])
def list_incidents(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Role-scoped incident listing:
      - admin / control_room: all incidents
      - citizen: only incidents they created
      - constable: only incidents currently assigned to them
      - station: incidents whose `station_id` matches the authenticated
        user's `station_id` (Phase 4: now resolvable via User.station_id --
        see models.py/migration 3d6e8a2c4f19). A station user with no
        station_id set gets an empty list rather than an error.
    """
    query = db.query(models.Incident, func.ST_AsText(models.Incident.location).label("loc_str"))

    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass  # full visibility
    elif role == models.UserRole.citizen:
        query = query.filter(models.Incident.citizen_id == current_user.id)
    elif role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable:
            return []
        assigned_incident_ids = db.query(models.IncidentAssignment.incident_id).filter(
            models.IncidentAssignment.constable_id == own_constable.id
        )
        query = query.filter(models.Incident.id.in_(assigned_incident_ids))
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        query = query.filter(models.Incident.station_id == current_user.station_id)
    else:
        return []

    incidents_data = query.all()
    results = []
    for inc, loc_str in incidents_data:
        data = {c.name: getattr(inc, c.name) for c in inc.__table__.columns}
        data["location"] = loc_str
        results.append(data)
    return results


@router.put("/{incident_id}/status", response_model=schemas.IncidentOut)
def update_incident_status(
    incident_id: uuid.UUID,
    status: models.IncidentStatus,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    LEGACY generic status setter, kept from Phase 2 for backward
    compatibility. New workflow-specific actions (verify/reject/
    needs-review, and constable response-progress) should use the
    dedicated endpoints below / PUT /constables/me/incidents/{id}/status,
    which enforce proper state-machine transitions -- this endpoint still
    allows admin/control_room to set ANY status directly (unchanged from
    Phase 2), since it predates the dedicated verify/reject workflow and
    removing admin/control_room's ability to force a status would be a
    functional regression, not an authorization fix.

      - admin / control_room: any transition
      - station: any transition, but ONLY for incidents belonging to their
        own station (Phase 6 -- previously station was excluded entirely;
        now that User.station_id/Incident.station_id give a reliable
        scoping mechanism, station acts as a scoped-down admin for their
        own jurisdiction's incidents)
      - constable: ONLY for incidents they are assigned to, ONLY to
        en_route/arrived/resolved (unchanged from Phase 2)
      - citizen: never
    """
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
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
        own_constable = get_own_constable(db, current_user)
        assigned = None
        if own_constable:
            assigned = db.query(models.IncidentAssignment).filter(
                models.IncidentAssignment.incident_id == incident_id,
                models.IncidentAssignment.constable_id == own_constable.id,
            ).first()
        if not own_constable or not assigned:
            raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to update this incident")
        if status not in _CONSTABLE_ALLOWED_STATUS_TRANSITIONS:
            raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to set this status")
    else:
        # citizen, or any other/unknown role
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Not authorized to update this incident")

    old_status = incident.status.value if incident.status else None
    incident.status = status
    log_action(
        db,
        user_id=current_user.id,
        action="incident.status_changed",
        incident_id=incident.id,
        details={"old_status": old_status, "new_status": status.value},
    )
    db.commit()
    db.refresh(incident)

    if status == models.IncidentStatus.closed:
        # Logic to clear evidence files from S3/MinIO goes here if they don't need review
        pass

    return incident


# ---------------------------------------------------------------------------
# Dedicated verification workflow. Explicit actions, not a generic status
# setter. admin/control_room: any incident. station (Phase 6): only
# incidents belonging to their own station. constable/citizen: never.
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


def _set_incident_verification_status(
    incident_id: uuid.UUID,
    new_status: models.IncidentStatus,
    db: Session,
    current_user: models.User,
    action: str,
    reason: str = None,
):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    _check_verification_authority(incident, current_user)

    old_status = incident.status.value if incident.status else None
    incident.status = new_status

    details = {"old_status": old_status, "new_status": new_status.value}
    if reason:
        details["reason"] = reason
    log_action(db, user_id=current_user.id, action=action, incident_id=incident.id, details=details)

    db.commit()
    db.refresh(incident)
    return incident


@router.post("/{incident_id}/verify", response_model=schemas.IncidentOut)
async def verify_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """Explicit verification action. admin/control_room: any incident. station: only their own station's incidents (Phase 6) -- see _check_verification_authority."""
    incident = _set_incident_verification_status(incident_id, models.IncidentStatus.verified, db, current_user, "incident.verified")
    await events.publish_incident_verified(incident)
    return incident


@router.post("/{incident_id}/reject", response_model=schemas.IncidentOut)
async def reject_incident(
    incident_id: uuid.UUID,
    payload: schemas.IncidentActionReason = schemas.IncidentActionReason(),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """Explicit rejection. A rejected incident can never be dispatched (see dispatch_incident). Station-scoped per _check_verification_authority."""
    incident = _set_incident_verification_status(
        incident_id, models.IncidentStatus.rejected, db, current_user, "incident.rejected", reason=payload.reason
    )
    await events.publish_incident_rejected(incident)
    return incident


@router.post("/{incident_id}/needs-review", response_model=schemas.IncidentOut)
async def flag_incident_needs_review(
    incident_id: uuid.UUID,
    payload: schemas.IncidentActionReason = schemas.IncidentActionReason(),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """Explicit 'needs more information before we can verify/reject' flag. Station-scoped per _check_verification_authority."""
    incident = _set_incident_verification_status(
        incident_id, models.IncidentStatus.needs_review, db, current_user, "incident.needs_review", reason=payload.reason
    )
    await events.publish_incident_needs_review(incident)
    return incident


# ---------------------------------------------------------------------------
# Responsible station lookup (primary/backup nearest PoliceStation)
# ---------------------------------------------------------------------------

@router.get("/{incident_id}/responsible-stations", response_model=schemas.NearestStationsResponse)
def get_responsible_stations(
    incident_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """
    Primary (nearest) and backup (second-nearest) PoliceStation for this
    incident's location, using the same dialect-aware distance helper as
    /police-stations/nearest. Does not itself assign incident.station_id --
    that happens as a side effect of dispatch (see dispatch_incident) once
    a station is actually being acted on, not merely queried.
    """
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    loc_wkt = db.query(func.ST_AsText(models.Incident.location)).filter(models.Incident.id == incident_id).scalar()
    if not loc_wkt:
        raise HTTPException(status_code=422, detail="Incident has no location to route from")

    lon_str, lat_str = loc_wkt.replace("POINT(", "").replace(")", "").split(" ")
    rows = find_nearest_stations(db, float(lon_str), float(lat_str), limit=2)

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

@router.post("/{incident_id}/dispatch", response_model=schemas.DispatchResponse)
async def dispatch_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station")),
):
    """
    admin/control_room: any dispatchable incident. station (Phase 6): only
    incidents belonging to their own station -- a constable can never
    dispatch themselves or anyone else, and a station user can never
    dispatch another station's incident.

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
      - have a ConstableLocation row no older than
        CONSTABLE_LOCATION_MAX_AGE_SECONDS (constables.py) -- a stale GPS
        fix is not treated as "reliably available"
      - have no other active assignment (pending/accepted/en_route/arrived)

    Concurrency: the candidate Constable row is selected with
    `SELECT ... FOR UPDATE SKIP LOCKED` (Postgres-only; see distance_expr's
    dialect check) inside this request's transaction, so two concurrent
    dispatch calls cannot both select and assign the same constable --
    a second request's SELECT will simply skip a row already locked by the
    first request's still-open transaction and fall through to the next
    nearest eligible candidate (or find none). This is NOT reproducible
    under the SQLite test database (SQLite has no row-level locking model
    at all -- `with_for_update()` is a silent no-op there), so the test
    suite instead exercises the eligibility-filtering logic directly
    (see tests/test_dispatch.py) rather than claiming to prove the
    Postgres locking behavior from a single-threaded SQLite test process.

    "No eligible constable found" deliberately stays a 200 with a
    machine-readable `status: "no_available_constable"` body (NOT a 404/409)
    -- this is an established, already-tested contract from Phase 4/5
    (see test_dispatch.py), not an error: the request was entirely valid,
    there just isn't capacity right now. Changing this to an HTTP error
    code would break that existing contract for no functional gain.
    """
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
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

    existing_active_assignment = db.query(models.IncidentAssignment).filter(
        models.IncidentAssignment.incident_id == incident_id,
        models.IncidentAssignment.status.in_(ACTIVE_ASSIGNMENT_STATUSES),
    ).first()
    if existing_active_assignment:
        raise HTTPException(status_code=http_status.HTTP_409_CONFLICT, detail="Incident already has an active assignment")

    # --- Determine primary/backup station (reporting + best-effort station_id assignment) ---
    primary_summary = None
    backup_summary = None
    loc_wkt = db.query(func.ST_AsText(models.Incident.location)).filter(models.Incident.id == incident_id).scalar()
    if loc_wkt:
        lon_str, lat_str = loc_wkt.replace("POINT(", "").replace(")", "").split(" ")
        station_rows = find_nearest_stations(db, float(lon_str), float(lat_str), limit=2)
        if len(station_rows) >= 1:
            station, distance = station_rows[0]
            primary_summary = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)
            if not incident.station_id:
                incident.station_id = station.id
        if len(station_rows) >= 2:
            station, distance = station_rows[1]
            backup_summary = schemas.StationSummaryResponse(id=station.id, name=station.name, distance_meters=distance)

    # --- Nearest eligible constable, with concurrency-safe locking -------
    freshness_cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=CONSTABLE_LOCATION_MAX_AGE_SECONDS
    )

    # "Latest location per constable" via GROUP BY + MAX(timestamp) + join-back
    # rather than Postgres-only DISTINCT ON, so this query is portable across
    # both the real Postgres backend and the SQLite test database.
    latest_ts_subq = (
        db.query(
            models.ConstableLocation.constable_id.label("constable_id"),
            func.max(models.ConstableLocation.timestamp).label("max_ts"),
        )
        .group_by(models.ConstableLocation.constable_id)
        .subquery()
    )
    latest_loc_subq = (
        db.query(
            models.ConstableLocation.constable_id.label("constable_id"),
            models.ConstableLocation.location.label("location"),
            models.ConstableLocation.timestamp.label("timestamp"),
        )
        .join(
            latest_ts_subq,
            (models.ConstableLocation.constable_id == latest_ts_subq.c.constable_id)
            & (models.ConstableLocation.timestamp == latest_ts_subq.c.max_ts),
        )
        .subquery()
    )

    busy_constable_ids = db.query(models.IncidentAssignment.constable_id).filter(
        models.IncidentAssignment.status.in_(ACTIVE_ASSIGNMENT_STATUSES)
    )

    # (Incident.location and the subquery's location column may be plain
    # TEXT under the SQLite test schema or PostGIS Geometry under Postgres;
    # distance_expr() handles both -- see police_stations.py.)
    # NOTE: deliberately NOT `incident.location` (the already-loaded Python-side
    # WKBElement) here. That value happened to work under the SQLite test
    # shim (where a Geometry column is monkeypatched to plain TEXT, so
    # `incident.location` is just a WKT string) but is genuinely broken
    # against real PostgreSQL: SQLAlchemy binds a raw already-loaded
    # WKBElement as literal EWKB hex bytes, and `ST_GeogFromText(...)`
    # (which distance_expr wraps a literal value in) expects WKT syntax,
    # not WKB hex -- this produced a real "parse error - invalid geometry"
    # against Postgres, undetected until dispatch was tested against a
    # real database for the first time (see the production-hardening audit
    # report). A scalar subquery re-selects the incident's location as a
    # genuine SQL column expression instead, which compiles correctly
    # under any dialect.
    incident_location_subq = (
        db.query(models.Incident.location)
        .filter(models.Incident.id == incident.id)
        .scalar_subquery()
    )
    dist = distance_expr(db, latest_loc_subq.c.location, incident_location_subq).label("distance_meters")

    candidates_query = (
        db.query(models.Constable, dist)
        .join(latest_loc_subq, latest_loc_subq.c.constable_id == models.Constable.id)
        .join(models.User, models.User.id == models.Constable.user_id)
        .filter(
            models.Constable.status == models.ConstableStatus.available,
            models.User.status == models.UserStatus.active,
            latest_loc_subq.c.timestamp >= freshness_cutoff,
            ~models.Constable.id.in_(busy_constable_ids),
        )
    )

    # Restrict candidates to the incident's own station's constables when
    # the incident actually has a station attributed (see create_incident's
    # auto-assignment / dispatch's own fallback assignment above). If for
    # any reason it doesn't (e.g. no PoliceStation rows exist at all yet),
    # fall back to an unrestricted search rather than refusing to dispatch
    # -- this also preserves the pre-existing eligibility tests that don't
    # set up a PoliceStation at all. This filter MUST be applied before
    # order_by/limit below -- SQLAlchemy raises if .filter() is called
    # after .limit()/.offset() have already been set on the query.
    if incident.station_id:
        candidates_query = candidates_query.filter(models.Constable.station_id == incident.station_id)

    candidates_query = candidates_query.order_by("distance_meters").limit(5)

    if db.bind is not None and db.bind.dialect.name == "postgresql":
        candidates_query = candidates_query.with_for_update(of=models.Constable, skip_locked=True)

    candidates = candidates_query.all()

    if not candidates:
        db.commit()  # persist any station_id we set above even if no constable is available
        return schemas.DispatchResponse(
            status="no_available_constable",
            incident_id=incident.id,
            primary_station=primary_summary,
            backup_station=backup_summary,
        )

    chosen_constable, _distance = candidates[0]

    assignment = models.IncidentAssignment(
        incident_id=incident.id,
        constable_id=chosen_constable.id,
        status=models.AssignmentStatus.pending,
    )
    db.add(assignment)

    incident.status = models.IncidentStatus.assigned
    if incident.display_id and chosen_constable.badge_number:
        incident.display_id = f"{incident.display_id}-{chosen_constable.badge_number}"

    chosen_constable.status = models.ConstableStatus.busy

    try:
        # This flush is where uq_active_assignment_per_incident (see
        # models.py/migration 2b7f4e9a1d63) would actually raise --
        # it's the genuine DB-level safety net beneath the
        # existing_active_assignment pre-check above, which only protects
        # against the common sequential case, not two transactions racing
        # past that check concurrently.
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail="Incident already has an active assignment",
        )

    log_action(
        db,
        user_id=current_user.id,
        action="incident.dispatched",
        incident_id=incident.id,
        details={"constable_id": str(chosen_constable.id), "assignment_id": str(assignment.id)},
    )

    db.commit()
    db.refresh(assignment)

    await events.publish_incident_dispatched(incident, chosen_constable.id, assignment.id)

    return schemas.DispatchResponse(
        status="dispatched",
        incident_id=incident.id,
        constable_id=chosen_constable.id,
        assignment_id=assignment.id,
        primary_station=primary_summary,
        backup_station=backup_summary,
    )
