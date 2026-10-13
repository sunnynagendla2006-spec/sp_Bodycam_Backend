"""
Location ingestion: the single path every officer position takes into the system.

Guarantees (each one is covered by tests/test_location_tracking.py):

  * Only an enrolled+approved device inside an authorised duty session can
    contribute positions. Identity comes from the JWT, never the body.
  * Fixes are validated: coordinate range, no (0,0) "null island", no mock
    providers, recorded_at within a sane window and inside the duty session.
  * Exactly-once: the (duty_session_id, sequence_number) pair is claimed in a
    unique-indexed ledger BEFORE anything else is written, so a retry, a
    replay or a concurrent duplicate can never create a second record or a
    second event.
  * The officer's current position only ever moves FORWARD in recorded time.
    A late-arriving older fix (queue flushed after reconnect, or one that
    overtook a newer one) is stored as history but never moves the marker and
    never emits a live event. Position freshness is derived from the fix's own
    recorded_at, so buffered coordinates are never presented as live.
  * Zone transitions follow services/zones.py (accuracy gating, boundary
    margin, consecutive confirmations).
"""
import dataclasses
import datetime
import logging
import os
import uuid
from typing import Optional

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from .. import geo, models, schemas
from . import events, tracking, zones
from .audit import log_action

logger = logging.getLogger(__name__)

CLOCK_SKEW = datetime.timedelta(seconds=60)
MAX_FIX_AGE = datetime.timedelta(hours=24)
# A fix recorded while the session was still active is accepted for this long
# after "stop duty" so a final queue flush is not lost.
END_GRACE = datetime.timedelta(seconds=10)


class IngestError(Exception):
    """An expected, client-facing rejection. `code` is machine-readable (the mobile client keys its retry/drop decision on it)."""

    def __init__(self, code: str, message: str, http_status: int = 422, retryable: bool = False):
        self.code = code
        self.message = message
        self.http_status = http_status
        self.retryable = retryable
        super().__init__(message)


@dataclasses.dataclass
class IngestOutcome:
    result: str  # accepted | accepted_history | duplicate
    session: models.DutySession
    recorded_at: datetime.datetime
    server_received_at: datetime.datetime
    projection_advanced: bool = False
    zone_code: Optional[str] = None
    zone_status: Optional[str] = None
    zone_changed: bool = False
    buffered: bool = False


def _aware(dt: datetime.datetime) -> datetime.datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def allow_mock_location() -> bool:
    """Development convenience only; never honoured in production."""
    if os.getenv("ENVIRONMENT", "development").strip().lower() == "production":
        return False
    return os.getenv("ALLOW_MOCK_LOCATION", "false").strip().lower() in ("1", "true", "yes")


async def find_session(constable: models.Constable, requested_id: Optional[uuid.UUID]) -> models.DutySession:
    if requested_id is not None:
        session = await models.DutySession.get(requested_id)
        if session is None or session.constable_id != constable.id:
            # Same answer for "does not exist" and "belongs to someone else".
            raise IngestError("duty_session_not_found", "No such duty session for this officer", 404)
        return session
    session = await models.DutySession.find_one(
        models.DutySession.constable_id == constable.id, models.DutySession.status == models.DutySessionStatus.active
    )
    if session is None:
        raise IngestError(
            "no_active_duty_session",
            "Location tracking requires an active duty session. Start duty first (POST /constables/me/duty-session/start).",
            409,
        )
    return session


async def ingest_fix(
    *,
    constable: models.Constable,
    user: models.User,
    payload: schemas.ConstableMeLocationUpdate,
    now: Optional[datetime.datetime] = None,
) -> IngestOutcome:
    now = now or datetime.datetime.now(datetime.timezone.utc)

    # ---- 1. Plausibility -------------------------------------------------
    if payload.is_mock_provider and not allow_mock_location():
        raise IngestError("mock_location_rejected", "Fixes from a mock location provider are not accepted", 422)
    if payload.latitude == 0.0 and payload.longitude == 0.0:
        raise IngestError("invalid_coordinates", "Coordinates (0, 0) are not a real position", 422)
    recorded_at = _aware(payload.recorded_at)
    if recorded_at > now + CLOCK_SKEW:
        raise IngestError("timestamp_in_future", "recorded_at is in the future beyond the allowed clock skew", 422)
    if now - recorded_at > MAX_FIX_AGE:
        raise IngestError("fix_too_old", "recorded_at is older than 24 hours; the fix was dropped", 422)

    # ---- 2. Duty session / device authorisation --------------------------
    session = await find_session(constable, payload.duty_session_id)
    if recorded_at < _aware(session.started_at) - CLOCK_SKEW:
        raise IngestError("fix_before_duty_start", "recorded_at is before this duty session started", 422)
    if session.status == models.DutySessionStatus.ended:
        ended_at = _aware(session.ended_at) if session.ended_at else now
        if recorded_at > ended_at + END_GRACE:
            raise IngestError("duty_session_ended", "This duty session has ended; start a new one to resume tracking", 409)
        if now - ended_at > MAX_FIX_AGE:
            raise IngestError("duty_session_ended", "This duty session ended too long ago to accept queued fixes", 409)
    if payload.device_identifier and payload.device_identifier != session.device_identifier:
        raise IngestError("device_mismatch", "This duty session belongs to a different device", 403)
    device = await models.Device.get(session.device_id)
    if device is None or device.constable_id != constable.id or device.enrolment_status != models.EnrolmentStatus.approved:
        raise IngestError("device_not_approved", "The device for this duty session is not an approved, enrolled device", 403)

    # ---- 3. Exactly-once ledger -----------------------------------------
    key = models.LocationIngestKey(
        duty_session_id=session.id, sequence_number=payload.sequence_number, constable_id=constable.id
    )
    try:
        await key.insert()
    except DuplicateKeyError:
        return IngestOutcome("duplicate", session, recorded_at, now)

    try:
        return await _store(constable, user, payload, session, device, recorded_at, now)
    except Exception:
        # Do not leave a claimed key behind for a fix that was never stored,
        # or the client's retry would be told "duplicate" and lose the fix.
        try:
            await key.delete()
        except Exception:  # pragma: no cover
            logger.exception("failed to release ingest key")
        raise


async def _store(
    constable: models.Constable,
    user: models.User,
    payload: schemas.ConstableMeLocationUpdate,
    session: models.DutySession,
    device: models.Device,
    recorded_at: datetime.datetime,
    now: datetime.datetime,
) -> IngestOutcome:
    seq = payload.sequence_number
    buffered = (now - recorded_at).total_seconds() > tracking.buffered_after_seconds()
    point = geo.point(payload.longitude, payload.latitude)

    # ---- 4. Atomically claim the position projection if this fix is newer ---
    projection_set = {
        "last_location_point": point.model_dump(),
        "last_location_at": now,
        "last_location_accuracy": payload.accuracy,
        "last_location_sequence": seq,
        "last_location_recorded_at": recorded_at,
    }
    if payload.battery_level is not None:
        projection_set["battery_level"] = payload.battery_level
    before = await models.Constable.get_motor_collection().find_one_and_update(
        {
            "_id": constable.id,
            "$or": [
                {"last_location_recorded_at": None},
                {"last_location_recorded_at": {"$lt": recorded_at}},
                {"last_location_recorded_at": recorded_at, "last_location_sequence": {"$lt": seq}},
            ],
        },
        {"$set": projection_set},
        return_document=ReturnDocument.BEFORE,
    )
    advanced = before is not None

    # ---- 5. Zone policy (only fixes that move the officer) ---------------
    zone_code: Optional[str] = None
    zone_status: Optional[str] = "HISTORICAL"
    zone_changed = False
    previous_zone: Optional[str] = None
    if advanced:
        previous_zone = before.get("current_geographic_zone")
        matched = await zones.find_matching_zones(payload.longitude, payload.latitude, payload.deployment)
        zones_by_code = {z.code: z for z in matched}
        if previous_zone and previous_zone not in zones_by_code:
            prior = await models.EventZone.find_one(models.EventZone.code == previous_zone)
            if prior:
                zones_by_code[prior.code] = prior
        resolution = zones.resolve_zone_transition(
            current_zone=previous_zone,
            evaluated_before=before.get("zone_status") is not None,
            candidate=before.get("zone_candidate"),
            candidate_count=before.get("zone_candidate_count") or 0,
            matched=matched,
            zones_by_code=zones_by_code,
            longitude=payload.longitude,
            latitude=payload.latitude,
            accuracy=payload.accuracy,
        )
        zone_code, zone_status, zone_changed = resolution.zone_code, resolution.status, resolution.changed
        zone_set = {
            "current_geographic_zone": resolution.zone_code,
            "zone_status": resolution.status,
            "zone_candidate": resolution.candidate,
            "zone_candidate_count": resolution.candidate_count,
        }
        if resolution.changed:
            zone_set["zone_changed_at"] = now
        # Guarded: if an even newer fix already claimed the projection, leave its zone state alone.
        await models.Constable.get_motor_collection().update_one(
            {"_id": constable.id, "last_location_recorded_at": recorded_at, "last_location_sequence": seq},
            {"$set": zone_set},
        )
    else:
        # History only: raw geometry for the record, no policy, no state change.
        matched = await zones.find_matching_zones(payload.longitude, payload.latitude, payload.deployment)
        zone_code = matched[0].code if matched else None

    # ---- 6. Append-only history ------------------------------------------
    await models.ConstableLocation(
        constable_id=constable.id,
        location=point,
        accuracy=payload.accuracy,
        timestamp=recorded_at,  # time-series time field: when the fix was TAKEN
        device_id=device.id,
        sequence_number=seq,
        recorded_at=recorded_at,
        server_received_at=now,
        geographic_zone=zone_code,
        zone_status=zone_status,
        source=payload.source,
        deployment=payload.deployment,
        is_stale=not advanced,
        duty_session_id=session.id,
        buffered=buffered,
        advanced_projection=advanced,
    ).insert()
    await models.DutySession.get_motor_collection().update_one({"_id": session.id}, {"$inc": {"fix_count": 1}})

    # ---- 7. Live events: ONLY when the officer's position actually moved --
    if advanced:
        await events.publish_constable_location_updated(
            constable_id=constable.id,
            station_id=constable.station_id,
            latitude=payload.latitude,
            longitude=payload.longitude,
            accuracy=payload.accuracy,
            device_id=device.id,
            recorded_at=recorded_at,
            server_received_at=now,
            sequence_number=seq,
            geographic_zone=zone_code,
            zone_status=zone_status,
            source=payload.source,
            duty_session_id=session.id,
            buffered=buffered,
            assigned_zone=constable.assigned_zone_code,
        )
        if zone_changed:
            await events.publish_constable_zone_changed(
                constable_id=constable.id,
                station_id=constable.station_id,
                previous_zone=previous_zone,
                current_zone=zone_code,
                latitude=payload.latitude,
                longitude=payload.longitude,
                timestamp=now,
                zone_status=zone_status,
            )
            await log_action(
                user_id=user.id,
                action="constable.zone_changed",
                details={
                    "constable_id": str(constable.id),
                    "previous_zone": previous_zone,
                    "current_zone": zone_code,
                    "zone_status": zone_status,
                    "duty_session_id": str(session.id),
                },
            )

    return IngestOutcome(
        "accepted" if advanced else "accepted_history",
        session,
        recorded_at,
        now,
        projection_advanced=advanced,
        zone_code=zone_code,
        zone_status=zone_status,
        zone_changed=zone_changed,
        buffered=buffered,
    )
