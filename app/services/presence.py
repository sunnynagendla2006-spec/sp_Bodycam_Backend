"""
PresenceService: the single, reusable business-logic path for recording
an AP association. Every caller (the real constable-device endpoint
today; a future edge server or dev-only simulator endpoint later) must
go through `process_association()` -- never write PolicePresence or
PresenceHandoff directly from a router. This is what keeps "one business
logic path" true regardless of how many entry points eventually call it.

Also owns the lazy stale/offline computation
(`compute_effective_presence_status`), mirroring
app/routers/devices.py::compute_effective_status exactly: there is no
background scheduler here either, by the same deliberate design as that
module.
"""
import dataclasses
import datetime
from typing import Optional

from pymongo.errors import DuplicateKeyError

from .. import models

_DEFAULT_PRESENCE_STALE_SECONDS = 120
_DEFAULT_PRESENCE_OFFLINE_SECONDS = 600


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class PresenceError(Exception):
    """Raised for an expected, caller-facing rejection (never a bug) -- `code` maps to a specific HTTP status in routers/presence.py."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclasses.dataclass
class ProcessAssociationResult:
    presence: models.PolicePresence
    handoff: Optional[models.PresenceHandoff]
    handoff_created: bool
    is_first_association: bool = False
    duplicate_event: bool = False


async def process_association(
    *,
    device: models.Device,
    constable: models.Constable,
    access_point: models.AccessPoint,
    event_id: Optional[str],
    occurred_at: Optional[datetime.datetime],
    source: models.PresenceEventSource,
) -> ProcessAssociationResult:
    """
    Raises PresenceError("access_point_disabled", ...) if the target AP is
    administratively disabled -- the caller (router) is responsible for
    translating that into a 409. Never raises for a same-AP duplicate
    heartbeat; that is the expected, idempotent, no-handoff path.
    """
    if not access_point.enabled:
        raise PresenceError("access_point_disabled", f"Access point {access_point.code} is disabled")

    now = occurred_at or _utcnow()
    presence = await models.PolicePresence.find_one(models.PolicePresence.device_id == device.id)

    # --- Duplicate / same-AP heartbeat: idempotent no-op on handoff -------
    if presence and presence.current_access_point_id == access_point.id:
        presence.last_seen_at = now
        presence.status = models.PresenceConnectionStatus.connected
        if event_id:
            presence.last_event_id = event_id
        await presence.save()
        return ProcessAssociationResult(presence=presence, handoff=None, handoff_created=False)

    previous_ap_id = presence.current_access_point_id if presence else None
    is_first_association = previous_ap_id is None

    handoff = models.PresenceHandoff(
        device_id=device.id,
        constable_id=constable.id,
        previous_access_point_id=previous_ap_id,
        access_point_id=access_point.id,
        event_id=event_id,
        source=source,
        occurred_at=now,
    )
    try:
        await handoff.insert()
    except DuplicateKeyError:
        # A retried request carrying the exact same event_id as one
        # already processed -- re-fetch what actually happened rather
        # than silently re-applying (or silently dropping) the mutation.
        existing = await models.PresenceHandoff.find_one(models.PresenceHandoff.event_id == event_id)
        current_presence = presence or await models.PolicePresence.find_one(models.PolicePresence.device_id == device.id)
        return ProcessAssociationResult(presence=current_presence, handoff=existing, handoff_created=False, duplicate_event=True)

    if presence:
        presence.current_access_point_id = access_point.id
        presence.current_zone = access_point.zone
        presence.status = models.PresenceConnectionStatus.connected
        presence.last_seen_at = now
        presence.last_event_id = event_id
        presence.handoff_count += 1
        presence.current_zone_since = now
        presence.updated_at = now
        await presence.save()
    else:
        presence = models.PolicePresence(
            device_id=device.id,
            constable_id=constable.id,
            current_access_point_id=access_point.id,
            current_zone=access_point.zone,
            status=models.PresenceConnectionStatus.connected,
            location_source="ACCESS_POINT",
            last_event_id=event_id,
            last_seen_at=now,
            handoff_count=0,  # the first-ever association is NOT a handoff
            current_zone_since=now,
            updated_at=now,
        )
        await presence.insert()

    return ProcessAssociationResult(
        presence=presence, handoff=handoff, handoff_created=True, is_first_association=is_first_association,
    )


def compute_effective_presence_status(
    presence: models.PolicePresence, settings: dict, now: Optional[datetime.datetime] = None
) -> models.PresenceConnectionStatus:
    """Lazy, read-time only -- see module docstring. Never mutates `presence`; callers decide whether/how to persist a transition."""
    now = now or _utcnow()
    if presence.last_seen_at is None:
        return models.PresenceConnectionStatus.disconnected

    last_seen_at = presence.last_seen_at
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=datetime.timezone.utc)

    elapsed = (now - last_seen_at).total_seconds()
    stale_after = settings.get("presence_stale_seconds", _DEFAULT_PRESENCE_STALE_SECONDS)
    offline_after = settings.get("presence_offline_seconds", _DEFAULT_PRESENCE_OFFLINE_SECONDS)
    if elapsed <= stale_after:
        return models.PresenceConnectionStatus.connected
    if elapsed <= offline_after:
        return models.PresenceConnectionStatus.stale
    return models.PresenceConnectionStatus.disconnected
