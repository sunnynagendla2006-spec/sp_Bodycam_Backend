"""
APAssociationProvider: the explicit seam between "where did an AP
association event come from" and the actual presence/handoff logic.

Every provider below is a THIN wrapper -- none of them contain business
logic. All of it already lives in
`services/presence.py::PresenceService.process_association`, which was
written source-agnostic from the start (it takes `source` as a plain
parameter). That is deliberate: a future PhysicalAPAssociationProvider
(fed by a real edge server reporting genuine Wi-Fi AP association) would
be exactly as short as VirtualAPAssociationProvider below -- same
`process_association` call, same database writes, same WebSocket events,
different `source` tag and a different caller/auth path upstream of it
(an edge server's own credential, instead of a constable's own JWT).

Nothing here decides auth, nothing here decides what counts as a
duplicate, nothing here decides what a handoff is -- that would
duplicate PresenceService, which is exactly what this module exists to
avoid.
"""
import dataclasses
import datetime
from typing import Optional, Tuple

from .. import models
from . import presence as presence_service


@dataclasses.dataclass
class AssociationEvent:
    device_identifier: str
    access_point_code: str
    event_id: Optional[str] = None
    occurred_at: Optional[datetime.datetime] = None


class APAssociationProvider:
    """Base class -- `source` identifies which concrete provider produced the event, for audit/event payloads. Subclasses must not override `submit`'s actual logic, only `source`."""
    source: models.PresenceEventSource

    async def submit(
        self,
        event: AssociationEvent,
        *,
        device: models.Device,
        constable: models.Constable,
        access_point: models.AccessPoint,
    ) -> presence_service.ProcessAssociationResult:
        return await presence_service.process_association(
            device=device,
            constable=constable,
            access_point=access_point,
            event_id=event.event_id,
            occurred_at=event.occurred_at,
            source=self.source,
        )


class VirtualAPAssociationProvider(APAssociationProvider):
    """Fed by the simulator (routers/presence.py's virtual endpoints) -- a police user explicitly selecting a destination AP in demo mode. Never used for a real AP association."""
    source = models.PresenceEventSource.simulator


class RealAPAssociationProvider(APAssociationProvider):
    """
    Fed by an authenticated device reporting its own genuine association
    (routers/presence.py::associate, today the only caller). A future
    PhysicalAPAssociationProvider -- fed by an edge server instead of a
    device's own JWT -- would be this exact same class with a different
    upstream caller; there is nothing else to add.
    """
    source = models.PresenceEventSource.real


async def find_nearest_access_point(
    *, longitude: float, latitude: float, deployment: Optional[str] = None, enabled_only: bool = True
) -> Optional[Tuple[models.AccessPoint, float]]:
    """
    Real geographic nearest-AP lookup via $geoNear (needs the 2dsphere
    index on AccessPoint.location -- see models.py) -- never a pixel/UI
    distance, and never a claim of actual Wi-Fi radio association (see
    this module's docstring and docs/VIRTUAL_AP_POLICE_PRESENCE.md).
    Returns None if no AP in range has a location set at all.
    """
    query: dict = {"location": {"$ne": None}}
    if enabled_only:
        query["enabled"] = True
    if deployment:
        query["deployment"] = deployment

    pipeline = [
        {
            "$geoNear": {
                "near": {"type": "Point", "coordinates": [longitude, latitude]},
                "distanceField": "distance_meters",
                "spherical": True,
                "query": query,
            }
        },
        {"$limit": 1},
    ]
    async for doc in models.AccessPoint.get_motor_collection().aggregate(pipeline):
        ap = models.AccessPoint(
            id=doc["_id"], code=doc["code"], name=doc["name"], zone=doc.get("zone"),
            deployment=doc.get("deployment"), station_id=doc.get("station_id"),
            location=doc.get("location"), enabled=doc.get("enabled", True),
            status=doc.get("status", models.AccessPointStatus.online),
            is_demo=doc.get("is_demo", False), created_at=doc["created_at"], updated_at=doc["updated_at"],
        )
        return ap, doc["distance_meters"]
    return None
