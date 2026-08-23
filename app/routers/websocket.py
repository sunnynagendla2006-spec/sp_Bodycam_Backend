"""
Authenticated, role-scoped WebSocket gateway.

Phase 5 replaces the old fully-open global broadcast (every connected
client received every message, with no authentication at all) with:
  - mandatory JWT authentication before the connection is accepted
  - role-scoped "rooms" (control_room / station:<id> / constable:<id>)
  - a small event-publishing API (see app/services/events.py) used by
    incidents.py/constables.py/media.py instead of a raw global broadcast

Authentication: browsers' native WebSocket API cannot set a custom
`Authorization` header on the handshake request, so (per the Phase 5 spec)
this uses a `?token=<JWT>` query parameter instead of a Bearer header --
not both, to avoid two parallel and potentially inconsistent auth paths.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional, Set

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from jose import JWTError
from sqlalchemy.orm import Session

from .. import database, models
from ..auth.security import decode_access_token

router = APIRouter(prefix="/ws", tags=["WebSockets"])


class ConnectionManager:
    """
    Role-scoped connection registry. No connection is ever added to any of
    these sets before authentication succeeds (see websocket_endpoint
    below) -- there is no "default"/global room anymore.
    """

    def __init__(self):
        self.control_room_connections: Set[WebSocket] = set()
        self.station_connections: Dict[uuid.UUID, Set[WebSocket]] = {}
        self.constable_connections: Dict[uuid.UUID, Set[WebSocket]] = {}

    def add_control_room(self, ws: WebSocket):
        self.control_room_connections.add(ws)

    def add_station(self, station_id: uuid.UUID, ws: WebSocket):
        self.station_connections.setdefault(station_id, set()).add(ws)

    def add_constable(self, constable_id: uuid.UUID, ws: WebSocket):
        self.constable_connections.setdefault(constable_id, set()).add(ws)

    def disconnect(self, ws: WebSocket, *, station_id: Optional[uuid.UUID] = None, constable_id: Optional[uuid.UUID] = None):
        """Remove a connection from wherever it was registered. Safe to call even if it was never added (e.g. auth failed before accept)."""
        self.control_room_connections.discard(ws)
        if station_id is not None and station_id in self.station_connections:
            self.station_connections[station_id].discard(ws)
        if constable_id is not None and constable_id in self.constable_connections:
            self.constable_connections[constable_id].discard(ws)

    @staticmethod
    async def _send_to_all(connections: Set[WebSocket], message: dict):
        """
        Sends to every connection in the set, pruning any that fail (e.g.
        already disconnected). A failed/broken WebSocket send NEVER raises
        out of this method -- callers (incidents.py/constables.py/media.py)
        must be able to complete their database commit regardless of
        WebSocket delivery outcome (see Phase 5 report Part 12/Part 5).
        """
        dead = set()
        payload = json.dumps(message)
        for connection in list(connections):
            try:
                await connection.send_text(payload)
            except Exception:
                dead.add(connection)
        for connection in dead:
            connections.discard(connection)

    async def send_to_control_room(self, message: dict):
        await self._send_to_all(self.control_room_connections, message)

    async def send_to_station(self, station_id: Optional[uuid.UUID], message: dict):
        if station_id is None:
            return
        connections = self.station_connections.get(station_id)
        if connections:
            await self._send_to_all(connections, message)

    async def send_to_constable(self, constable_id: Optional[uuid.UUID], message: dict):
        if constable_id is None:
            return
        connections = self.constable_connections.get(constable_id)
        if connections:
            await self._send_to_all(connections, message)


manager = ConnectionManager()


def build_event(event: str, data: dict) -> dict:
    """Consistent event envelope: {event, timestamp (server-generated), data}. See app/services/events.py for the publish-side helpers built on top of this."""
    return {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


async def _authenticate_websocket(token: Optional[str], db: Session) -> Optional[models.User]:
    """
    Returns the authenticated, active User for a valid token, or None for
    ANY failure (missing token, malformed/invalid/expired JWT, unknown
    user, inactive user) -- the caller rejects the connection uniformly on
    None rather than distinguishing failure reasons to the client.
    """
    if not token:
        return None
    try:
        payload = decode_access_token(token)
    except JWTError:
        return None
    try:
        user_id = uuid.UUID(payload.sub) if isinstance(payload.sub, str) else payload.sub
    except (ValueError, AttributeError, TypeError):
        return None
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or user.status != models.UserStatus.active:
        return None
    return user


@router.websocket("/control_room")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None),
    db: Session = Depends(database.get_db),
):
    """
    Single WebSocket gateway for all authenticated operational roles
    (despite the historical "/control_room" path name, kept for backward
    URL compatibility -- see Phase 5 report). The caller's role determines
    which room they're placed in server-side; nothing here is
    client-selectable:
      - admin / control_room -> the control_room room (receives every
        operational event)
      - station               -> station:<their own station_id> ONLY
                                  (rejected if they have no station_id)
      - constable              -> constable:<their own constable_id> ONLY
      - citizen / anything else -> rejected (no operational room)

    The connection is NEVER accepted before authentication succeeds --
    on any auth failure this closes the socket immediately without
    calling websocket.accept() first.
    """
    user = await _authenticate_websocket(token, db)
    if not user:
        await websocket.close(code=4401)
        return

    role = user.role
    station_id: Optional[uuid.UUID] = None
    constable_id: Optional[uuid.UUID] = None

    if role in (models.UserRole.admin, models.UserRole.control_room):
        await websocket.accept()
        manager.add_control_room(websocket)
    elif role == models.UserRole.station:
        if not user.station_id:
            await websocket.close(code=4403)
            return
        station_id = user.station_id
        await websocket.accept()
        manager.add_station(station_id, websocket)
    elif role == models.UserRole.constable:
        constable = db.query(models.Constable).filter(models.Constable.user_id == user.id).first()
        if not constable:
            await websocket.close(code=4404)
            return
        constable_id = constable.id
        await websocket.accept()
        manager.add_constable(constable_id, websocket)
    else:
        # citizen or any other role: no operational WebSocket room exists for them.
        await websocket.close(code=4403)
        return

    try:
        while True:
            # No business logic is accepted from client messages -- this is
            # purely a keep-alive/ping-pong channel. Anything received is
            # acknowledged and otherwise ignored.
            await websocket.receive_text()
            await websocket.send_text(json.dumps(build_event("ack", {"received": True})))
    except WebSocketDisconnect:
        pass
    except Exception:
        # Any other transport-level error: still fall through to cleanup below.
        pass
    finally:
        manager.disconnect(websocket, station_id=station_id, constable_id=constable_id)
