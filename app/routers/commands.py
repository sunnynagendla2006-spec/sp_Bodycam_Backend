"""
RemoteCommand lifecycle.

Creation and "sent" happen as one atomic step (see models.RemoteCommand's
docstring). ACK/result/cancel transitions use an atomic
`find_one_and_update` compare-and-swap (keyed on the command's expected
CURRENT status) rather than the DuplicateKeyError/unique-index pattern
used for alerts/chunks -- this protects an UPDATE/state-transition race on
an EXISTING document, not a duplicate-insert race, which is exactly what a
conditional update is for (the direct Mongo equivalent of the old
`SELECT ... FOR UPDATE` row locking, mirrors media.py's
_transition_evidence_status).
"""
import datetime
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pymongo import ReturnDocument

from beanie.operators import In

from .. import models, schemas
from ..auth.deps import get_current_user, require_role
from ..services.audit import log_action
from ..services import events
from ..services import alerts as alerts_service
from .constables import get_own_constable
from .devices import _device_station_id

router = APIRouter(tags=["Remote Commands"])


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


async def _authorize_command_issue(device: models.Device, current_user: models.User):
    """admin/control_room: any device. station: only devices belonging to constables in their own station. constable/citizen: never."""
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        return
    if role == models.UserRole.station:
        if current_user.station_id and device.constable_id:
            constable = await models.Constable.get(device.constable_id)
            if constable and constable.station_id == current_user.station_id:
                return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to command this device")


async def _get_device_or_404(device_id: uuid.UUID) -> models.Device:
    device = await models.Device.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


async def _get_command_or_404(command_id: uuid.UUID) -> models.RemoteCommand:
    command = await models.RemoteCommand.get(command_id)
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    return command


async def _require_own_command_device(current_user: models.User, command: models.RemoteCommand):
    """The caller must be the constable who owns the TARGET device of this command."""
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the target device's constable may perform this action")
    own_constable = await get_own_constable(current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")
    device = await models.Device.get(command.device_id)
    if not device or device.constable_id != own_constable.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to act on this command")
    return own_constable, device


async def _cas_command_status(command_id: uuid.UUID, expected: list, update_fields: dict):
    """
    Atomically transitions `command_id` from one of `expected` statuses,
    applying `update_fields`. Returns the command's state as it was BEFORE
    the update on success, or None if the current status wasn't one of
    `expected` (caller re-fetches to build the right error message).
    """
    return await models.RemoteCommand.get_motor_collection().find_one_and_update(
        {"_id": command_id, "status": {"$in": [s.value for s in expected]}},
        {"$set": update_fields},
        return_document=ReturnDocument.BEFORE,
    )


@router.post("/devices/{device_id}/commands", response_model=schemas.RemoteCommandResponse)
async def create_command(
    device_id: uuid.UUID,
    payload: schemas.RemoteCommandCreateRequest,
    current_user: models.User = Depends(get_current_user),
):
    device = await _get_device_or_404(device_id)
    await _authorize_command_issue(device, current_user)

    now = _utcnow()
    command = models.RemoteCommand(
        device_id=device_id,
        issued_by=current_user.id,
        command_type=payload.command_type,
        status=models.RemoteCommandStatus.sent,
        sent_at=now,
    )
    await command.insert()

    await log_action(user_id=current_user.id, action="command.created", details={"command_id": str(command.id), "device_id": str(device_id), "command_type": payload.command_type.value})
    await log_action(user_id=current_user.id, action="command.sent", details={"command_id": str(command.id), "device_id": str(device_id)})

    station_id = await _device_station_id(device)
    await events.publish_command_sent(command, device.constable_id, station_id)

    return command


@router.get("/commands/", response_model=list[schemas.RemoteCommandResponse])
async def list_all_commands(
    device_id: Optional[uuid.UUID] = None,
    status: Optional[models.RemoteCommandStatus] = None,
    command_type: Optional[models.RemoteCommandType] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: models.User = Depends(require_role("admin", "control_room", "station", "constable")),
):
    """
    Read-only global command history. Preserves the exact authorization
    model:
      admin/control_room: all commands.
      station: only commands targeting devices whose constable belongs to
        their own station.
      constable: only commands targeting their own device.
      citizen: denied entirely at the dependency level (require_role).
    """
    role = current_user.role
    query = models.RemoteCommand.find()

    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = [
            c.id for c in await models.Constable.find(models.Constable.station_id == current_user.station_id).to_list()
        ]
        station_device_ids = [
            d.id for d in await models.Device.find(In(models.Device.constable_id, station_constable_ids)).to_list()
        ]
        query = query.find(In(models.RemoteCommand.device_id, station_device_ids))
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            return []
        own_device_ids = [d.id for d in await models.Device.find(models.Device.constable_id == own_constable.id).to_list()]
        query = query.find(In(models.RemoteCommand.device_id, own_device_ids))

    if device_id is not None:
        query = query.find(models.RemoteCommand.device_id == device_id)
    if status is not None:
        query = query.find(models.RemoteCommand.status == status)
    if command_type is not None:
        query = query.find(models.RemoteCommand.command_type == command_type)

    return await query.sort(-models.RemoteCommand.created_at).skip(offset).limit(limit).to_list()


@router.get("/devices/{device_id}/commands", response_model=list[schemas.RemoteCommandResponse])
async def list_commands(
    device_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """
    Lets the target device (constable) poll for its own commands. Same
    ownership rules as command issuance for admin/control_room/station
    (viewing history); constable is additionally allowed here (but never
    to issue).
    """
    device = await _get_device_or_404(device_id)
    role = current_user.role
    authorized = False
    if role in (models.UserRole.admin, models.UserRole.control_room):
        authorized = True
    elif role == models.UserRole.station:
        if current_user.station_id and device.constable_id:
            constable = await models.Constable.get(device.constable_id)
            authorized = constable is not None and constable.station_id == current_user.station_id
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        authorized = own_constable is not None and device.constable_id == own_constable.id

    if not authorized:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this device's commands")

    return await models.RemoteCommand.find(
        models.RemoteCommand.device_id == device_id
    ).sort(-models.RemoteCommand.created_at).to_list()


@router.post("/commands/{command_id}/ack", response_model=schemas.RemoteCommandResponse)
async def ack_command(
    command_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """SENT -> ACKNOWLEDGED only. A repeated/duplicate ack (already ACKNOWLEDGED or beyond) is rejected with 409, not silently accepted."""
    command = await _get_command_or_404(command_id)
    own_constable, device = await _require_own_command_device(current_user, command)

    now = _utcnow()
    before = await _cas_command_status(
        command_id, [models.RemoteCommandStatus.sent],
        {"status": models.RemoteCommandStatus.acknowledged.value, "acknowledged_at": now},
    )
    if before is None:
        current = await models.RemoteCommand.get(command_id)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot acknowledge a command in status {current.status.value}")

    await log_action(user_id=current_user.id, action="command.acknowledged", details={"command_id": str(command_id)})

    command = await models.RemoteCommand.get(command_id)
    station_id = own_constable.station_id
    await events.publish_command_acknowledged(command, device.constable_id, station_id)

    return command


@router.post("/commands/{command_id}/result", response_model=schemas.RemoteCommandResponse)
async def command_result(
    command_id: uuid.UUID,
    payload: schemas.RemoteCommandResultRequest,
    current_user: models.User = Depends(get_current_user),
):
    """ACKNOWLEDGED -> EXECUTED (success) or ACKNOWLEDGED -> FAILED (failure) only. A failure additionally creates/updates a command_failed alert."""
    command = await _get_command_or_404(command_id)
    own_constable, device = await _require_own_command_device(current_user, command)

    now = _utcnow()
    if payload.success:
        update_fields = {"status": models.RemoteCommandStatus.executed.value, "executed_at": now}
        action = "command.executed"
    else:
        update_fields = {"status": models.RemoteCommandStatus.failed.value, "executed_at": now, "failure_reason": payload.failure_reason}
        action = "command.failed"

    before = await _cas_command_status(command_id, [models.RemoteCommandStatus.acknowledged], update_fields)
    if before is None:
        current = await models.RemoteCommand.get(command_id)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot report a result for a command in status {current.status.value}")

    await log_action(user_id=current_user.id, action=action, details={"command_id": str(command_id), "success": payload.success, "failure_reason": payload.failure_reason})

    alert = None
    alert_action = None
    if not payload.success:
        alert, alert_action = await alerts_service.upsert_open_alert(
            device, models.AlertType.command_failed, models.AlertSeverity.warning,
            f"Command {command_id} failed: {payload.failure_reason or 'no reason given'}",
        )
        if alert_action == "created":
            await log_action(user_id=current_user.id, action="alert.created", details={"alert_type": "command_failed", "command_id": str(command_id)})

    command = await models.RemoteCommand.get(command_id)
    station_id = own_constable.station_id
    await events.publish_command_result(command, device.constable_id, station_id)
    if alert_action == "created":
        await events.publish_generic_alert_event(alert, station_id, "alert.created")

    return command


@router.post("/commands/{command_id}/cancel", response_model=schemas.RemoteCommandResponse)
async def cancel_command(
    command_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """PENDING/SENT -> CANCELLED only. Same issuer-authorization rules as creating a command (admin/control_room/station-own) -- the constable does not cancel their own incoming commands."""
    command = await _get_command_or_404(command_id)
    device = await models.Device.get(command.device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    await _authorize_command_issue(device, current_user)

    before = await _cas_command_status(
        command_id, [models.RemoteCommandStatus.pending, models.RemoteCommandStatus.sent],
        {"status": models.RemoteCommandStatus.cancelled.value},
    )
    if before is None:
        current = await models.RemoteCommand.get(command_id)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot cancel a command in status {current.status.value}")

    await log_action(user_id=current_user.id, action="command.cancelled", details={"command_id": str(command_id)})

    command = await models.RemoteCommand.get(command_id)
    station_id = await _device_station_id(device)
    await events.publish_command_cancelled(command, device.constable_id, station_id)

    return command
