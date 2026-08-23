"""
Phase 3 (body-camera system): RemoteCommand lifecycle.

Creation and "sent" happen as one atomic step (see models.RemoteCommand's
docstring). ACK/result transitions use row-level locking (SELECT ... FOR
UPDATE) rather than the SAVEPOINT/unique-index pattern used for alerts/
chunks -- this protects an UPDATE/state-transition race on an EXISTING
row, not a duplicate-INSERT race, so row locking is the correct mechanism
here (mirrors app/routers/media.py::_transition_evidence_status).
"""
import datetime
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .. import database, models, schemas
from ..auth.deps import get_current_user, require_role
from ..services.audit import log_action
from ..services import events
from ..services import alerts as alerts_service
from .constables import get_own_constable
from .devices import _device_station_id

router = APIRouter(tags=["Remote Commands"])


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _authorize_command_issue(db: Session, device: models.Device, current_user: models.User):
    """admin/control_room: any device. station: only devices belonging to constables in their own station. constable/citizen: never."""
    role = current_user.role
    if role in (models.UserRole.admin, models.UserRole.control_room):
        return
    if role == models.UserRole.station:
        if current_user.station_id and device.constable_id:
            constable = db.query(models.Constable).filter(models.Constable.id == device.constable_id).first()
            if constable and constable.station_id == current_user.station_id:
                return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to command this device")


def _get_device_or_404(db: Session, device_id: uuid.UUID) -> models.Device:
    device = db.query(models.Device).filter(models.Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


def _locked_command_or_404(db: Session, command_id: uuid.UUID) -> models.RemoteCommand:
    command = db.query(models.RemoteCommand).filter(models.RemoteCommand.id == command_id).with_for_update().first()
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    return command


def _require_own_command_device(db: Session, current_user: models.User, command: models.RemoteCommand):
    """The caller must be the constable who owns the TARGET device of this command. Rolls back before raising -- the caller already holds a row lock via _locked_command_or_404, and a rejected auth check must release it promptly rather than holding it until the session closes."""
    if current_user.role != models.UserRole.constable:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the target device's constable may perform this action")
    own_constable = get_own_constable(db, current_user)
    if not own_constable:
        db.rollback()
        raise HTTPException(status_code=404, detail="Constable profile not found")
    device = db.query(models.Device).filter(models.Device.id == command.device_id).first()
    if not device or device.constable_id != own_constable.id:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to act on this command")
    return own_constable, device


@router.post("/devices/{device_id}/commands", response_model=schemas.RemoteCommandResponse)
async def create_command(
    device_id: uuid.UUID,
    payload: schemas.RemoteCommandCreateRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    device = _get_device_or_404(db, device_id)
    _authorize_command_issue(db, device, current_user)

    command = models.RemoteCommand(
        device_id=device_id,
        issued_by=current_user.id,
        command_type=payload.command_type,
        status=models.RemoteCommandStatus.pending,
    )
    db.add(command)
    db.flush()
    log_action(db, user_id=current_user.id, action="command.created", details={"command_id": str(command.id), "device_id": str(device_id), "command_type": payload.command_type.value})

    command.status = models.RemoteCommandStatus.sent
    command.sent_at = _utcnow()
    log_action(db, user_id=current_user.id, action="command.sent", details={"command_id": str(command.id), "device_id": str(device_id)})

    db.commit()
    db.refresh(command)

    station_id = _device_station_id(db, device)
    await events.publish_command_sent(command, device.constable_id, station_id)

    return command


@router.get("/commands/", response_model=list[schemas.RemoteCommandResponse])
def list_all_commands(
    device_id: Optional[uuid.UUID] = None,
    status: Optional[models.RemoteCommandStatus] = None,
    command_type: Optional[models.RemoteCommandType] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin", "control_room", "station", "constable")),
):
    """
    Phase 4A: read-only global command history, so Control Room can see
    command activity without opening each device individually. Purely a
    query over existing RemoteCommand rows -- never changes status, never
    acknowledges/executes/cancels anything (that remains exclusively in
    the ack/result/cancel endpoints below, unchanged).

    Preserves the exact Phase 3 authorization model:
      admin/control_room: all commands.
      station: only commands targeting devices whose constable belongs to
        their own station (RemoteCommand.device_id -> Device.constable_id
        -> Constable.station_id).
      constable: only commands targeting their own device.
      citizen: denied entirely at the dependency level (require_role),
        never reaches this function body.

    NOTE: the `status` parameter here intentionally shadows the
    `fastapi.status` module import within this function's scope -- this
    function never needs to reference an HTTP status code (require_role
    already handles the 403 case before this body runs), so that's safe,
    but it's why this function does NOT raise its own HTTPException the
    way a naive implementation might.
    """
    role = current_user.role
    query = db.query(models.RemoteCommand)

    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_device_ids = (
            db.query(models.Device.id)
            .join(models.Constable, models.Device.constable_id == models.Constable.id)
            .filter(models.Constable.station_id == current_user.station_id)
        )
        query = query.filter(models.RemoteCommand.device_id.in_(station_device_ids))
    elif role == models.UserRole.constable:
        from .constables import get_own_constable
        own_constable = get_own_constable(db, current_user)
        if not own_constable:
            return []
        own_device_ids = db.query(models.Device.id).filter(models.Device.constable_id == own_constable.id)
        query = query.filter(models.RemoteCommand.device_id.in_(own_device_ids))

    if device_id is not None:
        query = query.filter(models.RemoteCommand.device_id == device_id)
    if status is not None:
        query = query.filter(models.RemoteCommand.status == status)
    if command_type is not None:
        query = query.filter(models.RemoteCommand.command_type == command_type)

    return (
        query.order_by(models.RemoteCommand.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/devices/{device_id}/commands", response_model=list[schemas.RemoteCommandResponse])
def list_commands(
    device_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Lets the target device (constable) poll for its own commands -- this
    is how a device that was offline when a command was issued discovers
    it after reconnecting. Same ownership rules as command issuance for
    admin/control_room/station (viewing history); constable is additionally
    allowed here (but never to issue) since it must be able to retrieve
    its own pending/sent commands.
    """
    device = _get_device_or_404(db, device_id)
    role = current_user.role
    authorized = False
    if role in (models.UserRole.admin, models.UserRole.control_room):
        authorized = True
    elif role == models.UserRole.station:
        if current_user.station_id and device.constable_id:
            constable = db.query(models.Constable).filter(models.Constable.id == device.constable_id).first()
            authorized = constable is not None and constable.station_id == current_user.station_id
    elif role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        authorized = own_constable is not None and device.constable_id == own_constable.id

    if not authorized:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this device's commands")

    return (
        db.query(models.RemoteCommand)
        .filter(models.RemoteCommand.device_id == device_id)
        .order_by(models.RemoteCommand.created_at.desc())
        .all()
    )


@router.post("/commands/{command_id}/ack", response_model=schemas.RemoteCommandResponse)
async def ack_command(
    command_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """SENT -> ACKNOWLEDGED only. A repeated/duplicate ack (already ACKNOWLEDGED or beyond) is rejected with 409, not silently accepted -- state must never be corrupted by a retry."""
    command = _locked_command_or_404(db, command_id)
    own_constable, device = _require_own_command_device(db, current_user, command)

    if command.status != models.RemoteCommandStatus.sent:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot acknowledge a command in status {command.status.value}")

    command.status = models.RemoteCommandStatus.acknowledged
    command.acknowledged_at = _utcnow()
    log_action(db, user_id=current_user.id, action="command.acknowledged", details={"command_id": str(command_id)})
    db.commit()
    db.refresh(command)

    station_id = own_constable.station_id
    await events.publish_command_acknowledged(command, device.constable_id, station_id)

    return command


@router.post("/commands/{command_id}/result", response_model=schemas.RemoteCommandResponse)
async def command_result(
    command_id: uuid.UUID,
    payload: schemas.RemoteCommandResultRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """ACKNOWLEDGED -> EXECUTED (success) or ACKNOWLEDGED -> FAILED (failure) only. A failure additionally creates/updates a command_failed alert."""
    command = _locked_command_or_404(db, command_id)
    own_constable, device = _require_own_command_device(db, current_user, command)

    if command.status != models.RemoteCommandStatus.acknowledged:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot report a result for a command in status {command.status.value}")

    command.executed_at = _utcnow()
    if payload.success:
        command.status = models.RemoteCommandStatus.executed
        action = "command.executed"
    else:
        command.status = models.RemoteCommandStatus.failed
        command.failure_reason = payload.failure_reason
        action = "command.failed"
    log_action(db, user_id=current_user.id, action=action, details={"command_id": str(command_id), "success": payload.success, "failure_reason": payload.failure_reason})

    alert = None
    alert_action = None
    if not payload.success:
        alert, alert_action = alerts_service.upsert_open_alert(
            db, device, models.AlertType.command_failed, models.AlertSeverity.warning,
            f"Command {command_id} failed: {payload.failure_reason or 'no reason given'}",
        )
        if alert_action == "created":
            log_action(db, user_id=current_user.id, action="alert.created", details={"alert_type": "command_failed", "command_id": str(command_id)})

    db.commit()
    db.refresh(command)

    station_id = own_constable.station_id
    await events.publish_command_result(command, device.constable_id, station_id)
    if alert_action == "created":
        db.refresh(alert)
        await events.publish_generic_alert_event(alert, station_id, "alert.created")

    return command


@router.post("/commands/{command_id}/cancel", response_model=schemas.RemoteCommandResponse)
async def cancel_command(
    command_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """PENDING/SENT -> CANCELLED only. Same issuer-authorization rules as creating a command (admin/control_room/station-own) -- the constable does not cancel their own incoming commands."""
    command = _locked_command_or_404(db, command_id)
    device = db.query(models.Device).filter(models.Device.id == command.device_id).first()
    if not device:
        db.rollback()
        raise HTTPException(status_code=404, detail="Device not found")

    try:
        _authorize_command_issue(db, device, current_user)
    except HTTPException:
        db.rollback()
        raise

    if command.status not in (models.RemoteCommandStatus.pending, models.RemoteCommandStatus.sent):
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Cannot cancel a command in status {command.status.value}")

    command.status = models.RemoteCommandStatus.cancelled
    log_action(db, user_id=current_user.id, action="command.cancelled", details={"command_id": str(command_id)})
    db.commit()
    db.refresh(command)

    station_id = _device_station_id(db, device)
    await events.publish_command_cancelled(command, device.constable_id, station_id)

    return command
