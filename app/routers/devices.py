"""
Phase 1 (body-camera system): Device registration, heartbeat, battery
reporting, and the minimal battery-alert generation this phase requires.

Location is deliberately NOT duplicated here -- POST /constables/me/location
(constables.py) already exists, already derives identity from the JWT the
same way this router does, and is reused as-is; inventing a second,
competing "device location" endpoint would create two sources of truth for
the same fact.

RecordingSession / VideoChunk / RemoteCommand / the full Alerts REST API
(GET/acknowledge/resolve) are explicitly out of scope for this phase -- see
the models.Alert docstring for what's deferred.
"""
import datetime
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import database, models, schemas
from ..auth.deps import get_current_user
from ..services.audit import log_action
from ..services import events
from ..services import alerts as alerts_service
from .constables import get_own_constable
from .settings import load_settings

router = APIRouter(prefix="/devices", tags=["Devices"])


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def compute_effective_status(device: models.Device, settings: dict, now=None) -> models.DeviceStatus:
    """
    Computed lazily on every read/response -- there is NO background
    scheduler in this phase that proactively downgrades a device's stored
    `status` column to stale/offline. This means a device that stopped
    communicating will still show its last-written stored status
    (`online`) until the NEXT time anything queries it, at which point
    this function (not the stored column) is what the API actually
    returns.

    Based on `last_seen_at` -- updated by register/heartbeat/battery
    alike -- rather than `last_heartbeat_at` specifically. A device that
    just registered but hasn't sent a dedicated heartbeat yet has
    genuinely just communicated with the backend and should not be
    reported as offline; `last_heartbeat_at` remains a separate field for
    tracking heartbeat cadence specifically, not the sole liveness signal.

    PHASE 2 ADDITION: if the stored status is `recording` (set by
    routers/recordings.py::start_recording, cleared back to `online` on
    complete/cancel), that is surfaced here AS LONG AS the device is still
    within the online window -- i.e. `recording` never overrides genuine
    staleness/offline detection. A device that stopped communicating
    mid-recording still degrades to stale/offline like any other device;
    detecting and alerting on "recording stopped communicating" is
    explicitly deferred (see Phase 2 report), not silently assumed here.

    HONEST LIMITATION (see phase report): this is correct for anyone
    actively viewing a device (e.g. Control Room dashboard polling/viewing
    GET /devices/), but a device going silent will NOT generate a
    `device.offline` WebSocket alert on its own -- nothing is watching the
    clock when nobody is asking. A real deployment should run a periodic
    job (e.g. every 30s) that re-evaluates all devices and calls the same
    status-change/alert logic used here, so offline detection happens even
    when no one is looking at the dashboard. That job is NOT implemented
    in this phase.
    """
    now = now or _utcnow()
    if device.last_seen_at is None:
        return models.DeviceStatus.offline

    last_seen_at = device.last_seen_at
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=datetime.timezone.utc)

    elapsed = (now - last_seen_at).total_seconds()
    if elapsed <= settings.get("device_stale_seconds", 120):
        if device.status == models.DeviceStatus.recording:
            return models.DeviceStatus.recording
        return models.DeviceStatus.online
    if elapsed <= settings.get("device_offline_seconds", 600):
        return models.DeviceStatus.stale
    return models.DeviceStatus.offline


def _latest_battery(db: Session, device_id: uuid.UUID):
    return (
        db.query(models.BatteryReading)
        .filter(models.BatteryReading.device_id == device_id)
        .order_by(models.BatteryReading.recorded_at.desc())
        .first()
    )


def _latest_location(db: Session, constable_id: Optional[uuid.UUID]):
    if not constable_id:
        return None, None, None
    row = (
        db.query(
            func.ST_X(models.ConstableLocation.location).label("lon"),
            func.ST_Y(models.ConstableLocation.location).label("lat"),
            models.ConstableLocation.timestamp,
        )
        .filter(models.ConstableLocation.constable_id == constable_id)
        .order_by(models.ConstableLocation.timestamp.desc())
        .first()
    )
    if not row:
        return None, None, None
    return row.lat, row.lon, row.timestamp


def _to_device_response(db: Session, device: models.Device, settings: dict) -> schemas.DeviceResponse:
    battery = _latest_battery(db, device.id)
    lat, lon, loc_ts = _latest_location(db, device.constable_id)
    return schemas.DeviceResponse(
        id=device.id,
        constable_id=device.constable_id,
        device_identifier=device.device_identifier,
        platform=device.platform,
        app_version=device.app_version,
        device_model=device.device_model,
        status=compute_effective_status(device, settings),
        last_heartbeat_at=device.last_heartbeat_at,
        last_seen_at=device.last_seen_at,
        created_at=device.created_at,
        updated_at=device.updated_at,
        battery_percent=battery.battery_percent if battery else None,
        is_charging=battery.is_charging if battery else None,
        latitude=lat,
        longitude=lon,
        location_updated_at=loc_ts,
    )


def _require_own_device_for_constable(db: Session, current_user: models.User, device_identifier: str):
    """
    Shared by heartbeat/battery: the calling constable must own the device
    they're reporting for. Never trusts a client-supplied constable_id --
    ownership is checked against the authenticated user's own Constable row.
    """
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a constable may report device state")
    own_constable = get_own_constable(db, current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")

    device = db.query(models.Device).filter(models.Device.device_identifier == device_identifier).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found -- register it first")
    if device.constable_id != own_constable.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This device belongs to another constable")

    return own_constable, device


def _process_battery_thresholds(db: Session, device: models.Device, battery_percent: int, settings: dict):
    """
    De-duplicated battery alert state machine (see phase report for the
    exact worked example this implements):
      - battery > warning threshold: resolve any open alert (recovery).
      - battery in (critical, warning]: ensure ONE open `low_battery` alert
        exists; repeated readings in this range are a no-op, never spam.
      - battery <= critical threshold: ensure ONE open `critical_battery`
        alert exists; escalates an existing open low_battery alert in
        place (same row) rather than creating a second one.

    Returns (alert, threshold_used, action_label) where action_label is
    one of "created", "escalated", "resolved", or None (genuine no-op --
    caller must not audit/publish anything for None).
    """
    warning = settings.get("battery_warning_threshold", 20)
    critical = settings.get("battery_critical_threshold", 10)

    existing_open = (
        db.query(models.Alert)
        .filter(
            models.Alert.device_id == device.id,
            models.Alert.status == models.AlertStatus.open,
            models.Alert.type.in_([models.AlertType.low_battery, models.AlertType.critical_battery]),
        )
        .first()
    )

    if battery_percent > warning:
        if existing_open:
            existing_open.status = models.AlertStatus.resolved
            existing_open.resolved_at = _utcnow()
            existing_open.resolved_by = None  # system-resolved (battery recovered), not a human action
            return existing_open, warning, "resolved"
        return None, None, None

    if battery_percent <= critical:
        target_type, target_severity, threshold_used = models.AlertType.critical_battery, models.AlertSeverity.critical, critical
    else:
        target_type, target_severity, threshold_used = models.AlertType.low_battery, models.AlertSeverity.warning, warning

    if existing_open:
        if existing_open.type == target_type:
            return None, None, None  # already open at this level -- do not spam
        existing_open.type = target_type
        existing_open.severity = target_severity
        existing_open.message = f"Battery at {battery_percent}% (threshold {threshold_used}%)"
        return existing_open, threshold_used, "escalated"

    # No existing open alert visible to OUR query -- but a concurrent
    # request for the same device may be doing the exact same thing right
    # now. Attempt the insert inside a SAVEPOINT (db.begin_nested()) so a
    # unique-constraint violation here only rolls back THIS nested attempt,
    # never the outer transaction -- which, in the caller, may already
    # contain a just-added BatteryReading that must not be lost just
    # because the alert side of this call lost a race.
    new_alert = models.Alert(
        type=target_type,
        severity=target_severity,
        constable_id=device.constable_id,
        device_id=device.id,
        message=f"Battery at {battery_percent}% (threshold {threshold_used}%)",
        status=models.AlertStatus.open,
    )
    try:
        with db.begin_nested():
            db.add(new_alert)
            db.flush()
        return new_alert, threshold_used, "created"
    except IntegrityError:
        # Lost the race against uq_open_battery_alert_per_device -- a
        # concurrent request already committed (or is in the process of
        # committing) an open alert for this device. Re-read it and treat
        # it exactly like `existing_open` would have been handled above,
        # rather than surfacing a 500 to the caller.
        #
        # The SAVEPOINT rollback above may have ALREADY auto-detached
        # `new_alert` from the session as part of rolling back -- calling
        # db.expunge() on it again would then itself raise
        # InvalidRequestError (discovered via the Phase 3 alert-race test
        # for a different alert type; the same latent bug existed here
        # too, just hadn't been triggered by this test's specific timing
        # yet). Guard both cases rather than assuming one.
        try:
            db.expunge(new_alert)
        except Exception:
            pass
        winner = (
            db.query(models.Alert)
            .filter(
                models.Alert.device_id == device.id,
                models.Alert.status == models.AlertStatus.open,
                models.Alert.type.in_([models.AlertType.low_battery, models.AlertType.critical_battery]),
            )
            .first()
        )
        if winner is None:
            # Extremely unlikely (the conflicting row would have to have
            # been deleted between the failed insert and this re-read),
            # but never silently swallow an inconsistent state.
            raise
        if winner.type != target_type:
            winner.type = target_type
            winner.severity = target_severity
            winner.message = f"Battery at {battery_percent}% (threshold {threshold_used}%)"
            return winner, threshold_used, "escalated"
        return winner, threshold_used, None  # winner already at the right level -- no-op


@router.post("/register", response_model=schemas.DeviceResponse)
async def register_device(
    payload: schemas.DeviceRegisterRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Constable-only: registers (or re-claims) a device for the AUTHENTICATED
    constable's own account. `device_identifier` uniqueness is enforced at
    the database level (see migration) as the genuine safety net beneath
    the application-level check below -- two concurrent registration
    attempts for the same identifier can only ever result in one row.
    """
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a constable may register a device")
    own_constable = get_own_constable(db, current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")

    now = _utcnow()
    device = db.query(models.Device).filter(models.Device.device_identifier == payload.device_identifier).first()

    if device:
        if device.constable_id is not None and device.constable_id != own_constable.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This device is already registered to another constable")
        device.constable_id = own_constable.id
        if payload.platform is not None:
            device.platform = payload.platform
        if payload.app_version is not None:
            device.app_version = payload.app_version
        if payload.device_model is not None:
            device.device_model = payload.device_model
        device.status = models.DeviceStatus.online
        device.last_seen_at = now
        action = "device.re_registered"
    else:
        device = models.Device(
            constable_id=own_constable.id,
            device_identifier=payload.device_identifier,
            platform=payload.platform,
            app_version=payload.app_version,
            device_model=payload.device_model,
            status=models.DeviceStatus.online,
            last_seen_at=now,
        )
        db.add(device)
        action = "device.registered"

    log_action(
        db,
        user_id=current_user.id,
        action=action,
        details={"device_identifier": payload.device_identifier},
    )

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This device identifier was just registered by another request",
        )
    db.refresh(device)

    settings = load_settings()
    await events.publish_device_registered(device, own_constable.station_id)

    return _to_device_response(db, device, settings)


@router.post("/heartbeat", response_model=schemas.DeviceResponse)
async def device_heartbeat(
    payload: schemas.DeviceHeartbeatRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Idempotent/safe to call repeatedly. Does NOT create an audit row for
    the heartbeat itself (would be excessive noise for a periodic call) --
    only a resulting battery-alert state CHANGE (created/escalated/
    resolved) is audited, since that's a meaningful event, not routine
    traffic.
    """
    own_constable, device = _require_own_device_for_constable(db, current_user, payload.device_identifier)
    settings = load_settings()
    now = _utcnow()

    old_effective = compute_effective_status(device, settings, now)

    device.last_heartbeat_at = now
    device.last_seen_at = now
    if device.status != models.DeviceStatus.recording:
        device.status = models.DeviceStatus.online

    alert_result = (None, None, None)
    if payload.battery_percent is not None:
        db.add(models.BatteryReading(device_id=device.id, battery_percent=payload.battery_percent, is_charging=payload.is_charging))
        alert_result = _process_battery_thresholds(db, device, payload.battery_percent, settings)
        alert, threshold, action_label = alert_result
        if action_label:
            log_action(
                db,
                user_id=current_user.id,
                action=f"alert.{action_label}",
                details={"alert_type": alert.type.value, "device_id": str(device.id), "battery_percent": payload.battery_percent},
            )

    db.commit()
    db.refresh(device)

    new_effective = compute_effective_status(device, settings, now)
    station_id = own_constable.station_id

    await events.publish_device_heartbeat(device, station_id, new_effective.value)
    if old_effective != new_effective:
        await events.publish_device_status_changed(device, station_id, old_effective.value, new_effective.value)
    if payload.battery_percent is not None:
        await events.publish_battery_updated(device, station_id, payload.battery_percent, payload.is_charging)
        alert, threshold, action_label = alert_result
        if action_label:
            await events.publish_battery_alert(alert, device, station_id, payload.battery_percent, threshold)

    # Recovery detection: the device just reported in, so this is the
    # natural moment to resolve any open stale/offline/recording-offline
    # alerts (see _observe_and_alert_device_status's docstring for why
    # this is called from both directions -- GET for degradation, here
    # for recovery).
    await _observe_and_alert_device_status(db, device, settings, station_id)

    return _to_device_response(db, device, settings)


@router.post("/battery", response_model=schemas.BatteryReadingResponse)
async def report_battery(
    payload: schemas.DeviceBatteryReportRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Standalone battery report, independent of a full heartbeat call. Also counts as evidence the device is alive (updates last_seen_at), but does NOT update last_heartbeat_at -- that field is reserved for POST /devices/heartbeat specifically."""
    own_constable, device = _require_own_device_for_constable(db, current_user, payload.device_identifier)
    settings = load_settings()
    now = _utcnow()

    device.last_seen_at = now
    reading = models.BatteryReading(device_id=device.id, battery_percent=payload.battery_percent, is_charging=payload.is_charging)
    db.add(reading)

    alert, threshold, action_label = _process_battery_thresholds(db, device, payload.battery_percent, settings)
    if action_label:
        log_action(
            db,
            user_id=current_user.id,
            action=f"alert.{action_label}",
            details={"alert_type": alert.type.value, "device_id": str(device.id), "battery_percent": payload.battery_percent},
        )

    db.commit()
    db.refresh(reading)

    station_id = own_constable.station_id
    await events.publish_battery_updated(device, station_id, payload.battery_percent, payload.is_charging)
    if action_label:
        await events.publish_battery_alert(alert, device, station_id, payload.battery_percent, threshold)

    return reading


async def _observe_and_alert_device_status(db: Session, device: models.Device, settings: dict, current_station_id):
    """
    Phase 3: opportunistically materializes device.stale/device.offline
    alerts (+ recording_device_offline if a recording is active) the
    moment ANYONE observes a device in that state -- there is still no
    background scheduler in this phase (see compute_effective_status's
    docstring), so this is deliberately called from BOTH directions:
      - GET /devices/ and GET /devices/{id} (an outside observer is the
        only thing that can notice a device has gone quiet)
      - POST /devices/heartbeat (the device itself reporting back in is
        the natural moment to detect and resolve a recovery)//
    Each call is idempotent and spam-free: upsert_open_alert/
    resolve_open_alert are no-ops if the alert is already in the target
    state, so repeated GETs while a device stays offline do not create
    duplicate alerts or repeatedly publish events.
    """
    effective = compute_effective_status(device, settings)

    if effective in (models.DeviceStatus.online, models.DeviceStatus.recording):
        # Recovery: resolve any open stale/offline alerts for this device.
        for alert_type in (models.AlertType.device_stale, models.AlertType.device_offline, models.AlertType.recording_device_offline):
            resolved = alerts_service.resolve_open_alert(db, device, alert_type)
            if resolved:
                db.commit()
                db.refresh(resolved)
                await events.publish_generic_alert_event(resolved, current_station_id, "alert.resolved")
        return

    if effective == models.DeviceStatus.stale:
        alert, action = alerts_service.upsert_open_alert(
            db, device, models.AlertType.device_stale, models.AlertSeverity.warning,
            f"Device has not communicated in over {settings.get('device_stale_seconds', 120)}s",
        )
        if action == "created":
            log_action(db, user_id=None, action="alert.created", details={"alert_type": "device_stale", "device_id": str(device.id)})
            db.commit()
            db.refresh(alert)
            await events.publish_generic_alert_event(alert, current_station_id, "device.stale")
        return

    if effective == models.DeviceStatus.offline:
        alert, action = alerts_service.upsert_open_alert(
            db, device, models.AlertType.device_offline, models.AlertSeverity.critical,
            f"Device has not communicated in over {settings.get('device_offline_seconds', 600)}s",
        )
        if action == "created":
            log_action(db, user_id=None, action="alert.created", details={"alert_type": "device_offline", "device_id": str(device.id)})
            db.commit()
            db.refresh(alert)
            await events.publish_generic_alert_event(alert, current_station_id, "device.offline")

        # Task 12: if this device has an ACTIVE recording, this is a
        # high-priority, distinct alert -- never fabricates a location if
        # none exists (see _latest_location, which already returns
        # (None, None, None) when there's no ConstableLocation row).
        active_recording = (
            db.query(models.RecordingSession)
            .filter(models.RecordingSession.device_id == device.id, models.RecordingSession.status == models.RecordingStatus.recording)
            .first()
        )
        if active_recording:
            lat, lon, loc_ts = _latest_location(db, device.constable_id)
            location_note = f" last known location: {lat},{lon} at {loc_ts}" if lat is not None else " no known location on record"
            rec_alert, rec_action = alerts_service.upsert_open_alert(
                db, device, models.AlertType.recording_device_offline, models.AlertSeverity.critical,
                f"Device went offline during active recording {active_recording.id}.{location_note}",
            )
            if rec_action == "created":
                log_action(
                    db, user_id=None, action="alert.created",
                    details={"alert_type": "recording_device_offline", "device_id": str(device.id), "recording_session_id": str(active_recording.id), "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None},
                )
                db.commit()
                db.refresh(rec_alert)
                await events.publish_generic_alert_event(rec_alert, current_station_id, "recording.device_offline")
        return


def _device_station_id(db: Session, device: models.Device):
    if not device.constable_id:
        return None
    constable = db.query(models.Constable).filter(models.Constable.id == device.constable_id).first()
    return constable.station_id if constable else None


@router.get("/", response_model=list[schemas.DeviceResponse])
async def list_devices(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """admin/control_room: all devices. station: only devices whose constable belongs to their station. constable: only their own device(s). citizen: denied."""
    settings = load_settings()
    role = current_user.role
    query = db.query(models.Device)

    if role in (models.UserRole.admin, models.UserRole.control_room):
        pass
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        query = query.join(models.Constable, models.Device.constable_id == models.Constable.id).filter(
            models.Constable.station_id == current_user.station_id
        )
    elif role == models.UserRole.constable:
        own_constable = get_own_constable(db, current_user)
        if not own_constable:
            return []
        query = query.filter(models.Device.constable_id == own_constable.id)
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view devices")

    devices = query.order_by(models.Device.created_at.desc()).all()
    for d in devices:
        await _observe_and_alert_device_status(db, d, settings, _device_station_id(db, d))
    return [_to_device_response(db, d, settings) for d in devices]


@router.get("/{device_id}", response_model=schemas.DeviceResponse)
async def get_device(
    device_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Same ownership rules as list_devices, applied to a single device. 404 if genuinely missing; 403 if it exists but the caller isn't authorized for it."""
    settings = load_settings()
    device = db.query(models.Device).filter(models.Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this device")

    await _observe_and_alert_device_status(db, device, settings, _device_station_id(db, device))

    return _to_device_response(db, device, settings)
