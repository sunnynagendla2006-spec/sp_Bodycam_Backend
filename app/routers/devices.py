"""
Device registration, heartbeat, battery reporting, and the minimal
battery-alert generation this phase requires.

Location is deliberately NOT duplicated here -- POST /constables/me/location
(constables.py) already exists, already derives identity from the JWT the
same way this router does, and is reused as-is; inventing a second,
competing "device location" endpoint would create two sources of truth for
the same fact.
"""
import datetime
import uuid
from typing import Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.errors import DuplicateKeyError

from .. import models, schemas
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
    `status` column to stale/offline (see the original module docstring
    for the full rationale, unchanged by this migration).
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


async def _latest_battery(device_id: uuid.UUID) -> Optional[models.BatteryReading]:
    return await models.BatteryReading.find(
        models.BatteryReading.device_id == device_id
    ).sort(-models.BatteryReading.recorded_at).first_or_none()


async def _latest_location(constable_id: Optional[uuid.UUID]) -> Tuple[Optional[float], Optional[float], Optional[datetime.datetime]]:
    if not constable_id:
        return None, None, None
    row = await models.ConstableLocation.find(
        models.ConstableLocation.constable_id == constable_id
    ).sort(-models.ConstableLocation.timestamp).first_or_none()
    if not row:
        return None, None, None
    return row.location.coordinates[1], row.location.coordinates[0], row.timestamp


async def _to_device_response(device: models.Device, settings: dict) -> schemas.DeviceResponse:
    battery = await _latest_battery(device.id)
    lat, lon, loc_ts = await _latest_location(device.constable_id)
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


async def _require_own_device_for_constable(current_user: models.User, device_identifier: str):
    """
    Shared by heartbeat/battery: the calling constable must own the device
    they're reporting for. Never trusts a client-supplied constable_id --
    ownership is checked against the authenticated user's own Constable row.
    """
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a constable may report device state")
    own_constable = await get_own_constable(current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")

    device = await models.Device.find_one(models.Device.device_identifier == device_identifier)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found -- register it first")
    if device.constable_id != own_constable.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This device belongs to another constable")

    return own_constable, device


async def _process_battery_thresholds(device: models.Device, battery_percent: int, settings: dict):
    """
    De-duplicated battery alert state machine:
      - battery > warning threshold: resolve any open alert (recovery).
      - battery in (critical, warning]: ensure ONE open `low_battery` alert
        exists; repeated readings in this range are a no-op, never spam.
      - battery <= critical threshold: ensure ONE open `critical_battery`
        alert exists; escalates an existing open low_battery alert in
        place (same document) rather than creating a second one.

    Returns (alert, threshold_used, action_label) where action_label is
    one of "created", "escalated", "resolved", or None (genuine no-op --
    caller must not audit/publish anything for None).
    """
    warning = settings.get("battery_warning_threshold", 20)
    critical = settings.get("battery_critical_threshold", 10)

    existing_open = await models.Alert.find_one(
        models.Alert.device_id == device.id,
        models.Alert.status == models.AlertStatus.open,
        {"type": {"$in": [models.AlertType.low_battery.value, models.AlertType.critical_battery.value]}},
    )

    if battery_percent > warning:
        if existing_open:
            existing_open.status = models.AlertStatus.resolved
            existing_open.resolved_at = _utcnow()
            existing_open.resolved_by = None  # system-resolved (battery recovered), not a human action
            await existing_open.save()
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
        await existing_open.save()
        return existing_open, threshold_used, "escalated"

    # No existing open alert visible to OUR query -- but a concurrent
    # request for the same device may be doing the exact same thing right
    # now. A plain insert against uq_open_battery_alert_per_device is
    # already atomic on Mongo, so losing the race surfaces as
    # DuplicateKeyError rather than needing a SAVEPOINT the way Postgres did.
    new_alert = models.Alert(
        type=target_type,
        severity=target_severity,
        constable_id=device.constable_id,
        device_id=device.id,
        message=f"Battery at {battery_percent}% (threshold {threshold_used}%)",
        status=models.AlertStatus.open,
    )
    try:
        await new_alert.insert()
        return new_alert, threshold_used, "created"
    except DuplicateKeyError:
        # Lost the race against uq_open_battery_alert_per_device -- a
        # concurrent request already inserted an open alert for this
        # device. Re-read it and treat it exactly like `existing_open`
        # would have been handled above, rather than surfacing a 500.
        winner = await models.Alert.find_one(
            models.Alert.device_id == device.id,
            models.Alert.status == models.AlertStatus.open,
            {"type": {"$in": [models.AlertType.low_battery.value, models.AlertType.critical_battery.value]}},
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
            await winner.save()
            return winner, threshold_used, "escalated"
        return winner, threshold_used, None  # winner already at the right level -- no-op


@router.post("/register", response_model=schemas.DeviceResponse)
async def register_device(
    payload: schemas.DeviceRegisterRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Constable-only: registers (or re-claims) a device for the AUTHENTICATED
    constable's own account. `device_identifier` uniqueness is enforced at
    the database level (unique index, see models.Device.Settings) as the
    genuine safety net beneath the application-level check below -- two
    concurrent registration attempts for the same identifier can only ever
    result in one document.
    """
    if current_user.role != models.UserRole.constable:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a constable may register a device")
    own_constable = await get_own_constable(current_user)
    if not own_constable:
        raise HTTPException(status_code=404, detail="Constable profile not found")

    now = _utcnow()
    device = await models.Device.find_one(models.Device.device_identifier == payload.device_identifier)

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
        device.updated_at = now
        action = "device.re_registered"
        await device.save()
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
        action = "device.registered"
        try:
            await device.insert()
        except DuplicateKeyError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This device identifier was just registered by another request",
            )

    await log_action(
        user_id=current_user.id,
        action=action,
        details={"device_identifier": payload.device_identifier},
    )

    settings = load_settings()
    await events.publish_device_registered(device, own_constable.station_id)

    return await _to_device_response(device, settings)


@router.post("/heartbeat", response_model=schemas.DeviceResponse)
async def device_heartbeat(
    payload: schemas.DeviceHeartbeatRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Idempotent/safe to call repeatedly. Does NOT create an audit row for
    the heartbeat itself (would be excessive noise for a periodic call) --
    only a resulting battery-alert state CHANGE (created/escalated/
    resolved) is audited, since that's a meaningful event, not routine
    traffic.
    """
    own_constable, device = await _require_own_device_for_constable(current_user, payload.device_identifier)
    settings = load_settings()
    now = _utcnow()

    old_effective = compute_effective_status(device, settings, now)

    device.last_heartbeat_at = now
    device.last_seen_at = now
    device.updated_at = now
    if device.status != models.DeviceStatus.recording:
        device.status = models.DeviceStatus.online

    alert_result = (None, None, None)
    if payload.battery_percent is not None:
        await models.BatteryReading(device_id=device.id, battery_percent=payload.battery_percent, is_charging=payload.is_charging).insert()
        alert_result = await _process_battery_thresholds(device, payload.battery_percent, settings)
        alert, threshold, action_label = alert_result
        if action_label:
            await log_action(
                user_id=current_user.id,
                action=f"alert.{action_label}",
                details={"alert_type": alert.type.value, "device_id": str(device.id), "battery_percent": payload.battery_percent},
            )

    await device.save()

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
    await _observe_and_alert_device_status(device, settings, station_id)

    return await _to_device_response(device, settings)


@router.post("/battery", response_model=schemas.BatteryReadingResponse)
async def report_battery(
    payload: schemas.DeviceBatteryReportRequest,
    current_user: models.User = Depends(get_current_user),
):
    """Standalone battery report, independent of a full heartbeat call. Also counts as evidence the device is alive (updates last_seen_at), but does NOT update last_heartbeat_at -- that field is reserved for POST /devices/heartbeat specifically."""
    own_constable, device = await _require_own_device_for_constable(current_user, payload.device_identifier)
    settings = load_settings()
    now = _utcnow()

    device.last_seen_at = now
    device.updated_at = now
    await device.save()
    reading = models.BatteryReading(device_id=device.id, battery_percent=payload.battery_percent, is_charging=payload.is_charging)
    await reading.insert()

    alert, threshold, action_label = await _process_battery_thresholds(device, payload.battery_percent, settings)
    if action_label:
        await log_action(
            user_id=current_user.id,
            action=f"alert.{action_label}",
            details={"alert_type": alert.type.value, "device_id": str(device.id), "battery_percent": payload.battery_percent},
        )

    station_id = own_constable.station_id
    await events.publish_battery_updated(device, station_id, payload.battery_percent, payload.is_charging)
    if action_label:
        await events.publish_battery_alert(alert, device, station_id, payload.battery_percent, threshold)

    return reading


async def _observe_and_alert_device_status(device: models.Device, settings: dict, current_station_id):
    """
    Opportunistically materializes device.stale/device.offline alerts
    (+ recording_device_offline if a recording is active) the moment
    ANYONE observes a device in that state -- there is still no background
    scheduler in this phase (see compute_effective_status's docstring), so
    this is deliberately called from BOTH directions: GET /devices/(/{id})
    and POST /devices/heartbeat (recovery). Each call is idempotent and
    spam-free: upsert_open_alert/resolve_open_alert are no-ops if the
    alert is already in the target state.
    """
    effective = compute_effective_status(device, settings)

    if effective in (models.DeviceStatus.online, models.DeviceStatus.recording):
        # Recovery: resolve any open stale/offline alerts for this device.
        for alert_type in (models.AlertType.device_stale, models.AlertType.device_offline, models.AlertType.recording_device_offline):
            resolved = await alerts_service.resolve_open_alert(device, alert_type)
            if resolved:
                await events.publish_generic_alert_event(resolved, current_station_id, "alert.resolved")
        return

    if effective == models.DeviceStatus.stale:
        alert, action = await alerts_service.upsert_open_alert(
            device, models.AlertType.device_stale, models.AlertSeverity.warning,
            f"Device has not communicated in over {settings.get('device_stale_seconds', 120)}s",
        )
        if action == "created":
            await log_action(user_id=None, action="alert.created", details={"alert_type": "device_stale", "device_id": str(device.id)})
            await events.publish_generic_alert_event(alert, current_station_id, "device.stale")
        return

    if effective == models.DeviceStatus.offline:
        alert, action = await alerts_service.upsert_open_alert(
            device, models.AlertType.device_offline, models.AlertSeverity.critical,
            f"Device has not communicated in over {settings.get('device_offline_seconds', 600)}s",
        )
        if action == "created":
            await log_action(user_id=None, action="alert.created", details={"alert_type": "device_offline", "device_id": str(device.id)})
            await events.publish_generic_alert_event(alert, current_station_id, "device.offline")

        # If this device has an ACTIVE recording, this is a high-priority,
        # distinct alert -- never fabricates a location if none exists
        # (see _latest_location, which already returns (None, None, None)
        # when there's no ConstableLocation reading).
        active_recording = await models.RecordingSession.find_one(
            models.RecordingSession.device_id == device.id,
            models.RecordingSession.status == models.RecordingStatus.recording,
        )
        if active_recording:
            lat, lon, loc_ts = await _latest_location(device.constable_id)
            location_note = f" last known location: {lat},{lon} at {loc_ts}" if lat is not None else " no known location on record"
            rec_alert, rec_action = await alerts_service.upsert_open_alert(
                device, models.AlertType.recording_device_offline, models.AlertSeverity.critical,
                f"Device went offline during active recording {active_recording.id}.{location_note}",
            )
            if rec_action == "created":
                await log_action(
                    user_id=None, action="alert.created",
                    details={"alert_type": "recording_device_offline", "device_id": str(device.id), "recording_session_id": str(active_recording.id), "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None},
                )
                await events.publish_generic_alert_event(rec_alert, current_station_id, "recording.device_offline")
        return


async def _device_station_id(device: models.Device):
    if not device.constable_id:
        return None
    constable = await models.Constable.get(device.constable_id)
    return constable.station_id if constable else None


@router.get("/", response_model=list[schemas.DeviceResponse])
async def list_devices(
    current_user: models.User = Depends(get_current_user),
):
    """admin/control_room: all devices. station: only devices whose constable belongs to their station. constable: only their own device(s). citizen: denied."""
    settings = load_settings()
    role = current_user.role

    if role in (models.UserRole.admin, models.UserRole.control_room):
        devices = await models.Device.find_all().sort(-models.Device.created_at).to_list()
    elif role == models.UserRole.station:
        if not current_user.station_id:
            return []
        station_constable_ids = [
            c.id for c in await models.Constable.find(models.Constable.station_id == current_user.station_id).to_list()
        ]
        from beanie.operators import In
        devices = await models.Device.find(In(models.Device.constable_id, station_constable_ids)).sort(-models.Device.created_at).to_list()
    elif role == models.UserRole.constable:
        own_constable = await get_own_constable(current_user)
        if not own_constable:
            return []
        devices = await models.Device.find(models.Device.constable_id == own_constable.id).sort(-models.Device.created_at).to_list()
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view devices")

    for d in devices:
        await _observe_and_alert_device_status(d, settings, await _device_station_id(d))
    return [await _to_device_response(d, settings) for d in devices]


@router.get("/{device_id}", response_model=schemas.DeviceResponse)
async def get_device(
    device_id: uuid.UUID,
    current_user: models.User = Depends(get_current_user),
):
    """Same ownership rules as list_devices, applied to a single device. 404 if genuinely missing; 403 if it exists but the caller isn't authorized for it."""
    settings = load_settings()
    device = await models.Device.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this device")

    await _observe_and_alert_device_status(device, settings, await _device_station_id(device))

    return await _to_device_response(device, settings)
