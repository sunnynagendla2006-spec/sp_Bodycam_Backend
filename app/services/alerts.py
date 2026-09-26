"""
Generic open-alert upsert/resolve helpers for the non-battery alert types
(device_offline, device_stale, recording_device_offline, command_failed,
command_timeout).

Mirrors the exact two-layer pattern already proven for battery alerts in
app/routers/devices.py::_process_battery_thresholds: an application-level
fast-path check, backed by a genuine database-level partial unique index
(uq_open_alert_per_device_and_type, see models.Alert.Settings.indexes) as
the actual safety net against a race between two concurrent requests both
creating an alert for the same (device_id, type) at once. On Mongo, a
single-document insert against that unique index is already atomic, so
losing the race surfaces as `DuplicateKeyError` -- no SAVEPOINT/nested
transaction is needed the way Postgres required.
"""
import datetime
from typing import Optional, Tuple

from pymongo.errors import DuplicateKeyError

from .. import models


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


async def upsert_open_alert(
    device: models.Device,
    alert_type: models.AlertType,
    severity: models.AlertSeverity,
    message: str,
) -> Tuple[Optional[models.Alert], Optional[str]]:
    """
    Returns (alert, action_label) where action_label is "created" if a new
    alert was genuinely created by THIS call, or None if an open alert of
    this exact type already existed (a deliberate no-op -- callers must
    not audit/publish an event when action_label is None, to avoid
    spamming on every repeated observation of an already-known condition).
    """
    existing = await models.Alert.find_one(
        models.Alert.device_id == device.id,
        models.Alert.type == alert_type,
        models.Alert.status == models.AlertStatus.open,
    )
    if existing:
        return existing, None

    new_alert = models.Alert(
        type=alert_type,
        severity=severity,
        constable_id=device.constable_id,
        device_id=device.id,
        message=message,
        status=models.AlertStatus.open,
    )
    try:
        await new_alert.insert()
        return new_alert, "created"
    except DuplicateKeyError:
        # Lost the race against uq_open_alert_per_device_and_type -- a
        # concurrent request already inserted this exact (device, type)
        # alert first. Re-fetch and return the winner.
        winner = await models.Alert.find_one(
            models.Alert.device_id == device.id,
            models.Alert.type == alert_type,
            models.Alert.status == models.AlertStatus.open,
        )
        return winner, None


async def resolve_open_alert(device: models.Device, alert_type: models.AlertType) -> Optional[models.Alert]:
    """Returns the resolved Alert if one was open, or None if there was nothing to resolve (also a no-op for audit/publish purposes)."""
    existing = await models.Alert.find_one(
        models.Alert.device_id == device.id,
        models.Alert.type == alert_type,
        models.Alert.status == models.AlertStatus.open,
    )
    if not existing:
        return None
    existing.status = models.AlertStatus.resolved
    existing.resolved_at = _utcnow()
    existing.resolved_by = None  # system-resolved, not a human acknowledgement
    await existing.save()
    return existing
