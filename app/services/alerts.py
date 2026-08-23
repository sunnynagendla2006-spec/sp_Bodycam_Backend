"""
Phase 3 (body-camera system): generic open-alert upsert/resolve helpers
for the non-battery alert types (device_offline, device_stale,
recording_device_offline, command_failed, command_timeout).

Mirrors the exact two-layer pattern already proven for battery alerts in
Phase 1 (app/routers/devices.py::_process_battery_thresholds): an
application-level fast-path check, backed by a genuine database-level
partial unique index (uq_open_alert_per_device_and_type) as the actual
safety net against a race between two concurrent requests both creating
an alert for the same (device_id, type) at once.
"""
import datetime
from typing import Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def upsert_open_alert(
    db: Session,
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
    existing = (
        db.query(models.Alert)
        .filter(models.Alert.device_id == device.id, models.Alert.type == alert_type, models.Alert.status == models.AlertStatus.open)
        .first()
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
        with db.begin_nested():
            db.add(new_alert)
            db.flush()
        return new_alert, "created"
    except IntegrityError:
        # Lost the race against uq_open_alert_per_device_and_type -- a
        # concurrent request already committed this exact (device, type)
        # alert. The SAVEPOINT rollback (handled by the `with` block
        # above) leaves the outer session/transaction perfectly usable --
        # but it may ALSO have already auto-detached `new_alert` from the
        # session as part of that rollback, in which case calling
        # db.expunge() on it again would itself raise InvalidRequestError.
        # Guard both cases rather than assuming one.
        try:
            db.expunge(new_alert)
        except Exception:
            pass
        winner = (
            db.query(models.Alert)
            .filter(models.Alert.device_id == device.id, models.Alert.type == alert_type, models.Alert.status == models.AlertStatus.open)
            .first()
        )
        return winner, None


def resolve_open_alert(db: Session, device: models.Device, alert_type: models.AlertType) -> Optional[models.Alert]:
    """Returns the resolved Alert if one was open, or None if there was nothing to resolve (also a no-op for audit/publish purposes)."""
    existing = (
        db.query(models.Alert)
        .filter(models.Alert.device_id == device.id, models.Alert.type == alert_type, models.Alert.status == models.AlertStatus.open)
        .first()
    )
    if not existing:
        return None
    existing.status = models.AlertStatus.resolved
    existing.resolved_at = _utcnow()
    existing.resolved_by = None  # system-resolved, not a human acknowledgement
    return existing
