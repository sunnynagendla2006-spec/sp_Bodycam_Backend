"""
Officer tracking freshness policy.

One place decides whether an officer's position is live, delayed, stale or
unavailable, so the REST snapshot, the WebSocket payload and the tests all
agree. Freshness is ALWAYS computed from the fix's own `recorded_at` (device
GNSS clock, validated against server time at ingestion) -- never from when
the server happened to receive it. A fix that was queued offline and uploaded
an hour later is therefore an hour old, not live.

Thresholds are env-configurable; the defaults follow the operational
concept (live under a minute, stale after a few minutes without a fix).
"""
import dataclasses
import datetime
import os
from typing import Optional

from .. import models


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def live_seconds() -> int:
    return _int_env("TRACKING_LIVE_SECONDS", 60)


def delayed_seconds() -> int:
    return _int_env("TRACKING_DELAYED_SECONDS", 300)


def stale_seconds() -> int:
    return _int_env("TRACKING_STALE_SECONDS", 1800)


def buffered_after_seconds() -> int:
    """A fix received this long after it was recorded is labelled `buffered` (it sat in the device queue)."""
    return _int_env("TRACKING_BUFFERED_AFTER_SECONDS", 30)


def thresholds() -> dict:
    return {
        "live_seconds": live_seconds(),
        "delayed_seconds": delayed_seconds(),
        "stale_seconds": stale_seconds(),
        "buffered_after_seconds": buffered_after_seconds(),
    }


@dataclasses.dataclass
class TrackingState:
    state: str  # live | delayed | stale | unavailable
    reason: Optional[str]  # why `unavailable` (off_duty / no_fix_yet / fix_too_old) -- None otherwise
    age_seconds: Optional[float]
    buffered: bool


def _aware(dt: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def compute_tracking_state(
    *,
    on_duty: bool,
    recorded_at: Optional[datetime.datetime],
    server_received_at: Optional[datetime.datetime] = None,
    now: Optional[datetime.datetime] = None,
) -> TrackingState:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    recorded_at = _aware(recorded_at)
    server_received_at = _aware(server_received_at)

    if not on_duty:
        return TrackingState("unavailable", "off_duty", None, False)
    if recorded_at is None:
        return TrackingState("unavailable", "no_fix_yet", None, False)

    age = max((now - recorded_at).total_seconds(), 0.0)
    buffered = bool(
        server_received_at is not None
        and (server_received_at - recorded_at).total_seconds() > buffered_after_seconds()
    )
    if age <= live_seconds():
        return TrackingState("live", None, age, buffered)
    if age <= delayed_seconds():
        return TrackingState("delayed", None, age, buffered)
    if age <= stale_seconds():
        return TrackingState("stale", None, age, buffered)
    return TrackingState("unavailable", "fix_too_old", age, buffered)


def is_trackable_device(device: Optional[models.Device]) -> bool:
    return device is not None and device.enrolment_status == models.EnrolmentStatus.approved
