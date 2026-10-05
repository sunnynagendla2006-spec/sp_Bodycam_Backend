"""
In-memory, single-process tracker for "which devices are currently
mid-simulated-movement" -- mirrors app/auth/rate_limit.py's exact pattern
and honesty about scope: single-process, not shared across replicas, not
durable across a restart. This is deliberate, not a shortcut: "moving" is
transient animation/UI state by design (see
routers/presence.py::moving_ping's docstring -- "do not store every
animation frame"), so persisting it to MongoDB would be storing something
that was explicitly specified NOT to be stored. A horizontally-scaled
deployment would need a shared store (Redis) for this one specific signal
to stay accurate across replicas -- out of scope here, same as
rate_limit.py's own documented limitation.

Entries expire on their own (TTL) rather than requiring an explicit
"stop moving" call -- if a client's animation loop dies, gets backgrounded,
or the device goes offline mid-simulation, the admin's "moving" indicator
clears itself within _TTL_SECONDS instead of being stuck forever.
"""
import threading
import time
from typing import Dict, Optional, Tuple

_TTL_SECONDS = 15

_lock = threading.Lock()
# device_id (str) -> (target_access_point_code, target_zone, progress, expires_at)
_moving: Dict[str, Tuple[str, Optional[str], int, float]] = {}


def record_moving_ping(device_id: str, target_access_point_code: str, target_zone: Optional[str], progress: int) -> None:
    with _lock:
        _moving[device_id] = (target_access_point_code, target_zone, progress, time.time() + _TTL_SECONDS)


def clear_moving(device_id: str) -> None:
    """Called once a real handoff/association lands -- the device has arrived, it's no longer 'moving'."""
    with _lock:
        _moving.pop(device_id, None)


def is_moving(device_id: str) -> bool:
    with _lock:
        entry = _moving.get(device_id)
        if not entry:
            return False
        _target_ap, _target_zone, _progress, expires_at = entry
        if time.time() > expires_at:
            del _moving[device_id]
            return False
        return True


def moving_device_ids() -> set:
    """All device ids (str) currently considered moving, pruning expired entries first."""
    with _lock:
        now = time.time()
        expired = [k for k, v in _moving.items() if v[3] < now]
        for k in expired:
            del _moving[k]
        return set(_moving.keys())


def moving_zone_counts() -> Dict[str, int]:
    """target_zone -> count of devices currently moving toward a zone with that label, pruning expired entries first."""
    with _lock:
        now = time.time()
        expired = [k for k, v in _moving.items() if v[3] < now]
        for k in expired:
            del _moving[k]
        counts: Dict[str, int] = {}
        for _target_ap, target_zone, _progress, _exp in _moving.values():
            if target_zone:
                counts[target_zone] = counts.get(target_zone, 0) + 1
        return counts
