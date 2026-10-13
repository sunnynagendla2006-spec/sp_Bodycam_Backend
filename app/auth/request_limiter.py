"""
Per-key sliding-window request limiter (single process, in-memory).

Same honest scope as app/auth/rate_limit.py: counters are per worker process,
so a multi-worker deployment gets (limit x workers). It exists to stop a
runaway or abusive client from flooding the location endpoints, not to be a
distributed quota system.
"""
import collections
import threading
import time
from typing import Deque, Dict

_lock = threading.Lock()
_hits: Dict[str, Deque[float]] = {}


def allow(key: str, limit: int, window_seconds: float = 60.0) -> bool:
    """Record a hit for `key`; return False (without recording) once `limit` hits are already inside the window."""
    now = time.monotonic()
    with _lock:
        q = _hits.setdefault(key, collections.deque())
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


def reset() -> None:
    with _lock:
        _hits.clear()
