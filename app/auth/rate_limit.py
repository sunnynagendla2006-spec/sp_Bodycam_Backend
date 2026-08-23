"""
Minimal, in-process login rate limiter.

HONEST SCOPE: this is a single-process, in-memory fixed-window counter. It
protects a single `uvicorn` worker process against rapid brute-force
attempts against one account, but it does NOT share state across multiple
worker processes/containers -- a horizontally-scaled deployment (multiple
backend replicas, or `uvicorn --workers N`) gets independent counters per
process, so the effective limit is (per-process limit) x (worker count).
This is a deliberate, minimal fix for a real gap (no rate limiting existed
at all before this), not a claim of production-grade, distributed
rate limiting -- that would require shared state (e.g. Redis), which is
explicitly out of scope for this phase (no such infrastructure exists in
this project, and introducing it was explicitly excluded from this phase's
scope).

Keyed by the ATTEMPTED account identifier (phone), not by client IP:
this protects a specific account from being brute-forced regardless of
which IP(s) the attempts come from, which is the more effective mitigation
for a login endpoint (IP-based limiting is easily defeated by rotating
source IPs, and can also cause false-positive lockouts for many users
behind a shared corporate NAT/proxy).
"""
import threading
import time
from typing import Dict, Tuple

_MAX_ATTEMPTS = 10          # failed attempts allowed within the window
_WINDOW_SECONDS = 300       # 5 minutes

_lock = threading.Lock()
_attempts: Dict[str, Tuple[int, float]] = {}  # phone -> (count, window_start_ts)


def record_failed_attempt(phone: str) -> None:
    now = time.time()
    with _lock:
        count, window_start = _attempts.get(phone, (0, now))
        if now - window_start > _WINDOW_SECONDS:
            count, window_start = 0, now
        _attempts[phone] = (count + 1, window_start)


def record_successful_login(phone: str) -> None:
    """A successful login clears the counter for that account."""
    with _lock:
        _attempts.pop(phone, None)


def is_rate_limited(phone: str) -> bool:
    now = time.time()
    with _lock:
        count, window_start = _attempts.get(phone, (0, now))
        if now - window_start > _WINDOW_SECONDS:
            return False
        return count >= _MAX_ATTEMPTS
