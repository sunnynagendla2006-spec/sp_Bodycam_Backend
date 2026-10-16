"""
Vendor-neutral telemetry adapter interface.

An adapter turns ONE source of network truth (a controller API, a cloud API,
SNMP, syslog, a streaming telemetry feed, ...) into normalized items. It does
nothing else: no buffering, no HTTP to the backend, no retries of the backend
upload. The runner owns those.

`poll()` returns a list of items, each a dict {"kind": ..., "payload": ...}:

  kind "events"    payload = one event, the shape of backend schema CollectorEvent:
       {"event_id", "event_type" (association|disassociation|roam), "source_timestamp" (ISO-8601 WITH offset),
        "client_id" (raw client identifier; the backend pseudonymizes it immediately),
        "ap": {"bssid"|"ap_code"|"management_ip"|"serial_number"}, "from_ap": {...} (roam),
        "radio_bssid", "source_seq", "seq_stream", "session_id"}
  kind "snapshot"  payload = backend schema SnapshotRequest
  kind "health"    payload = one AP health item of backend schema HealthBatchRequest.aps
                   (or {"controller": {...}} for controller health)

CAPABILITIES the adapter really has (and no others!) are declared by capabilities(),
so the dashboard never implies data the hardware cannot supply. Known names:
  inventory, client_snapshots, association_events, disassociation_events,
  roam_events, ap_health, client_counts, controller_health, switch_ports, radio_stats

Requirements for a real adapter:
  * event_id unique per collector and stable across restarts for the same source event
    (so replay after a crash is a duplicate, not a double count);
  * source_timestamp is the time at the SOURCE, not "now", whenever the source provides one;
  * give source_seq + seq_stream when the source numbers its events (the backend then orders by sequence);
  * never log credentials; raise on failure, the runner records it as adapter health.
"""
import abc
import datetime
from typing import Dict, List


class AdapterError(Exception):
    """A recoverable adapter failure (source unreachable, bad response). The runner records it and tries again at the next poll."""


class AdapterNotImplemented(Exception):
    """Raised by skeleton adapters. The runner refuses to start with them."""


class TelemetryAdapter(abc.ABC):
    kind: str = "base"
    simulated: bool = False  # True only for generated data; the backend ALSO forces the SYNTHETIC label from the collector record

    def __init__(self, config: dict):
        self.config = config or {}

    @abc.abstractmethod
    def capabilities(self) -> List[str]:
        """The capabilities this adapter genuinely provides."""

    @abc.abstractmethod
    def poll(self, now: datetime.datetime) -> List[Dict]:
        """Returns new items since the last call (possibly none). May raise AdapterError."""

    def health(self) -> Dict:
        """Small JSON-serializable status for the heartbeat (no secrets, no raw identifiers)."""
        return {"ok": True}

    def close(self) -> None:
        return None
