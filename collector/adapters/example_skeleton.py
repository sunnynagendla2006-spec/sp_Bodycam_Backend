"""
EXAMPLE SKELETON for a real vendor/controller adapter. It does not talk to any
hardware and REFUSES TO RUN: copy it, replace the TODOs with a verified
implementation, register it in adapters/__init__.py and select it with
COLLECTOR_ADAPTER.

Before writing a real adapter you need, from the vendor's own documentation and
from the actual equipment:

  1. WHERE client associations are exposed: per-AP management interface, a central
     controller, a cloud API, SNMP, syslog, streaming telemetry, RADIUS accounting.
     (Many APs expose nothing about clients through their own management IP.)
  2. HOW to authenticate, and a read-only account/token for it (kept in the collector's
     environment or secret file, never in source or in the dashboard).
  3. WHAT you can read: a client list snapshot, association/disassociation/roam events,
     per-AP client counts, AP health, switch port tables.
  4. WHAT identifier a client has (MAC, 802.1X user, ...) and whether it rotates
     (randomized MACs) -- this limits what the numbers mean.
  5. WHETHER events carry a source timestamp and/or a sequence number.

Implementation outline (all TODO):

    class ExampleVendorAdapter(TelemetryAdapter):
        kind = "example_vendor"

        def __init__(self, config):
            super().__init__(config)
            # TODO: read endpoint/credentials from config + environment, build a session with timeouts.

        def capabilities(self):
            # TODO: list ONLY what this source can really provide, e.g.
            # ["client_snapshots", "ap_health", "client_counts"]
            return []

        def poll(self, now):
            # TODO: query the source. Map each result to the normalized dict shapes documented in
            # adapters/base.py, with stable event ids and source timestamps. Raise AdapterError on failure.
            return []
"""
from .base import AdapterNotImplemented, TelemetryAdapter


class ExampleSkeletonAdapter(TelemetryAdapter):
    kind = "example_skeleton"

    def __init__(self, config: dict):
        super().__init__(config)
        raise AdapterNotImplemented(
            "example_skeleton is a documentation template, not a working adapter. "
            "Implement a real adapter for your hardware (see this file) and select it with COLLECTOR_ADAPTER."
        )

    def capabilities(self):  # pragma: no cover - unreachable
        return []

    def poll(self, now):  # pragma: no cover - unreachable
        return []
