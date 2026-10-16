"""
Static catalogue of telemetry adapter kinds, shown in the admin UI.

It mirrors the adapters registered by the standalone collector package
(backend/collector/adapters). It is informational: the collector, not the
backend, runs adapters. A vendor adapter appears here only after it has really
been written AND verified against that vendor's hardware or documented API.
"""
from .. import schemas_network as sn

ADAPTERS = [
    sn.AdapterInfo(
        kind="synthetic",
        simulated=True,
        description="Generates artificial roaming clients among the site's registered APs for development and demonstrations. "
        "Everything it sends is stored and displayed as SIMULATED and is never mixed up with live telemetry.",
        capabilities=["association_events", "disassociation_events", "client_snapshots", "ap_health"],
        production_ready=False,
    ),
    sn.AdapterInfo(
        kind="example_skeleton",
        simulated=False,
        description="Documentation skeleton showing where a real vendor/controller adapter plugs in. It does not talk to any "
        "hardware and refuses to run until it is replaced with a real implementation.",
        capabilities=[],
        production_ready=False,
    ),
]
