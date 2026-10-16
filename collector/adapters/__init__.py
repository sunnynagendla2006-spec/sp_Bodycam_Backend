"""
Adapter registry. COLLECTOR_ADAPTER selects one of these kinds.

Only add a vendor adapter here after it has been implemented against that
vendor's documented API and verified on real equipment; the backend's adapter
catalogue (app/services/adapter_catalog.py) should be updated to match.
"""
from typing import Dict, Type

from .base import AdapterError, AdapterNotImplemented, TelemetryAdapter
from .example_skeleton import ExampleSkeletonAdapter
from .synthetic import SyntheticAdapter

REGISTRY: Dict[str, Type[TelemetryAdapter]] = {
    SyntheticAdapter.kind: SyntheticAdapter,
    ExampleSkeletonAdapter.kind: ExampleSkeletonAdapter,
}


def get_adapter(kind: str, config: dict) -> TelemetryAdapter:
    try:
        cls = REGISTRY[kind]
    except KeyError:
        raise AdapterError(f"unknown adapter '{kind}'. Available: {', '.join(sorted(REGISTRY))}")
    return cls(config)


__all__ = ["get_adapter", "REGISTRY", "TelemetryAdapter", "AdapterError", "AdapterNotImplemented"]
