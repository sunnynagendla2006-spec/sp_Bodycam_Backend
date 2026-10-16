"""
SYNTHETIC telemetry source: SIMULATED DATA FOR DEVELOPMENT ONLY.

It invents clients that associate, roam among the site's registered APs and
disassociate, so the pipeline, ordering rules and dashboards can be exercised
without hardware. It is never real telemetry:

  * it only runs when COLLECTOR_ALLOW_SYNTHETIC=true;
  * the backend forces every item from a collector created with the "synthetic"
    adapter to be stored with source SYNTHETIC, whatever the payload says, and the
    dashboard labels the data SIMULATED;
  * generated client identifiers are locally-administered MACs (02:00:...) that
    cannot belong to a real vendor.

Config (JSON file via COLLECTOR_ADAPTER_CONFIG):
  aps               REQUIRED list of AP references already registered at the site, e.g.
                    [{"bssid": "02:aa:00:00:00:01"}, {"ap_code": "AP-02"}]
  clients           number of simulated clients (default 20)
  seed              integer for reproducible runs (default: random)
  roam_probability  chance per client per poll of roaming (default 0.10)
  leave_probability chance per associated client per poll of disassociating (default 0.02)
  join_probability  chance per idle client per poll of associating (default 0.30)
  inject_disorder   true = also emit duplicate events and events delivered out of order, to exercise the backend (default false)
  snapshot_every    emit a COMPLETE site snapshot every N polls, 0 = never (default 0)
"""
import datetime
import os
import random
import uuid
from typing import Dict, List, Optional

from .base import AdapterError, TelemetryAdapter


class SyntheticAdapter(TelemetryAdapter):
    kind = "synthetic"
    simulated = True

    def __init__(self, config: dict):
        super().__init__(config)
        if os.getenv("COLLECTOR_ALLOW_SYNTHETIC", "").strip().lower() not in ("1", "true", "yes"):
            raise AdapterError("the synthetic adapter produces SIMULATED data and only runs when COLLECTOR_ALLOW_SYNTHETIC=true")
        self.aps: List[Dict] = list(self.config.get("aps") or [])
        if not self.aps:
            raise AdapterError("synthetic adapter config needs a non-empty 'aps' list of AP references registered at the site")
        self.rng = random.Random(self.config.get("seed"))
        n = int(self.config.get("clients", 20))
        self.clients = [f"02:00:00:00:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}" for i in range(1, n + 1)]
        self.state: Dict[str, Optional[int]] = {c: None for c in self.clients}  # client -> AP index or None
        self.roam_p = float(self.config.get("roam_probability", 0.10))
        self.leave_p = float(self.config.get("leave_probability", 0.02))
        self.join_p = float(self.config.get("join_probability", 0.30))
        self.disorder = bool(self.config.get("inject_disorder", False))
        self.snapshot_every = int(self.config.get("snapshot_every", 0))
        self.run_id = uuid.uuid4().hex[:8]
        self.seq = 0
        self.polls = 0
        self._held: List[Dict] = []  # events deliberately delivered one poll late (inject_disorder)

    def capabilities(self) -> List[str]:
        caps = ["association_events", "disassociation_events", "roam_events", "ap_health"]
        if self.snapshot_every:
            caps.append("client_snapshots")
        return caps

    def _event(self, etype: str, client: str, ap_idx: int, now: datetime.datetime, from_idx: Optional[int] = None) -> Dict:
        self.seq += 1
        payload = {
            "event_id": f"syn-{self.run_id}-{self.seq}", "event_type": etype, "source_timestamp": now.isoformat(), "client_id": client,
            "ap": dict(self.aps[ap_idx]), "source_seq": self.seq, "seq_stream": f"synthetic-{self.run_id}", "source": "REAL",  # the backend overrides to SYNTHETIC
        }
        if from_idx is not None:
            payload["from_ap"] = dict(self.aps[from_idx])
        return {"kind": "events", "payload": payload}

    def poll(self, now: datetime.datetime) -> List[Dict]:
        self.polls += 1
        items: List[Dict] = list(self._held)
        self._held = []
        step = datetime.timedelta(milliseconds=1)
        t = now
        for client in self.clients:
            cur = self.state[client]
            if cur is None:
                if self.rng.random() < self.join_p:
                    idx = self.rng.randrange(len(self.aps))
                    self.state[client] = idx
                    items.append(self._event("association", client, idx, t))
                    t += step
            elif self.rng.random() < self.leave_p:
                self.state[client] = None
                items.append(self._event("disassociation", client, cur, t))
                t += step
            elif len(self.aps) > 1 and self.rng.random() < self.roam_p:
                idx = self.rng.choice([i for i in range(len(self.aps)) if i != cur])
                self.state[client] = idx
                items.append(self._event("roam", client, idx, t, from_idx=cur))
                t += step

        if self.disorder and items:
            # a duplicate of an event, and one event delayed to the next poll (older timestamp arrives later)
            dup = items[self.rng.randrange(len(items))]
            items.append({"kind": dup["kind"], "payload": dict(dup["payload"])})
            if len(items) > 2:
                self._held.append(items.pop(self.rng.randrange(len(items) - 1)))

        for ap in self.aps:
            items.append({"kind": "health", "payload": {"ap": dict(ap), "state": "online", "observed_at": now.isoformat()}})

        if self.snapshot_every and self.polls % self.snapshot_every == 0:
            items.append({"kind": "snapshot", "payload": {
                "snapshot_id": f"syn-{self.run_id}-snap-{self.polls}", "source_timestamp": now.isoformat(), "complete": True, "scope": "site",
                "clients": [{"client_id": c, "ap": dict(self.aps[i])} for c, i in self.state.items() if i is not None],
            }})
        return items

    def health(self) -> Dict:
        return {"ok": True, "simulated": True, "clients": len(self.clients), "associated": sum(1 for v in self.state.values() if v is not None)}
