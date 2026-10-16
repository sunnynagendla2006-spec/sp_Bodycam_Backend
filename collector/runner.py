"""
Collector main loop: poll adapter -> buffer -> upload, plus heartbeat.

Delivery semantics: AT-LEAST-ONCE. Items are persisted before upload and deleted only
after the backend answered successfully; the backend de-duplicates by event_id /
snapshot_id, so replays are harmless.

Failure handling:
  * network/5xx/429  -> keep everything, exponential back-off with jitter (capped);
  * 401/403          -> stop uploading (keep buffering, log loudly) until an operator fixes the credential;
  * 4xx on a payload -> split the batch to find the offender, quarantine only that item;
  * adapter error    -> recorded in adapter health, retried at the next poll; the loop never exits because of it.
"""
import datetime
import json
import logging
import random
import signal
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

from . import __version__
from .adapters import AdapterError, AdapterNotImplemented, get_adapter
from .buffer import Buffer
from .client import AuthError, BackendClient, PermanentError, TransientError
from .config import Config, ConfigError, load

log = logging.getLogger("collector")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(), "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        for key in ("event", "count", "detail", "retry_in"):
            if hasattr(record, key):
                data[key] = getattr(record, key)
        return json.dumps(data)


def _setup_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=getattr(logging, level, logging.INFO), handlers=[handler], force=True)


class Runner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.client = BackendClient(cfg)
        self.buffer = Buffer(cfg.buffer_path, cfg.max_buffer_items)
        self.adapter = get_adapter(cfg.adapter, cfg.adapter_config)
        self.stop = threading.Event()
        self._fail_count = 0
        self._next_upload_at = 0.0
        self._auth_failed = False
        self._adapter_error: Optional[str] = None
        self._last_poll = 0.0
        self._last_heartbeat = 0.0

    # -- adapter -------------------------------------------------------------
    def poll_adapter(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            items = self.adapter.poll(now)
            self._adapter_error = None
        except AdapterError as exc:
            self._adapter_error = str(exc)[:200]
            log.warning("adapter poll failed", extra={"event": "adapter_error", "detail": self._adapter_error})
            return
        except Exception as exc:  # a bug in an adapter must not stop buffering/uploading
            self._adapter_error = f"unexpected {type(exc).__name__}"
            log.exception("adapter crashed during poll")
            return
        for item in items:
            self.buffer.enqueue(item["kind"], item["payload"])
        if items:
            log.info("polled adapter", extra={"event": "polled", "count": len(items)})

    # -- upload --------------------------------------------------------------
    def _send(self, kind: str, payloads: List[dict]) -> None:
        site = {"site_code": self.cfg.site_code} if self.cfg.site_code else {}
        if kind == "events":
            self.client.post("/collector/ingest/events", {**site, "events": payloads})
        elif kind == "snapshot":
            self.client.post("/collector/ingest/snapshot", {**site, **payloads[0]})
        elif kind == "health":
            aps = [p for p in payloads if "ap" in p]
            controllers = [p["controller"] for p in payloads if "controller" in p]
            self.client.post("/collector/ingest/health", {**site, "aps": aps, "controllers": controllers})
        else:
            raise PermanentError(f"unknown item kind {kind}")

    def flush(self) -> None:
        if self._auth_failed or time.monotonic() < self._next_upload_at:
            return
        while not self.stop.is_set():
            limit = 1 if self._peek_kind() == "snapshot" else self.cfg.batch_size
            kind, batch = self.buffer.next_batch(limit)
            if not batch:
                self._fail_count = 0
                return
            try:
                self._send(kind, [p for _, p in batch])
                self.buffer.delete([i for i, _ in batch])
                self._fail_count = 0
            except AuthError as exc:
                self._auth_failed = True
                log.error("credential rejected; uploads paused (data keeps buffering)", extra={"event": "auth_failed", "detail": str(exc)})
                return
            except TransientError as exc:
                self._fail_count += 1
                delay = exc.retry_after or min(self.cfg.backoff_max, self.cfg.backoff_base * (2 ** min(self._fail_count, 10)))
                delay = delay * (0.8 + 0.4 * random.random())
                self._next_upload_at = time.monotonic() + delay
                log.warning("upload failed, backing off", extra={"event": "upload_failed", "detail": str(exc), "retry_in": round(delay, 1)})
                return
            except PermanentError as exc:
                self._isolate(kind, batch, str(exc))

    def _peek_kind(self) -> str:
        kind, _ = self.buffer.next_batch(1)
        return kind

    def _isolate(self, kind: str, batch: List[Tuple[int, dict]], reason: str) -> None:
        """The backend refused this batch for good: find the offending item(s) without losing the good ones."""
        if len(batch) == 1:
            item_id, payload = batch[0]
            self.buffer.quarantine([(item_id, kind, payload)], reason)
            log.error("item quarantined", extra={"event": "quarantined", "detail": reason})
            return
        for item_id, payload in batch:
            try:
                self._send(kind, [payload])
                self.buffer.delete([item_id])
            except PermanentError as exc:
                self.buffer.quarantine([(item_id, kind, payload)], str(exc))
                log.error("item quarantined", extra={"event": "quarantined", "detail": str(exc)})
            except (TransientError, AuthError):
                return  # handled by the next flush

    # -- heartbeat -----------------------------------------------------------
    def heartbeat(self) -> None:
        if self._auth_failed:
            return
        health = dict(self.adapter.health())
        if self._adapter_error:
            health.update(ok=False, last_error=self._adapter_error)
        body = {
            "version": __version__, "adapter": self.cfg.adapter, "capabilities": self.adapter.capabilities(), "adapter_health": health,
            "buffer_depth": self.buffer.depth(), "dropped_events": self.buffer.dropped(),
        }
        if self.cfg.site_code:
            body["site_code"] = self.cfg.site_code
        try:
            self.client.post("/collector/heartbeat", body)
        except AuthError as exc:
            self._auth_failed = True
            log.error("credential rejected; uploads paused", extra={"event": "auth_failed", "detail": str(exc)})
        except (TransientError, PermanentError) as exc:
            log.warning("heartbeat failed", extra={"event": "heartbeat_failed", "detail": str(exc)})

    # -- main loop -----------------------------------------------------------
    def run(self) -> None:
        log.info("collector started", extra={"event": "started", "detail": f"adapter={self.cfg.adapter} simulated={self.adapter.simulated}"})
        if self.adapter.simulated:
            log.warning("SIMULATED telemetry source: data is artificial and is labelled SIMULATED by the backend", extra={"event": "simulated"})
        while not self.stop.is_set():
            now = time.monotonic()
            if now - self._last_poll >= self.cfg.poll_interval:
                self._last_poll = now
                self.poll_adapter()
            if now - self._last_heartbeat >= self.cfg.heartbeat_interval:
                self._last_heartbeat = now
                self.heartbeat()
            self.flush()
            self.stop.wait(1.0)
        self.adapter.close()
        self.buffer.close()
        log.info("collector stopped", extra={"event": "stopped"})


def main() -> int:
    try:
        cfg = load()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    _setup_logging(cfg.log_level)
    try:
        runner = Runner(cfg)
    except (AdapterError, AdapterNotImplemented) as exc:
        log.error("cannot start adapter", extra={"event": "adapter_start_failed", "detail": str(exc)})
        return 3

    def _stop(_sig, _frame):
        runner.stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    runner.run()
    return 0
