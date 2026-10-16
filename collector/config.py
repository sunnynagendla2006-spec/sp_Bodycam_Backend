"""Collector configuration, read from COLLECTOR_* environment variables (secrets never come from source or from logs)."""
import dataclasses
import json
import os
from typing import Optional


class ConfigError(Exception):
    pass


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer")
    return max(minimum, min(maximum, value))


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes")


@dataclasses.dataclass
class Config:
    backend_url: str
    token: str = dataclasses.field(repr=False)  # never printed
    adapter: str
    adapter_config: dict
    site_code: Optional[str]
    poll_interval: int
    heartbeat_interval: int
    batch_size: int
    buffer_path: str
    max_buffer_items: int
    http_timeout: int
    backoff_base: int
    backoff_max: int
    allow_synthetic: bool
    allow_insecure_http: bool
    ca_file: Optional[str]
    log_level: str


def load() -> Config:
    url = os.getenv("COLLECTOR_BACKEND_URL", "").strip().rstrip("/")
    if not url:
        raise ConfigError("COLLECTOR_BACKEND_URL is required")
    allow_http = _bool("COLLECTOR_ALLOW_INSECURE_HTTP")
    if url.startswith("http://") and not allow_http:
        raise ConfigError("COLLECTOR_BACKEND_URL must be https:// (set COLLECTOR_ALLOW_INSECURE_HTTP=true only for a trusted isolated LAN or development)")
    if not url.startswith(("http://", "https://")):
        raise ConfigError("COLLECTOR_BACKEND_URL must start with https://")

    token = os.getenv("COLLECTOR_TOKEN", "").strip()
    token_file = os.getenv("COLLECTOR_TOKEN_FILE", "").strip()
    if not token and token_file:
        try:
            with open(token_file, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
        except OSError as exc:
            raise ConfigError(f"cannot read COLLECTOR_TOKEN_FILE: {exc.strerror}")
    if not token:
        raise ConfigError("COLLECTOR_TOKEN or COLLECTOR_TOKEN_FILE is required (the credential issued when the collector was created)")

    adapter = os.getenv("COLLECTOR_ADAPTER", "").strip().lower()
    if not adapter:
        raise ConfigError("COLLECTOR_ADAPTER is required (for example 'synthetic' for development only)")

    adapter_config: dict = {}
    cfg_path = os.getenv("COLLECTOR_ADAPTER_CONFIG", "").strip()
    if cfg_path:
        try:
            with open(cfg_path, "r", encoding="utf-8") as fh:
                adapter_config = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot read COLLECTOR_ADAPTER_CONFIG as JSON: {exc}")
        if not isinstance(adapter_config, dict):
            raise ConfigError("COLLECTOR_ADAPTER_CONFIG must contain a JSON object")

    return Config(
        backend_url=url, token=token, adapter=adapter, adapter_config=adapter_config,
        site_code=os.getenv("COLLECTOR_SITE_CODE", "").strip() or None,
        poll_interval=_int("COLLECTOR_POLL_INTERVAL_SECONDS", 5, 1, 3600),
        heartbeat_interval=_int("COLLECTOR_HEARTBEAT_SECONDS", 30, 5, 600),
        batch_size=_int("COLLECTOR_BATCH_SIZE", 100, 1, 200),
        buffer_path=os.getenv("COLLECTOR_BUFFER_PATH", "collector-buffer.sqlite3").strip(),
        max_buffer_items=_int("COLLECTOR_MAX_BUFFER_ITEMS", 200000, 1000, 10_000_000),
        http_timeout=_int("COLLECTOR_HTTP_TIMEOUT_SECONDS", 10, 2, 120),
        backoff_base=_int("COLLECTOR_BACKOFF_BASE_SECONDS", 2, 1, 60),
        backoff_max=_int("COLLECTOR_BACKOFF_MAX_SECONDS", 300, 5, 3600),
        allow_synthetic=_bool("COLLECTOR_ALLOW_SYNTHETIC"),
        allow_insecure_http=allow_http,
        ca_file=os.getenv("COLLECTOR_CA_FILE", "").strip() or None,
        log_level=os.getenv("COLLECTOR_LOG_LEVEL", "INFO").strip().upper(),
    )
