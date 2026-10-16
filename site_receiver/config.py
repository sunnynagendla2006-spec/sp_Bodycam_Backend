"""Receiver configuration from RECEIVER_* environment variables. Secrets are read from the environment or a file, never from source."""
import dataclasses
import logging
import os
import secrets
import uuid
from typing import Optional

logger = logging.getLogger("receiver.config")


class ConfigError(Exception):
    pass


def _int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        raise ConfigError(f"{name} must be an integer")


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes")


def _secret(env: str, file_env: str) -> Optional[str]:
    value = os.getenv(env, "").strip()
    if value:
        return value.replace("\\n", "\n") if "PEM" in env else value
    path = os.getenv(file_env, "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise ConfigError(f"cannot read {file_env}: {exc.strerror}")
    return None


@dataclasses.dataclass
class Settings:
    site_id: uuid.UUID
    site_code: str
    receiver_name: str
    central_url: Optional[str]
    central_token: Optional[str] = dataclasses.field(repr=False, default=None)
    allow_insecure_central: bool = False
    central_ca_file: Optional[str] = None
    grant_public_key_pem: str = dataclasses.field(repr=False, default="")
    grant_issuer: str = "sp-bodycam-control-room"
    grant_key_id: Optional[str] = None
    storage_root: str = "./receiver-data/media"
    db_path: str = "./receiver-data/receiver.sqlite3"
    max_chunk_bytes: int = 100 * 1024 * 1024
    min_free_bytes: int = 1024 * 1024 * 1024
    upload_concurrency: int = 8
    forward_concurrency: int = 2
    backoff_base: int = 5
    backoff_max: int = 900
    max_hard_errors: int = 10
    access_token_secret: str = dataclasses.field(repr=False, default="")
    access_token_minutes: int = 15
    admin_key: Optional[str] = dataclasses.field(repr=False, default=None)
    retention_after_sync_days: int = 7
    purge_synced_on_low_space: bool = False
    rate_limit_per_minute: int = 600
    heartbeat_seconds: int = 30
    local_livekit_url: Optional[str] = None
    local_livekit_key: Optional[str] = dataclasses.field(repr=False, default=None)
    local_livekit_secret: Optional[str] = dataclasses.field(repr=False, default=None)
    log_level: str = "INFO"
    ephemeral_access_secret: bool = False


def load() -> Settings:
    try:
        site_id = uuid.UUID(os.getenv("RECEIVER_SITE_ID", "").strip())
    except ValueError:
        raise ConfigError("RECEIVER_SITE_ID must be the site's UUID from the control room")
    site_code = os.getenv("RECEIVER_SITE_CODE", "").strip()
    if not site_code:
        raise ConfigError("RECEIVER_SITE_CODE is required")

    central = os.getenv("RECEIVER_CENTRAL_URL", "").strip().rstrip("/") or None
    insecure = _bool("RECEIVER_ALLOW_INSECURE_CENTRAL")
    if central and central.startswith("http://") and not insecure:
        raise ConfigError("RECEIVER_CENTRAL_URL must be https:// (RECEIVER_ALLOW_INSECURE_CENTRAL=true only for a trusted private link or development)")

    pem = _secret("RECEIVER_GRANT_PUBLIC_KEY_PEM", "RECEIVER_GRANT_PUBLIC_KEY_FILE")
    if not pem:
        raise ConfigError("RECEIVER_GRANT_PUBLIC_KEY_PEM or RECEIVER_GRANT_PUBLIC_KEY_FILE is required (the control room's grant PUBLIC key)")

    access_secret = _secret("RECEIVER_ACCESS_TOKEN_SECRET", "RECEIVER_ACCESS_TOKEN_SECRET_FILE")
    ephemeral = False
    if not access_secret:
        # Valid for the life of this process only: phones simply open a new session after a restart.
        access_secret, ephemeral = secrets.token_urlsafe(48), True
        logger.warning("RECEIVER_ACCESS_TOKEN_SECRET is not set: using a random per-process secret (run a single worker)")

    return Settings(
        site_id=site_id, site_code=site_code, receiver_name=os.getenv("RECEIVER_NAME", "site-receiver").strip() or "site-receiver",
        central_url=central, central_token=_secret("RECEIVER_CENTRAL_TOKEN", "RECEIVER_CENTRAL_TOKEN_FILE"), allow_insecure_central=insecure,
        central_ca_file=os.getenv("RECEIVER_CENTRAL_CA_FILE", "").strip() or None, grant_public_key_pem=pem,
        grant_issuer=os.getenv("RECEIVER_GRANT_ISSUER", "sp-bodycam-control-room").strip(), grant_key_id=os.getenv("RECEIVER_GRANT_KEY_ID", "").strip() or None,
        storage_root=os.getenv("RECEIVER_STORAGE_ROOT", "./receiver-data/media").strip(), db_path=os.getenv("RECEIVER_DB_PATH", "./receiver-data/receiver.sqlite3").strip(),
        max_chunk_bytes=_int("RECEIVER_MAX_CHUNK_MB", 100, 1, 2048) * 1024 * 1024, min_free_bytes=_int("RECEIVER_MIN_FREE_MB", 1024, 1, 10_000_000) * 1024 * 1024,
        upload_concurrency=_int("RECEIVER_UPLOAD_CONCURRENCY", 8, 1, 64), forward_concurrency=_int("RECEIVER_FORWARD_CONCURRENCY", 2, 1, 16),
        backoff_base=_int("RECEIVER_BACKOFF_BASE_SECONDS", 5, 1, 300), backoff_max=_int("RECEIVER_BACKOFF_MAX_SECONDS", 900, 10, 86400),
        max_hard_errors=_int("RECEIVER_MAX_HARD_ERRORS", 10, 1, 1000), access_token_secret=access_secret, access_token_minutes=_int("RECEIVER_ACCESS_TOKEN_MINUTES", 15, 1, 120),
        admin_key=_secret("RECEIVER_ADMIN_KEY", "RECEIVER_ADMIN_KEY_FILE"), retention_after_sync_days=_int("RECEIVER_RETENTION_AFTER_SYNC_DAYS", 7, 0, 3650),
        purge_synced_on_low_space=_bool("RECEIVER_PURGE_SYNCED_ON_LOW_SPACE"), rate_limit_per_minute=_int("RECEIVER_RATE_LIMIT_PER_MINUTE", 600, 10, 100000),
        heartbeat_seconds=_int("RECEIVER_HEARTBEAT_SECONDS", 30, 5, 600), local_livekit_url=os.getenv("RECEIVER_LOCAL_LIVEKIT_URL", "").strip() or None,
        local_livekit_key=_secret("RECEIVER_LOCAL_LIVEKIT_API_KEY", "RECEIVER_LOCAL_LIVEKIT_API_KEY_FILE"),
        local_livekit_secret=_secret("RECEIVER_LOCAL_LIVEKIT_API_SECRET", "RECEIVER_LOCAL_LIVEKIT_API_SECRET_FILE"),
        log_level=os.getenv("RECEIVER_LOG_LEVEL", "INFO").strip().upper(), ephemeral_access_secret=ephemeral,
    )
