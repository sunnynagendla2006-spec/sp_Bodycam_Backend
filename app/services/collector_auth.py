"""
Collector credentials.

Each collector has its OWN token, bound to exactly one site:

    <collector id (32 hex)>.<random secret>      sent as  Authorization: Bearer <token>

Only SHA-256(secret) is stored. The token is shown once (create/rotate). Rotation
keeps the previous token valid for ROTATION_GRACE so a collector can be updated
without a gap; revocation takes effect immediately and also cancels any grace.
A collector's site is taken from its stored record -- never from a request body.
"""
import dataclasses
import datetime
import hashlib
import hmac
import logging
import secrets
import uuid
from typing import Optional, Tuple

from fastapi import Header, HTTPException, status

from .. import models
from ..auth import request_limiter

logger = logging.getLogger("collector_auth")

ROTATION_GRACE = datetime.timedelta(minutes=10)
_FAILED_PER_MINUTE = 20


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def issue_token(collector_id: uuid.UUID) -> Tuple[str, str, str]:
    """Returns (full token, hash of the secret part, hint). Only the hash and hint are ever stored."""
    secret = secrets.token_urlsafe(32)
    return f"{collector_id.hex}.{secret}", _hash(secret), secret[-4:]


def apply_new_token(collector: models.Collector, *, keep_previous: bool) -> str:
    token, digest, hint = issue_token(collector.id)
    if keep_previous and collector.token_hash:
        collector.previous_token_hash = collector.token_hash
        collector.previous_valid_until = _utcnow() + ROTATION_GRACE
    else:
        collector.previous_token_hash = None
        collector.previous_valid_until = None
    collector.token_hash = digest
    collector.token_hint = hint
    collector.token_version += 1
    collector.revoked = False
    return token


@dataclasses.dataclass
class CollectorContext:
    collector: models.Collector
    site: models.MonitoredSite


def _unauthorized() -> HTTPException:
    # Deliberately identical for every failure cause.
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid collector credentials", headers={"WWW-Authenticate": "Bearer"})


async def get_current_collector(authorization: str = Header(default="")) -> CollectorContext:
    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or "." not in parts[1]:
        raise _unauthorized()
    ident, _, secret = parts[1].partition(".")
    try:
        collector_id = uuid.UUID(hex=ident)
    except ValueError:
        raise _unauthorized()

    if not request_limiter.allow(f"colauthfail-check:{collector_id.hex}", 600):
        raise HTTPException(status_code=429, detail="Too many requests")

    collector = await models.Collector.get(collector_id)
    digest = _hash(secret)
    valid = False
    if collector is not None:
        valid = bool(collector.token_hash) and hmac.compare_digest(digest, collector.token_hash)
        if not valid and collector.previous_token_hash and collector.previous_valid_until:
            until = collector.previous_valid_until
            if until.tzinfo is None:
                until = until.replace(tzinfo=datetime.timezone.utc)
            valid = until > _utcnow() and hmac.compare_digest(digest, collector.previous_token_hash)
    if not valid or collector is None or collector.revoked or not collector.active:
        if not request_limiter.allow(f"colauthfail:{collector_id.hex}", _FAILED_PER_MINUTE):
            raise HTTPException(status_code=429, detail="Too many failed attempts")
        logger.warning("collector authentication failed for id %s", collector_id.hex)
        raise _unauthorized()
    site = await models.MonitoredSite.get(collector.site_id)
    if site is None or not site.active:
        raise _unauthorized()
    return CollectorContext(collector=collector, site=site)
