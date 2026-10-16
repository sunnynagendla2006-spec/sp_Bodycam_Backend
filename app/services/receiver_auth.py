"""
Authentication of SITE RECEIVERS to the control room.

A receiver has its OWN credential, independent of any officer login and bound to exactly one site:

    <receiver id (32 hex)>.<random secret>      Authorization: Bearer <token>

Only SHA-256 of the secret is stored; the token is shown once (create/rotate). Rotation keeps the previous token
valid for ROTATION_GRACE; revocation is immediate. The site is always taken from the stored receiver record, never
from a request body.
"""
import dataclasses
import datetime
import hashlib
import hmac
import logging
import secrets
import uuid

from fastapi import Header, HTTPException, status

from .. import models
from ..auth import request_limiter

logger = logging.getLogger("receiver_auth")

ROTATION_GRACE = datetime.timedelta(minutes=10)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def apply_new_token(receiver: models.SiteReceiver, *, keep_previous: bool) -> str:
    secret = secrets.token_urlsafe(32)
    if keep_previous and receiver.token_hash:
        receiver.previous_token_hash = receiver.token_hash
        receiver.previous_valid_until = _utcnow() + ROTATION_GRACE
    else:
        receiver.previous_token_hash = None
        receiver.previous_valid_until = None
    receiver.token_hash = _hash(secret)
    receiver.token_hint = secret[-4:]
    receiver.token_version += 1
    receiver.revoked = False
    return f"{receiver.id.hex}.{secret}"


@dataclasses.dataclass
class ReceiverContext:
    receiver: models.SiteReceiver
    site: models.MonitoredSite


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid receiver credentials", headers={"WWW-Authenticate": "Bearer"})


async def get_current_receiver(authorization: str = Header(default="")) -> ReceiverContext:
    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or "." not in parts[1]:
        raise _unauthorized()
    ident, _, secret = parts[1].partition(".")
    try:
        receiver_id = uuid.UUID(hex=ident)
    except ValueError:
        raise _unauthorized()

    receiver = await models.SiteReceiver.get(receiver_id)
    digest = _hash(secret)
    valid = False
    if receiver is not None:
        valid = bool(receiver.token_hash) and hmac.compare_digest(digest, receiver.token_hash)
        if not valid and receiver.previous_token_hash and receiver.previous_valid_until:
            until = receiver.previous_valid_until
            if until.tzinfo is None:
                until = until.replace(tzinfo=datetime.timezone.utc)
            valid = until > _utcnow() and hmac.compare_digest(digest, receiver.previous_token_hash)
    if not valid or receiver is None or receiver.revoked or not receiver.active:
        if not request_limiter.allow(f"rcvauthfail:{receiver_id.hex}", 20):
            raise HTTPException(status_code=429, detail="Too many failed attempts")
        logger.warning("receiver authentication failed for id %s", receiver_id.hex)
        raise _unauthorized()
    site = await models.MonitoredSite.get(receiver.site_id)
    if site is None or not site.active:
        raise _unauthorized()
    return ReceiverContext(receiver=receiver, site=site)
