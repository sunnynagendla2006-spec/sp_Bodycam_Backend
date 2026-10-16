"""
Signed, site-scoped OFFLINE GRANTS for Bodycam phones.

A grant is a JWS (JWT, ES256 = ECDSA P-256 + SHA-256, an established format
implemented by python-jose/cryptography; nothing custom). It lets a phone
authenticate to its site's local receiver while the control room is unreachable.

  * Signing happens ONLY here, in the control-room backend, with a private key from
    the environment (GRANT_SIGNING_PRIVATE_KEY_PEM or ..._FILE). The phone and the
    receiver never hold it. The receiver holds only the PUBLIC key.
  * Claims: iss, sub (officer/constable id), jti (grant id), site, site_code, org,
    dev (central device id), devid (device identifier), asg (assignment id), zone,
    ops (permitted operations), iat, exp, ver. Header `kid` identifies the key.
  * Lifetime: GRANT_LIFETIME_HOURS (default 8, clamped 1..168).
  * Renewal needs the central server (a phone renews while online). Revocation is
    recorded in OfflineGrant and PROPAGATED to receivers on their next sync.

UNAVOIDABLE LIMITATION: a receiver that is disconnected from the control room cannot
learn about a revocation made meanwhile. A revoked grant stays usable at that receiver
until it expires or the receiver next syncs. Choose GRANT_LIFETIME_HOURS accordingly
(shorter = faster effective revocation, more renewals). Evidence uploaded under a
grant revoked LATER is accepted centrally and flagged `grant_revoked_later`.
"""
import datetime
import os
import uuid
from typing import List, Optional, Tuple

from jose import jwt

from .. import models

ALGORITHM = "ES256"
DEFAULT_OPERATIONS = ["session", "upload", "live"]


class GrantError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 403):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def lifetime_hours() -> int:
    try:
        return max(1, min(168, int(os.getenv("GRANT_LIFETIME_HOURS", "8").strip())))
    except ValueError:
        return 8


def issuer() -> str:
    return os.getenv("GRANT_ISSUER", "sp-bodycam-control-room").strip() or "sp-bodycam-control-room"


def key_id() -> Optional[str]:
    return os.getenv("GRANT_SIGNING_KEY_ID", "").strip() or None


def _private_pem() -> Optional[str]:
    pem = os.getenv("GRANT_SIGNING_PRIVATE_KEY_PEM", "").strip()
    if pem:
        return pem.replace("\\n", "\n")
    path = os.getenv("GRANT_SIGNING_PRIVATE_KEY_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return None
    return None


def signing_configured() -> bool:
    return _private_pem() is not None


async def check_eligibility(
    site: models.MonitoredSite, constable: models.Constable, device: models.Device
) -> Tuple[models.SiteAssignment, models.DeviceSiteAuthorization]:
    """Everything that must be true before a grant may be issued. Raises GrantError with a stable code."""
    now = _utcnow()
    if not site.active:
        raise GrantError("site_inactive", "The site is not active")
    if device.constable_id != constable.id:
        raise GrantError("device_not_owned", "The device is not registered to this officer")
    if device.enrolment_status != models.EnrolmentStatus.approved:
        raise GrantError("device_not_approved", "The device enrolment is not approved")
    assignment = await models.SiteAssignment.find_one({"site_id": site.id, "constable_id": constable.id, "status": "active"})
    if assignment is None:
        raise GrantError("not_assigned", "The officer is not assigned to this site")
    if assignment.valid_from and _aware(assignment.valid_from) > now:
        raise GrantError("assignment_not_started", "The site assignment has not started yet")
    if assignment.valid_until and _aware(assignment.valid_until) < now:
        raise GrantError("assignment_expired", "The site assignment has expired")
    auth = await models.DeviceSiteAuthorization.find_one({"site_id": site.id, "device_id": device.id, "status": "authorized"})
    if auth is None or auth.constable_id != constable.id:
        raise GrantError("device_not_authorized", "The device is not authorized for this site")
    if auth.valid_until and _aware(auth.valid_until) < now:
        raise GrantError("device_authorization_expired", "The device's site authorization has expired")
    return assignment, auth


def _aware(dt: datetime.datetime) -> datetime.datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


async def issue(
    site: models.MonitoredSite, constable: models.Constable, device: models.Device, *, issued_by: Optional[uuid.UUID],
    operations: Optional[List[str]] = None,
) -> Tuple[str, models.OfflineGrant]:
    """Signs a grant and records it. Raises GrantError (not eligible) or GrantError(signing_not_configured, 503)."""
    pem = _private_pem()
    if pem is None:
        raise GrantError("signing_not_configured", "Offline grant signing is not configured on the server (GRANT_SIGNING_PRIVATE_KEY_PEM)", 503)
    assignment, auth = await check_eligibility(site, constable, device)
    now = _utcnow()
    expires = now + datetime.timedelta(hours=lifetime_hours())
    # A grant never outlives the assignment or device authorization it rests on.
    for limit in (assignment.valid_until, auth.valid_until):
        if limit and _aware(limit) < expires:
            expires = _aware(limit)
    ops = operations or DEFAULT_OPERATIONS
    grant = models.OfflineGrant(
        site_id=site.id, constable_id=constable.id, device_id=device.id, assignment_id=assignment.id, key_id=key_id(),
        operations=ops, issued_at=now, expires_at=expires, issued_by=issued_by,
    )
    await grant.insert()
    return _sign(grant, site, constable, device, assignment, pem), grant


def _sign(grant: models.OfflineGrant, site, constable, device, assignment, pem: str) -> str:
    claims = {
        "iss": issuer(), "sub": str(constable.id), "jti": str(grant.id), "site": str(site.id), "site_code": site.code,
        "org": site.organization, "dev": str(device.id), "devid": device.device_identifier, "asg": str(assignment.id),
        "zone": str(assignment.zone_id) if assignment.zone_id else None, "ops": list(grant.operations),
        "iat": int(_aware(grant.issued_at).timestamp()), "exp": int(_aware(grant.expires_at).timestamp()), "ver": 1,
    }
    headers = {"kid": grant.key_id} if grant.key_id else None
    return jwt.encode(claims, pem, algorithm=ALGORITHM, headers=headers)


async def issue_or_reuse(
    site: models.MonitoredSite, constable: models.Constable, device: models.Device, *, issued_by: Optional[uuid.UUID],
) -> Tuple[str, models.OfflineGrant, bool]:
    """Phone provisioning refreshes must not create a new grant record every time. While the officer and device are still
    eligible, a valid grant with more than half its lifetime left is RE-SIGNED with identical claims (same grant id, same
    issue and expiry times); otherwise a new one is issued. The token itself is never stored, only the grant record.
    Returns (token, grant, reused)."""
    pem = _private_pem()
    if pem is None:
        raise GrantError("signing_not_configured", "Offline grant signing is not configured on the server (GRANT_SIGNING_PRIVATE_KEY_PEM)", 503)
    assignment, _auth = await check_eligibility(site, constable, device)
    now = _utcnow()
    margin = datetime.timedelta(hours=lifetime_hours() / 2)
    existing = await models.OfflineGrant.find(
        {"site_id": site.id, "constable_id": constable.id, "device_id": device.id, "revoked": False, "expires_at": {"$gt": now + margin}, "assignment_id": assignment.id},
    ).sort("-expires_at").first_or_none()
    if existing is not None and existing.key_id == key_id():
        return _sign(existing, site, constable, device, assignment, pem), existing, True
    token, grant = await issue(site, constable, device, issued_by=issued_by)
    return token, grant, False


def public_keys() -> List[dict]:
    """The PUBLIC half of the signing key, for phones and receivers to verify grants. Empty if signing is not configured."""
    pem = _private_pem()
    if pem is None:
        return []
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(pem.encode(), password=None)
        pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return [{"kid": key_id(), "pem": pub}]
    except Exception:
        return []


def record_retention_days() -> int:
    try:
        return max(7, int(os.getenv("GRANT_RECORD_RETENTION_DAYS", "90").strip()))
    except ValueError:
        return 90


async def purge_expired_records(dry_run: bool = True) -> int:
    """Deletes grant RECORDS that expired more than GRANT_RECORD_RETENTION_DAYS ago (audit entries are separate and kept).
    Valid grants and recently expired ones are never touched. Returns how many matched. Not scheduled anywhere."""
    cutoff = _utcnow() - datetime.timedelta(days=record_retention_days())
    coll = models.OfflineGrant.get_motor_collection()
    query = {"expires_at": {"$lt": cutoff}}
    n = await coll.count_documents(query)
    if not dry_run and n:
        await coll.delete_many(query)
    return n


async def revoke(grant: models.OfflineGrant, reason: Optional[str]) -> models.OfflineGrant:
    grant.revoked = True
    grant.revoked_at = _utcnow()
    grant.revoked_reason = (reason or "")[:200] or None
    await grant.save()
    return grant


async def revoke_for_device(site_id: uuid.UUID, device_id: uuid.UUID, reason: str) -> int:
    """Revokes every still-valid grant of a device at a site (used when its authorization is revoked)."""
    now = _utcnow()
    res = await models.OfflineGrant.get_motor_collection().update_many(
        {"site_id": site_id, "device_id": device_id, "revoked": False, "expires_at": {"$gt": now}},
        {"$set": {"revoked": True, "revoked_at": now, "revoked_reason": reason[:200]}},
    )
    return res.modified_count


async def revoke_for_constable(site_id: uuid.UUID, constable_id: uuid.UUID, reason: str) -> int:
    now = _utcnow()
    res = await models.OfflineGrant.get_motor_collection().update_many(
        {"site_id": site_id, "constable_id": constable_id, "revoked": False, "expires_at": {"$gt": now}},
        {"$set": {"revoked": True, "revoked_at": now, "revoked_reason": reason[:200]}},
    )
    return res.modified_count
