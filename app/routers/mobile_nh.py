"""
Phone-facing provisioning for Network Hopping mode (prefix /mobile/v1).

  GET /mobile/v1/network-hopping/config?device_identifier=...

Requires the officer's normal central login (so it only works while the phone can reach the control room): this is where
the phone is PROVISIONED and where it RENEWS its offline grant. For every site the officer is actively assigned to it
returns the site's receivers (the LAN URL the phone must use) and, when the officer and device are eligible, a freshly
signed offline grant. Sites the officer is not assigned to are never listed; a site that is inactive or a device that is
not authorized is listed with `eligible=false` and a stable `reason` so the app can explain it.

The phone keeps the grant in platform secure storage and presents it to the site receiver, which verifies the signature
locally (no control-room round trip). See services/site_grants.py for lifetime, revocation and its limitation.
"""
import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import models, schemas_bodycam as sb
from ..auth.deps import require_role
from ..services import site_grants
from ..services.audit import log_action
from .constables import get_own_constable

router = APIRouter(prefix="/mobile/v1", tags=["Mobile"])


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@router.get("/network-hopping/config", response_model=sb.PhoneNetworkHoppingConfig)
async def network_hopping_config(
    device_identifier: str = Query(..., min_length=1, max_length=255),
    current_user: models.User = Depends(require_role("constable")),
):
    constable = await get_own_constable(current_user)
    if constable is None:
        raise HTTPException(status_code=404, detail="Constable profile not found")
    device = await models.Device.find_one({"device_identifier": device_identifier})
    if device is None or device.constable_id != constable.id:
        raise HTTPException(status_code=404, detail="Device is not registered to this officer")

    now = _utcnow()
    assignments = await models.SiteAssignment.find({"constable_id": constable.id, "status": "active"}).to_list()
    sites_out = []
    for a in assignments:
        site = await models.MonitoredSite.get(a.site_id)
        if site is None:
            continue
        receivers = await models.SiteReceiver.find({"site_id": site.id, "active": True, "revoked": False}).sort("code").to_list()
        entry = sb.PhoneSiteConfig(
            site_id=site.id, site_code=site.code, site_name=site.name, organization=site.organization, assignment_id=a.id, zone_id=a.zone_id,
            eligible=False,
            # A receiver with no address is listed (so the app can say so) but marked unusable; it never hides the others.
            receivers=[sb.PhoneReceiverOut(id=r.id, code=r.code, name=r.name, endpoint_url=r.endpoint_url or None, local_live_enabled=r.local_live_enabled, configured=bool(r.endpoint_url)) for r in receivers],
        )
        try:
            token, grant, reused = await site_grants.issue_or_reuse(site, constable, device, issued_by=None)
            entry.eligible, entry.grant, entry.grant_id, entry.grant_expires_at = True, token, grant.id, site_grants._aware(grant.expires_at)  # always timezone-aware: the phone parses this string
            if not reused:  # a refresh that only re-signs an existing grant creates no record and no new audit entry
                await log_action(user_id=current_user.id, action="bodycam.grant_issued", details={"site_id": str(site.id), "grant_id": str(grant.id), "device_id": str(device.id), "self_service": True})
        except site_grants.GrantError as exc:
            entry.reason = exc.code
        sites_out.append(entry)
    return sb.PhoneNetworkHoppingConfig(
        server_time=now, device_id=device.id, grant_lifetime_hours=site_grants.lifetime_hours(), constable_id=constable.id,
        grant_issuer=site_grants.issuer(), grant_public_keys=[sb.PhoneGrantKey(**k) for k in site_grants.public_keys()], sites=sites_out)
