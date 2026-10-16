"""
Control-room management of Bodycam video transport at a monitored site (prefix /sites/{site_id}/bodycam).

  admin           assignments, device authorizations, grants, receivers (create/rotate/revoke/commands)
  control_room    read-only overview, recordings, grants (restricted sites only for listed users)

Every route resolves the site through routers.sites.get_site_or_404, so site visibility rules (restricted sites)
apply uniformly, and every object looked up by id is checked to belong to THAT site (an id from another site
answers 404). Secrets (receiver tokens, grant JWTs) are returned once on creation and never stored in plain form.
"""
import datetime
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pymongo.errors import DuplicateKeyError

from .. import models, schemas_bodycam as sb
from ..services import chunk_manifest as chunk_manifest_service
from ..services import receiver_auth, site_counts, site_grants
from ..services.audit import log_action
from .sites import get_site_or_404, require_site_admin, require_site_viewer

router = APIRouter(prefix="/sites/{site_id}/bodycam", tags=["Site Bodycam"])


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt: datetime.datetime) -> datetime.datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


async def _constable_labels(ids) -> dict:
    labels = {}
    for c in await models.Constable.find({"_id": {"$in": list(set(ids))}}).to_list():
        labels[c.id] = c.badge_number or str(c.id)[:8]
    return labels


# ===========================================================================
# Assignments
# ===========================================================================

def _assignment_out(a: models.SiteAssignment, labels: dict) -> sb.AssignmentOut:
    return sb.AssignmentOut(
        id=a.id, site_id=a.site_id, constable_id=a.constable_id, constable_label=labels.get(a.constable_id), zone_id=a.zone_id,
        building_id=a.building_id, floor_id=a.floor_id, status=a.status, valid_from=a.valid_from, valid_until=a.valid_until,
        notes=a.notes, created_at=a.created_at, revoked_at=a.revoked_at, revoked_reason=a.revoked_reason,
    )


@router.post("/assignments", response_model=sb.AssignmentOut, status_code=201)
async def create_assignment(site_id: uuid.UUID, body: sb.AssignmentIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    constable = await models.Constable.get(body.constable_id)
    if constable is None:
        raise HTTPException(status_code=422, detail="Unknown constable")
    for model, value, name in ((models.SiteZone, body.zone_id, "zone_id"), (models.SiteBuilding, body.building_id, "building_id"), (models.SiteFloor, body.floor_id, "floor_id")):
        if value is not None:
            doc = await model.get(value)
            if not doc or doc.site_id != site.id:
                raise HTTPException(status_code=422, detail=f"{name} does not belong to this site")
    a = models.SiteAssignment(
        site_id=site.id, constable_id=constable.id, zone_id=body.zone_id, building_id=body.building_id, floor_id=body.floor_id,
        valid_from=body.valid_from or _utcnow(), valid_until=body.valid_until, notes=body.notes, created_by=current_user.id,
    )
    try:
        await a.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="This officer already has an active assignment at the site; revoke it first")
    await log_action(user_id=current_user.id, action="bodycam.assignment_created", details={"site_id": str(site.id), "constable_id": str(constable.id), "assignment_id": str(a.id)})
    return _assignment_out(a, await _constable_labels([constable.id]))


@router.get("/assignments", response_model=List[sb.AssignmentOut])
async def list_assignments(site_id: uuid.UUID, status_: Optional[str] = Query(default=None, alias="status", pattern="^(active|revoked)$"), current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    query = {"site_id": site.id, **({"status": status_} if status_ else {})}
    rows = await models.SiteAssignment.find(query).sort("-created_at").limit(500).to_list()
    labels = await _constable_labels([r.constable_id for r in rows])
    return [_assignment_out(r, labels) for r in rows]


@router.post("/assignments/{assignment_id}/revoke", response_model=sb.AssignmentOut)
async def revoke_assignment(site_id: uuid.UUID, assignment_id: uuid.UUID, body: sb.ReasonIn, current_user: models.User = Depends(require_site_admin)):
    """Revokes the assignment AND every still-valid offline grant of that officer at the site (receivers learn of it on their next sync)."""
    site = await get_site_or_404(site_id, current_user)
    a = await models.SiteAssignment.get(assignment_id)
    if not a or a.site_id != site.id:
        raise HTTPException(status_code=404, detail="Assignment not found")
    a.status, a.revoked_at, a.revoked_reason = "revoked", _utcnow(), body.reason
    await a.save()
    n = await site_grants.revoke_for_constable(site.id, a.constable_id, body.reason or "assignment revoked")
    await log_action(user_id=current_user.id, action="bodycam.assignment_revoked", details={"site_id": str(site.id), "assignment_id": str(a.id), "grants_revoked": n})
    return _assignment_out(a, await _constable_labels([a.constable_id]))


# ===========================================================================
# Device authorizations
# ===========================================================================

async def _device_out(a: models.DeviceSiteAuthorization, labels: dict, devices: dict, seen: dict) -> sb.DeviceAuthorizationOut:
    dev = devices.get(a.device_id)
    return sb.DeviceAuthorizationOut(
        id=a.id, site_id=a.site_id, device_id=a.device_id, device_identifier=dev.device_identifier if dev else None, constable_id=a.constable_id,
        constable_label=labels.get(a.constable_id), status=a.status, authorized_at=a.authorized_at, valid_until=a.valid_until,
        revoked_at=a.revoked_at, revoked_reason=a.revoked_reason, last_seen_by_receiver_at=seen.get(dev.device_identifier) if dev else None,
    )


async def _seen_map(site_id: uuid.UUID) -> dict:
    seen: dict = {}
    for r in await models.SiteReceiver.find({"site_id": site_id}).to_list():
        for k, v in (r.recent_devices or {}).items():
            if v > seen.get(k, ""):
                seen[k] = v
    return seen


@router.post("/device-authorizations", response_model=sb.DeviceAuthorizationOut, status_code=201)
async def authorize_device(site_id: uuid.UUID, body: sb.DeviceAuthorizationIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    device = await models.Device.get(body.device_id)
    if device is None or device.constable_id is None:
        raise HTTPException(status_code=422, detail="Unknown device, or it is not registered to an officer")
    if device.enrolment_status != models.EnrolmentStatus.approved:
        raise HTTPException(status_code=422, detail="The device enrolment must be approved first")
    assignment = await models.SiteAssignment.find_one({"site_id": site.id, "constable_id": device.constable_id, "status": "active"})
    if assignment is None:
        raise HTTPException(status_code=409, detail="The device's officer has no active assignment at this site")
    a = models.DeviceSiteAuthorization(site_id=site.id, device_id=device.id, constable_id=device.constable_id, authorized_by=current_user.id, valid_until=body.valid_until)
    try:
        await a.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="The device is already authorized at this site")
    await log_action(user_id=current_user.id, action="bodycam.device_authorized", details={"site_id": str(site.id), "device_id": str(device.id)})
    return await _device_out(a, await _constable_labels([a.constable_id]), {device.id: device}, {})


@router.get("/device-authorizations", response_model=List[sb.DeviceAuthorizationOut])
async def list_device_authorizations(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    rows = await models.DeviceSiteAuthorization.find({"site_id": site.id}).sort("-authorized_at").limit(500).to_list()
    devices = {d.id: d for d in await models.Device.find({"_id": {"$in": [r.device_id for r in rows]}}).to_list()}
    labels = await _constable_labels([r.constable_id for r in rows])
    seen = await _seen_map(site.id)
    return [await _device_out(r, labels, devices, seen) for r in rows]


@router.post("/device-authorizations/{authorization_id}/revoke", response_model=sb.DeviceAuthorizationOut)
async def revoke_device_authorization(site_id: uuid.UUID, authorization_id: uuid.UUID, body: sb.ReasonIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    a = await models.DeviceSiteAuthorization.get(authorization_id)
    if not a or a.site_id != site.id:
        raise HTTPException(status_code=404, detail="Authorization not found")
    a.status, a.revoked_at, a.revoked_reason = "revoked", _utcnow(), body.reason
    await a.save()
    n = await site_grants.revoke_for_device(site.id, a.device_id, body.reason or "device authorization revoked")
    await log_action(user_id=current_user.id, action="bodycam.device_authorization_revoked", details={"site_id": str(site.id), "device_id": str(a.device_id), "grants_revoked": n})
    device = await models.Device.get(a.device_id)
    return await _device_out(a, await _constable_labels([a.constable_id]), {a.device_id: device} if device else {}, {})


# ===========================================================================
# Grants
# ===========================================================================

def _grant_out(g: models.OfflineGrant) -> sb.GrantOut:
    now = _utcnow()
    state = "revoked" if g.revoked else ("expired" if _aware(g.expires_at) <= now else "valid")
    return sb.GrantOut(
        id=g.id, site_id=g.site_id, constable_id=g.constable_id, device_id=g.device_id, issued_at=g.issued_at, expires_at=g.expires_at,
        operations=g.operations, key_id=g.key_id, revoked=g.revoked, revoked_at=g.revoked_at, revoked_reason=g.revoked_reason, state=state,
    )


@router.post("/grants", response_model=sb.GrantIssuedOut, status_code=201)
async def issue_grant(site_id: uuid.UUID, body: sb.GrantIssueIn, current_user: models.User = Depends(require_site_admin)):
    """Issues a signed offline grant for a device (e.g. to provision a phone by hand). The token is returned once and not stored."""
    site = await get_site_or_404(site_id, current_user)
    device = await models.Device.get(body.device_id)
    constable = await models.Constable.get(device.constable_id) if device and device.constable_id else None
    if device is None or constable is None:
        raise HTTPException(status_code=422, detail="Unknown device or officer")
    try:
        token, grant = await site_grants.issue(site, constable, device, issued_by=current_user.id, operations=body.operations)
    except site_grants.GrantError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message, headers={"X-Conflict-Reason": exc.code})
    await log_action(user_id=current_user.id, action="bodycam.grant_issued", details={"site_id": str(site.id), "grant_id": str(grant.id), "device_id": str(device.id)})
    return sb.GrantIssuedOut(grant=_grant_out(grant), token=token)


@router.get("/grants", response_model=List[sb.GrantOut])
async def list_grants(site_id: uuid.UUID, state: Optional[str] = Query(default=None, pattern="^(valid|expired|revoked)$"), limit: int = Query(default=100, ge=1, le=500), current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    rows = await models.OfflineGrant.find({"site_id": site.id}).sort("-issued_at").limit(limit).to_list()
    out = [_grant_out(g) for g in rows]
    return [g for g in out if state is None or g.state == state]


@router.post("/grants/{grant_id}/revoke", response_model=sb.GrantOut)
async def revoke_grant(site_id: uuid.UUID, grant_id: uuid.UUID, body: sb.ReasonIn, current_user: models.User = Depends(require_site_admin)):
    """Revocation takes effect at the control room immediately and at each receiver on its next sync (see services/site_grants.py for the offline limitation)."""
    site = await get_site_or_404(site_id, current_user)
    g = await models.OfflineGrant.get(grant_id)
    if not g or g.site_id != site.id:
        raise HTTPException(status_code=404, detail="Grant not found")
    if not g.revoked:
        await site_grants.revoke(g, body.reason)
    await log_action(user_id=current_user.id, action="bodycam.grant_revoked", details={"site_id": str(site.id), "grant_id": str(g.id)})
    return _grant_out(g)


# ===========================================================================
# Receivers
# ===========================================================================

def receiver_out(r: models.SiteReceiver, now: datetime.datetime) -> sb.ReceiverOut:
    state = "offline" if (r.revoked or not r.active) else site_counts.freshness_state(r.last_seen_at, now)
    alerts: List[str] = []
    if r.revoked:
        alerts.append("credential revoked")
    elif state in ("stale", "offline"):
        alerts.append(f"receiver {state}")
    elif state == "unknown":
        alerts.append("receiver has never connected")
    if r.accepting_uploads is False:
        alerts.append("not accepting uploads (storage)")
    pct = None
    if r.disk_total_bytes and r.disk_free_bytes is not None:
        pct = round(100.0 * (1 - r.disk_free_bytes / r.disk_total_bytes), 1)
        if r.min_free_bytes is not None and r.disk_free_bytes < r.min_free_bytes * 2:
            alerts.append("storage low")
    if r.quarantined_chunks:
        alerts.append(f"{r.quarantined_chunks} quarantined chunk(s)")
    if not r.endpoint_url:
        alerts.append("no phone endpoint configured")
    return sb.ReceiverOut(
        id=r.id, site_id=r.site_id, code=r.code, name=r.name, endpoint_url=r.endpoint_url, local_live_enabled=r.local_live_enabled,
        local_live_url=r.local_live_url, active=r.active, revoked=r.revoked, token_hint=r.token_hint, token_version=r.token_version,
        version=r.version, capabilities=r.capabilities, state=state, last_seen_at=r.last_seen_at, last_sync_at=r.last_sync_at,
        last_central_ack_at=r.last_central_ack_at, last_local_upload_at=r.last_local_upload_at, disk_total_bytes=r.disk_total_bytes,
        disk_free_bytes=r.disk_free_bytes, disk_used_pct=pct, min_free_bytes=r.min_free_bytes, accepting_uploads=r.accepting_uploads,
        pending_chunks=r.pending_chunks, syncing_chunks=r.syncing_chunks, quarantined_chunks=r.quarantined_chunks,
        received_chunks_total=r.received_chunks_total, failures=list(r.failures or []), pending_commands=len(r.pending_commands or []), alerts=alerts,
    )


async def _get_receiver(site: models.MonitoredSite, receiver_id: uuid.UUID) -> models.SiteReceiver:
    r = await models.SiteReceiver.get(receiver_id)
    if not r or r.site_id != site.id:
        raise HTTPException(status_code=404, detail="Receiver not found")
    return r


@router.post("/receivers", response_model=sb.ReceiverCredentialOut, status_code=201)
async def create_receiver(site_id: uuid.UUID, body: sb.ReceiverIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    r = models.SiteReceiver(
        site_id=site.id, code=body.code, name=body.name, endpoint_url=body.endpoint_url, local_live_enabled=body.local_live_enabled,
        local_live_url=body.local_live_url, created_by=current_user.id,
    )
    token = receiver_auth.apply_new_token(r, keep_previous=False)
    try:
        await r.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail=f"Receiver code '{body.code}' already exists in this site")
    await log_action(user_id=current_user.id, action="bodycam.receiver_created", details={"site_id": str(site.id), "receiver_id": str(r.id)})
    return sb.ReceiverCredentialOut(receiver=receiver_out(r, _utcnow()), token=token)


@router.get("/receivers", response_model=List[sb.ReceiverOut])
async def list_receivers(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    now = _utcnow()
    return [receiver_out(r, now) for r in await models.SiteReceiver.find({"site_id": site.id}).sort("code").to_list()]


@router.get("/receivers/{receiver_id}/local-recordings", response_model=sb.ReceiverLocalRecordingsOut)
async def receiver_local_recordings(site_id: uuid.UUID, receiver_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    """What the receiver itself last reported about recordings it still holds (heartbeat summary, bounded). It is the
    RECEIVER'S statement, not central evidence: `stale` is true when the report is older than three heartbeats, and
    `registered_centrally` says whether the control room already has a record with the same id."""
    site = await get_site_or_404(site_id, current_user)
    receiver = await _get_receiver(site, receiver_id)
    items = [dict(i) for i in (receiver.local_recordings or [])]
    ids = []
    for i in items:
        try:
            ids.append(uuid.UUID(str(i.get("recording_id"))))
        except ValueError:
            continue
    known = {d["_id"] for d in await models.RecordingSession.get_motor_collection().find({"_id": {"$in": ids}}, {"_id": 1}).to_list(None)} if ids else set()
    labels = await _constable_labels([c for c in (_uuid_or_none(i.get("constable_id")) for i in items) if c])
    out = []
    for i in items:
        rid = _uuid_or_none(i.get("recording_id"))
        if rid is None:
            continue
        def _int(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return None
        def _flag(v):
            return str(v) in ("1", "True", "true")
        cid = _uuid_or_none(i.get("constable_id"))
        out.append(sb.ReceiverLocalRecordingOut(
            recording_id=rid, status=i.get("status"), constable_label=labels.get(cid) if cid else None, device_identifier=i.get("device_identifier"),
            started_at=i.get("started_at"), created_at=i.get("created_at"), expected_chunks=_int(i.get("expected_chunks")),
            chunks_received=_int(i.get("chunks_received")) or 0, chunks_synced=_int(i.get("chunks_synced")) or 0, chunks_quarantined=_int(i.get("chunks_quarantined")) or 0,
            central_registered=_flag(i.get("central_registered")), central_completed=_flag(i.get("central_completed")), last_error=i.get("last_error"),
            registered_centrally=rid in known,
        ))
    at = receiver.local_recordings_at
    stale = at is None or (_utcnow() - (at if at.tzinfo else at.replace(tzinfo=datetime.timezone.utc))).total_seconds() > 120
    return sb.ReceiverLocalRecordingsOut(receiver_id=receiver.id, reported_at=at, stale=stale, items=out)


def _uuid_or_none(v):
    try:
        return uuid.UUID(str(v))
    except (ValueError, TypeError):
        return None


@router.patch("/receivers/{receiver_id}", response_model=sb.ReceiverOut)
async def update_receiver(site_id: uuid.UUID, receiver_id: uuid.UUID, body: sb.ReceiverPatch, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    r = await _get_receiver(site, receiver_id)
    if body.name is not None:
        r.name = body.name
    if body.clear_endpoint_url:
        r.endpoint_url = None
    elif body.endpoint_url is not None:
        r.endpoint_url = body.endpoint_url
    if body.local_live_enabled is not None:
        r.local_live_enabled = body.local_live_enabled
    if body.local_live_url is not None:
        r.local_live_url = body.local_live_url
    if body.active is not None:
        r.active = body.active
    r.updated_at = _utcnow()
    await r.save()
    await log_action(user_id=current_user.id, action="bodycam.receiver_updated", details={"site_id": str(site.id), "receiver_id": str(r.id), "fields": sorted(body.model_fields_set)})
    return receiver_out(r, _utcnow())


@router.post("/receivers/{receiver_id}/rotate-token", response_model=sb.ReceiverCredentialOut)
async def rotate_receiver_token(site_id: uuid.UUID, receiver_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    r = await _get_receiver(site, receiver_id)
    token = receiver_auth.apply_new_token(r, keep_previous=True)
    r.updated_at = _utcnow()
    await r.save()
    await log_action(user_id=current_user.id, action="bodycam.receiver_token_rotated", details={"site_id": str(site.id), "receiver_id": str(r.id), "version": r.token_version})
    return sb.ReceiverCredentialOut(receiver=receiver_out(r, _utcnow()), token=token)


@router.post("/receivers/{receiver_id}/revoke", response_model=sb.ReceiverOut)
async def revoke_receiver(site_id: uuid.UUID, receiver_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    r = await _get_receiver(site, receiver_id)
    r.revoked, r.previous_token_hash, r.previous_valid_until, r.updated_at = True, None, None, _utcnow()
    await r.save()
    await log_action(user_id=current_user.id, action="bodycam.receiver_revoked", details={"site_id": str(site.id), "receiver_id": str(r.id)})
    return receiver_out(r, _utcnow())


@router.post("/receivers/{receiver_id}/commands", response_model=sb.ReceiverOut)
async def queue_receiver_command(site_id: uuid.UUID, receiver_id: uuid.UUID, body: sb.ReceiverCommandIn, current_user: models.User = Depends(require_site_admin)):
    """
    Safe, idempotent operator actions for the receiver (retry quarantined chunks, re-run synchronization, retry one recording).
    The control room cannot reach a receiver on a site LAN, so the command waits here and is delivered the next time
    the receiver syncs; it is removed once the receiver reports it done.
    """
    site = await get_site_or_404(site_id, current_user)
    r = await _get_receiver(site, receiver_id)
    if len(r.pending_commands or []) >= 20:
        raise HTTPException(status_code=409, detail="Too many commands are already waiting for this receiver")
    cmd = {"id": uuid.uuid4().hex, "type": body.type, "recording_id": str(body.recording_id) if body.recording_id else None, "created_at": _utcnow().isoformat()}
    r.pending_commands = list(r.pending_commands or []) + [cmd]
    await r.save()
    await log_action(user_id=current_user.id, action="bodycam.receiver_command_queued", details={"site_id": str(site.id), "receiver_id": str(r.id), "type": body.type})
    return receiver_out(r, _utcnow())


@router.delete("/receivers/{receiver_id}")
async def delete_receiver(site_id: uuid.UUID, receiver_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    r = await _get_receiver(site, receiver_id)
    await r.delete()
    await log_action(user_id=current_user.id, action="bodycam.receiver_deleted", details={"site_id": str(site.id), "receiver_id": str(receiver_id)})
    return {"status": "deleted"}


# ===========================================================================
# Recordings, overview, audit
# ===========================================================================

def _sync_state(s: models.RecordingSession) -> str:
    if s.origin != "site_receiver":
        return "online"
    if s.status == models.RecordingStatus.completed:
        # "central" means the control room holds EVERY chunk up to the highest one. A completed recording with gaps is
        # reported as incomplete, never as fully synchronized; the gaps stay visible and recoverable at the receiver.
        numbers = sorted(c.chunk_number for c in s.chunks)
        return "central" if numbers and numbers == list(range(1, numbers[-1] + 1)) else "incomplete"
    return "partial" if s.chunks else "local_only"


async def _recording_out(s: models.RecordingSession, labels: dict, devices: dict) -> sb.SiteRecordingOut:
    summary = chunk_manifest_service.summarize_chunks([c.chunk_number for c in s.chunks])
    dev = devices.get(s.device_id)
    return sb.SiteRecordingOut(
        id=s.id, site_id=s.site_id, receiver_id=s.receiver_id, origin=s.origin, constable_id=s.constable_id, constable_label=labels.get(s.constable_id),
        device_id=s.device_id, device_identifier=dev.device_identifier if dev else None, status=s.status, started_at=s.started_at, ended_at=s.ended_at,
        chunk_count=len(summary.received_chunk_numbers), missing_chunk_numbers=summary.missing_chunk_numbers, flags=list(s.flags or []),
        sync_state=_sync_state(s), created_at=s.created_at,
    )


@router.get("/recordings", response_model=sb.SiteRecordingPage)
async def list_site_recordings(
    site_id: uuid.UUID, origin: Optional[str] = Query(default=None, pattern="^(central|site_receiver)$"),
    status_: Optional[models.RecordingStatus] = Query(default=None, alias="status"), constable_id: Optional[uuid.UUID] = None,
    limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0), current_user: models.User = Depends(require_site_viewer),
):
    site = await get_site_or_404(site_id, current_user)
    query: dict = {"site_id": site.id}
    if origin:
        query["origin"] = origin
    if status_:
        query["status"] = status_.value
    if constable_id:
        query["constable_id"] = constable_id
    total = await models.RecordingSession.find(query).count()
    rows = await models.RecordingSession.find(query).sort("-created_at").skip(offset).limit(limit).to_list()
    labels = await _constable_labels([r.constable_id for r in rows])
    devices = {d.id: d for d in await models.Device.find({"_id": {"$in": [r.device_id for r in rows]}}).to_list()}
    return sb.SiteRecordingPage(items=[await _recording_out(r, labels, devices) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/recordings/{recording_id}", response_model=sb.SiteRecordingDetail)
async def site_recording_detail(site_id: uuid.UUID, recording_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    s = await models.RecordingSession.get(recording_id)
    if not s or s.site_id != site.id:
        raise HTTPException(status_code=404, detail="Recording not found at this site")
    labels = await _constable_labels([s.constable_id])
    dev = await models.Device.get(s.device_id)
    base = await _recording_out(s, labels, {s.device_id: dev} if dev else {})
    chunks = [
        sb.SiteRecordingChunkOut(
            chunk_id=c.id, chunk_number=c.chunk_number, file_size=c.file_size, original_hash=c.original_hash, derived_hash=c.derived_hash,
            has_original=bool(c.original_storage_key), received_via=c.received_via, site_received_at=c.site_received_at, created_at=c.created_at,
            processing=[{k: v for k, v in step.items() if k in ("step", "tool", "at", "input_hash", "output_hash")} for step in (c.processing or [])],
        )
        for c in sorted(s.chunks, key=lambda c: c.chunk_number)
    ]
    return sb.SiteRecordingDetail(**base.model_dump(), chunks=chunks)


@router.get("/overview", response_model=sb.BodycamOverview)
async def overview(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    now = _utcnow()
    receivers = [receiver_out(r, now) for r in await models.SiteReceiver.find({"site_id": site.id}).to_list()]
    coll = models.RecordingSession.get_motor_collection()
    alerts = [f"{r.code}: {a}" for r in receivers for a in r.alerts]
    return sb.BodycamOverview(
        site_id=site.id, receivers=receivers,
        active_assignments=await models.SiteAssignment.find({"site_id": site.id, "status": "active"}).count(),
        authorized_devices=await models.DeviceSiteAuthorization.find({"site_id": site.id, "status": "authorized"}).count(),
        active_grants=await models.OfflineGrant.find({"site_id": site.id, "revoked": False, "expires_at": {"$gt": now}}).count(),
        recordings_total=await coll.count_documents({"site_id": site.id}),
        recordings_via_receiver=await coll.count_documents({"site_id": site.id, "origin": "site_receiver"}),
        recordings_in_progress=await coll.count_documents({"site_id": site.id, "status": "recording"}),
        receiver_pending_chunks=sum(r.pending_chunks for r in receivers), receiver_quarantined_chunks=sum(r.quarantined_chunks for r in receivers), alerts=alerts,
    )


@router.get("/audit", response_model=List[sb.AuditEntryOut])
async def audit(site_id: uuid.UUID, limit: int = Query(default=100, ge=1, le=500), current_user: models.User = Depends(require_site_admin)):
    """admin-only. Bodycam transport audit entries for THIS site (the details carry no tokens, hashes of secrets or raw identifiers)."""
    site = await get_site_or_404(site_id, current_user)
    rows = await models.AuditLog.find({"action": {"$regex": "^bodycam\\."}, "details.site_id": str(site.id)}).sort("-timestamp").limit(limit).to_list()
    return [sb.AuditEntryOut(id=r.id, action=r.action, timestamp=r.timestamp, details=r.details) for r in rows]
