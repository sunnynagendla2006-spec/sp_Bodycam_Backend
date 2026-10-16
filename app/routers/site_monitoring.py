"""
Read-side of the network monitoring platform: live summary, current
associations, event history, analytics, exports, plus the privacy-sensitive
"reveal" and the operational run-now actions.

PRIVACY: every client in a response is a MASKED pseudonym (first 8 characters).
Raw identifiers are never returned here; the only path to one is POST
/sites/{id}/privacy/reveal (admin only, requires the site to store raw
identifiers and a server key, always audited with the caller's stated reason).

METRIC HONESTY: all counts are ACTIVE CLIENT ASSOCIATIONS from telemetry (see
services/site_counts.py). Responses carry the data quality (live / simulated /
mixed / snapshot / none) and a `stale` flag.
"""
import csv
import datetime
import io
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from .. import models, schemas_network as sn
from ..services import site_counts, site_monitor, site_privacy, site_retention
from ..services.audit import log_action
from .sites import get_site_or_404, require_site_admin, require_site_viewer

router = APIRouter(prefix="/sites", tags=["Site Monitoring"])

MAX_EVENT_WINDOW = datetime.timedelta(days=7)
MAX_SERIES_WINDOW = datetime.timedelta(days=31)
MAX_EXPORT_ROWS = 50000


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _window(start: Optional[datetime.datetime], end: Optional[datetime.datetime], default: datetime.timedelta, maximum: datetime.timedelta):
    end = end or _utcnow()
    if end.tzinfo is None:
        end = end.replace(tzinfo=datetime.timezone.utc)
    start = start or (end - default)
    if start.tzinfo is None:
        start = start.replace(tzinfo=datetime.timezone.utc)
    if start >= end:
        raise HTTPException(status_code=422, detail="`from` must be before `to`")
    if end - start > maximum:
        raise HTTPException(status_code=422, detail=f"The time window may not exceed {maximum.days} days")
    return start, end


# ===========================================================================
# Live
# ===========================================================================

@router.get("/{site_id}/summary", response_model=sn.SiteSummary)
async def site_summary(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    return await site_counts.summarize(site)


@router.get("/{site_id}/associations", response_model=sn.AssociationPage)
async def current_associations(
    site_id: uuid.UUID, ap_id: Optional[uuid.UUID] = None, zone_id: Optional[uuid.UUID] = None,
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0), current_user: models.User = Depends(require_site_viewer),
):
    """Currently ACTIVE associations only (closed ones are history). Clients are masked pseudonyms."""
    site = await get_site_or_404(site_id, current_user)
    query: dict = {"site_id": site.id, "state": "active"}
    if ap_id:
        query["ap_id"] = ap_id
    if zone_id:
        query["zone_id"] = zone_id
    total = await models.ClientAssociation.find(query).count()
    rows = await models.ClientAssociation.find(query).sort("-last_event_at").skip(offset).limit(limit).to_list()
    return sn.AssociationPage(
        items=[sn.AssociationOut(
            client=site_privacy.mask(r.client_pseudonym), ap_id=r.ap_id, zone_id=r.zone_id, radio_bssid=r.radio_bssid, source=r.source,
            associated_at=r.associated_at, last_event_at=r.last_event_at, ordering_confidence=r.ordering_confidence,
        ) for r in rows],
        total=total, limit=limit, offset=offset,
    )


@router.get("/{site_id}/events", response_model=sn.NetworkEventPage)
async def list_events(
    site_id: uuid.UUID, event_type: Optional[str] = Query(default=None, pattern="^(association|disassociation|roam)$"),
    outcome: Optional[str] = Query(default=None, max_length=32), ap_id: Optional[uuid.UUID] = None, zone_id: Optional[uuid.UUID] = None,
    from_: Optional[datetime.datetime] = Query(default=None, alias="from"), to: Optional[datetime.datetime] = None,
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0), current_user: models.User = Depends(require_site_viewer),
):
    """Event history (newest first), bounded to a window of at most 7 days (default 24 h)."""
    site = await get_site_or_404(site_id, current_user)
    start, end = _window(from_, to, datetime.timedelta(hours=24), MAX_EVENT_WINDOW)
    query: dict = {"site_id": site.id, "source_timestamp": {"$gte": start, "$lte": end}, "event_type": {"$ne": "snapshot"}}
    if event_type:
        query["event_type"] = event_type
    if outcome:
        query["outcome"] = outcome
    if ap_id:
        query["ap_id"] = ap_id
    if zone_id:
        query["zone_id"] = zone_id
    total = await models.NetworkEvent.find(query).count()
    rows = await models.NetworkEvent.find(query).sort("-source_timestamp").skip(offset).limit(limit).to_list()
    return sn.NetworkEventPage(
        items=[sn.NetworkEventOut(
            id=e.id, event_type=e.event_type, client=site_privacy.mask(e.client_pseudonym), ap_id=e.ap_id, from_ap_id=e.from_ap_id, zone_id=e.zone_id,
            source_timestamp=e.source_timestamp, received_at=e.received_at, source=e.source, outcome=e.outcome, outcome_detail=e.outcome_detail,
            ordering_confidence=e.ordering_confidence,
        ) for e in rows],
        total=total, limit=limit, offset=offset,
    )


# ===========================================================================
# Analytics
# ===========================================================================

async def _series(site: models.MonitoredSite, scope: str, scope_id: Optional[uuid.UUID], start, end, bucket: int) -> List[sn.SeriesPoint]:
    query = {"site_id": site.id, "scope": scope, "scope_id": scope_id, "bucket_start": {"$gte": start, "$lte": end}}
    rows = await models.OccupancySample.find(query).sort("bucket_start").limit(50000).to_list()
    native = site_monitor.bucket_seconds()
    if bucket <= native:
        return [sn.SeriesPoint(t=r.bucket_start, active_clients=r.active_clients, peak_clients=r.peak_clients, quality=r.quality) for r in rows]
    grouped: dict = {}
    for r in rows:
        ts = r.bucket_start if r.bucket_start.tzinfo else r.bucket_start.replace(tzinfo=datetime.timezone.utc)
        key = int(ts.timestamp()) // bucket * bucket
        g = grouped.setdefault(key, {"last": r.active_clients, "peak": 0, "quality": r.quality})
        g["last"], g["quality"] = r.active_clients, r.quality
        g["peak"] = max(g["peak"], r.peak_clients)
    return [
        sn.SeriesPoint(t=datetime.datetime.fromtimestamp(k, tz=datetime.timezone.utc), active_clients=v["last"], peak_clients=v["peak"], quality=v["quality"])
        for k, v in sorted(grouped.items())
    ]


@router.get("/{site_id}/analytics/occupancy", response_model=sn.OccupancySeries)
async def occupancy_series(
    site_id: uuid.UUID, scope: str = Query(default="site", pattern="^(site|zone|ap|floor)$"), scope_id: Optional[uuid.UUID] = None,
    from_: Optional[datetime.datetime] = Query(default=None, alias="from"), to: Optional[datetime.datetime] = None,
    bucket_seconds: int = Query(default=300, ge=60, le=86400), current_user: models.User = Depends(require_site_viewer),
):
    """Active client associations over time for the site, a zone, an AP or a floor. Not a head count; gaps are real gaps."""
    site = await get_site_or_404(site_id, current_user)
    if scope != "site" and scope_id is None:
        raise HTTPException(status_code=422, detail="scope_id is required unless scope is 'site'")
    start, end = _window(from_, to, datetime.timedelta(hours=24), MAX_SERIES_WINDOW)
    points = await _series(site, scope, None if scope == "site" else scope_id, start, end, bucket_seconds)
    return sn.OccupancySeries(scope=scope, scope_id=scope_id, bucket_seconds=max(bucket_seconds, site_monitor.bucket_seconds()), points=points)


@router.get("/{site_id}/analytics/peaks")
async def peaks(
    site_id: uuid.UUID, scope: str = Query(default="zone", pattern="^(site|zone|ap|floor)$"),
    from_: Optional[datetime.datetime] = Query(default=None, alias="from"), to: Optional[datetime.datetime] = None,
    top: int = Query(default=10, ge=1, le=50), current_user: models.User = Depends(require_site_viewer),
):
    """The highest-load entities and when each peaked, for site/zone/AP comparison."""
    site = await get_site_or_404(site_id, current_user)
    start, end = _window(from_, to, datetime.timedelta(hours=24), MAX_SERIES_WINDOW)
    pipeline = [
        {"$match": {"site_id": site.id, "scope": scope, "bucket_start": {"$gte": start, "$lte": end}}},
        {"$sort": {"peak_clients": -1}},
        {"$group": {"_id": "$scope_id", "peak": {"$first": "$peak_clients"}, "peak_at": {"$first": "$bucket_start"}, "mean": {"$avg": "$active_clients"}}},
        {"$sort": {"peak": -1}},
        {"$limit": top},
    ]
    out = []
    async for row in models.OccupancySample.get_motor_collection().aggregate(pipeline, allowDiskUse=True):
        out.append({"scope_id": str(row["_id"]) if row["_id"] else None, "peak_clients": row["peak"], "peak_at": row["peak_at"], "mean_clients": round(row["mean"], 1)})
    return {"scope": scope, "from": start, "to": end, "items": out}


@router.get("/{site_id}/analytics/roaming", response_model=sn.RoamingSummary)
async def roaming_summary(
    site_id: uuid.UUID, from_: Optional[datetime.datetime] = Query(default=None, alias="from"), to: Optional[datetime.datetime] = None,
    current_user: models.User = Depends(require_site_viewer),
):
    site = await get_site_or_404(site_id, current_user)
    start, end = _window(from_, to, datetime.timedelta(hours=24), MAX_EVENT_WINDOW)
    coll = models.NetworkEvent.get_motor_collection()
    base = {"site_id": site.id, "source_timestamp": {"$gte": start, "$lte": end}, "event_type": {"$ne": "snapshot"}}
    associations = await coll.count_documents({**base, "event_type": {"$in": ["association", "roam"]}, "outcome": "applied"})
    disassociations = await coll.count_documents({**base, "event_type": "disassociation", "outcome": "applied"})
    roams = await coll.count_documents({**base, "outcome": "applied", "outcome_detail": "roam"})
    stale = await coll.count_documents({**base, "outcome": "stale"})
    unique = 0
    async for _ in coll.aggregate([{"$match": base}, {"$group": {"_id": "$client_pseudonym"}}], allowDiskUse=True):
        unique += 1
    top = []
    async for row in coll.aggregate([
        {"$match": {**base, "outcome": "applied", "outcome_detail": "roam", "from_ap_id": {"$ne": None}}},
        {"$group": {"_id": {"from": "$from_ap_id", "to": "$ap_id"}, "n": {"$sum": 1}}}, {"$sort": {"n": -1}}, {"$limit": 10},
    ]):
        top.append({"from_ap_id": str(row["_id"]["from"]), "to_ap_id": str(row["_id"]["to"]), "count": row["n"]})
    avg = None
    async for row in models.ClientAssociation.get_motor_collection().aggregate([
        {"$match": {"site_id": site.id, "state": "closed", "closed_at": {"$gte": start, "$lte": end}, "associated_at": {"$ne": None}}},
        {"$group": {"_id": None, "ms": {"$avg": {"$subtract": ["$closed_at", "$associated_at"]}}}},
    ]):
        avg = round(row["ms"] / 1000.0, 1) if row.get("ms") is not None else None
    return sn.RoamingSummary(
        window_from=start, window_to=end, associations=associations, disassociations=disassociations, roams=roams, ignored_stale=stale,
        unique_client_pseudonyms=unique, top_transitions=top, average_association_seconds=avg,
    )


@router.get("/{site_id}/analytics/breaches", response_model=List[sn.BreachOut])
async def list_breaches(
    site_id: uuid.UUID, active: Optional[bool] = None, from_: Optional[datetime.datetime] = Query(default=None, alias="from"), to: Optional[datetime.datetime] = None,
    limit: int = Query(default=100, ge=1, le=500), current_user: models.User = Depends(require_site_viewer),
):
    site = await get_site_or_404(site_id, current_user)
    start, end = _window(from_, to, datetime.timedelta(days=7), MAX_SERIES_WINDOW)
    query: dict = {"site_id": site.id, "started_at": {"$gte": start, "$lte": end}}
    if active is not None:
        query["active"] = active
    rows = await models.ThresholdBreach.find(query).sort("-started_at").limit(limit).to_list()
    return [sn.BreachOut(
        id=b.id, scope=b.scope, scope_id=b.scope_id, level=b.level, threshold=b.threshold, peak_clients=b.peak_clients,
        started_at=b.started_at, last_seen_at=b.last_seen_at, ended_at=b.ended_at, active=b.active,
    ) for b in rows]


@router.get("/{site_id}/analytics/availability", response_model=List[sn.AvailabilityOut])
async def availability_history(
    site_id: uuid.UUID, entity_type: Optional[str] = Query(default=None, pattern="^(collector|ap|controller)$"),
    from_: Optional[datetime.datetime] = Query(default=None, alias="from"), to: Optional[datetime.datetime] = None,
    limit: int = Query(default=200, ge=1, le=1000), current_user: models.User = Depends(require_site_viewer),
):
    """State changes (online/stale/offline) of collectors and APs: the record of stale-telemetry periods."""
    site = await get_site_or_404(site_id, current_user)
    start, end = _window(from_, to, datetime.timedelta(days=7), MAX_SERIES_WINDOW)
    query: dict = {"site_id": site.id, "at": {"$gte": start, "$lte": end}}
    if entity_type:
        query["entity_type"] = entity_type
    rows = await models.AvailabilityEvent.find(query).sort("-at").limit(limit).to_list()
    return [sn.AvailabilityOut(entity_type=r.entity_type, entity_id=r.entity_id, state=r.state, at=r.at) for r in rows]


@router.get("/{site_id}/analytics/export.csv")
async def export_csv(
    site_id: uuid.UUID, kind: str = Query(default="occupancy", pattern="^(occupancy|events)$"), scope: str = Query(default="zone", pattern="^(site|zone|ap|floor)$"),
    from_: Optional[datetime.datetime] = Query(default=None, alias="from"), to: Optional[datetime.datetime] = None,
    current_user: models.User = Depends(require_site_admin),
):
    """admin-only CSV of occupancy samples or (masked) events, bounded in time and rows. Audited."""
    site = await get_site_or_404(site_id, current_user)
    start, end = _window(from_, to, datetime.timedelta(hours=24), MAX_SERIES_WINDOW if kind == "occupancy" else MAX_EVENT_WINDOW)
    buf = io.StringIO()
    writer = csv.writer(buf)
    if kind == "occupancy":
        writer.writerow(["bucket_start_utc", "scope", "scope_id", "active_clients", "peak_clients", "quality", "simulated"])
        rows = await models.OccupancySample.find({"site_id": site.id, "scope": scope, "bucket_start": {"$gte": start, "$lte": end}}).sort("bucket_start").limit(MAX_EXPORT_ROWS).to_list()
        for r in rows:
            writer.writerow([r.bucket_start.isoformat(), r.scope, r.scope_id or "", r.active_clients, r.peak_clients, r.quality, r.simulated])
    else:
        writer.writerow(["source_timestamp_utc", "event_type", "client_masked", "ap_id", "from_ap_id", "zone_id", "source", "outcome", "ordering_confidence"])
        rows = await models.NetworkEvent.find({"site_id": site.id, "source_timestamp": {"$gte": start, "$lte": end}, "event_type": {"$ne": "snapshot"}}).sort("source_timestamp").limit(MAX_EXPORT_ROWS).to_list()
        for e in rows:
            writer.writerow([e.source_timestamp.isoformat(), e.event_type, site_privacy.mask(e.client_pseudonym), e.ap_id or "", e.from_ap_id or "", e.zone_id or "", e.source, e.outcome, e.ordering_confidence or ""])
    await log_action(user_id=current_user.id, action="site_export", details={"site_id": str(site.id), "kind": kind, "rows": len(rows)})
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{site.code}-{kind}.csv"'})


# ===========================================================================
# Privacy and operations
# ===========================================================================

@router.post("/{site_id}/privacy/reveal", response_model=sn.RevealResponse)
async def reveal_identifier(site_id: uuid.UUID, body: sn.RevealRequest, current_user: models.User = Depends(require_site_admin)):
    """
    admin-only. Returns the raw identifier behind a pseudonym ONLY if the site policy stores raw identifiers and the server holds
    CLIENT_RAW_ID_KEY. Always audited with the caller's reason. Never available for sites that do not retain raw values.
    """
    site = await get_site_or_404(site_id, current_user)
    if not site.policy.store_raw_identifiers or not site_privacy.raw_storage_available():
        raise HTTPException(status_code=404, detail="Raw identifiers are not stored for this site")
    row = await models.ClientAssociation.find_one({"site_id": site.id, "client_pseudonym": {"$regex": f"^{_safe_prefix(body.client)}"}})
    if not row or not row.raw_identifier_encrypted:
        await log_action(user_id=current_user.id, action="site_identifier_reveal_miss", details={"site_id": str(site.id), "client": body.client[:8], "reason": body.reason})
        raise HTTPException(status_code=404, detail="No stored identifier for that client")
    raw = site_privacy.decrypt_raw(row.raw_identifier_encrypted)
    if raw is None:
        raise HTTPException(status_code=500, detail="Stored identifier could not be decrypted (key changed?)")
    await log_action(user_id=current_user.id, action="site_identifier_revealed", details={"site_id": str(site.id), "client": row.client_pseudonym[:8], "reason": body.reason})
    return sn.RevealResponse(client=site_privacy.mask(row.client_pseudonym), identifier=raw)


def _safe_prefix(value: str) -> str:
    cleaned = "".join(c for c in value.lower() if c in "0123456789abcdef…")
    cleaned = cleaned.replace("…", "")
    if len(cleaned) < 8:
        raise HTTPException(status_code=422, detail="client must be a pseudonym of at least 8 hexadecimal characters")
    return cleaned


@router.post("/{site_id}/monitor/run", response_model=sn.MonitorRunResponse)
async def run_monitor(site_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    """Evaluates the site now (samples, breaches, availability) and broadcasts counts. For external schedulers or after a config change."""
    site = await get_site_or_404(site_id, current_user)
    return sn.MonitorRunResponse(**await site_monitor.run_site_cycle(site))


@router.post("/{site_id}/retention/run", response_model=sn.RetentionRunResponse)
async def run_retention(site_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    result = await site_retention.purge_site(site)
    await log_action(user_id=current_user.id, action="site_retention_run", details={"site_id": str(site.id), **result})
    return sn.RetentionRunResponse(**result)
