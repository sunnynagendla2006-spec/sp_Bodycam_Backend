"""
Collector -> backend ingestion. NOT a user API: every endpoint requires a
collector credential (services/collector_auth.py), and everything a collector
sends is scoped to the single site that credential belongs to.

  POST /collector/heartbeat          liveness, capabilities, adapter health, buffer depth
  POST /collector/ingest/events      batch of normalized association events (idempotent)
  POST /collector/ingest/snapshot    point-in-time client list (idempotent by snapshot id)
  POST /collector/ingest/health      AP / controller health observations

Safeguards: per-collector rate limit, bounded batch sizes (schemas), source
timestamps must be timezone-aware, not in the future beyond a skew allowance and
not older than COLLECTOR_MAX_EVENT_AGE_HOURS (buffered replay after an outage
is expected, so this is generous), a claimed site_code must match the
credential's site, and APs are resolved only among the credential's own site
(nothing is auto-created). Client identifiers are pseudonymized on arrival.
"""
import datetime
import os
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from .. import models, schemas_network as sn
from ..auth import request_limiter
from ..services import events, site_events, site_monitor
from ..services.collector_auth import CollectorContext, get_current_collector
from ..services import site_privacy

router = APIRouter(prefix="/collector", tags=["Collector Ingest"])


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default)).strip()))
    except ValueError:
        return default


def _check_site_claim(ctx: CollectorContext, claimed: str | None) -> None:
    if claimed and claimed != ctx.site.code:
        # Never honour a site named in the body: it must agree with the credential or the request is refused.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This credential is not authorized for the named site")


def _rate_limit(ctx: CollectorContext) -> None:
    if not request_limiter.allow(f"colingest:{ctx.collector.id}", _int_env("COLLECTOR_RATE_LIMIT_PER_MINUTE", 600)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": "10"})


def _time_problem(ts: datetime.datetime, now: datetime.datetime) -> str | None:
    skew = datetime.timedelta(seconds=_int_env("COLLECTOR_MAX_FUTURE_SKEW_SECONDS", 300))
    max_age = datetime.timedelta(hours=_int_env("COLLECTOR_MAX_EVENT_AGE_HOURS", 72))
    if ts > now + skew:
        return "source_timestamp is in the future"
    if ts < now - max_age:
        return "source_timestamp is too old to accept"
    return None


async def _touch(ctx: CollectorContext, ingest: bool, **extra) -> None:
    now = _utcnow()
    fields = {"last_seen_at": now, "updated_at": now, **extra}
    if ingest:
        fields["last_ingest_at"] = now
    await models.Collector.get_motor_collection().update_one({"_id": ctx.collector.id}, {"$set": fields})


@router.post("/heartbeat", response_model=sn.HeartbeatResponse)
async def heartbeat(body: sn.HeartbeatRequest, ctx: CollectorContext = Depends(get_current_collector)):
    _check_site_claim(ctx, body.site_code)
    _rate_limit(ctx)
    await _touch(
        ctx, False, capabilities=body.capabilities, adapter_health=body.adapter_health, version=body.version,
        buffer_depth=body.buffer_depth, dropped_events=body.dropped_events,
    )
    return sn.HeartbeatResponse(
        server_time=_utcnow(), collector_code=ctx.collector.code, site_code=ctx.site.code,
        is_simulated=ctx.collector.is_simulated, token_version=ctx.collector.token_version,
    )


@router.post("/ingest/events", response_model=sn.EventBatchResponse)
async def ingest_events(body: sn.EventBatchRequest, ctx: CollectorContext = Depends(get_current_collector)):
    _check_site_claim(ctx, body.site_code)
    _rate_limit(ctx)
    if not site_privacy.is_configured():
        raise HTTPException(status_code=503, detail="Client identifier pseudonymization is not configured (CLIENT_ID_HMAC_KEY)")

    now = _utcnow()
    resolver = site_events.APResolver(ctx.site.id)
    results: List[sn.EventResultItem] = []
    applied = 0
    roams = []
    # Oldest first so a batch that carries a client's whole story is applied in source order.
    ordered = sorted(body.events, key=lambda e: e.source_timestamp)
    for ev in ordered:
        problem = _time_problem(ev.source_timestamp, now)
        if problem:
            results.append(sn.EventResultItem(event_id=ev.event_id, outcome="rejected_timestamp", detail=problem))
            continue
        res = await site_events.process_event(ctx.site, ctx.collector, ev, resolver, now=now)
        results.append(sn.EventResultItem(event_id=ev.event_id, outcome=res.outcome, detail=res.detail))
        if res.outcome == site_events.APPLIED:
            applied += 1
        if res.roamed and len(roams) < 50:
            roams.append({"from_ap_id": str(res.from_ap_id), "to_ap_id": str(res.ap_id), "at": ev.source_timestamp.isoformat()})

    await _touch(ctx, True)
    for r in roams:  # aggregate only: AP ids and a time, never a client
        await events.publish_network_roam(ctx.site, {**r, "simulated": ctx.collector.is_simulated})
    await site_monitor.maybe_cycle_after_ingest(ctx.site)
    return sn.EventBatchResponse(received=len(body.events), applied=applied, results=results)


@router.post("/ingest/snapshot", response_model=sn.SnapshotResponse)
async def ingest_snapshot(body: sn.SnapshotRequest, ctx: CollectorContext = Depends(get_current_collector)):
    _check_site_claim(ctx, body.site_code)
    _rate_limit(ctx)
    if not site_privacy.is_configured():
        raise HTTPException(status_code=503, detail="Client identifier pseudonymization is not configured (CLIENT_ID_HMAC_KEY)")
    problem = _time_problem(body.source_timestamp, _utcnow())
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    resolver = site_events.APResolver(ctx.site.id)
    result = await site_events.process_snapshot(ctx.site, ctx.collector, body, resolver)
    await _touch(ctx, True)
    await site_monitor.maybe_cycle_after_ingest(ctx.site)
    return result


@router.post("/ingest/health", response_model=sn.HealthBatchResponse)
async def ingest_health(body: sn.HealthBatchRequest, ctx: CollectorContext = Depends(get_current_collector)):
    _check_site_claim(ctx, body.site_code)
    _rate_limit(ctx)
    now = _utcnow()
    resolver = site_events.APResolver(ctx.site.id)
    updated = unknown = 0
    for item in body.aps:
        if _time_problem(item.observed_at, now):
            continue
        ap = await resolver.resolve(item.ap)
        if ap is None:
            unknown += 1  # never auto-registered
            continue
        health = {"online": models.APIntegrationHealth.healthy, "degraded": models.APIntegrationHealth.degraded, "offline": models.APIntegrationHealth.error}[item.state]
        fields = {"integration_health": health.value, "integration_checked_at": now}
        if item.state != "offline":
            fields["last_seen_at"] = item.observed_at  # only a reachable AP counts as "heard from"
        await models.AccessPoint.get_motor_collection().update_one({"_id": ap.id}, {"$set": fields})
        updated += 1
    controllers = 0
    for item in body.controllers:
        if _time_problem(item.observed_at, now):
            continue
        res = await models.NetworkController.get_motor_collection().update_one(
            {"site_id": ctx.site.id, "code": item.code}, {"$set": {"health": item.health, "last_seen_at": item.observed_at}}
        )
        controllers += res.matched_count
    await _touch(ctx, True)
    return sn.HealthBatchResponse(aps_updated=updated, aps_unknown=unknown, controllers_updated=controllers)
