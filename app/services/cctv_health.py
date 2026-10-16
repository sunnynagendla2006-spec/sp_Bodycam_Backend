"""
CCTV health monitoring: periodic, bounded, de-duplicated reachability checks.

Design (see docs/CCTV_BUILDINGS_AND_GATEWAY.md):
  * ONE cycle checks every due, enabled camera of every enabled building.
    Cameras that share an endpoint (all channels of one NVR) are probed ONCE
    and the result is applied to all of them -- never one probe per channel.
  * Concurrency is capped (CCTV_HEALTH_CONCURRENCY) and every probe has a
    hard timeout, so a dead recorder can never stall the cycle or block API
    requests (probes run as ordinary asyncio tasks, off the request path).
  * Failures back off exponentially (interval * 2**failures, capped at
    CCTV_HEALTH_MAX_BACKOFF_SECONDS) via CCTVCamera.next_check_at, instead of
    re-probing a dead camera every cycle.
  * Status transitions are published over the existing control-room
    WebSocket, plus a per-building roll-up.
  * Multi-replica safe: the in-process loop only runs while holding a short
    Mongo lease, so scaling the backend does not multiply probes.

A reachable recorder does NOT prove a given channel has video. Channel-level
failures are discovered at playback time and reported by the dashboard
(POST /cctv/cameras/{id}/playback/report), which feeds the same status fields.

OPERATIONAL REQUIREMENT: the in-process loop only runs when
CCTV_HEALTH_ENABLED=true. Otherwise drive monitoring from an external
scheduler by calling POST /cctv/buildings/health/run (admin) periodically.
"""
import asyncio
import dataclasses
import datetime
import logging
import os
import re
import uuid
from typing import Dict, List, Optional, Tuple

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from .. import database as db_module
from .. import models, schemas
from . import cctv_buildings, cctv_providers, cctv_security, cctv_sources, events

logger = logging.getLogger("cctv_health")

_LEASE_ID = "cctv_health"
_ADDRESS_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default)).strip()))
    except ValueError:
        return default


def enabled() -> bool:
    return os.getenv("CCTV_HEALTH_ENABLED", "false").strip().lower() in ("1", "true", "yes")


def interval_seconds() -> int:
    return _env_int("CCTV_HEALTH_INTERVAL_SECONDS", 60, 10)


def max_backoff_seconds() -> int:
    return _env_int("CCTV_HEALTH_MAX_BACKOFF_SECONDS", 900, 30)


def concurrency() -> int:
    return _env_int("CCTV_HEALTH_CONCURRENCY", 8, 1)


def probe_timeout_seconds() -> int:
    return _env_int("CCTV_HEALTH_PROBE_TIMEOUT_SECONDS", 8, 2)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def sanitize_error(message: Optional[str]) -> Optional[str]:
    """Stored/broadcast error text never contains literal addresses or runs on: it is shown to control-room operators."""
    if not message:
        return None
    return _ADDRESS_RE.sub("<address>", message)[:160]


@dataclasses.dataclass
class CycleSummary:
    cameras_checked: int = 0
    targets_probed: int = 0
    status_changes: int = 0
    skipped_not_due: int = 0

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def _backoff(failures: int) -> int:
    return min(interval_seconds() * (2 ** min(failures, 6)), max_backoff_seconds())


async def _probe(rep: models.CCTVCamera, building: Optional[models.Building], sem: asyncio.Semaphore) -> cctv_providers.CCTVConnectionResult:
    async with sem:
        provider = cctv_providers.get_provider(rep.provider_type)
        try:
            with cctv_security.extra_networks(cctv_sources.networks_for_building(building)):
                return await asyncio.wait_for(provider.validate_connection(rep), timeout=probe_timeout_seconds())
        except asyncio.TimeoutError:
            return cctv_providers.CCTVConnectionResult(status=models.CCTVCameraStatus.offline, error="probe timed out")
        except NotImplementedError:
            return cctv_providers.CCTVConnectionResult(status=models.CCTVCameraStatus.unknown, error="provider not implemented")
        except Exception:  # never let one bad target abort the cycle; details intentionally not stored
            logger.warning("health probe failed unexpectedly for camera %s", rep.id)
            return cctv_providers.CCTVConnectionResult(status=models.CCTVCameraStatus.unknown, error="probe failed")


def _group_key(camera: models.CCTVCamera, building: Optional[models.Building]) -> Tuple:
    if building is not None and building.connection_mode == models.CCTVConnectionMode.nvr:
        return ("nvr", building.id)
    return (camera.provider_type.value, camera.stream_host, camera.stream_port)


async def _apply_result(cameras: List[models.CCTVCamera], result: cctv_providers.CCTVConnectionResult, now: datetime.datetime) -> List[Tuple[models.CCTVCamera, str]]:
    """Persists the probe outcome on every camera of the group; returns [(camera, old_status)] for those whose status changed."""
    changed: List[Tuple[models.CCTVCamera, str]] = []
    ok = result.status == models.CCTVCameraStatus.online
    error = sanitize_error(result.error)
    for cam in cameras:
        old = cam.status.value
        failures = 0 if ok else cam.consecutive_failures + 1
        fields = {
            "status": result.status.value,
            "last_status_check_at": now,
            "last_error": None if ok else error,
            "consecutive_failures": failures,
            "next_check_at": now + datetime.timedelta(seconds=interval_seconds() if ok else _backoff(failures)),
        }
        if ok:
            fields["last_seen_at"] = now
        await models.CCTVCamera.get_motor_collection().update_one({"_id": cam.id}, {"$set": fields})
        cam.status = result.status
        cam.last_error = fields["last_error"]
        if old != result.status.value:
            changed.append((cam, old))
    return changed


async def _publish_changes(changed: List[Tuple[models.CCTVCamera, str]], buildings: Dict[uuid.UUID, models.Building]) -> None:
    touched = set()
    for cam, old in changed:
        await events.publish_cctv_status_changed(cam, old, cam.status.value)
        if cam.building_id:
            touched.add(cam.building_id)
    for building_id in touched:
        building = buildings.get(building_id) or await models.Building.get(building_id)
        if not building:
            continue
        cams = await models.CCTVCamera.find(models.CCTVCamera.building_id == building_id).to_list()
        stats = cctv_buildings.stats_from_cameras(building, cams)
        await events.publish_cctv_building_health(building_id, stats["health"], {k: v for k, v in stats.items() if k != "health"})


async def run_cycle(force: bool = False, now: Optional[datetime.datetime] = None) -> CycleSummary:
    """One bounded pass over all due cameras. `force=True` ignores back-off schedules."""
    now = now or _utcnow()
    summary = CycleSummary()
    cameras = await models.CCTVCamera.find({"enabled": True}).limit(5000).to_list()
    building_ids = {c.building_id for c in cameras if c.building_id}
    buildings: Dict[uuid.UUID, models.Building] = {}
    if building_ids:
        for b in await models.Building.find({"_id": {"$in": list(building_ids)}}).to_list():
            buildings[b.id] = b

    groups: Dict[Tuple, List[models.CCTVCamera]] = {}
    for cam in cameras:
        building = buildings.get(cam.building_id) if cam.building_id else None
        if cam.building_id and (building is None or not building.enabled):
            continue
        next_check = cam.next_check_at
        if next_check is not None and next_check.tzinfo is None:
            next_check = next_check.replace(tzinfo=datetime.timezone.utc)
        if not force and next_check is not None and next_check > now:
            summary.skipped_not_due += 1
            continue
        groups.setdefault(_group_key(cam, building), []).append(cam)

    sem = asyncio.Semaphore(concurrency())

    async def run_group(members: List[models.CCTVCamera]):
        building = buildings.get(members[0].building_id) if members[0].building_id else None
        result = await _probe(members[0], building, sem)
        return members, await _apply_result(members, result, _utcnow())

    outcomes = await asyncio.gather(*(run_group(m) for m in groups.values()), return_exceptions=True)
    all_changed: List[Tuple[models.CCTVCamera, str]] = []
    for outcome in outcomes:
        if isinstance(outcome, Exception):
            logger.warning("health group failed: %s", type(outcome).__name__)
            continue
        members, changed = outcome
        summary.targets_probed += 1
        summary.cameras_checked += len(members)
        all_changed.extend(changed)
    summary.status_changes = len(all_changed)
    await _publish_changes(all_changed, buildings)
    return summary


async def probe_building(building: models.Building, force: bool = True) -> List[schemas.BuildingTestTarget]:
    """Probes one building now (admin/operator-triggered test). NVR mode: the recorder once; direct-IP: each distinct camera endpoint."""
    cameras = await models.CCTVCamera.find(models.CCTVCamera.building_id == building.id).to_list()
    enabled_cams = [c for c in cameras if c.enabled]
    sem = asyncio.Semaphore(concurrency())
    results: List[schemas.BuildingTestTarget] = []
    all_changed: List[Tuple[models.CCTVCamera, str]] = []

    if building.connection_mode == models.CCTVConnectionMode.nvr:
        rep = enabled_cams[0] if enabled_cams else models.CCTVCamera(
            name="recorder", camera_code="recorder-probe", stream_host=building.recorder_host or "", stream_port=building.recorder_port,
            stream_protocol=building.recorder_protocol,
        )
        result = await _probe(rep, building, sem)
        if enabled_cams:
            all_changed.extend(await _apply_result(enabled_cams, result, _utcnow()))
        results.append(schemas.BuildingTestTarget(
            target="recorder", status=result.status, latency_ms=result.latency_ms, error=sanitize_error(result.error),
            camera_ids=[c.id for c in enabled_cams],
        ))
    else:
        groups: Dict[Tuple, List[models.CCTVCamera]] = {}
        for cam in enabled_cams:
            groups.setdefault(_group_key(cam, building), []).append(cam)
        for members in groups.values():
            result = await _probe(members[0], building, sem)
            all_changed.extend(await _apply_result(members, result, _utcnow()))
            results.append(schemas.BuildingTestTarget(
                target=members[0].camera_code, status=result.status, latency_ms=result.latency_ms,
                error=sanitize_error(result.error), camera_ids=[c.id for c in members],
            ))
    await _publish_changes(all_changed, {building.id: building})
    return results


# ---------------------------------------------------------------------------
# Optional in-process loop with a Mongo lease (see module docstring).
# ---------------------------------------------------------------------------

async def _acquire_lease(owner: str, ttl_seconds: int) -> bool:
    coll = db_module.database["cctv_health_lease"]
    now = _utcnow()
    try:
        await coll.find_one_and_update(
            {"_id": _LEASE_ID, "$or": [{"expires_at": {"$lt": now}}, {"owner": owner}]},
            {"$set": {"owner": owner, "expires_at": now + datetime.timedelta(seconds=ttl_seconds)}},
            upsert=True, return_document=ReturnDocument.AFTER,
        )
        return True
    except DuplicateKeyError:
        return False  # another replica holds an unexpired lease


async def health_loop(stop: asyncio.Event) -> None:
    owner = uuid.uuid4().hex
    interval = interval_seconds()
    logger.info("CCTV health monitor started (interval=%ss)", interval)
    while not stop.is_set():
        try:
            if await _acquire_lease(owner, ttl_seconds=interval * 2 + 30):
                summary = await run_cycle()
                logger.info("CCTV health cycle: %s", summary.as_dict())
        except Exception:
            logger.exception("CCTV health cycle failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("CCTV health monitor stopped")
