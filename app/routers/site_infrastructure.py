"""
Site network infrastructure inventory: access points, switches (with port
mapping), controllers and collectors.

Identifiers are kept apart on purpose: an AP's MANAGEMENT IP, its radios'
BSSIDs and a client's MAC are three different things. Management IPs are
expected to differ between APs (a duplicate inside one site is refused);
clients roam between APs that share an SSID.

Nothing here talks to hardware. Registration records what an administrator
states; an AP is only ever considered "online" because real telemetry arrived
(see services/site_counts.py::ap_state).
"""
import datetime
import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pymongo.errors import DuplicateKeyError

from .. import geo, models, schemas_network as sn
from ..services import collector_auth, site_counts
from ..services.audit import log_action
from .sites import get_site_or_404, is_admin, require_site_admin, require_site_viewer

router = APIRouter(prefix="/sites", tags=["Site Infrastructure"])

_ADAPTER_KIND_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{1,31}$")


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ===========================================================================
# Access points
# ===========================================================================

def ap_out(ap: models.AccessPoint, active_clients: int, now: datetime.datetime) -> sn.SiteAPOut:
    lon, lat = geo.lon_lat(ap.location)
    return sn.SiteAPOut(
        id=ap.id, code=ap.code, name=ap.name, manufacturer=ap.manufacturer, model=ap.model, serial_number=ap.serial_number,
        management_ip=ap.management_ip, bssid=ap.bssid,
        radios=[sn.RadioIn(band=r.band, channel=r.channel, bssid=r.bssid, ssid=r.ssid) for r in ap.radios],
        ssids=list(ap.ssids), controller_id=ap.controller_id, switch_id=ap.switch_id, switch_port=ap.switch_port,
        zone_id=ap.site_zone_id, building_id=ap.site_building_id, floor_id=ap.site_floor_id, environment=ap.environment,
        latitude=lat, longitude=lon, plan_x=ap.plan_x, plan_y=ap.plan_y, client_capacity=ap.client_capacity,
        enabled=ap.enabled, state=site_counts.ap_state(ap, now), last_seen_at=ap.last_seen_at, active_clients=active_clients,
    )


async def _check_placement(site: models.MonitoredSite, *, zone_id=None, building_id=None, floor_id=None, controller_id=None, switch_id=None):
    checks = [
        (zone_id, models.SiteZone, "zone_id"), (building_id, models.SiteBuilding, "building_id"), (floor_id, models.SiteFloor, "floor_id"),
        (controller_id, models.NetworkController, "controller_id"), (switch_id, models.NetworkSwitch, "switch_id"),
    ]
    for value, model, name in checks:
        if value is not None:
            doc = await model.get(value)
            if not doc or doc.site_id != site.id:
                raise HTTPException(status_code=422, detail=f"{name} does not belong to this site")


async def _check_unique_ap_fields(site: models.MonitoredSite, *, management_ip, bssids, exclude_id=None) -> None:
    if management_ip:
        clash = await models.AccessPoint.find_one({"site_id": site.id, "management_ip": management_ip, "_id": {"$ne": exclude_id}})
        if clash:
            raise HTTPException(status_code=409, detail=f"Management IP {management_ip} is already used by AP {clash.code}; each AP normally has its own")
    for b in bssids:
        clash = await models.AccessPoint.find_one({"$or": [{"bssid": b}, {"radios.bssid": b}], "_id": {"$ne": exclude_id}})
        if clash:
            raise HTTPException(status_code=409, detail=f"BSSID {b} is already registered to AP {clash.code}")


async def _sync_switch_port(site: models.MonitoredSite, ap: models.AccessPoint, old_switch_id, old_port) -> None:
    """Keeps NetworkSwitch.ports[].ap_id and AccessPoint.switch_id/switch_port in agreement."""
    coll = models.NetworkSwitch.get_motor_collection()
    if old_switch_id and (old_switch_id != ap.switch_id or old_port != ap.switch_port):
        await coll.update_many({"_id": old_switch_id, "ports.ap_id": ap.id}, {"$set": {"ports.$[p].ap_id": None}}, array_filters=[{"p.ap_id": ap.id}])
    if ap.switch_id and ap.switch_port:
        sw = await models.NetworkSwitch.get(ap.switch_id)
        if sw:
            for p in sw.ports:
                if p.ap_id == ap.id and p.port != ap.switch_port:
                    p.ap_id = None
            existing = next((p for p in sw.ports if p.port == ap.switch_port), None)
            if existing is None:
                sw.ports.append(models.SwitchPort(port=ap.switch_port, ap_id=ap.id))
            else:
                existing.ap_id = ap.id
            sw.updated_at = _utcnow()
            await sw.save()


async def _denormalize_clients(ap: models.AccessPoint) -> None:
    """Counting reads zone/floor/building from the association rows, so they follow the AP's placement."""
    await models.ClientAssociation.get_motor_collection().update_many(
        {"site_id": ap.site_id, "ap_id": ap.id},
        {"$set": {"zone_id": ap.site_zone_id, "floor_id": ap.site_floor_id, "building_id": ap.site_building_id}},
    )


@router.post("/{site_id}/access-points", response_model=sn.SiteAPOut, status_code=201)
async def register_access_point(site_id: uuid.UUID, payload: sn.SiteAPIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    await _check_placement(site, zone_id=payload.zone_id, building_id=payload.building_id, floor_id=payload.floor_id,
                           controller_id=payload.controller_id, switch_id=payload.switch_id)
    bssids = [b for b in [payload.bssid] + [r.bssid for r in payload.radios] if b]
    await _check_unique_ap_fields(site, management_ip=payload.management_ip, bssids=bssids)
    zone = await models.SiteZone.get(payload.zone_id) if payload.zone_id else None
    now = _utcnow()
    ap = models.AccessPoint(
        code=payload.code, name=payload.name, manufacturer=payload.manufacturer, model=payload.model, serial_number=payload.serial_number,
        management_ip=payload.management_ip, bssid=payload.bssid, ssid=(payload.ssids[0] if payload.ssids else None),
        zone=zone.code if zone else None, building=None, floor=None,  # legacy free-text fields: left to the older flow
        location=geo.point(payload.longitude, payload.latitude) if payload.latitude is not None else None,
        site_id=site.id, site_zone_id=payload.zone_id, site_building_id=payload.building_id or (zone.building_id if zone else None),
        site_floor_id=payload.floor_id or (zone.floor_id if zone else None), controller_id=payload.controller_id,
        switch_id=payload.switch_id, switch_port=payload.switch_port, environment=payload.environment,
        radios=[models.APRadio(band=r.band, channel=r.channel, bssid=r.bssid, ssid=r.ssid) for r in payload.radios],
        ssids=payload.ssids, plan_x=payload.plan_x, plan_y=payload.plan_y, client_capacity=payload.client_capacity,
        network_metadata=payload.network_metadata, created_at=now, updated_at=now, created_by=current_user.id, updated_by=current_user.id,
    )
    try:
        await ap.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="An access point with this code, BSSID or serial number already exists")
    await _sync_switch_port(site, ap, None, None)
    await log_action(user_id=current_user.id, action="site_ap_registered", details={"site_id": str(site.id), "ap_id": str(ap.id), "code": ap.code})
    return ap_out(ap, 0, now)


@router.post("/{site_id}/access-points/{ap_id}/adopt", response_model=sn.SiteAPOut)
async def adopt_access_point(site_id: uuid.UUID, ap_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    """Brings an AP registered through the older /access-points flow into this site. Refuses an AP that already belongs to another site."""
    site = await get_site_or_404(site_id, current_user)
    ap = await models.AccessPoint.get(ap_id)
    if not ap:
        raise HTTPException(status_code=404, detail="Access point not found")
    if ap.site_id and ap.site_id != site.id:
        raise HTTPException(status_code=409, detail="Access point already belongs to another site")
    ap.site_id = site.id
    ap.updated_at = _utcnow()
    await ap.save()
    await log_action(user_id=current_user.id, action="site_ap_adopted", details={"site_id": str(site.id), "ap_id": str(ap.id)})
    return ap_out(ap, 0, _utcnow())


@router.get("/{site_id}/access-points", response_model=List[sn.SiteAPOut])
async def list_site_access_points(
    site_id: uuid.UUID, zone_id: Optional[uuid.UUID] = None, floor_id: Optional[uuid.UUID] = None, state: Optional[str] = Query(default=None, pattern="^(online|stale|offline|unknown)$"),
    limit: int = Query(default=300, ge=1, le=1000), offset: int = Query(default=0, ge=0), current_user: models.User = Depends(require_site_viewer),
):
    site = await get_site_or_404(site_id, current_user)
    query: dict = {"site_id": site.id}
    if zone_id:
        query["site_zone_id"] = zone_id
    if floor_id:
        query["site_floor_id"] = floor_id
    aps = await models.AccessPoint.find(query).sort("code").skip(offset).limit(limit).to_list()
    counts = (await site_counts.raw_counts(site.id))["by_ap"]
    now = _utcnow()
    out = [ap_out(a, counts.get(a.id, 0), now) for a in aps]
    return [a for a in out if state is None or a.state == state]


@router.patch("/{site_id}/access-points/{ap_id}", response_model=sn.SiteAPOut)
async def update_site_access_point(
    site_id: uuid.UUID, ap_id: uuid.UUID, payload: sn.SiteAPPatch, current_user: models.User = Depends(require_site_admin)
):
    site = await get_site_or_404(site_id, current_user)
    ap = await models.AccessPoint.get(ap_id)
    if not ap or ap.site_id != site.id:
        raise HTTPException(status_code=404, detail="Access point not found in this site")
    await _check_placement(site, zone_id=payload.zone_id, building_id=payload.building_id, floor_id=payload.floor_id,
                           controller_id=payload.controller_id, switch_id=payload.switch_id)
    bssids = [b for b in [payload.bssid] + [r.bssid for r in (payload.radios or [])] if b]
    await _check_unique_ap_fields(site, management_ip=payload.management_ip, bssids=bssids, exclude_id=ap.id)
    old_switch, old_port = ap.switch_id, ap.switch_port

    for field in ("name", "manufacturer", "model", "serial_number", "management_ip", "bssid", "controller_id", "environment",
                  "client_capacity", "network_metadata", "ssids"):
        value = getattr(payload, field)
        if value is not None:
            setattr(ap, field, value)
    if payload.radios is not None:
        ap.radios = [models.APRadio(band=r.band, channel=r.channel, bssid=r.bssid, ssid=r.ssid) for r in payload.radios]
    if payload.clear_zone:
        ap.site_zone_id = None
    elif payload.zone_id is not None:
        ap.site_zone_id = payload.zone_id
        zone = await models.SiteZone.get(payload.zone_id)
        ap.zone = zone.code
        if payload.floor_id is None and zone.floor_id:
            ap.site_floor_id = zone.floor_id
        if payload.building_id is None and zone.building_id:
            ap.site_building_id = zone.building_id
    if payload.floor_id is not None:
        ap.site_floor_id = payload.floor_id
    if payload.building_id is not None:
        ap.site_building_id = payload.building_id
    if payload.clear_switch:
        ap.switch_id = None
        ap.switch_port = None
    else:
        if payload.switch_id is not None:
            ap.switch_id = payload.switch_id
        if payload.switch_port is not None:
            ap.switch_port = payload.switch_port
    if payload.clear_plan_position:
        ap.plan_x = ap.plan_y = None
    elif payload.plan_x is not None and payload.plan_y is not None:
        ap.plan_x, ap.plan_y = payload.plan_x, payload.plan_y
    if payload.latitude is not None and payload.longitude is not None:
        ap.location = geo.point(payload.longitude, payload.latitude)
    ap.updated_at = _utcnow()
    ap.updated_by = current_user.id
    try:
        await ap.save()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="BSSID or serial number already registered to another access point")
    await _sync_switch_port(site, ap, old_switch, old_port)
    await _denormalize_clients(ap)
    await log_action(user_id=current_user.id, action="site_ap_updated", details={"site_id": str(site.id), "ap_id": str(ap.id), "fields": sorted(payload.model_fields_set)})
    counts = (await site_counts.raw_counts(site.id))["by_ap"]
    return ap_out(ap, counts.get(ap.id, 0), _utcnow())


# ===========================================================================
# Switches
# ===========================================================================

def switch_out(sw: models.NetworkSwitch) -> sn.SwitchOut:
    return sn.SwitchOut(
        id=sw.id, site_id=sw.site_id, code=sw.code, name=sw.name, management_ip=sw.management_ip, vendor=sw.vendor, model=sw.model,
        serial_number=sw.serial_number, building_id=sw.building_id, floor_id=sw.floor_id,
        ports=[sn.SwitchPortOut(port=p.port, description=p.description, ap_id=p.ap_id, vlan=p.vlan, link_status=p.link_status, last_seen_at=p.last_seen_at) for p in sw.ports],
        active=sw.active, last_seen_at=sw.last_seen_at, metadata=sw.metadata,
    )


async def _apply_ports(site: models.MonitoredSite, sw: models.NetworkSwitch, ports_in: List[sn.SwitchPortIn]) -> None:
    seen_ports, seen_aps = set(), set()
    new_ports: List[models.SwitchPort] = []
    previous = {p.port: p for p in sw.ports}
    for p in ports_in:
        if p.port in seen_ports:
            raise HTTPException(status_code=422, detail=f"Port {p.port} is listed twice")
        seen_ports.add(p.port)
        if p.ap_id:
            if p.ap_id in seen_aps:
                raise HTTPException(status_code=422, detail="An AP can be connected to only one port of a switch")
            seen_aps.add(p.ap_id)
            ap = await models.AccessPoint.get(p.ap_id)
            if not ap or ap.site_id != site.id:
                raise HTTPException(status_code=422, detail="ap_id does not belong to this site")
        old = previous.get(p.port)
        new_ports.append(models.SwitchPort(
            port=p.port, description=p.description, ap_id=p.ap_id, vlan=p.vlan,
            link_status=old.link_status if old else "unknown", last_seen_at=old.last_seen_at if old else None,
        ))
    removed_aps = {p.ap_id for p in sw.ports if p.ap_id} - seen_aps
    sw.ports = new_ports
    apc = models.AccessPoint.get_motor_collection()
    if removed_aps:
        await apc.update_many({"_id": {"$in": list(removed_aps)}, "switch_id": sw.id}, {"$set": {"switch_id": None, "switch_port": None}})
    for p in new_ports:
        if p.ap_id:
            await apc.update_one({"_id": p.ap_id}, {"$set": {"switch_id": sw.id, "switch_port": p.port}})


@router.post("/{site_id}/switches", response_model=sn.SwitchOut, status_code=201)
async def create_switch(site_id: uuid.UUID, payload: sn.SwitchIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    await _check_placement(site, building_id=payload.building_id, floor_id=payload.floor_id)
    sw = models.NetworkSwitch(
        site_id=site.id, code=payload.code, name=payload.name, management_ip=payload.management_ip, vendor=payload.vendor, model=payload.model,
        serial_number=payload.serial_number, building_id=payload.building_id, floor_id=payload.floor_id, metadata=payload.metadata,
    )
    await _apply_ports(site, sw, payload.ports)
    try:
        await sw.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail=f"Switch code '{payload.code}' already exists in this site")
    await log_action(user_id=current_user.id, action="site_switch_created", details={"site_id": str(site.id), "switch_id": str(sw.id)})
    return switch_out(sw)


@router.get("/{site_id}/switches", response_model=List[sn.SwitchOut])
async def list_switches(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    return [switch_out(s) for s in await models.NetworkSwitch.find({"site_id": site.id}).sort("code").to_list()]


@router.patch("/{site_id}/switches/{switch_id}", response_model=sn.SwitchOut)
async def update_switch(site_id: uuid.UUID, switch_id: uuid.UUID, payload: sn.SwitchPatch, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    sw = await models.NetworkSwitch.get(switch_id)
    if not sw or sw.site_id != site.id:
        raise HTTPException(status_code=404, detail="Switch not found")
    await _check_placement(site, building_id=payload.building_id, floor_id=payload.floor_id)
    for field in ("name", "management_ip", "vendor", "model", "serial_number", "building_id", "floor_id", "active", "metadata"):
        value = getattr(payload, field)
        if value is not None:
            setattr(sw, field, value)
    if payload.ports is not None:
        await _apply_ports(site, sw, payload.ports)
    sw.updated_at = _utcnow()
    await sw.save()
    await log_action(user_id=current_user.id, action="site_switch_updated", details={"site_id": str(site.id), "switch_id": str(sw.id)})
    return switch_out(sw)


@router.delete("/{site_id}/switches/{switch_id}")
async def delete_switch(site_id: uuid.UUID, switch_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    sw = await models.NetworkSwitch.get(switch_id)
    if not sw or sw.site_id != site.id:
        raise HTTPException(status_code=404, detail="Switch not found")
    await models.AccessPoint.get_motor_collection().update_many({"switch_id": sw.id}, {"$set": {"switch_id": None, "switch_port": None}})
    await sw.delete()
    await log_action(user_id=current_user.id, action="site_switch_deleted", details={"site_id": str(site.id), "switch_id": str(switch_id)})
    return {"status": "deleted"}


# ===========================================================================
# Controllers
# ===========================================================================

def controller_out(c: models.NetworkController, now: datetime.datetime) -> sn.ControllerOut:
    return sn.ControllerOut(
        id=c.id, site_id=c.site_id, code=c.code, name=c.name, vendor=c.vendor, model=c.model, management_ip=c.management_ip,
        adapter_kind=c.adapter_kind, active=c.active, health=c.health, state=site_counts.freshness_state(c.last_seen_at, now),
        last_seen_at=c.last_seen_at, metadata=c.metadata,
    )


@router.post("/{site_id}/controllers", response_model=sn.ControllerOut, status_code=201)
async def create_controller(site_id: uuid.UUID, payload: sn.ControllerIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    c = models.NetworkController(
        site_id=site.id, code=payload.code, name=payload.name, vendor=payload.vendor, model=payload.model,
        management_ip=payload.management_ip, adapter_kind=payload.adapter_kind, metadata=payload.metadata,
    )
    try:
        await c.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail=f"Controller code '{payload.code}' already exists in this site")
    await log_action(user_id=current_user.id, action="site_controller_created", details={"site_id": str(site.id), "controller_id": str(c.id)})
    return controller_out(c, _utcnow())


@router.get("/{site_id}/controllers", response_model=List[sn.ControllerOut])
async def list_controllers(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    now = _utcnow()
    return [controller_out(c, now) for c in await models.NetworkController.find({"site_id": site.id}).sort("code").to_list()]


@router.patch("/{site_id}/controllers/{controller_id}", response_model=sn.ControllerOut)
async def update_controller(site_id: uuid.UUID, controller_id: uuid.UUID, payload: sn.ControllerPatch, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    c = await models.NetworkController.get(controller_id)
    if not c or c.site_id != site.id:
        raise HTTPException(status_code=404, detail="Controller not found")
    for field in ("name", "vendor", "model", "management_ip", "adapter_kind", "active", "metadata"):
        value = getattr(payload, field)
        if value is not None:
            setattr(c, field, value)
    c.updated_at = _utcnow()
    await c.save()
    await log_action(user_id=current_user.id, action="site_controller_updated", details={"site_id": str(site.id), "controller_id": str(c.id)})
    return controller_out(c, _utcnow())


@router.delete("/{site_id}/controllers/{controller_id}")
async def delete_controller(site_id: uuid.UUID, controller_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    c = await models.NetworkController.get(controller_id)
    if not c or c.site_id != site.id:
        raise HTTPException(status_code=404, detail="Controller not found")
    await models.AccessPoint.get_motor_collection().update_many({"controller_id": c.id}, {"$set": {"controller_id": None}})
    await c.delete()
    await log_action(user_id=current_user.id, action="site_controller_deleted", details={"site_id": str(site.id), "controller_id": str(controller_id)})
    return {"status": "deleted"}


# ===========================================================================
# Collectors (credentials are shown ONCE)
# ===========================================================================

async def _get_collector(site: models.MonitoredSite, collector_id: uuid.UUID) -> models.Collector:
    c = await models.Collector.get(collector_id)
    if not c or c.site_id != site.id:
        raise HTTPException(status_code=404, detail="Collector not found")
    return c


@router.post("/{site_id}/collectors", response_model=sn.CollectorCredentialResponse, status_code=201)
async def create_collector(site_id: uuid.UUID, payload: sn.CollectorIn, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    if not _ADAPTER_KIND_RE.match(payload.adapter_kind):
        raise HTTPException(status_code=422, detail="adapter_kind must be 2-32 characters: lowercase letters, digits, '_' or '-'")
    c = models.Collector(
        site_id=site.id, code=payload.code, name=payload.name, adapter_kind=payload.adapter_kind,
        is_simulated=payload.is_simulated or payload.adapter_kind == "synthetic",  # synthetic data can never be labelled real
        config=payload.config, created_by=current_user.id,
    )
    token = collector_auth.apply_new_token(c, keep_previous=False)
    try:
        await c.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail=f"Collector code '{payload.code}' already exists in this site")
    await log_action(user_id=current_user.id, action="collector_created", details={"site_id": str(site.id), "collector_id": str(c.id), "adapter": c.adapter_kind, "simulated": c.is_simulated})
    return sn.CollectorCredentialResponse(collector=site_counts.collector_out(c, _utcnow()), token=token)


@router.get("/{site_id}/collectors", response_model=List[sn.CollectorOut])
async def list_collectors(site_id: uuid.UUID, current_user: models.User = Depends(require_site_viewer)):
    site = await get_site_or_404(site_id, current_user)
    now = _utcnow()
    return [site_counts.collector_out(c, now) for c in await models.Collector.find({"site_id": site.id}).sort("code").to_list()]


@router.patch("/{site_id}/collectors/{collector_id}", response_model=sn.CollectorOut)
async def update_collector(site_id: uuid.UUID, collector_id: uuid.UUID, payload: sn.CollectorPatch, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    c = await _get_collector(site, collector_id)
    if payload.adapter_kind is not None:
        if not _ADAPTER_KIND_RE.match(payload.adapter_kind):
            raise HTTPException(status_code=422, detail="invalid adapter_kind")
        c.adapter_kind = payload.adapter_kind
        c.is_simulated = c.is_simulated or payload.adapter_kind == "synthetic"
    for field in ("name", "active", "config"):
        value = getattr(payload, field)
        if value is not None:
            setattr(c, field, value)
    c.updated_at = _utcnow()
    await c.save()
    await log_action(user_id=current_user.id, action="collector_updated", details={"site_id": str(site.id), "collector_id": str(c.id), "fields": sorted(payload.model_fields_set)})
    return site_counts.collector_out(c, _utcnow())


@router.post("/{site_id}/collectors/{collector_id}/rotate-token", response_model=sn.CollectorCredentialResponse)
async def rotate_collector_token(site_id: uuid.UUID, collector_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    """Issues a new token. The previous one keeps working for ten minutes so the collector can be reconfigured without a gap."""
    site = await get_site_or_404(site_id, current_user)
    c = await _get_collector(site, collector_id)
    token = collector_auth.apply_new_token(c, keep_previous=True)
    c.updated_at = _utcnow()
    await c.save()
    await log_action(user_id=current_user.id, action="collector_token_rotated", details={"site_id": str(site.id), "collector_id": str(c.id), "version": c.token_version})
    return sn.CollectorCredentialResponse(collector=site_counts.collector_out(c, _utcnow()), token=token)


@router.post("/{site_id}/collectors/{collector_id}/revoke", response_model=sn.CollectorOut)
async def revoke_collector(site_id: uuid.UUID, collector_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    """Immediate: the current token and any rotation grace stop working at once."""
    site = await get_site_or_404(site_id, current_user)
    c = await _get_collector(site, collector_id)
    c.revoked = True
    c.previous_token_hash = None
    c.previous_valid_until = None
    c.updated_at = _utcnow()
    await c.save()
    await log_action(user_id=current_user.id, action="collector_revoked", details={"site_id": str(site.id), "collector_id": str(c.id)})
    return site_counts.collector_out(c, _utcnow())


@router.delete("/{site_id}/collectors/{collector_id}")
async def delete_collector(site_id: uuid.UUID, collector_id: uuid.UUID, current_user: models.User = Depends(require_site_admin)):
    site = await get_site_or_404(site_id, current_user)
    c = await _get_collector(site, collector_id)
    await c.delete()
    await log_action(user_id=current_user.id, action="collector_deleted", details={"site_id": str(site.id), "collector_id": str(collector_id)})
    return {"status": "deleted"}
