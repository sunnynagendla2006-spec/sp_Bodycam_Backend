"""
API schemas for the generic site / network telemetry platform.

Kept in their own module (not schemas.py, which is already very large) but
following the same conventions: pydantic v2, explicit validation, no secrets
in any response model.
"""
import ipaddress
import re
import uuid
from datetime import datetime
from typing import Annotated, Any, Dict, List, Literal, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import SiteMonitoringScope, SiteType
from .schemas import normalise_bssid

_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{1,63}$")
_PORT_RE = re.compile(r"^[A-Za-z0-9/._\-: ]{1,64}$")


def _code(v: str) -> str:
    v = (v or "").strip()
    if not _CODE_RE.match(v):
        raise ValueError("code must be 2-64 characters: letters, digits, '.', '_' or '-'")
    return v


Code = Annotated[str, AfterValidator(_code)]


def _reject_secret_keys(v: Optional[dict]) -> Optional[dict]:
    if v is None:
        return v
    bad = [k for k in v if re.search(r"(secret|password|token|key|credential)", str(k), re.I)]
    if bad:
        raise ValueError(f"config must not contain secrets (found {', '.join(bad)}); credentials belong in the collector's environment")
    return v


def _ip(v: Optional[str]) -> Optional[str]:
    if v is None or not str(v).strip():
        return None
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        raise ValueError("must be a valid IP address")


def validate_polygon_rings(rings: List[List[List[float]]]) -> List[List[List[float]]]:
    """GeoJSON polygon rings in WGS84 [lon, lat]: closed rings of at least 4 positions, coordinates in range."""
    if not rings:
        raise ValueError("polygon needs at least one ring")
    for ring in rings:
        if len(ring) < 4:
            raise ValueError("each polygon ring needs at least 4 positions")
        if ring[0] != ring[-1]:
            raise ValueError("each polygon ring must be closed (first position equals last)")
        for pos in ring:
            if len(pos) != 2 or not (-180 <= pos[0] <= 180) or not (-90 <= pos[1] <= 90):
                raise ValueError("positions must be [longitude, latitude] within range")
    return rings


def _plan_polygon(v: Optional[List[List[float]]]) -> Optional[List[List[float]]]:
    if v is None:
        return None
    if len(v) < 3 or len(v) > 200:
        raise ValueError("plan_polygon needs 3 to 200 points")
    for pt in v:
        if len(pt) != 2 or not (0.0 <= pt[0] <= 1.0) or not (0.0 <= pt[1] <= 1.0):
            raise ValueError("plan_polygon points must be [x, y] between 0 and 1 (fractions of the plan image)")
    return v


# ===========================================================================
# Ingest (collector -> backend)
# ===========================================================================

class APRef(BaseModel):
    """How the SOURCE identifies an AP. Resolved to a registered AP of the collector's own site only; nothing is auto-created."""
    bssid: Optional[str] = None
    ap_code: Optional[str] = Field(default=None, max_length=64)
    management_ip: Optional[str] = None
    serial_number: Optional[str] = Field(default=None, max_length=128)

    @field_validator("bssid")
    @classmethod
    def _bssid(cls, v):
        return normalise_bssid(v) if v else None

    @field_validator("management_ip")
    @classmethod
    def _mgmt(cls, v):
        return _ip(v)

    @model_validator(mode="after")
    def _one(self):
        if not (self.bssid or self.ap_code or self.management_ip or self.serial_number):
            raise ValueError("an AP reference needs at least one of bssid, ap_code, management_ip, serial_number")
        return self


class CollectorEvent(BaseModel):
    """A normalized association event. `client_id` is the raw client identifier; the backend pseudonymizes it immediately and does not keep it."""
    event_id: str = Field(..., min_length=1, max_length=128)  # unique per collector (idempotency key)
    event_type: Literal["association", "disassociation", "roam"]
    source_timestamp: datetime  # when it happened at the SOURCE (timezone-aware)
    source_seq: Optional[int] = Field(default=None, ge=0)
    seq_stream: Optional[str] = Field(default=None, max_length=64)  # sequence numbers are only comparable within one stream
    client_id: str = Field(..., min_length=1, max_length=128)
    ap: Optional[APRef] = None
    from_ap: Optional[APRef] = None
    radio_bssid: Optional[str] = None
    session_id: Optional[str] = Field(default=None, max_length=128)
    source: Literal["REAL", "SNAPSHOT"] = "REAL"  # SYNTHETIC is never accepted from a client: the server decides

    @field_validator("radio_bssid")
    @classmethod
    def _radio(cls, v):
        return normalise_bssid(v) if v else None

    @field_validator("source_timestamp")
    @classmethod
    def _tz(cls, v):
        if v.tzinfo is None:
            raise ValueError("source_timestamp must include a timezone offset")
        return v

    @model_validator(mode="after")
    def _needs_ap(self):
        if self.event_type in ("association", "roam") and self.ap is None:
            raise ValueError(f"a {self.event_type} event needs `ap`")
        return self


class EventBatchRequest(BaseModel):
    site_code: Optional[str] = Field(default=None, max_length=64)  # optional cross-check only; the site comes from the credential
    events: List[CollectorEvent] = Field(..., min_length=1, max_length=200)


class EventResultItem(BaseModel):
    event_id: str
    outcome: str
    detail: Optional[str] = None


class EventBatchResponse(BaseModel):
    received: int
    applied: int
    results: List[EventResultItem]


class SnapshotClient(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=128)
    ap: APRef
    radio_bssid: Optional[str] = None

    @field_validator("radio_bssid")
    @classmethod
    def _radio(cls, v):
        return normalise_bssid(v) if v else None


class SnapshotRequest(BaseModel):
    """A point-in-time list of associated clients. When `complete` is true, active associations in scope that are absent from it are closed (snapshot-derived)."""
    site_code: Optional[str] = Field(default=None, max_length=64)
    snapshot_id: str = Field(..., min_length=1, max_length=128)
    source_timestamp: datetime
    complete: bool = False
    scope: Literal["site", "aps"] = "aps"
    covered_aps: List[APRef] = Field(default_factory=list, max_length=500)
    clients: List[SnapshotClient] = Field(default_factory=list, max_length=5000)

    @field_validator("source_timestamp")
    @classmethod
    def _tz(cls, v):
        if v.tzinfo is None:
            raise ValueError("source_timestamp must include a timezone offset")
        return v

    @model_validator(mode="after")
    def _scope(self):
        if self.complete and self.scope == "aps" and not self.covered_aps:
            raise ValueError("a complete snapshot with scope 'aps' must list covered_aps")
        return self


class SnapshotResponse(BaseModel):
    snapshot_id: str
    clients_processed: int
    applied: int
    closed_absent: int
    out_of_scope: int
    duplicate: bool = False


class HeartbeatRequest(BaseModel):
    site_code: Optional[str] = Field(default=None, max_length=64)
    version: Optional[str] = Field(default=None, max_length=64)
    adapter: Optional[str] = Field(default=None, max_length=64)
    capabilities: List[str] = Field(default_factory=list, max_length=32)
    adapter_health: Optional[Dict[str, Any]] = None
    buffer_depth: int = Field(default=0, ge=0)
    dropped_events: int = Field(default=0, ge=0)

    @field_validator("adapter_health")
    @classmethod
    def _small(cls, v):
        if v is not None and len(str(v)) > 2000:
            raise ValueError("adapter_health is too large")
        return v


class HeartbeatResponse(BaseModel):
    status: str = "ok"
    server_time: datetime
    collector_code: str
    site_code: str
    is_simulated: bool
    token_version: int


class APHealthItem(BaseModel):
    ap: APRef
    state: Literal["online", "degraded", "offline"]
    client_count: Optional[int] = Field(default=None, ge=0)  # the source's own count, informational
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def _tz(cls, v):
        if v.tzinfo is None:
            raise ValueError("observed_at must include a timezone offset")
        return v


class ControllerHealthItem(BaseModel):
    code: str = Field(..., max_length=64)
    health: Literal["healthy", "degraded", "error"]
    observed_at: datetime


class HealthBatchRequest(BaseModel):
    site_code: Optional[str] = Field(default=None, max_length=64)
    aps: List[APHealthItem] = Field(default_factory=list, max_length=500)
    controllers: List[ControllerHealthItem] = Field(default_factory=list, max_length=50)


class HealthBatchResponse(BaseModel):
    aps_updated: int
    aps_unknown: int
    controllers_updated: int


# ===========================================================================
# Management (admin UI)
# ===========================================================================

class SitePolicyIn(BaseModel):
    scope_mode: Optional[SiteMonitoringScope] = None
    authorization_reference: Optional[str] = Field(default=None, max_length=500)
    retention_days: Optional[int] = Field(default=None, ge=1, le=365)
    store_raw_identifiers: Optional[bool] = None


class SiteCreate(BaseModel):
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    site_type: SiteType = SiteType.custom
    custom_type_label: Optional[str] = Field(default=None, max_length=64)
    organization: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = Field(default=None, max_length=2000)
    address: Optional[str] = Field(default=None, max_length=500)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    boundary: Optional[List[List[List[float]]]] = None
    timezone: str = "UTC"
    access_mode: Literal["all_control_room", "restricted"] = "all_control_room"
    viewer_user_ids: List[uuid.UUID] = Field(default_factory=list, max_length=200)
    policy: Optional[SitePolicyIn] = None
    ap_warning_clients: Optional[int] = Field(default=None, ge=1)
    ap_critical_clients: Optional[int] = Field(default=None, ge=1)
    metadata: Optional[dict] = None

    @field_validator("boundary")
    @classmethod
    def _boundary(cls, v):
        return validate_polygon_rings(v) if v else None

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v):
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError, KeyError):
            raise ValueError("unknown IANA time zone")
        return v

    @model_validator(mode="after")
    def _coords(self):
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be given together")
        if self.site_type == SiteType.custom and self.custom_type_label is None:
            pass  # allowed: a custom site without a label is shown as "custom"
        if self.ap_warning_clients and self.ap_critical_clients and self.ap_warning_clients > self.ap_critical_clients:
            raise ValueError("ap_warning_clients cannot exceed ap_critical_clients")
        return self


class SiteUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    site_type: Optional[SiteType] = None
    custom_type_label: Optional[str] = Field(default=None, max_length=64)
    organization: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = Field(default=None, max_length=2000)
    address: Optional[str] = Field(default=None, max_length=500)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    boundary: Optional[List[List[List[float]]]] = None
    clear_boundary: bool = False
    timezone: Optional[str] = None
    active: Optional[bool] = None
    access_mode: Optional[Literal["all_control_room", "restricted"]] = None
    viewer_user_ids: Optional[List[uuid.UUID]] = Field(default=None, max_length=200)
    policy: Optional[SitePolicyIn] = None
    ap_warning_clients: Optional[int] = Field(default=None, ge=1)
    ap_critical_clients: Optional[int] = Field(default=None, ge=1)
    metadata: Optional[dict] = None

    @field_validator("boundary")
    @classmethod
    def _boundary(cls, v):
        return validate_polygon_rings(v) if v else None

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v):
        if v is None:
            return v
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError, KeyError):
            raise ValueError("unknown IANA time zone")
        return v


class SitePolicyOut(BaseModel):
    scope_mode: SiteMonitoringScope
    authorization_reference: Optional[str] = None
    retention_days: int
    store_raw_identifiers: bool
    allowlist_size: int


class SiteResponse(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    site_type: SiteType
    custom_type_label: Optional[str] = None
    organization: Optional[str] = None
    description: Optional[str] = None
    address: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    boundary: Optional[List[List[List[float]]]] = None
    timezone: str
    active: bool
    access_mode: str
    viewer_user_ids: List[uuid.UUID] = Field(default_factory=list)  # admins only
    policy: SitePolicyOut
    ap_warning_clients: Optional[int] = None
    ap_critical_clients: Optional[int] = None
    metadata: Optional[dict] = None
    created_at: datetime
    updated_at: datetime


class AllowlistRequest(BaseModel):
    """Raw identifiers are hashed immediately; only pseudonyms are stored."""
    identifiers: List[str] = Field(..., min_length=1, max_length=500)


class AllowlistResponse(BaseModel):
    added: int
    allowlist_size: int


class BuildingIn(BaseModel):
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1000)
    cctv_building_id: Optional[uuid.UUID] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    metadata: Optional[dict] = None


class BuildingPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1000)
    cctv_building_id: Optional[uuid.UUID] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    metadata: Optional[dict] = None


class BuildingOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    code: str
    name: str
    description: Optional[str] = None
    cctv_building_id: Optional[uuid.UUID] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    metadata: Optional[dict] = None


class FloorIn(BaseModel):
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    building_id: Optional[uuid.UUID] = None
    level: Optional[int] = Field(default=None, ge=-20, le=300)
    height_m: Optional[float] = Field(default=None, gt=0, le=50)
    plan_meters_per_pixel: Optional[float] = Field(default=None, gt=0)
    display_order: int = 0
    metadata: Optional[dict] = None


class FloorPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    building_id: Optional[uuid.UUID] = None
    level: Optional[int] = Field(default=None, ge=-20, le=300)
    height_m: Optional[float] = Field(default=None, gt=0, le=50)
    plan_meters_per_pixel: Optional[float] = Field(default=None, gt=0)
    display_order: Optional[int] = None
    metadata: Optional[dict] = None


class FloorOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    building_id: Optional[uuid.UUID] = None
    code: str
    name: str
    level: Optional[int] = None
    height_m: Optional[float] = None
    has_plan: bool
    plan_width_px: Optional[int] = None
    plan_height_px: Optional[int] = None
    plan_meters_per_pixel: Optional[float] = None
    display_order: int
    metadata: Optional[dict] = None


class ZoneIn(BaseModel):
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    zone_type: str = Field(default="general", max_length=64)
    description: Optional[str] = Field(default=None, max_length=1000)
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    boundary: Optional[List[List[List[float]]]] = None
    plan_polygon: Optional[List[List[float]]] = None
    capacity: Optional[int] = Field(default=None, ge=1)
    warning_threshold: Optional[int] = Field(default=None, ge=1)
    critical_threshold: Optional[int] = Field(default=None, ge=1)
    display_order: int = 0
    metadata: Optional[dict] = None

    @field_validator("boundary")
    @classmethod
    def _boundary(cls, v):
        return validate_polygon_rings(v) if v else None

    @field_validator("plan_polygon")
    @classmethod
    def _plan(cls, v):
        return _plan_polygon(v)

    @model_validator(mode="after")
    def _thresholds(self):
        if self.warning_threshold and self.critical_threshold and self.warning_threshold > self.critical_threshold:
            raise ValueError("warning_threshold cannot exceed critical_threshold")
        return self


class ZonePatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    zone_type: Optional[str] = Field(default=None, max_length=64)
    description: Optional[str] = Field(default=None, max_length=1000)
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    boundary: Optional[List[List[List[float]]]] = None
    clear_boundary: bool = False
    plan_polygon: Optional[List[List[float]]] = None
    clear_plan_polygon: bool = False
    capacity: Optional[int] = Field(default=None, ge=1)
    warning_threshold: Optional[int] = Field(default=None, ge=1)
    critical_threshold: Optional[int] = Field(default=None, ge=1)
    clear_thresholds: bool = False
    active: Optional[bool] = None
    display_order: Optional[int] = None
    metadata: Optional[dict] = None

    @field_validator("boundary")
    @classmethod
    def _boundary(cls, v):
        return validate_polygon_rings(v) if v else None

    @field_validator("plan_polygon")
    @classmethod
    def _plan(cls, v):
        return _plan_polygon(v)


class ZoneOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    code: str
    name: str
    zone_type: str
    description: Optional[str] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    boundary: Optional[List[List[List[float]]]] = None
    plan_polygon: Optional[List[List[float]]] = None
    capacity: Optional[int] = None
    warning_threshold: Optional[int] = None
    critical_threshold: Optional[int] = None
    active: bool
    display_order: int
    metadata: Optional[dict] = None


class RadioIn(BaseModel):
    band: Optional[str] = Field(default=None, max_length=16)
    channel: Optional[int] = Field(default=None, ge=1, le=300)
    bssid: Optional[str] = None
    ssid: Optional[str] = Field(default=None, max_length=64)

    @field_validator("bssid")
    @classmethod
    def _bssid(cls, v):
        return normalise_bssid(v) if v else None


class SiteAPIn(BaseModel):
    """Register an AP (or place an existing one) inside a site. Management IP, BSSID(s) and client MACs are different identifiers and are stored separately."""
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    manufacturer: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    serial_number: Optional[str] = Field(default=None, max_length=128)
    management_ip: Optional[str] = None
    bssid: Optional[str] = None  # primary BSSID; further radios go in `radios`
    radios: List[RadioIn] = Field(default_factory=list, max_length=8)
    ssids: List[str] = Field(default_factory=list, max_length=16)
    controller_id: Optional[uuid.UUID] = None
    switch_id: Optional[uuid.UUID] = None
    switch_port: Optional[str] = Field(default=None, max_length=64)
    zone_id: Optional[uuid.UUID] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    environment: Literal["indoor", "outdoor", "unknown"] = "unknown"
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    plan_x: Optional[float] = Field(default=None, ge=0, le=1)
    plan_y: Optional[float] = Field(default=None, ge=0, le=1)
    client_capacity: Optional[int] = Field(default=None, ge=1)
    network_metadata: Optional[dict] = None

    @field_validator("management_ip")
    @classmethod
    def _mgmt(cls, v):
        return _ip(v)

    @field_validator("bssid")
    @classmethod
    def _bssid(cls, v):
        return normalise_bssid(v) if v else None

    @field_validator("switch_port")
    @classmethod
    def _port(cls, v):
        if v is not None and not _PORT_RE.match(v):
            raise ValueError("unsupported characters in switch_port")
        return v

    @model_validator(mode="after")
    def _pairs(self):
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be given together")
        if (self.plan_x is None) != (self.plan_y is None):
            raise ValueError("plan_x and plan_y must be given together")
        return self


class SiteAPPatch(BaseModel):
    """Placement/inventory update. Unset fields stay as they are; use the clear_* flags to remove a value."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    manufacturer: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    serial_number: Optional[str] = Field(default=None, max_length=128)
    management_ip: Optional[str] = None
    bssid: Optional[str] = None
    radios: Optional[List[RadioIn]] = Field(default=None, max_length=8)
    ssids: Optional[List[str]] = Field(default=None, max_length=16)
    controller_id: Optional[uuid.UUID] = None
    switch_id: Optional[uuid.UUID] = None
    switch_port: Optional[str] = Field(default=None, max_length=64)
    zone_id: Optional[uuid.UUID] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    environment: Optional[Literal["indoor", "outdoor", "unknown"]] = None
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    plan_x: Optional[float] = Field(default=None, ge=0, le=1)
    plan_y: Optional[float] = Field(default=None, ge=0, le=1)
    client_capacity: Optional[int] = Field(default=None, ge=1)
    clear_zone: bool = False
    clear_switch: bool = False
    clear_plan_position: bool = False
    network_metadata: Optional[dict] = None

    @field_validator("management_ip")
    @classmethod
    def _mgmt(cls, v):
        return _ip(v)

    @field_validator("bssid")
    @classmethod
    def _bssid(cls, v):
        return normalise_bssid(v) if v else None

    @field_validator("switch_port")
    @classmethod
    def _port(cls, v):
        if v is not None and not _PORT_RE.match(v):
            raise ValueError("unsupported characters in switch_port")
        return v


class SiteAPOut(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    management_ip: Optional[str] = None
    bssid: Optional[str] = None
    radios: List[RadioIn] = Field(default_factory=list)
    ssids: List[str] = Field(default_factory=list)
    controller_id: Optional[uuid.UUID] = None
    switch_id: Optional[uuid.UUID] = None
    switch_port: Optional[str] = None
    zone_id: Optional[uuid.UUID] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    environment: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    plan_x: Optional[float] = None
    plan_y: Optional[float] = None
    client_capacity: Optional[int] = None
    enabled: bool
    state: str  # online | stale | offline | unknown (from real telemetry age only)
    last_seen_at: Optional[datetime] = None
    active_clients: int = 0


class SwitchPortIn(BaseModel):
    port: str
    description: Optional[str] = Field(default=None, max_length=200)
    ap_id: Optional[uuid.UUID] = None
    vlan: Optional[int] = Field(default=None, ge=1, le=4094)

    @field_validator("port")
    @classmethod
    def _port(cls, v):
        if not _PORT_RE.match(v or ""):
            raise ValueError("unsupported characters in port")
        return v


class SwitchIn(BaseModel):
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    management_ip: Optional[str] = None
    vendor: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    serial_number: Optional[str] = Field(default=None, max_length=128)
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    ports: List[SwitchPortIn] = Field(default_factory=list, max_length=128)
    metadata: Optional[dict] = None

    @field_validator("management_ip")
    @classmethod
    def _mgmt(cls, v):
        return _ip(v)


class SwitchPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    management_ip: Optional[str] = None
    vendor: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    serial_number: Optional[str] = Field(default=None, max_length=128)
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    ports: Optional[List[SwitchPortIn]] = Field(default=None, max_length=128)
    active: Optional[bool] = None
    metadata: Optional[dict] = None

    @field_validator("management_ip")
    @classmethod
    def _mgmt(cls, v):
        return _ip(v)


class SwitchPortOut(BaseModel):
    port: str
    description: Optional[str] = None
    ap_id: Optional[uuid.UUID] = None
    vlan: Optional[int] = None
    link_status: str = "unknown"
    last_seen_at: Optional[datetime] = None


class SwitchOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    code: str
    name: str
    management_ip: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    ports: List[SwitchPortOut] = Field(default_factory=list)
    active: bool
    last_seen_at: Optional[datetime] = None
    metadata: Optional[dict] = None


class ControllerIn(BaseModel):
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    vendor: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    management_ip: Optional[str] = None
    adapter_kind: Optional[str] = Field(default=None, max_length=64)
    metadata: Optional[dict] = None

    @field_validator("management_ip")
    @classmethod
    def _mgmt(cls, v):
        return _ip(v)


class ControllerPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    vendor: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    management_ip: Optional[str] = None
    adapter_kind: Optional[str] = Field(default=None, max_length=64)
    active: Optional[bool] = None
    metadata: Optional[dict] = None

    @field_validator("management_ip")
    @classmethod
    def _mgmt(cls, v):
        return _ip(v)


class ControllerOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    code: str
    name: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    management_ip: Optional[str] = None
    adapter_kind: Optional[str] = None
    active: bool
    health: str
    state: str
    last_seen_at: Optional[datetime] = None
    metadata: Optional[dict] = None


class CollectorIn(BaseModel):
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    adapter_kind: str = Field(default="synthetic", max_length=64)
    is_simulated: bool = False
    config: Optional[dict] = None  # NON-secret operational settings only

    @field_validator("config")
    @classmethod
    def _no_secrets(cls, v):
        return _reject_secret_keys(v)


class CollectorPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    adapter_kind: Optional[str] = Field(default=None, max_length=64)
    active: Optional[bool] = None
    config: Optional[dict] = None

    @field_validator("config")
    @classmethod
    def _no_secrets(cls, v):
        return _reject_secret_keys(v)


class CollectorOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    code: str
    name: str
    adapter_kind: str
    is_simulated: bool
    active: bool
    revoked: bool
    token_hint: Optional[str] = None
    token_version: int
    capabilities: List[str] = Field(default_factory=list)
    adapter_health: Optional[dict] = None
    version: Optional[str] = None
    buffer_depth: int = 0
    dropped_events: int = 0
    state: str  # online | stale | offline | unknown
    last_seen_at: Optional[datetime] = None
    last_ingest_at: Optional[datetime] = None
    config: Optional[dict] = None


class CollectorCredentialResponse(BaseModel):
    """The ONLY response that ever contains a collector token. It is shown once and cannot be retrieved again."""
    collector: CollectorOut
    token: str
    note: str = "Store this token now. It is not shown again; rotate to issue a new one."


# ===========================================================================
# Monitoring / analytics responses
# ===========================================================================

class CountItem(BaseModel):
    id: uuid.UUID
    code: Optional[str] = None
    name: Optional[str] = None
    active_clients: int
    capacity: Optional[int] = None
    utilization_pct: Optional[float] = None
    level: Optional[str] = None  # warning | critical


class SiteSummary(BaseModel):
    site_id: uuid.UUID
    site_code: str
    metric: str = "active_client_associations"
    metric_note: str = (
        "Counts current client ASSOCIATIONS reported by network telemetry. It is not a count of people: "
        "one person may carry several devices and some devices are not associated at all."
    )
    total_active_clients: int
    quality: str  # live | simulated | mixed | snapshot | none
    stale: bool
    last_updated: Optional[datetime] = None
    by_zone: List[CountItem]
    by_ap: List[CountItem]
    by_floor: List[CountItem]
    unassigned_clients: int = 0  # active associations on APs without a zone
    collectors: List[CollectorOut]
    open_breaches: int
    ap_states: Dict[str, int]


class AssociationOut(BaseModel):
    client: str  # masked pseudonym
    ap_id: Optional[uuid.UUID] = None
    zone_id: Optional[uuid.UUID] = None
    radio_bssid: Optional[str] = None
    source: str
    associated_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None
    ordering_confidence: str


class AssociationPage(BaseModel):
    items: List[AssociationOut]
    total: int
    limit: int
    offset: int


class NetworkEventOut(BaseModel):
    id: uuid.UUID
    event_type: str
    client: str  # masked pseudonym
    ap_id: Optional[uuid.UUID] = None
    from_ap_id: Optional[uuid.UUID] = None
    zone_id: Optional[uuid.UUID] = None
    source_timestamp: datetime
    received_at: datetime
    source: str
    outcome: str
    outcome_detail: Optional[str] = None
    ordering_confidence: Optional[str] = None


class NetworkEventPage(BaseModel):
    items: List[NetworkEventOut]
    total: int
    limit: int
    offset: int


class SeriesPoint(BaseModel):
    t: datetime
    active_clients: int
    peak_clients: int
    quality: str


class OccupancySeries(BaseModel):
    scope: str
    scope_id: Optional[uuid.UUID] = None
    bucket_seconds: int
    points: List[SeriesPoint]
    note: str = "Active client associations over time; periods without telemetry have no points and are not interpolated."


class RoamingSummary(BaseModel):
    window_from: datetime
    window_to: datetime
    associations: int
    disassociations: int
    roams: int
    ignored_stale: int
    unique_client_pseudonyms: int
    top_transitions: List[Dict[str, Any]]
    average_association_seconds: Optional[float] = None


class BreachOut(BaseModel):
    id: uuid.UUID
    scope: str
    scope_id: uuid.UUID
    level: str
    threshold: int
    peak_clients: int
    started_at: datetime
    last_seen_at: datetime
    ended_at: Optional[datetime] = None
    active: bool


class AvailabilityOut(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    state: str
    at: datetime


class RevealRequest(BaseModel):
    client: str = Field(..., min_length=8, max_length=64)  # a pseudonym
    reason: str = Field(..., min_length=5, max_length=300)


class RevealResponse(BaseModel):
    client: str
    identifier: str


class MonitorRunResponse(BaseModel):
    samples_written: int
    breaches_open: int
    availability_changes: int


class RetentionRunResponse(BaseModel):
    events_deleted: int
    samples_deleted: int
    availability_deleted: int
    associations_deleted: int
    breaches_deleted: int


class AdapterInfo(BaseModel):
    kind: str
    simulated: bool
    description: str
    capabilities: List[str]
    production_ready: bool
