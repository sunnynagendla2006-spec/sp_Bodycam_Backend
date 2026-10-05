import enum
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from beanie import Document, TimeSeriesConfig, Granularity
from pydantic import BaseModel, Field
from pymongo import ASCENDING, IndexModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRole(str, enum.Enum):
    admin = "admin"
    control_room = "control_room"
    station = "station"
    constable = "constable"
    citizen = "citizen"


class UserStatus(str, enum.Enum):
    active = "active"
    inactive = "inactive"


class ConstableStatus(str, enum.Enum):
    available = "available"
    busy = "busy"
    offline = "offline"


class IncidentStatus(str, enum.Enum):
    new = "new"
    verified = "verified"
    rejected = "rejected"
    assigned = "assigned"
    en_route = "en_route"
    arrived = "arrived"
    resolved = "resolved"
    closed = "closed"
    needs_review = "needs_review"


class UploadStatus(str, enum.Enum):
    """
    Evidence upload lifecycle. "uploaded" only means the backend received
    and stored the file successfully -- it is NOT the same as "verified".
    """
    uploading = "uploading"
    uploaded = "uploaded"
    verified = "verified"
    rejected = "rejected"
    archived = "archived"


class AssignmentStatus(str, enum.Enum):
    pending = "pending"
    accepted = "accepted"
    rejected = "rejected"
    en_route = "en_route"
    arrived = "arrived"
    completed = "completed"


# Statuses that make an IncidentAssignment "active" -- mirrors the old
# Postgres partial-unique-index predicate (uq_active_assignment_per_incident).
ACTIVE_ASSIGNMENT_STATUSES = {
    AssignmentStatus.pending,
    AssignmentStatus.accepted,
    AssignmentStatus.en_route,
    AssignmentStatus.arrived,
}


class MediaType(str, enum.Enum):
    photo = "photo"
    audio = "audio"
    video = "video"


class DeviceStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    stale = "stale"
    recording = "recording"


class AlertType(str, enum.Enum):
    low_battery = "low_battery"
    critical_battery = "critical_battery"
    device_offline = "device_offline"
    device_stale = "device_stale"
    recording_device_offline = "recording_device_offline"
    command_failed = "command_failed"
    command_timeout = "command_timeout"


BATTERY_ALERT_TYPES = [AlertType.low_battery, AlertType.critical_battery]
NON_BATTERY_ALERT_TYPES = [
    AlertType.device_offline,
    AlertType.device_stale,
    AlertType.recording_device_offline,
    AlertType.command_failed,
    AlertType.command_timeout,
]


class AlertSeverity(str, enum.Enum):
    warning = "warning"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class RecordingTriggerType(str, enum.Enum):
    emergency_button = "emergency_button"
    manual = "manual"
    remote = "remote"
    live_stream = "live_stream"


class RecordingStatus(str, enum.Enum):
    recording = "recording"
    completed = "completed"
    cancelled = "cancelled"
    failed = "failed"


class ChunkUploadStatus(str, enum.Enum):
    uploaded = "uploaded"


class RemoteCommandType(str, enum.Enum):
    start_recording = "start_recording"
    stop_recording = "stop_recording"
    start_live_stream = "start_live_stream"
    stop_live_stream = "stop_live_stream"
    # Sets which camera the device uses for its NEXT recording -- never
    # rebinds the camera mid-recording (the app's own local volume-button
    # trigger already never does that either, see
    # mobile_app/lib/utils/volume_trigger_logic.dart's doc comment: any
    # trigger while already recording only ever stops it, to avoid
    # corrupting the upload pipeline or creating a duplicate session). If
    # a recording IS active when this arrives, the device stops it (same
    # as the existing local behavior) rather than silently ignoring the
    # command or rebinding hardware mid-capture.
    switch_camera_front = "switch_camera_front"
    switch_camera_back = "switch_camera_back"


class RemoteCommandStatus(str, enum.Enum):
    pending = "pending"
    sent = "sent"
    acknowledged = "acknowledged"
    executed = "executed"
    failed = "failed"
    timeout = "timeout"
    cancelled = "cancelled"


class LiveStreamStatus(str, enum.Enum):
    live = "live"
    ended = "ended"


class LiveStreamStartedBy(str, enum.Enum):
    self = "self"
    remote_command = "remote_command"


# ===========================================================================
# GeoJSON helpers -- replace PostGIS Geometry('POINT'/'POLYGON', srid=4326).
# Every point is [longitude, latitude], per the GeoJSON spec (and matching
# ST_X/ST_Y's existing lon/lat argument order in the old router code).
# ===========================================================================

class GeoPoint(BaseModel):
    type: str = "Point"
    coordinates: List[float]  # [lon, lat]


class GeoPolygon(BaseModel):
    type: str = "Polygon"
    coordinates: List[List[List[float]]]


class User(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    phone: Optional[str] = None
    sso_id: Optional[str] = None
    role: UserRole
    status: UserStatus = UserStatus.active
    hashed_password: Optional[str] = None
    # Which PoliceStation this user represents, for role=station users --
    # see the original models.py for the full rationale (unchanged).
    station_id: Optional[uuid.UUID] = None
    created_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "users"
        indexes = [
            IndexModel(
                [("phone", ASCENDING)],
                unique=True,
                partialFilterExpression={"phone": {"$type": "string"}},
            ),
            IndexModel(
                [("sso_id", ASCENDING)],
                unique=True,
                partialFilterExpression={"sso_id": {"$type": "string"}},
            ),
            IndexModel([("station_id", ASCENDING)]),
        ]


class PoliceStation(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: Optional[str] = None
    location: Optional[GeoPoint] = None
    jurisdiction: Optional[GeoPolygon] = None
    contact: Optional[str] = None

    class Settings:
        name = "police_stations"
        indexes = [
            IndexModel([("name", ASCENDING)]),
            IndexModel([("location", "2dsphere")]),
            IndexModel([("jurisdiction", "2dsphere")]),
        ]


class Constable(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    user_id: Optional[uuid.UUID] = None
    badge_number: Optional[str] = None
    station_id: Optional[uuid.UUID] = None
    status: ConstableStatus = ConstableStatus.offline
    battery_level: Optional[int] = None
    last_login: Optional[datetime] = None

    class Settings:
        name = "constables"
        indexes = [
            IndexModel([("badge_number", ASCENDING)], unique=True, sparse=True),
            IndexModel([("user_id", ASCENDING)]),
            IndexModel([("station_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
        ]


class ConstableLocation(Document):
    """
    Append-only GPS history. A MongoDB time-series collection (native fit --
    Postgres had no direct equivalent): `constable_id` is the metaField,
    `timestamp` is the timeField. Beanie still gives every reading its own
    `id`; queries for "latest per constable" use `.find(...).sort(-timestamp).limit(1)`
    instead of the old GROUP BY + MAX(timestamp) join-back subquery.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    constable_id: uuid.UUID
    location: GeoPoint
    accuracy: Optional[float] = None
    timestamp: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "constable_locations"
        timeseries = TimeSeriesConfig(
            time_field="timestamp",
            meta_field="constable_id",
            granularity=Granularity.seconds,
        )
        indexes = [
            IndexModel([("constable_id", ASCENDING), ("timestamp", -1)]),
        ]


class Assignment(BaseModel):
    """Embedded in Incident.assignments -- was the IncidentAssignment table."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    constable_id: uuid.UUID
    status: AssignmentStatus = AssignmentStatus.pending
    assigned_at: datetime = Field(default_factory=_utcnow)
    responded_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None


class Incident(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    display_id: Optional[str] = None
    citizen_id: Optional[uuid.UUID] = None
    location: Optional[GeoPoint] = None
    description: Optional[str] = None
    status: IncidentStatus = IncidentStatus.new
    station_id: Optional[uuid.UUID] = None
    created_at: datetime = Field(default_factory=_utcnow)

    # Assignment history lives here (embedded) since it's always accessed
    # in the context of its parent incident and is bounded in size.
    assignments: List[Assignment] = []
    # Mirrors the old uq_active_assignment_per_incident partial unique
    # index: non-None means "an active assignment already exists". Because
    # a MongoDB single-document update is atomic, a dispatch attempt does
    # `find_one_and_update({"_id": id, "active_assignment_id": None}, ...)`
    # in one round trip -- no separate constraint/retry loop is needed to
    # close the race two concurrent dispatches used to have in Postgres.
    active_assignment_id: Optional[uuid.UUID] = None

    class Settings:
        name = "incidents"
        indexes = [
            IndexModel(
                [("display_id", ASCENDING)],
                unique=True,
                partialFilterExpression={"display_id": {"$type": "string"}},
            ),
            IndexModel([("citizen_id", ASCENDING)]),
            IndexModel([("station_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("location", "2dsphere")]),
            IndexModel([("created_at", ASCENDING)]),
        ]


class Evidence(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    incident_id: uuid.UUID
    constable_id: Optional[uuid.UUID] = None  # null if uploaded by citizen
    type: MediaType
    comment: Optional[str] = None
    location: Optional[GeoPoint] = None

    # --- Server-authoritative identity/integrity fields (never client-set) -
    uploader_id: Optional[uuid.UUID] = None
    uploader_role: Optional[UserRole] = None
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    mime_type: Optional[str] = None
    upload_status: UploadStatus = UploadStatus.uploaded

    # --- Storage representation ---------------------------------------
    storage_key: Optional[str] = None
    file_path: Optional[str] = None
    original_filename: Optional[str] = None

    # --- Metadata (client-reported, never authoritative) ----------------
    evidence_metadata: Optional[dict] = None

    timestamp: datetime = Field(default_factory=_utcnow)

    # --- Verification lifecycle -----------------------------------------
    verified_by: Optional[uuid.UUID] = None
    verified_at: Optional[datetime] = None
    rejected_by: Optional[uuid.UUID] = None
    rejected_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    archived_by: Optional[uuid.UUID] = None
    archived_at: Optional[datetime] = None

    class Settings:
        name = "evidence"
        indexes = [
            IndexModel([("incident_id", ASCENDING), ("timestamp", ASCENDING)]),
            IndexModel([("uploader_id", ASCENDING)]),
            IndexModel([("upload_status", ASCENDING)]),
            IndexModel([("timestamp", ASCENDING)]),
        ]


class AuditLog(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    user_id: Optional[uuid.UUID] = None
    action: Optional[str] = None
    # Native embedded document -- was a JSON-serialized String column
    # (app/services/audit.py used to json.dumps/json.loads this by hand).
    details: Optional[dict] = None
    incident_id: Optional[uuid.UUID] = None
    evidence_id: Optional[uuid.UUID] = None
    ip_address: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "audit_logs"
        indexes = [
            IndexModel([("user_id", ASCENDING)]),
            IndexModel([("action", ASCENDING)]),
            IndexModel([("incident_id", ASCENDING)]),
            IndexModel([("evidence_id", ASCENDING)]),
            IndexModel([("timestamp", ASCENDING)]),
        ]


class Device(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    constable_id: Optional[uuid.UUID] = None
    device_identifier: str
    platform: Optional[str] = None
    app_version: Optional[str] = None
    device_model: Optional[str] = None
    status: DeviceStatus = DeviceStatus.offline
    last_heartbeat_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "devices"
        indexes = [
            IndexModel([("device_identifier", ASCENDING)], unique=True),
            IndexModel([("constable_id", ASCENDING)]),
        ]


class BatteryReading(Document):
    """Append-only battery history -- time-series collection, same reasoning as ConstableLocation."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    device_id: uuid.UUID
    battery_percent: int = Field(..., ge=0, le=100)
    is_charging: Optional[bool] = None
    recorded_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "battery_readings"
        timeseries = TimeSeriesConfig(
            time_field="recorded_at",
            meta_field="device_id",
            granularity=Granularity.seconds,
        )
        indexes = [
            IndexModel([("device_id", ASCENDING), ("recorded_at", -1)]),
        ]


class Alert(Document):
    """
    Battery-threshold/device-health/command-failure alerts. The two
    partial-unique indexes below are the direct Mongo equivalent of the old
    Postgres uq_open_battery_alert_per_device / uq_open_alert_per_device_and_type
    indexes: a plain `Alert(...).insert()` on a conflicting (device_id[,
    type], status="open") tuple raises `pymongo.errors.DuplicateKeyError`,
    which the caller catches and treats exactly like the old
    IntegrityError-triggered SAVEPOINT retry (re-fetch the winning open
    alert) -- except no explicit nested transaction is needed, since a
    single-document insert against a unique index is already atomic.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    type: AlertType
    severity: AlertSeverity
    constable_id: Optional[uuid.UUID] = None
    device_id: Optional[uuid.UUID] = None
    message: Optional[str] = None
    status: AlertStatus = AlertStatus.open
    acknowledged_by: Optional[uuid.UUID] = None
    resolved_by: Optional[uuid.UUID] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "alerts"
        indexes = [
            IndexModel([("device_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("created_at", ASCENDING)]),
            IndexModel(
                [("device_id", ASCENDING)],
                unique=True,
                partialFilterExpression={
                    "status": "open",
                    "type": {"$in": [t.value for t in BATTERY_ALERT_TYPES]},
                },
                name="uq_open_battery_alert_per_device",
            ),
            IndexModel(
                [("device_id", ASCENDING), ("type", ASCENDING)],
                unique=True,
                partialFilterExpression={
                    "status": "open",
                    "type": {"$in": [t.value for t in NON_BATTERY_ALERT_TYPES]},
                },
                name="uq_open_alert_per_device_and_type",
            ),
        ]


class Chunk(BaseModel):
    """
    Embedded in RecordingSession.chunks -- was the VideoChunk table. The old
    uq_chunk_number_per_recording partial unique index is now implicit:
    chunks only ever live inside their parent RecordingSession document, and
    a `find_one_and_update({"_id": session_id, "chunks.chunk_number": {"$ne": n}},
    {"$push": {"chunks": ...}})` is atomic per-document, so two concurrent
    uploads of the same chunk_number can't both succeed without needing a
    separate unique index or SAVEPOINT-retry loop.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    chunk_number: int
    storage_key: str
    file_size: Optional[int] = None
    duration_seconds: Optional[float] = None
    file_hash: Optional[str] = None
    mime_type: Optional[str] = None
    is_last_chunk: bool = False
    upload_status: ChunkUploadStatus = ChunkUploadStatus.uploaded
    created_at: datetime = Field(default_factory=_utcnow)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    recorded_at: Optional[datetime] = None


class RecordingSession(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    constable_id: uuid.UUID
    device_id: uuid.UUID
    trigger_type: RecordingTriggerType
    status: RecordingStatus = RecordingStatus.recording
    started_at: datetime = Field(default_factory=_utcnow)
    ended_at: Optional[datetime] = None
    incident_id: Optional[uuid.UUID] = None
    created_at: datetime = Field(default_factory=_utcnow)
    playable_status: str = "not_ready"
    playable_storage_key: Optional[str] = None
    camera_lens_direction: str = "back"
    chunks: List[Chunk] = []

    class Settings:
        name = "recording_sessions"
        indexes = [
            IndexModel([("constable_id", ASCENDING)]),
            IndexModel([("device_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("created_at", ASCENDING)]),
        ]


class RemoteCommand(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    device_id: uuid.UUID
    issued_by: uuid.UUID
    command_type: RemoteCommandType
    status: RemoteCommandStatus = RemoteCommandStatus.pending
    created_at: datetime = Field(default_factory=_utcnow)
    sent_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    result_payload: Optional[dict] = None

    class Settings:
        name = "remote_commands"
        indexes = [
            IndexModel([("device_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("created_at", ASCENDING)]),
        ]


class LiveStreamSession(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    device_id: uuid.UUID
    constable_id: uuid.UUID
    room_name: str
    status: LiveStreamStatus = LiveStreamStatus.live
    started_by: LiveStreamStartedBy
    triggering_command_id: Optional[uuid.UUID] = None
    started_at: datetime = Field(default_factory=_utcnow)
    ended_at: Optional[datetime] = None
    egress_id: Optional[str] = None
    recording_session_id: Optional[uuid.UUID] = None

    class Settings:
        name = "live_stream_sessions"
        indexes = [
            IndexModel([("device_id", ASCENDING)]),
            IndexModel([("constable_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("started_at", ASCENDING)]),
        ]


# ===========================================================================
# Authorized CCTV monitoring (separate domain from Body Camera `Device`).
#
# Deliberately NOT built on top of `Device`/`RecordingSession`: a CCTV
# camera is a fixed, station/zone-owned asset with no owning constable and
# no chunked-upload lifecycle, and its "recording" (if any) happens on an
# external NVR/VMS, never through this backend's chunk-upload pipeline. See
# app/services/cctv_security.py and app/services/cctv_providers.py for the
# SSRF-validated connectivity/streaming logic; app/routers/cctv.py is the
# only place that may read/write these two models.
# ===========================================================================

class CCTVProviderType(str, enum.Enum):
    rtsp = "rtsp"
    onvif = "onvif"
    nvr = "nvr"
    vms = "vms"


class CCTVStreamProtocol(str, enum.Enum):
    rtsp = "rtsp"
    rtsps = "rtsps"


class CCTVCameraStatus(str, enum.Enum):
    """
    `enabled` (administrative: should this camera be usable at all) and
    `status` (observed: is it actually reachable) are deliberately separate
    fields -- see app/routers/cctv.py's module docstring. A connectivity
    check that cannot reach the camera must report `unknown`, never fake
    `online`.
    """
    online = "online"
    offline = "offline"
    degraded = "degraded"
    unknown = "unknown"
    disabled = "disabled"


class CCTVStreamSessionStatus(str, enum.Enum):
    requested = "requested"
    starting = "starting"
    active = "active"
    stopped = "stopped"
    failed = "failed"


class CCTVCapabilities(BaseModel):
    """
    What THIS camera has actually been verified to support -- never assumed
    from provider_type alone. Set only from a real validate_connection()/
    ONVIF probe result (see cctv_providers.py), so the UI can honestly gate
    features (e.g. hide PTZ controls) instead of guessing from the vendor
    name. All default False -- an unknown/untested camera claims nothing.
    """
    onvif: bool = False
    rtsp: bool = False
    ptz: bool = False
    audio: bool = False
    snapshot: bool = False
    multiple_streams: bool = False


class CCTVCamera(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str
    camera_code: str
    description: Optional[str] = None
    # Informational only -- never changes which provider/protocol code path
    # handles this camera (see cctv_providers.py::get_provider, keyed on
    # provider_type, not manufacturer). A "Hikvision" camera that only
    # speaks generic RTSP is still provider_type=rtsp.
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    capabilities: CCTVCapabilities = Field(default_factory=CCTVCapabilities)
    station_id: Optional[uuid.UUID] = None
    zone: Optional[str] = None
    address: Optional[str] = None
    location: Optional[GeoPoint] = None

    provider_type: CCTVProviderType = CCTVProviderType.rtsp
    stream_protocol: CCTVStreamProtocol = CCTVStreamProtocol.rtsp
    # Connection target split into plain fields (never a single credentialed
    # URL string) -- see cctv_security.py::validate_stream_target. This also
    # means the client can never smuggle a non-rtsp scheme (file://,
    # gopher://, http(s)://, ...): `stream_protocol` is a closed enum, not a
    # free-text scheme.
    stream_host: str
    stream_port: int = 554
    stream_path: Optional[str] = None
    management_url: Optional[str] = None

    # --- Credentials: NEVER stored/returned in plaintext. `username` alone
    # is not secret; `encrypted_secret` is Fernet-encrypted ciphertext (see
    # cctv_security.py) and must never appear in any API response, log
    # line, or audit entry -- only `credentials_configured: bool` is ever
    # surfaced (see schemas.CCTVCameraResponse).
    username: Optional[str] = None
    encrypted_secret: Optional[str] = None

    enabled: bool = True
    status: CCTVCameraStatus = CCTVCameraStatus.unknown
    last_seen_at: Optional[datetime] = None
    last_status_check_at: Optional[datetime] = None
    last_error: Optional[str] = None

    # Per the authorized-camera policy (never presented as real city CCTV).
    is_demo: bool = False

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None
    updated_by: Optional[uuid.UUID] = None
    metadata: Optional[dict] = None

    class Settings:
        name = "cctv_cameras"
        indexes = [
            IndexModel([("camera_code", ASCENDING)], unique=True),
            IndexModel([("station_id", ASCENDING)]),
            IndexModel([("zone", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("location", "2dsphere")]),
        ]


class CCTVStreamSession(Document):
    """
    Ephemeral session metadata only -- NEVER the video itself (see
    app/services/cctv_providers.py). Deliberately separate from
    `LiveStreamSession` (body-cam/LiveKit) even though the shape rhymes:
    a CCTV source is pulled from an external RTSP/NVR/VMS endpoint, not
    published by a constable's own device.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    camera_id: uuid.UUID
    requested_by: uuid.UUID
    provider: CCTVProviderType
    protocol: CCTVStreamProtocol
    # Which bridging mechanism actually served this session, e.g.
    # "livekit_ingress" -- or None while that's still an unimplemented
    # extension point (see cctv_providers.py). Never a raw/credentialed URL.
    gateway: Optional[str] = None
    stream_reference: Optional[str] = None
    status: CCTVStreamSessionStatus = CCTVStreamSessionStatus.requested
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    viewer_count: int = 0
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "cctv_stream_sessions"
        indexes = [
            IndexModel([("camera_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("created_at", ASCENDING)]),
            # Direct equivalent of Alert's uq_open_*_per_device pattern: at
            # most one non-terminal (requested/starting/active) session per
            # camera at a time. A plain insert against this index is
            # already atomic, so two concurrent "start stream" requests for
            # the same camera can never both succeed -- the loser gets
            # DuplicateKeyError (see routers/cctv.py::request_stream).
            IndexModel(
                [("camera_id", ASCENDING)],
                unique=True,
                partialFilterExpression={
                    "status": {"$in": [s.value for s in (
                        CCTVStreamSessionStatus.requested,
                        CCTVStreamSessionStatus.starting,
                        CCTVStreamSessionStatus.active,
                    )]}
                },
                name="uq_active_stream_session_per_camera",
            ),
        ]


# ===========================================================================
# AP-based police presence / movement handoff.
#
# A real-world deployment has no continuous GPS indoors/in dense areas, so
# this models presence as "which authorized Wi-Fi access point is this
# device currently associated with" instead -- a coarse, zone-level signal,
# never a precise coordinate. Deliberately three separate concerns, each
# its own model (mirrors how Device/BatteryReading/Alert are split rather
# than folded into one document):
#   - AccessPoint:       the fixed infrastructure asset (like PoliceStation)
#   - PolicePresence:    current state per device (like Device.status)
#   - PresenceHandoff:   append-only movement history (like AuditLog)
#
# PresenceHandoff is deliberately NOT a time-series collection (unlike
# ConstableLocation/BatteryReading above) -- MongoDB does not support
# unique indexes on time-series collections, and a genuine unique index on
# `event_id` is exactly what makes a retried/duplicated association
# request idempotent (see services/presence.py::PresenceService). A
# regular Document with a sparse unique index is the correct trade-off
# here even though the write pattern otherwise rhymes with the time-series
# collections above.
# ===========================================================================

class AccessPointStatus(str, enum.Enum):
    online = "online"
    offline = "offline"


class PresenceConnectionStatus(str, enum.Enum):
    connected = "connected"
    stale = "stale"
    disconnected = "disconnected"


class PresenceEventSource(str, enum.Enum):
    """
    Server-determined, NEVER accepted from a request body (see
    routers/presence.py) -- distinguishes a genuine AP/edge-reported
    association from a future development-only simulator path. Only
    `real` is ever actually produced by any endpoint that exists today;
    `simulator` is reserved for a not-yet-built dev-only endpoint.
    """
    real = "REAL"
    simulator = "SIMULATOR"


class AccessPoint(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    code: str  # natural key, e.g. "AP-01"
    name: str  # e.g. "Main Gate"
    description: Optional[str] = None
    zone: Optional[str] = None  # e.g. "MAIN_GATE" -- coarse zone label, not a precise location
    deployment: Optional[str] = None  # groups APs into one coverage deployment, e.g. "DEMO JATARA ZONE"
    station_id: Optional[uuid.UUID] = None
    location: Optional[GeoPoint] = None  # optional, for map display only -- presence/handoff logic never queries by distance
    coverage_radius_m: Optional[float] = None  # display/admin-config only, same as `location` -- presence/handoff logic never queries by distance
    # Placeholder for a future physical AP's own hardware/edge-controller
    # address -- unused by any business logic today (every AP in this
    # codebase is virtual/simulated). Admin-configurable now so the data
    # model doesn't need another migration the day a real AP is added --
    # see docs/VIRTUAL_AP_POLICE_PRESENCE.md's "virtual -> physical" plan.
    edge_node_id: Optional[str] = None
    enabled: bool = True
    status: AccessPointStatus = AccessPointStatus.online
    is_demo: bool = False
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None
    updated_by: Optional[uuid.UUID] = None

    class Settings:
        name = "access_points"
        indexes = [
            IndexModel([("code", ASCENDING)], unique=True),
            IndexModel([("station_id", ASCENDING)]),
            IndexModel([("deployment", ASCENDING)]),
            IndexModel([("zone", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
            IndexModel([("location", "2dsphere")]),
        ]


class PolicePresence(Document):
    """
    One row per device -- the current AP-association analogue of
    Device.status/last_seen_at. `handoff_count`/`current_zone_since` are
    maintained here (not recomputed from PresenceHandoff on every read) so
    reads stay O(1); they are only ever mutated by
    services/presence.py::PresenceService, never written directly by a
    router.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    device_id: uuid.UUID
    constable_id: uuid.UUID
    current_access_point_id: Optional[uuid.UUID] = None
    current_zone: Optional[str] = None
    status: PresenceConnectionStatus = PresenceConnectionStatus.disconnected
    location_source: str = "ACCESS_POINT"
    last_event_id: Optional[str] = None
    last_seen_at: Optional[datetime] = None
    handoff_count: int = 0
    current_zone_since: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "police_presence"
        indexes = [
            IndexModel([("device_id", ASCENDING)], unique=True),
            IndexModel([("constable_id", ASCENDING)]),
            IndexModel([("current_access_point_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
        ]


class PresenceHandoff(Document):
    """
    Append-only. One row per actual association CHANGE -- a repeated
    heartbeat to the SAME access point never creates a row here (see
    PresenceService.process_association). `previous_access_point_id` is
    None only for a device's very first-ever association (nothing to hand
    off from).
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    device_id: uuid.UUID
    constable_id: uuid.UUID
    previous_access_point_id: Optional[uuid.UUID] = None
    access_point_id: uuid.UUID
    event_id: Optional[str] = None
    source: PresenceEventSource = PresenceEventSource.real
    occurred_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "presence_handoffs"
        indexes = [
            IndexModel([("device_id", ASCENDING), ("occurred_at", -1)]),
            IndexModel([("constable_id", ASCENDING)]),
            IndexModel([("access_point_id", ASCENDING)]),
            IndexModel([("source", ASCENDING)]),
            # The actual idempotency safety net for a retried/duplicated
            # request carrying the same client-supplied event_id -- see
            # PresenceService.process_association's DuplicateKeyError
            # handling. PARTIAL, not sparse: Beanie stores an omitted
            # Optional field as an explicit `null`, not an absent field --
            # a `sparse` index still indexes an explicit null (MongoDB
            # only excludes documents truly MISSING the field), so every
            # handoff with no event_id would collide on the same null
            # entry after the very first one. A partial index with an
            # explicit $type filter is the only thing that actually
            # excludes `null`/omitted values -- confirmed the hard way:
            # running this for real against a live MongoDB produced
            # exactly that collision (second handoff for a device wrongly
            # reported as a duplicate of the first). This mirrors the
            # same partialFilterExpression pattern already used on
            # User.phone/User.sso_id/Incident.display_id above -- NOT the
            # `sparse=True` used on Constable.badge_number, which only
            # avoids this bug today because every real caller always
            # supplies a badge_number; event_id is routinely omitted.
            IndexModel(
                [("event_id", ASCENDING)],
                unique=True,
                partialFilterExpression={"event_id": {"$type": "string"}},
            ),
        ]


class DeploymentStatus(str, enum.Enum):
    active = "active"
    ended = "ended"


class Deployment(Document):
    """
    Lightweight metadata for a named event/operation (e.g. a Jatara) that
    groups a set of AccessPoints together -- deliberately NOT the same
    concept as `Incident` (a citizen-reported, single-location event) or
    a full scheduling system. `AccessPoint.deployment` (a plain string,
    already in use and already seeded) is the actual linkage -- this
    model only adds the admin-configurable name/status/time-window
    metadata that a bare string can't carry, matched by name. No
    migration of AccessPoint is needed: an AccessPoint whose `deployment`
    string has no matching Deployment row still works exactly as before,
    it just has no status/time-window metadata attached.

    Zones are deliberately NOT a separate stored entity -- see
    app/routers/access_points.py::list_zones. A zone is a derived view
    over the distinct AccessPoint.zone values within a deployment, not a
    new collection, per the explicit "don't create a duplicate concept"
    principle: every zone-level fact (police count, moving count,
    enabled) is already fully computable from AccessPoint + PolicePresence.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str  # natural key, e.g. "JATARA-DEMO-001"
    description: Optional[str] = None
    status: DeploymentStatus = DeploymentStatus.active
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    is_demo: bool = False
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None

    class Settings:
        name = "deployments"
        indexes = [
            IndexModel([("name", ASCENDING)], unique=True),
            IndexModel([("status", ASCENDING)]),
        ]


DOCUMENT_MODELS = [
    User,
    PoliceStation,
    Constable,
    ConstableLocation,
    Incident,
    Evidence,
    AuditLog,
    Device,
    BatteryReading,
    Alert,
    RecordingSession,
    RemoteCommand,
    LiveStreamSession,
    CCTVCamera,
    CCTVStreamSession,
    AccessPoint,
    PolicePresence,
    PresenceHandoff,
    Deployment,
]
