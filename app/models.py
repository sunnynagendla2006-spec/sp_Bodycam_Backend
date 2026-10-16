import enum
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from beanie import Document, TimeSeriesConfig, Granularity
from pydantic import BaseModel, Field
from pymongo import ASCENDING, IndexModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def location_retention_days() -> int:
    """How long location history is kept (LOCATION_RETENTION_DAYS, default 30; 0 is treated as the default, never 'forever')."""
    try:
        days = int(os.getenv("LOCATION_RETENTION_DAYS", "30"))
    except ValueError:
        days = 30
    return days if days > 0 else 30


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
    last_location_point: Optional[GeoPoint] = None
    last_location_at: Optional[datetime] = None
    last_location_accuracy: Optional[float] = None
    last_location_sequence: Optional[int] = None
    # Device-clock time of the fix the projection above reflects. Freshness
    # (live/delayed/stale) is ALWAYS derived from this, never from
    # last_location_at (server receipt), so an old buffered fix that is
    # uploaded late can never look like a live position.
    last_location_recorded_at: Optional[datetime] = None
    current_geographic_zone: Optional[str] = None  # DETECTED zone (from coordinates)
    zone_status: Optional[str] = None
    zone_changed_at: Optional[datetime] = None
    # Hysteresis state: a differing zone must be observed on consecutive
    # trusted fixes before it replaces current_geographic_zone.
    zone_candidate: Optional[str] = None
    zone_candidate_count: int = 0
    # ASSIGNED duty zone (EventZone.code) -- administrative intent, stored
    # separately from the detected zone above.
    assigned_zone_code: Optional[str] = None
    assigned_zone_updated_at: Optional[datetime] = None
    assigned_zone_updated_by: Optional[uuid.UUID] = None
    active_duty_session_id: Optional[uuid.UUID] = None

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
    device_id: Optional[uuid.UUID] = None
    sequence_number: Optional[int] = None
    recorded_at: Optional[datetime] = None
    server_received_at: datetime = Field(default_factory=_utcnow)
    geographic_zone: Optional[str] = None
    zone_status: Optional[str] = "CONFIRMED"
    source: str = "GNSS"
    deployment: Optional[str] = None
    is_stale: bool = False
    duty_session_id: Optional[uuid.UUID] = None
    # True when the fix reached the server long after it was recorded
    # (queued while offline). Buffered fixes are history, never "live".
    buffered: bool = False
    # False when this fix was older than the position projection already
    # held (out-of-order arrival) and therefore did not move the marker.
    advanced_projection: bool = True

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


class EnrolmentStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    revoked = "revoked"


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
    # Enrolment approval. Documents written before this field existed load
    # as `approved` (they were already in service); new self-registrations
    # are stored as `pending` by routers/devices.py unless
    # DEVICE_AUTO_APPROVE is explicitly enabled. Only an `approved` device
    # may start a duty session / submit tracked locations.
    enrolment_status: EnrolmentStatus = EnrolmentStatus.approved
    enrolment_reviewed_by: Optional[uuid.UUID] = None
    enrolment_reviewed_at: Optional[datetime] = None
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
    # --- Evidence preservation (all optional; chunks stored before this existed simply have none) ---
    # `storage_key`/`file_hash` describe the SERVED media (possibly watermarked). The bytes exactly as
    # captured by the phone are kept separately and never rewritten:
    original_storage_key: Optional[str] = None
    original_hash: Optional[str] = None  # SHA-256 of the captured bytes (client-declared and server-verified when supplied)
    original_size: Optional[int] = None
    derived_hash: Optional[str] = None  # SHA-256 of the watermarked/derived media (same as file_hash when a derivative exists)
    processing: List[dict] = Field(default_factory=list)  # custody/provenance: {step, at, tool, input_hash, output_hash}
    received_via: str = "central"  # central | site_receiver
    receiver_id: Optional[uuid.UUID] = None
    captured_start: Optional[datetime] = None
    captured_end: Optional[datetime] = None
    site_received_at: Optional[datetime] = None  # when the site receiver durably stored it


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
    # Site transport (optional): recordings made at a site, possibly received by a local receiver first.
    site_id: Optional[uuid.UUID] = None
    receiver_id: Optional[uuid.UUID] = None
    origin: str = "central"  # central | site_receiver
    grant_id: Optional[uuid.UUID] = None
    flags: List[str] = Field(default_factory=list)  # e.g. grant_revoked_later
    chunks: List[Chunk] = []

    class Settings:
        name = "recording_sessions"
        indexes = [
            IndexModel([("constable_id", ASCENDING)]),
            IndexModel([("device_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("created_at", ASCENDING)]),
            IndexModel([("site_id", ASCENDING), ("created_at", -1)]),
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

    # --- Building association (all optional: cameras registered before
    # buildings existed simply have building_id=None and keep working as
    # standalone cameras -- see app/routers/cctv_buildings.py).
    building_id: Optional[uuid.UUID] = None
    # NVR/DVR channel number. Only meaningful when the building's
    # connection_mode is "nvr"; the RTSP path is built from the building's
    # recorder settings plus this number (see services/cctv_sources.py).
    channel: Optional[int] = None
    sort_order: int = 0
    # Health-monitor bookkeeping (services/cctv_health.py): bounded retry
    # with exponential backoff instead of re-probing a dead camera every cycle.
    consecutive_failures: int = 0
    next_check_at: Optional[datetime] = None

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None
    updated_by: Optional[uuid.UUID] = None
    metadata: Optional[dict] = None

    class Settings:
        name = "cctv_cameras"
        indexes = [
            IndexModel([("building_id", ASCENDING), ("sort_order", ASCENDING)]),
            IndexModel([("camera_code", ASCENDING)], unique=True),
            IndexModel([("station_id", ASCENDING)]),
            IndexModel([("zone", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("location", "2dsphere")]),
        ]


class CCTVConnectionMode(str, enum.Enum):
    """How a building's cameras are reached. NVR/DVR is the preferred default: one recorder endpoint, cameras addressed by channel number."""
    nvr = "nvr"
    direct_ip = "direct_ip"


class CCTVNetworkAccess(str, enum.Enum):
    """
    How the backend/gateway reaches the building's network. Informational
    plus policy: only `public_direct` implies a public endpoint the building
    owner has deliberately exposed. VPN/tunnel/LAN do not require any public
    IP at all.
    """
    vpn = "vpn"
    tunnel = "tunnel"
    lan = "lan"
    public_direct = "public_direct"


class CCTVVendorPreset(str, enum.Enum):
    """Explicit RTSP path presets for NVR channels. `custom` means the admin supplies the template; no vendor format is ever guessed."""
    hikvision = "hikvision"
    dahua = "dahua"
    custom = "custom"


class Building(Document):
    """
    A monitored building: ONE control-room slot, MANY cameras (CCTVCamera
    rows with building_id == this id). The camera count is never stored --
    it is always derived from the camera rows so it cannot drift.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str
    code: str
    owner_name: Optional[str] = None
    owner_contact: Optional[str] = None
    zone: Optional[str] = None
    address: Optional[str] = None
    location: Optional[GeoPoint] = None

    # Public/static IP of the building's router or firewall, when it has one
    # and it is relevant. NOT interchangeable with recorder_host or any
    # camera's host (those are normally private addresses behind it).
    public_ip: Optional[str] = None
    connection_mode: CCTVConnectionMode = CCTVConnectionMode.nvr
    network_access: CCTVNetworkAccess = CCTVNetworkAccess.vpn
    # Admin-controlled, per-building SSRF authorization: CIDRs the backend and
    # media gateway may connect to for THIS building's cameras (e.g. the VPN
    # subnet the recorder lives on). Validated by
    # cctv_security.parse_authorized_networks; the global allowlist and the
    # permanently blocked ranges are unaffected.
    authorized_networks: List[str] = Field(default_factory=list)

    # NVR/DVR settings (connection_mode == nvr).
    recorder_vendor: CCTVVendorPreset = CCTVVendorPreset.custom
    recorder_protocol: CCTVStreamProtocol = CCTVStreamProtocol.rtsp
    recorder_host: Optional[str] = None
    recorder_port: int = 554
    # Path template with an optional {channel} placeholder; empty for presets.
    stream_path_template: Optional[str] = None
    recorder_username: Optional[str] = None
    recorder_encrypted_secret: Optional[str] = None  # Fernet ciphertext, never returned

    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None
    updated_by: Optional[uuid.UUID] = None

    class Settings:
        name = "cctv_buildings"
        indexes = [
            IndexModel([("code", ASCENDING)], unique=True),
            IndexModel([("zone", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
            IndexModel([("name", ASCENDING)]),
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
    """
    LEGACY stored value. Only a verified integration may ever make this
    `online`/`offline`; a freshly registered AP is `unknown`. API responses
    expose the derived `reachability` instead (see routers/access_points.py).
    """
    online = "online"
    offline = "offline"
    unknown = "unknown"


class APVerificationStatus(str, enum.Enum):
    registered = "registered"  # inventory row only; nothing configured to check
    configured = "configured"  # identifiers (BSSID etc.) recorded, NOT verified
    verified = "verified"  # confirmed by a real controller/API or authorised telemetry
    verification_failed = "verification_failed"  # last attempt against a configured integration failed


class APLifecycleStatus(str, enum.Enum):
    active = "active"
    disabled = "disabled"  # reversible administrative hold
    retired = "retired"  # decommissioned; terminal, history retained


class APIntegrationHealth(str, enum.Enum):
    unconfigured = "unconfigured"  # no controller integration available for this AP
    unknown = "unknown"  # configured but never checked
    healthy = "healthy"
    degraded = "degraded"
    error = "error"


class APConfigChange(BaseModel):
    at: datetime = Field(default_factory=_utcnow)
    by: Optional[uuid.UUID] = None
    action: str  # created / updated / enabled / disabled / retired / verified / ...
    changes: dict = Field(default_factory=dict)  # {field: {"from": x, "to": y}} -- never secrets


class PresenceConnectionStatus(str, enum.Enum):
    connected = "connected"
    stale = "stale"
    disconnected = "disconnected"


class PresenceEventSource(str, enum.Enum):
    """
    Server-determined, NEVER accepted from a request body -- distinguishes a
    genuine AP/edge-reported association from a simulator path.
    """
    real = "REAL"
    simulator = "SIMULATOR"
    controller = "PHYSICAL_CONTROLLER"


class APRadio(BaseModel):
    """One radio of an AP. A BSSID is per radio/SSID and is NOT the AP's management IP or a client MAC."""
    band: Optional[str] = None  # "2.4GHz" | "5GHz" | "6GHz" (as the source reports it)
    channel: Optional[int] = None
    bssid: Optional[str] = None  # normalised aa:bb:cc:dd:ee:ff
    ssid: Optional[str] = None


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
    # --- Real-world inventory ------------------------------------------------
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    bssid: Optional[str] = None  # normalised aa:bb:cc:dd:ee:ff (lower-case)
    ssid: Optional[str] = None
    management_ip: Optional[str] = None
    controller_source: Optional[str] = None  # which controller/NMS this AP is managed from
    building: Optional[str] = None
    floor: Optional[str] = None
    event_zone_codes: List[str] = Field(default_factory=list)  # EventZone.code values this AP serves
    # --- Lifecycle / verification / telemetry (never inferred from admin edits)
    enabled: bool = True  # kept in sync with lifecycle_status == active
    lifecycle_status: APLifecycleStatus = APLifecycleStatus.active
    status: AccessPointStatus = AccessPointStatus.unknown
    verification_status: APVerificationStatus = APVerificationStatus.registered
    verification_source: Optional[str] = None  # CONTROLLER_API / EDGE_TELEMETRY
    verified_at: Optional[datetime] = None
    last_verification_attempt_at: Optional[datetime] = None
    last_verification_error: Optional[str] = None
    last_seen_at: Optional[datetime] = None  # last REAL telemetry/controller report
    integration_health: APIntegrationHealth = APIntegrationHealth.unconfigured
    integration_checked_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    retire_reason: Optional[str] = None
    config_history: List[APConfigChange] = Field(default_factory=list)
    is_demo: bool = False
    # --- Generic-site placement (all optional; older APs simply have none of these) ---
    site_id: Optional[uuid.UUID] = None
    site_zone_id: Optional[uuid.UUID] = None  # SiteZone.id
    site_building_id: Optional[uuid.UUID] = None
    site_floor_id: Optional[uuid.UUID] = None
    controller_id: Optional[uuid.UUID] = None
    switch_id: Optional[uuid.UUID] = None
    switch_port: Optional[str] = None
    environment: str = "unknown"  # indoor | outdoor | unknown
    radios: List[APRadio] = Field(default_factory=list)
    ssids: List[str] = Field(default_factory=list)
    plan_x: Optional[float] = None  # position on the floor plan, normalized 0..1
    plan_y: Optional[float] = None
    client_capacity: Optional[int] = None  # per-AP override of the site's AP thresholds
    last_telemetry_state: str = "unknown"  # online | stale | offline (derived; availability history)
    network_metadata: Optional[dict] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None
    updated_by: Optional[uuid.UUID] = None

    class Settings:
        name = "access_points"
        indexes = [
            IndexModel([("code", ASCENDING)], unique=True),
            IndexModel([("bssid", ASCENDING)], unique=True, partialFilterExpression={"bssid": {"$type": "string"}}),
            IndexModel(
                [("manufacturer", ASCENDING), ("serial_number", ASCENDING)],
                unique=True,
                partialFilterExpression={"serial_number": {"$type": "string"}},
            ),
            IndexModel([("site_id", ASCENDING), ("site_zone_id", ASCENDING)]),
            IndexModel([("site_id", ASCENDING), ("management_ip", ASCENDING)]),
            IndexModel([("radios.bssid", ASCENDING)]),
            IndexModel([("lifecycle_status", ASCENDING)]),
            IndexModel([("verification_status", ASCENDING)]),
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
    # Who reported this association: PHYSICAL_CONTROLLER (real network
    # telemetry), REAL (the device's own claim) or SIMULATOR (demo only).
    source: Optional[PresenceEventSource] = None
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


class ZoneType(str, enum.Enum):
    security = "SECURITY"
    crowd_control = "CROWD_CONTROL"
    parking = "PARKING"
    temple = "TEMPLE"
    main_gate = "MAIN_GATE"
    emergency_route = "EMERGENCY_ROUTE"
    perimeter = "PERIMETER"
    other = "OTHER"


class EventZone(Document):
    """
    Geographic operational zone defined by a GeoJSON polygon boundary in WGS84
    [longitude, latitude] coordinates.
    Deliberately distinct from coarse AccessPoint.zone (AP association):
    this models the real physical geographic area of an event (e.g. Main Gate,
    Temple Sanctum, Parking, Emergency Route).
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    code: str  # Unique natural key, e.g. "ZONE-MAIN-GATE"
    name: str  # Display name, e.g. "Main Entrance & Security Checkpoint"
    description: Optional[str] = None
    deployment: Optional[str] = None  # Linkage to Deployment.name, e.g. "JATARA-DEMO-001"
    zone_type: ZoneType = ZoneType.security
    polygon: GeoPolygon  # Valid GeoJSON polygon with [lon, lat] coordinates
    priority: int = 0  # Deterministic overlap resolution: higher priority wins
    enabled: bool = True
    color: Optional[str] = "#3B82F6"  # Optional hex color for UI map rendering
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None
    updated_by: Optional[uuid.UUID] = None

    class Settings:
        name = "event_zones"
        indexes = [
            IndexModel([("code", ASCENDING)], unique=True),
            IndexModel([("deployment", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
            IndexModel([("priority", -1)]),
            IndexModel([("polygon", "2dsphere")]),
        ]


class DutySessionStatus(str, enum.Enum):
    active = "active"
    ended = "ended"


class DutySession(Document):
    """
    An explicitly started, officer-authorised period during which location
    tracking is permitted. Location fixes are only accepted for an active
    session (or for a fix recorded while a now-ended session was active, so
    a queue flushed just after "stop" is not lost). A partial unique index
    enforces at most ONE active session per constable at the database level.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    constable_id: uuid.UUID
    device_id: uuid.UUID
    device_identifier: str
    status: DutySessionStatus = DutySessionStatus.active
    started_at: datetime = Field(default_factory=_utcnow)
    ended_at: Optional[datetime] = None
    end_reason: Optional[str] = None  # officer_stopped / admin_ended / device_revoked
    ended_by: Optional[uuid.UUID] = None
    assigned_zone_code: Optional[str] = None  # snapshot of the duty zone at start
    fix_count: int = 0

    class Settings:
        name = "duty_sessions"
        indexes = [
            IndexModel(
                [("constable_id", ASCENDING)],
                unique=True,
                partialFilterExpression={"status": "active"},
                name="uq_one_active_duty_session_per_constable",
            ),
            IndexModel([("constable_id", ASCENDING), ("started_at", -1)]),
            IndexModel([("status", ASCENDING)]),
        ]


class LocationIngestKey(Document):
    """
    Idempotency ledger for location ingestion: ConstableLocation is a
    time-series collection (no unique indexes allowed), so duplicate
    prevention lives here. The (duty_session_id, sequence_number) unique
    index is what makes a retried/replayed fix a no-op even under a race.
    Rows expire with the location-retention window.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    duty_session_id: uuid.UUID
    sequence_number: int
    constable_id: uuid.UUID
    created_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "location_ingest_keys"
        indexes = [
            IndexModel([("duty_session_id", ASCENDING), ("sequence_number", ASCENDING)], unique=True),
            IndexModel([("created_at", ASCENDING)], expireAfterSeconds=location_retention_days() * 86400),
        ]


class EdgeControllerEventLog(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    controller_event_id: str  # unique event ID from the physical AP controller/edge collector
    controller_id: str  # identity of the authorized edge collector or controller
    ap_code: Optional[str] = None
    ap_bssid: Optional[str] = None
    device_identifier: Optional[str] = None
    station_mac: Optional[str] = None  # observed client MAC, correlation only (subject to Android MAC randomization)
    authenticated_identity: Optional[str] = None  # 802.1X / captive portal username or badge
    event_type: str  # association, disassociation, roam
    occurred_at: datetime
    server_received_at: datetime = Field(default_factory=_utcnow)
    status: str  # accepted, duplicate_ignored, unmapped_device, disassociated, unmapped_ap
    details: Optional[dict] = None

    class Settings:
        name = "edge_controller_events"
        indexes = [
            IndexModel([("controller_event_id", ASCENDING)], unique=True),
            IndexModel([("controller_id", ASCENDING), ("server_received_at", -1)]),
            IndexModel([("device_identifier", ASCENDING)]),
            IndexModel([("server_received_at", -1)]),
        ]


# ===========================================================================
# Generic monitored sites and network telemetry (Network Hopping platform).
#
# Hierarchy:  Site -> Zone -> network infrastructure (APs, switches, controllers)
# Optional:   Site -> Building -> Floor -> Zone   (buildings/floors are NEVER required;
#             an open festival ground or outdoor campus uses zones only).
#
# Deliberately separate from the older police-presence models (AccessPoint is
# extended additively; PolicePresence/PresenceHandoff are untouched) and from the
# CCTV `Building` (SiteBuilding may reference it via cctv_building_id).
# ===========================================================================

class SiteType(str, enum.Enum):
    campus = "campus"
    building = "building"
    mall = "mall"
    hospital = "hospital"
    transport_hub = "transport_hub"  # railway/bus station
    airport = "airport"
    stadium = "stadium"
    convention_centre = "convention_centre"
    festival = "festival"
    outdoor_grounds = "outdoor_grounds"
    industrial = "industrial"
    custom = "custom"  # pair with MonitoredSite.custom_type_label


class SiteMonitoringScope(str, enum.Enum):
    """Which client devices may be tracked at all. `allowlist` is the default: nothing is tracked unless the site explicitly authorizes it."""
    allowlist = "allowlist"  # only pseudonyms in SitePolicy.allowlist
    all_clients = "all_clients_pseudonymized"  # every client, pseudonymized; requires an authorization reference


class SitePolicy(BaseModel):
    scope_mode: SiteMonitoringScope = SiteMonitoringScope.allowlist
    authorization_reference: Optional[str] = None  # who/what authorizes monitoring (required for all_clients)
    retention_days: int = 30
    # Raw client identifiers are NOT stored unless this is on AND CLIENT_RAW_ID_KEY is configured.
    store_raw_identifiers: bool = False
    allowlist: List[str] = Field(default_factory=list)  # client PSEUDONYMS (never raw identifiers)


class MonitoredSite(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    code: str
    name: str
    site_type: SiteType = SiteType.custom
    custom_type_label: Optional[str] = None
    organization: Optional[str] = None  # tenant label; there is no Organization collection in this architecture
    description: Optional[str] = None
    address: Optional[str] = None
    location: Optional[GeoPoint] = None
    boundary: Optional[GeoPolygon] = None
    timezone: str = "UTC"
    active: bool = True
    # `restricted` sites are visible to admins and to the control_room users in viewer_user_ids only.
    access_mode: str = "all_control_room"
    viewer_user_ids: List[uuid.UUID] = Field(default_factory=list)
    policy: SitePolicy = Field(default_factory=SitePolicy)
    # Per-AP load thresholds (active clients). Zones carry their own thresholds.
    ap_warning_clients: Optional[int] = None
    ap_critical_clients: Optional[int] = None
    metadata: Optional[dict] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None
    updated_by: Optional[uuid.UUID] = None

    class Settings:
        name = "monitored_sites"
        indexes = [
            IndexModel([("code", ASCENDING)], unique=True),
            IndexModel([("active", ASCENDING)]),
            IndexModel([("organization", ASCENDING)]),
            IndexModel([("location", "2dsphere")]),
        ]


class SiteBuilding(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    code: str
    name: str
    description: Optional[str] = None
    cctv_building_id: Optional[uuid.UUID] = None  # optional link to the CCTV Building; no duplication of its data
    location: Optional[GeoPoint] = None
    metadata: Optional[dict] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "site_buildings"
        indexes = [IndexModel([("site_id", ASCENDING), ("code", ASCENDING)], unique=True)]


class SiteFloor(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    building_id: Optional[uuid.UUID] = None
    code: str
    name: str
    level: Optional[int] = None  # display ordering / 3D stacking (basements negative)
    height_m: Optional[float] = None  # storey height, used only for the layered view
    plan_storage_key: Optional[str] = None  # floor-plan image in the evidence storage backend
    plan_mime: Optional[str] = None
    plan_width_px: Optional[int] = None
    plan_height_px: Optional[int] = None
    plan_meters_per_pixel: Optional[float] = None
    display_order: int = 0
    metadata: Optional[dict] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "site_floors"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("code", ASCENDING)], unique=True),
            IndexModel([("site_id", ASCENDING), ("building_id", ASCENDING), ("display_order", ASCENDING)]),
        ]


class SiteZone(Document):
    """Indoor and outdoor zones alike. A zone needs neither a floor nor coordinates; give it a geographic boundary, a floor-plan polygon, both, or neither."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    code: str
    name: str
    zone_type: str = "general"  # free text: custom zone types are allowed
    description: Optional[str] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    boundary: Optional[GeoPolygon] = None  # WGS84 [lon, lat]
    plan_polygon: Optional[List[List[float]]] = None  # [[x, y], ...] normalized 0..1 on the floor plan
    capacity: Optional[int] = None
    warning_threshold: Optional[int] = None  # active clients
    critical_threshold: Optional[int] = None
    active: bool = True
    display_order: int = 0
    metadata: Optional[dict] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "site_zones"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("code", ASCENDING)], unique=True),
            IndexModel([("site_id", ASCENDING), ("floor_id", ASCENDING)]),
            IndexModel([("boundary", "2dsphere")]),
        ]


class SwitchPort(BaseModel):
    port: str  # as the switch labels it, e.g. "Gi1/0/12"
    description: Optional[str] = None
    ap_id: Optional[uuid.UUID] = None
    vlan: Optional[int] = None
    link_status: str = "unknown"  # up | down | unknown (only set when a source reports it)
    last_seen_at: Optional[datetime] = None


class NetworkSwitch(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    code: str
    name: str
    management_ip: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    ports: List[SwitchPort] = Field(default_factory=list)
    active: bool = True
    last_seen_at: Optional[datetime] = None  # only ever set by a real telemetry source
    metadata: Optional[dict] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "network_switches"
        indexes = [IndexModel([("site_id", ASCENDING), ("code", ASCENDING)], unique=True)]


class NetworkController(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    code: str
    name: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    management_ip: Optional[str] = None
    adapter_kind: Optional[str] = None
    active: bool = True
    health: str = "unknown"  # unknown | healthy | degraded | error (reported by a collector)
    last_seen_at: Optional[datetime] = None
    metadata: Optional[dict] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "network_controllers"
        indexes = [IndexModel([("site_id", ASCENDING), ("code", ASCENDING)], unique=True)]


class Collector(Document):
    """A site's LAN collector. It authenticates with its OWN credential, which is bound to exactly one site; the site is never taken from a request body."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    code: str
    name: str
    adapter_kind: str = "synthetic"
    is_simulated: bool = False  # server-side truth: everything this collector sends is labelled SYNTHETIC
    # Credential: only a SHA-256 of the secret part is stored. The token is shown once on create/rotate.
    token_hash: Optional[str] = None
    token_hint: Optional[str] = None  # last 4 characters, to tell tokens apart in the UI
    token_version: int = 1
    previous_token_hash: Optional[str] = None  # still accepted until previous_valid_until (rolling rotation)
    previous_valid_until: Optional[datetime] = None
    revoked: bool = False
    active: bool = True
    capabilities: List[str] = Field(default_factory=list)
    adapter_health: Optional[dict] = None
    version: Optional[str] = None
    buffer_depth: int = 0
    dropped_events: int = 0
    last_seen_at: Optional[datetime] = None  # last heartbeat or ingest
    last_ingest_at: Optional[datetime] = None
    last_state: str = "unknown"  # online | stale | offline (derived, for availability history)
    config: Optional[dict] = None  # non-secret operational config only
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None

    class Settings:
        name = "network_collectors"
        indexes = [IndexModel([("site_id", ASCENDING), ("code", ASCENDING)], unique=True)]


class ClientAssociation(Document):
    """
    CURRENT association state, one document per (site, client pseudonym).
    History lives in NetworkEvent; this row is only ever changed by
    services/site_events.py using a version-guarded compare-and-set.
    `state == "active"` rows are the ONLY thing counted as connected clients.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    client_pseudonym: str
    state: str = "closed"  # active | closed
    ap_id: Optional[uuid.UUID] = None
    ap_ref: Optional[str] = None  # the source's identifier for the AP (BSSID etc.)
    radio_bssid: Optional[str] = None
    zone_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    building_id: Optional[uuid.UUID] = None
    source: str = "REAL"  # REAL | SYNTHETIC | SNAPSHOT
    associated_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None  # SOURCE timestamp of the event that last set this state
    last_event_key: Optional[str] = None  # "<collector>:<event id>" of that event (tie-break)
    last_seq: Optional[int] = None
    seq_stream: Optional[str] = None
    ordering_confidence: str = "timestamp"  # sequence | timestamp | tie_break | snapshot
    previous_ap_id: Optional[uuid.UUID] = None
    closed_at: Optional[datetime] = None
    close_reason: Optional[str] = None
    raw_identifier_encrypted: Optional[str] = None  # only when the site policy and key allow it
    version: int = 0
    updated_at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "client_associations"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("client_pseudonym", ASCENDING)], unique=True),
            IndexModel([("site_id", ASCENDING), ("state", ASCENDING), ("ap_id", ASCENDING)]),
            IndexModel([("site_id", ASCENDING), ("state", ASCENDING), ("zone_id", ASCENDING)]),
            IndexModel([("site_id", ASCENDING), ("state", ASCENDING), ("floor_id", ASCENDING)]),
            IndexModel([("state", ASCENDING), ("updated_at", ASCENDING)]),
        ]


class NetworkEvent(Document):
    """Append-only history of every accepted ingest event, including ones that did not change state (outcome says why)."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    collector_id: uuid.UUID
    event_id: str  # unique per collector: the idempotency key
    event_type: str  # association | disassociation | roam
    client_pseudonym: str
    ap_id: Optional[uuid.UUID] = None
    ap_ref: Optional[str] = None
    from_ap_id: Optional[uuid.UUID] = None
    radio_bssid: Optional[str] = None
    zone_id: Optional[uuid.UUID] = None
    source_timestamp: datetime
    received_at: datetime = Field(default_factory=_utcnow)
    source_seq: Optional[int] = None
    seq_stream: Optional[str] = None
    session_id: Optional[str] = None
    source: str = "REAL"
    # received (not yet processed) | applied | stale | duplicate_state | ap_mismatch | no_active | unknown_ap | out_of_scope | uncertain
    outcome: str = "received"
    outcome_detail: Optional[str] = None
    ordering_confidence: Optional[str] = None

    class Settings:
        name = "network_events"
        indexes = [
            IndexModel([("collector_id", ASCENDING), ("event_id", ASCENDING)], unique=True),
            IndexModel([("site_id", ASCENDING), ("source_timestamp", -1)]),
            IndexModel([("site_id", ASCENDING), ("event_type", ASCENDING), ("source_timestamp", -1)]),
            IndexModel([("client_pseudonym", ASCENDING), ("source_timestamp", -1)]),
            IndexModel([("received_at", ASCENDING)]),
        ]


class OccupancySample(Document):
    """Per-minute (or coarser) time series of ACTIVE CLIENT ASSOCIATIONS for a site, zone, AP or floor. Not a head count of people."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    scope: str  # site | zone | ap | floor
    scope_id: Optional[uuid.UUID] = None
    bucket_start: datetime
    active_clients: int = 0  # last value seen in the bucket
    peak_clients: int = 0
    samples: int = 0
    quality: str = "none"  # live | simulated | mixed | snapshot | stale | none
    simulated: bool = False

    class Settings:
        name = "occupancy_samples"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("scope", ASCENDING), ("scope_id", ASCENDING), ("bucket_start", ASCENDING)], unique=True),
            IndexModel([("site_id", ASCENDING), ("bucket_start", -1)]),
        ]


class ThresholdBreach(Document):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    scope: str  # zone | ap
    scope_id: uuid.UUID
    level: str  # warning | critical
    threshold: int
    peak_clients: int
    started_at: datetime = Field(default_factory=_utcnow)
    last_seen_at: datetime = Field(default_factory=_utcnow)
    ended_at: Optional[datetime] = None
    active: bool = True

    class Settings:
        name = "threshold_breaches"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("started_at", -1)]),
            # at most ONE open breach per entity
            IndexModel(
                [("site_id", ASCENDING), ("scope", ASCENDING), ("scope_id", ASCENDING)],
                unique=True, partialFilterExpression={"active": True},
            ),
        ]


class AvailabilityEvent(Document):
    """State changes of collectors/APs/controllers, for availability and stale-telemetry history."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    entity_type: str  # collector | ap | controller
    entity_id: uuid.UUID
    state: str  # online | stale | offline
    at: datetime = Field(default_factory=_utcnow)

    class Settings:
        name = "availability_events"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("at", -1)]),
            IndexModel([("entity_type", ASCENDING), ("entity_id", ASCENDING), ("at", -1)]),
        ]


# ===========================================================================
# Bodycam <-> site (Network Hopping) offline video transport.
#
# Identity chain: Organization(label) -> MonitoredSite -> SiteAssignment (officer)
#                 -> DeviceSiteAuthorization (phone) -> OfflineGrant (signed, short-lived)
#                 -> RecordingSession (client UUID) -> Chunk (client UUID + SHA-256)
# A SiteReceiver is the LAN service that accepts chunks while the control room is
# unreachable and forwards them later; it authenticates to the control room with its
# OWN credential (never an officer login).
# ===========================================================================

class SiteAssignment(Document):
    """An officer's assignment to a monitored site (and optionally a zone/building/floor). NOT the legacy Constable.assigned_zone_code."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    constable_id: uuid.UUID
    zone_id: Optional[uuid.UUID] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    status: str = "active"  # active | revoked
    valid_from: datetime = Field(default_factory=_utcnow)
    valid_until: Optional[datetime] = None
    notes: Optional[str] = None
    created_by: Optional[uuid.UUID] = None
    created_at: datetime = Field(default_factory=_utcnow)
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None

    class Settings:
        name = "site_assignments"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("status", ASCENDING)]),
            IndexModel([("constable_id", ASCENDING), ("status", ASCENDING)]),
            IndexModel([("site_id", ASCENDING), ("constable_id", ASCENDING)], unique=True, partialFilterExpression={"status": "active"}, name="uq_active_assignment_per_site_officer"),
        ]


class DeviceSiteAuthorization(Document):
    """A registered phone is allowed to operate at a site. Revocation is explicit and keeps history."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    device_id: uuid.UUID
    constable_id: uuid.UUID
    status: str = "authorized"  # authorized | revoked
    authorized_by: Optional[uuid.UUID] = None
    authorized_at: datetime = Field(default_factory=_utcnow)
    valid_until: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None

    class Settings:
        name = "device_site_authorizations"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("status", ASCENDING)]),
            IndexModel([("device_id", ASCENDING), ("status", ASCENDING)]),
            IndexModel([("site_id", ASCENDING), ("device_id", ASCENDING)], unique=True, partialFilterExpression={"status": "authorized"}, name="uq_active_device_site"),
        ]


class OfflineGrant(Document):
    """Server-side record of a signed offline grant (the JWT itself is NOT stored). Used for listing, revocation and revocation propagation."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)  # also the JWT `jti`
    site_id: uuid.UUID
    constable_id: uuid.UUID
    device_id: uuid.UUID
    assignment_id: Optional[uuid.UUID] = None
    key_id: Optional[str] = None
    operations: List[str] = Field(default_factory=list)
    issued_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime
    issued_by: Optional[uuid.UUID] = None  # None = self-service renewal by the officer's own authenticated phone
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None

    class Settings:
        name = "offline_grants"
        indexes = [
            IndexModel([("site_id", ASCENDING), ("revoked", ASCENDING), ("expires_at", -1)]),
            IndexModel([("device_id", ASCENDING), ("issued_at", -1)]),
            IndexModel([("constable_id", ASCENDING), ("issued_at", -1)]),
        ]


class SiteReceiver(Document):
    """A site's local video receiver. Authenticates to the control room with its own credential (hash stored, shown once)."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    site_id: uuid.UUID
    code: str
    name: str
    endpoint_url: Optional[str] = None  # the URL PHONES use on the site LAN/Wi-Fi (never a public default)
    local_live_enabled: bool = False
    local_live_url: Optional[str] = None  # site-local LiveKit, when deployed
    active: bool = True
    revoked: bool = False
    token_hash: Optional[str] = None
    token_hint: Optional[str] = None
    token_version: int = 1
    previous_token_hash: Optional[str] = None
    previous_valid_until: Optional[datetime] = None
    version: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    last_seen_at: Optional[datetime] = None
    last_sync_at: Optional[datetime] = None
    last_central_ack_at: Optional[datetime] = None  # last time the receiver reported a successful central acknowledgement
    last_local_upload_at: Optional[datetime] = None
    # Latest self-reported health (heartbeat).
    disk_total_bytes: Optional[int] = None
    disk_free_bytes: Optional[int] = None
    min_free_bytes: Optional[int] = None
    accepting_uploads: Optional[bool] = None
    pending_chunks: int = 0
    syncing_chunks: int = 0
    quarantined_chunks: int = 0
    received_chunks_total: int = 0
    central_reachable: Optional[bool] = None
    recent_devices: Dict[str, str] = Field(default_factory=dict)  # device identifier -> ISO time last seen by the receiver
    failures: List[dict] = Field(default_factory=list)  # newest sync failures (bounded), for the dashboard
    pending_commands: List[dict] = Field(default_factory=list)  # {id, type, args, created_at}; delivered on the next sync
    local_recordings: List[dict] = Field(default_factory=list)  # latest bounded summary of recordings the receiver still holds
    local_recordings_at: Optional[datetime] = None
    config: Optional[dict] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    created_by: Optional[uuid.UUID] = None

    class Settings:
        name = "site_receivers"
        indexes = [IndexModel([("site_id", ASCENDING), ("code", ASCENDING)], unique=True)]


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
    Building,
    CCTVStreamSession,
    AccessPoint,
    PolicePresence,
    PresenceHandoff,
    Deployment,
    EventZone,
    EdgeControllerEventLog,
    MonitoredSite,
    SiteBuilding,
    SiteFloor,
    SiteZone,
    NetworkSwitch,
    NetworkController,
    Collector,
    ClientAssociation,
    NetworkEvent,
    OccupancySample,
    ThresholdBreach,
    AvailabilityEvent,
    DutySession,
    LocationIngestKey,
    SiteAssignment,
    DeviceSiteAuthorization,
    OfflineGrant,
    SiteReceiver,
]

