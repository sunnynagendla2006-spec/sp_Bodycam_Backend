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
]
