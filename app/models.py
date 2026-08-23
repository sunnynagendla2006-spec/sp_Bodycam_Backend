import uuid
from sqlalchemy import (
    Column, String, Integer, BigInteger, Float, DateTime, Enum, ForeignKey, JSON, Index, text, Boolean, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from geoalchemy2 import Geometry
from sqlalchemy.sql import func
from .database import Base
import enum

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
    Verification is a distinct, later, Control-Room-driven action (not
    implemented yet; this phase only establishes the state itself).
    """
    uploading = "uploading"
    uploaded = "uploaded"
    verified = "verified"
    rejected = "rejected"
    archived = "archived"

class AssignmentStatus(str, enum.Enum):
    """
    IncidentAssignment lifecycle for the future constable mobile app
    (accept/reject/respond flow). Only the database column is added in this
    phase -- the corresponding accept/reject/status-update APIs are a later
    phase, per scope.
    """
    pending = "pending"
    accepted = "accepted"
    rejected = "rejected"
    en_route = "en_route"
    arrived = "arrived"
    completed = "completed"

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone = Column(String, unique=True, index=True)
    sso_id = Column(String, unique=True, nullable=True)
    role = Column(Enum(UserRole), nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.active)
    hashed_password = Column(String, nullable=True) # for citizens mainly, SSO for others
    # Which PoliceStation this user represents, for role=station users. Nullable
    # because it's meaningless for admin/control_room/constable/citizen roles
    # (a constable's station affiliation lives on Constable.station_id, not
    # here). This is the authoritative source for "which station is this
    # station-role user allowed to see" -- never derived from phone number,
    # station name, or any client-supplied value.
    station_id = Column(UUID(as_uuid=True), ForeignKey("police_stations.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class PoliceStation(Base):
    __tablename__ = "police_stations"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, index=True)
    location = Column(Geometry('POINT', srid=4326))
    jurisdiction = Column(Geometry('POLYGON', srid=4326))
    contact = Column(String)

class Constable(Base):
    __tablename__ = "constables"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    badge_number = Column(String, unique=True)
    station_id = Column(UUID(as_uuid=True), ForeignKey("police_stations.id"))
    status = Column(Enum(ConstableStatus), default=ConstableStatus.offline)
    battery_level = Column(Integer, nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)

class ConstableLocation(Base):
    __tablename__ = "constable_locations"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    constable_id = Column(UUID(as_uuid=True), ForeignKey("constables.id"))
    location = Column(Geometry('POINT', srid=4326))
    accuracy = Column(Float, nullable=True)  # GPS accuracy in meters, as reported by the device
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    display_id = Column(String, unique=True, index=True, nullable=True)
    citizen_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    location = Column(Geometry('POINT', srid=4326))
    description = Column(String, nullable=True)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.new)
    station_id = Column(UUID(as_uuid=True), ForeignKey("police_stations.id"), nullable=True)  # responsible station, set on verify/dispatch (see incidents.py)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class IncidentAssignment(Base):
    __tablename__ = "incident_assignments"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"))
    constable_id = Column(UUID(as_uuid=True), ForeignKey("constables.id"))
    status = Column(Enum(AssignmentStatus), default=AssignmentStatus.pending, nullable=False)
    assigned_at = Column(DateTime(timezone=True), server_default=func.now())
    responded_at = Column(DateTime(timezone=True), nullable=True)  # when the constable accepted/rejected
    closed_at = Column(DateTime(timezone=True), nullable=True)     # when this assignment was completed/closed out

    # Only one ACTIVE assignment (pending/accepted/en_route/arrived) may
    # exist per incident at a time. This is a genuine DB-level constraint,
    # not just the application-level `if existing_active_assignment:` check
    # in incidents.py::dispatch_incident -- that check is a fast-path that
    # avoids a wasted round-trip in the common case, but only a real
    # constraint closes the race window between two concurrent
    # transactions both passing that check before either commits.
    # `rejected`/`completed` are intentionally excluded from the predicate
    # so an incident CAN accumulate multiple historical (non-active)
    # assignment rows over time (e.g. one rejection followed by a
    # successful reassignment) -- only one may be *active* at once.
    __table_args__ = (
        Index(
            "uq_active_assignment_per_incident",
            "incident_id",
            unique=True,
            postgresql_where=text("status IN ('pending', 'accepted', 'en_route', 'arrived')"),
            sqlite_where=text("status IN ('pending', 'accepted', 'en_route', 'arrived')"),
        ),
    )

class MediaType(str, enum.Enum):
    photo = "photo"
    audio = "audio"
    video = "video"

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="RESTRICT"), index=True)
    constable_id = Column(UUID(as_uuid=True), ForeignKey("constables.id", ondelete="RESTRICT"), nullable=True) # can be null if uploaded by citizen
    type = Column(Enum(MediaType))
    comment = Column(String, nullable=True)
    location = Column(Geometry('POINT', srid=4326), nullable=True)  # populated from client-reported GPS, when provided

    # --- Server-authoritative identity/integrity fields -------------------
    # These are NEVER accepted from the client request body; they are always
    # computed/derived server-side (see routers/media.py::upload_evidence).
    uploader_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True)
    uploader_role = Column(Enum(UserRole), nullable=True)
    file_hash = Column(String, nullable=True)     # SHA-256 of the actual uploaded bytes, server-computed
    file_size = Column(BigInteger, nullable=True) # actual bytes written to disk, server-computed
    mime_type = Column(String, nullable=True)     # server-detected/validated MIME type
    upload_status = Column(Enum(UploadStatus), default=UploadStatus.uploaded, nullable=False, index=True)

    # --- Storage representation -------------------------------------------
    # `storage_key` is the long-term, object-storage-compatible logical
    # identity (e.g. "evidence/{incident_id}/{evidence_id}.mp4"), independent
    # of whatever local/S3/MinIO root it's eventually resolved against.
    # `file_path` is retained (nullable, not exposed via any API response)
    # purely for backward compatibility with rows created before this phase
    # and as an internal absolute-path cache for local-disk storage; new code
    # should treat `storage_key` as authoritative and resolve the absolute
    # path via configuration (EVIDENCE_UPLOAD_ROOT), not by reading
    # `file_path` directly.
    storage_key = Column(String, nullable=True)
    file_path = Column(String, nullable=True)

    # --- Original filename (metadata only, never used to build a path) ----
    original_filename = Column(String, nullable=True)  # sanitized client-supplied filename, display/metadata only

    # --- Metadata ----------------------------------------------------------
    # Client-reported fields (latitude/longitude/accuracy/device_timestamp/
    # duration_seconds/camera, etc.) live here. This is explicitly NOT
    # treated as authoritative proof of anything -- it's device-reported
    # data, distinct from the server-generated `timestamp` column below.
    # Mapped to a plain SQL column named "metadata" (the Python attribute
    # can't be named `metadata` -- that name is reserved by SQLAlchemy's
    # declarative Base for its own schema metadata).
    evidence_metadata = Column("metadata", JSON, nullable=True)

    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)  # server-received timestamp, authoritative

    # --- Verification lifecycle (uploaded -> verified/rejected -> archived) -
    # Attribution fields mirroring the existing verified_by-style pattern
    # already used elsewhere in this codebase (e.g. IncidentAssignment's
    # responded_at/closed_at). ON DELETE SET NULL (not RESTRICT, unlike
    # uploader_id) since losing the ability to delete a user merely because
    # they once verified/rejected/archived a piece of evidence would be an
    # overly strong constraint for what is an attribution/audit detail, not
    # the evidentiary chain of custody itself (which uploader_id/constable_id
    # already protect with RESTRICT).
    verified_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    rejected_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    rejected_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(String, nullable=True)
    archived_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    archived_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_evidence_incident_timestamp", "incident_id", "timestamp"),
    )

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String, index=True)
    # JSON-serialized structured details (dict) -- kept as a plain String
    # column rather than changing its type, since the existing column
    # already supports storing arbitrary text; see app/services/audit.py
    # for what goes in here. Never contains passwords/JWTs/file contents.
    details = Column(String, nullable=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)


# ===========================================================================
# Phase 1 (body-camera system): Device + Battery + minimal Alert
#
# NOTE ON SCOPE: Constable.battery_level / Constable.last_login remain
# untouched for backward compatibility -- they are NOT removed. Device is
# the new source of truth for device-level state going forward; a
# constable and a physical phone are separate concepts (a constable could
# in principle be reassigned a replacement device).
# ===========================================================================

class DeviceStatus(str, enum.Enum):
    """
    Stored value reflects the device's state as of its last successful
    write (register/heartbeat/battery report always set this to `online`,
    or `recording` once RecordingSession exists in a later phase). It is
    NOT proactively downgraded to `stale`/`offline` by any background
    process in this phase -- see app/routers/devices.py's
    `compute_effective_status()` for why, and how that gap is closed for
    now (computed lazily on every read, not via a scheduler).
    """
    online = "online"
    offline = "offline"
    stale = "stale"
    recording = "recording"


class Device(Base):
    __tablename__ = "devices"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Nullable: a device can be registered before being claimed by a
    # constable, and ON DELETE SET NULL rather than CASCADE/RESTRICT --
    # deleting a Constable should not delete device history, just release
    # the association.
    constable_id = Column(UUID(as_uuid=True), ForeignKey("constables.id", ondelete="SET NULL"), nullable=True, index=True)
    device_identifier = Column(String, unique=True, nullable=False, index=True)
    platform = Column(String, nullable=True)       # e.g. "android"
    app_version = Column(String, nullable=True)
    device_model = Column(String, nullable=True)
    status = Column(Enum(DeviceStatus), default=DeviceStatus.offline, nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class BatteryReading(Base):
    """Append-only battery history -- NOT a single overwritten scalar. See Constable.battery_level (legacy, untouched) vs this (new source of truth)."""
    __tablename__ = "battery_readings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    battery_percent = Column(Integer, nullable=False)
    is_charging = Column(Boolean, nullable=True)
    recorded_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    __table_args__ = (
        CheckConstraint("battery_percent >= 0 AND battery_percent <= 100", name="ck_battery_percent_range"),
        Index("idx_battery_readings_device_recorded", "device_id", "recorded_at"),
    )


class AlertType(str, enum.Enum):
    """Phase 1 introduced the battery types only; Phase 3 adds device-health and command-failure types."""
    low_battery = "low_battery"
    critical_battery = "critical_battery"
    device_offline = "device_offline"
    device_stale = "device_stale"
    recording_device_offline = "recording_device_offline"
    command_failed = "command_failed"
    command_timeout = "command_timeout"


class AlertSeverity(str, enum.Enum):
    warning = "warning"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class Alert(Base):
    """
    Minimal Alert infrastructure for THIS phase: rows are created/updated
    by battery-threshold logic only (see app/routers/devices.py). The full
    Alert REST API (GET/acknowledge/resolve) is explicitly deferred to a
    later phase -- this phase only needs the table to exist and be
    correctly de-duplicated so the WebSocket events it drives are
    meaningful.
    """
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(Enum(AlertType), nullable=False)
    severity = Column(Enum(AlertSeverity), nullable=False)
    constable_id = Column(UUID(as_uuid=True), ForeignKey("constables.id", ondelete="SET NULL"), nullable=True)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    message = Column(String, nullable=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.open, nullable=False, index=True)
    acknowledged_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # Only one OPEN battery alert (low_battery/critical_battery) may exist
    # per device at a time. This is a genuine DB-level constraint, not just
    # the application-level `existing_open` check in
    # app/routers/devices.py::_process_battery_thresholds -- that check is
    # a fast-path, but only a real constraint closes the race window
    # between two concurrent battery/heartbeat requests both passing that
    # check before either commits (discovered and fixed during Phase 1
    # concurrency testing -- see the phase report). Scoped to the two
    # battery alert types specifically so a future, unrelated open alert
    # type (e.g. device_offline, added in a later phase) is never blocked
    # by this constraint.
    __table_args__ = (
        Index(
            "uq_open_battery_alert_per_device",
            "device_id",
            unique=True,
            postgresql_where=text("status = 'open' AND type IN ('low_battery', 'critical_battery')"),
            sqlite_where=text("status = 'open' AND type IN ('low_battery', 'critical_battery')"),
        ),
        # Phase 3: a SEPARATE partial unique index for the non-battery
        # alert types, scoped per (device_id, type) rather than per
        # device_id alone -- unlike the battery pair (which share one
        # escalating row, since a device can only meaningfully be "low" OR
        # "critical" on battery at once), device_offline and
        # recording_device_offline are independent conditions that can
        # genuinely be true simultaneously for the same device, so each
        # type gets its own deduplicated slot rather than being merged
        # into a single row.
        Index(
            "uq_open_alert_per_device_and_type",
            "device_id",
            "type",
            unique=True,
            postgresql_where=text(
                "status = 'open' AND type IN ('device_offline', 'device_stale', 'recording_device_offline', 'command_failed', 'command_timeout')"
            ),
            sqlite_where=text(
                "status = 'open' AND type IN ('device_offline', 'device_stale', 'recording_device_offline', 'command_failed', 'command_timeout')"
            ),
        ),
    )


# ===========================================================================
# Phase 2 (body-camera system): RecordingSession + VideoChunk
#
# IMPORTANT: RecordingSession deliberately does NOT require an Incident.
# incident_id is nullable/optional -- a constable must be able to start an
# emergency recording without any Incident existing first (per the
# approved Phase 2 specification).
# ===========================================================================

class RecordingTriggerType(str, enum.Enum):
    emergency_button = "emergency_button"
    manual = "manual"
    remote = "remote"


class RecordingStatus(str, enum.Enum):
    recording = "recording"
    completed = "completed"
    cancelled = "cancelled"
    failed = "failed"


class RecordingSession(Base):
    __tablename__ = "recording_sessions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    constable_id = Column(UUID(as_uuid=True), ForeignKey("constables.id", ondelete="RESTRICT"), nullable=False, index=True)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False, index=True)
    trigger_type = Column(Enum(RecordingTriggerType), nullable=False)
    status = Column(Enum(RecordingStatus), default=RecordingStatus.recording, nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    ended_at = Column(DateTime(timezone=True), nullable=True)
    # Optional link only -- see module docstring above. ON DELETE SET NULL
    # so deleting/archiving an Incident can never cascade into deleting
    # evidentiary recording data.
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class ChunkUploadStatus(str, enum.Enum):
    """Mirrors Evidence.upload_status's shape/spirit (uploaded is the only status a chunk actually reaches in this phase -- verification/rejection of individual chunks is not part of the approved Phase 2 scope)."""
    uploaded = "uploaded"


class VideoChunk(Base):
    __tablename__ = "video_chunks"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    recording_session_id = Column(UUID(as_uuid=True), ForeignKey("recording_sessions.id", ondelete="RESTRICT"), nullable=False, index=True)
    chunk_number = Column(Integer, nullable=False)
    storage_key = Column(String, nullable=False)
    file_size = Column(BigInteger, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    file_hash = Column(String, nullable=True)
    mime_type = Column(String, nullable=True)
    is_last_chunk = Column(Boolean, default=False, nullable=False)
    upload_status = Column(Enum(ChunkUploadStatus), default=ChunkUploadStatus.uploaded, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    __table_args__ = (
        # MANDATORY per the approved spec: a genuine DB-level constraint,
        # not just an application-level duplicate check -- see
        # app/routers/recordings.py::_process_chunk_upload for the
        # SAVEPOINT-based retry pattern (same as
        # uq_open_battery_alert_per_device in Phase 1) that closes the
        # race between two concurrent uploads of the same chunk_number.
        # This composite index also efficiently serves recording_session_id
        # -only queries (leftmost-prefix), so no separate single-column
        # index is needed.
        Index("uq_chunk_number_per_recording", "recording_session_id", "chunk_number", unique=True),
    )


# ===========================================================================
# Phase 3 (body-camera system): RemoteCommand
#
# Control Room -> device command lifecycle. Creation and "sent" happen as
# one atomic step in this implementation (see routers/commands.py) -- the
# command row is created and immediately marked SENT (with the
# command.sent WebSocket event published after commit); genuine delivery
# confirmation only happens via the device's own POST /commands/{id}/ack
# call once its mobile app actually receives it. If the device is
# offline, the row still exists at status SENT and is retrievable via
# GET /devices/{id}/commands when the device reconnects -- nothing here
# pretends offline delivery succeeded.
# ===========================================================================

class RemoteCommandType(str, enum.Enum):
    start_recording = "start_recording"
    stop_recording = "stop_recording"


class RemoteCommandStatus(str, enum.Enum):
    pending = "pending"
    sent = "sent"
    acknowledged = "acknowledged"
    executed = "executed"
    failed = "failed"
    timeout = "timeout"
    cancelled = "cancelled"


class RemoteCommand(Base):
    __tablename__ = "remote_commands"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False, index=True)
    issued_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    command_type = Column(Enum(RemoteCommandType), nullable=False)
    status = Column(Enum(RemoteCommandStatus), default=RemoteCommandStatus.pending, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)
    failure_reason = Column(String, nullable=True)
    result_payload = Column(JSON, nullable=True)
