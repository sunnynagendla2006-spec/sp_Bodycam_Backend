from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List
import uuid
from datetime import datetime
from .models import UserRole, UserStatus, ConstableStatus, IncidentStatus, MediaType, UploadStatus, AssignmentStatus, DeviceStatus, AlertType, AlertSeverity, AlertStatus, RecordingTriggerType, RecordingStatus, RemoteCommandType, RemoteCommandStatus, LiveStreamStatus, LiveStreamStartedBy

class UserBase(BaseModel):
    phone: str
    role: UserRole

class UserCreate(UserBase):
    password: Optional[str] = None
    sso_id: Optional[str] = None

class UserOut(UserBase):
    id: uuid.UUID
    status: UserStatus
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    phone: Optional[str] = None
    role: Optional[UserRole] = None

# ---------------------------------------------------------------------------
# Authentication schemas
# ---------------------------------------------------------------------------
# NOTE: The existing `User` model only has `phone`, `sso_id`, `role`,
# `status`, `hashed_password`, `created_at` -- there is no `name` or `email`
# column. `username` in LoginRequest is matched against `User.phone`, which
# preserves the existing frontend contract (Login.tsx already POSTs
# {username, password} to /auth/login) without requiring a schema change on
# the client. If/when a real `name`/`email` field is added to the User model
# in a future phase, this schema should be extended to surface it.

class LoginRequest(BaseModel):
    username: str = Field(..., description="Currently matched against User.phone")
    password: str

class UserPublic(BaseModel):
    """Safe, non-sensitive user profile. Never includes hashed_password."""
    id: uuid.UUID
    phone: str
    role: UserRole
    is_active: bool
    station_id: Optional[uuid.UUID] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_user(cls, user) -> "UserPublic":
        return cls(
            id=user.id,
            phone=user.phone,
            role=user.role,
            is_active=(user.status == UserStatus.active),
            station_id=user.station_id,
            created_at=user.created_at,
        )

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserPublic

class IncidentCreate(BaseModel):
    location_lon: float
    location_lat: float
    description: Optional[str] = None

class IncidentOut(BaseModel):
    id: uuid.UUID
    display_id: Optional[str] = None
    citizen_id: Optional[uuid.UUID] = None
    description: Optional[str] = None
    status: IncidentStatus
    station_id: Optional[uuid.UUID] = None
    location: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ConstableLocationUpdate(BaseModel):
    location_lon: float
    location_lat: float
    battery_level: Optional[int] = None

# ---------------------------------------------------------------------------
# Evidence schemas
# ---------------------------------------------------------------------------
# Client-reported metadata accepted alongside an upload (all optional -- the
# Flutter app may not always have a GPS fix, duration, etc. yet). None of
# this is treated as authoritative; it is stored as-is inside
# Evidence.evidence_metadata for later reference, clearly separate from the
# server-generated fields (file_hash, file_size, mime_type, upload_status,
# timestamp, uploader_id, uploader_role) which a client can never set.

class EvidenceClientMetadata(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy: Optional[float] = None
    device_timestamp: Optional[str] = None
    duration_seconds: Optional[float] = None
    camera: Optional[str] = None

class EvidenceResponse(BaseModel):
    """
    Safe, API-facing view of an Evidence row. Deliberately excludes
    `file_path`/`storage_key` (internal storage details) -- evidence bytes
    are only ever reachable through the authenticated download/stream
    endpoints, never by a path the client could construct or reuse itself.
    """
    id: uuid.UUID
    incident_id: uuid.UUID
    type: MediaType
    original_filename: Optional[str] = None
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    uploader_id: Optional[uuid.UUID] = None
    uploader_role: Optional[UserRole] = None
    upload_status: UploadStatus
    comment: Optional[str] = None
    metadata: Optional[dict] = None
    timestamp: datetime
    # Verification lifecycle -- all optional/None until the evidence is
    # actually verified/rejected/archived (see /media/{id}/verify|reject|archive).
    verified_by: Optional[uuid.UUID] = None
    verified_at: Optional[datetime] = None
    rejected_by: Optional[uuid.UUID] = None
    rejected_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    archived_by: Optional[uuid.UUID] = None
    archived_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_evidence(cls, evidence) -> "EvidenceResponse":
        return cls(
            id=evidence.id,
            incident_id=evidence.incident_id,
            type=evidence.type,
            original_filename=evidence.original_filename,
            mime_type=evidence.mime_type,
            file_size=evidence.file_size,
            file_hash=evidence.file_hash,
            uploader_id=evidence.uploader_id,
            uploader_role=evidence.uploader_role,
            upload_status=evidence.upload_status,
            comment=evidence.comment,
            metadata=evidence.evidence_metadata,
            timestamp=evidence.timestamp,
            verified_by=evidence.verified_by,
            verified_at=evidence.verified_at,
            rejected_by=evidence.rejected_by,
            rejected_at=evidence.rejected_at,
            rejection_reason=evidence.rejection_reason,
            archived_by=evidence.archived_by,
            archived_at=evidence.archived_at,
        )

class EvidenceRejectRequest(BaseModel):
    """Optional rejection reason -- mirrors the existing IncidentActionReason shape used by incidents.py's reject/needs-review endpoints."""
    reason: Optional[str] = None

class EvidenceUploadResponse(BaseModel):
    status: str
    evidence_id: uuid.UUID
    hash: str
    upload_status: UploadStatus

# ---------------------------------------------------------------------------
# Phase 4: Police Station / Dispatch / Constable self-service schemas
# ---------------------------------------------------------------------------

class StationSummaryResponse(BaseModel):
    """Minimal station identity + distance, used by nearest-station lookups
    and dispatch responses. Never a full station CRUD payload."""
    id: uuid.UUID
    name: Optional[str] = None
    distance_meters: Optional[float] = None
    model_config = ConfigDict(from_attributes=True)

class NearestStationsResponse(BaseModel):
    primary_station: Optional[StationSummaryResponse] = None
    backup_station: Optional[StationSummaryResponse] = None

# ---------------------------------------------------------------------------
# Phase 6: Police Station CRUD schemas
# ---------------------------------------------------------------------------

class PoliceStationCreate(BaseModel):
    name: str
    contact: Optional[str] = None
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)

class PoliceStationUpdate(BaseModel):
    """All fields optional -- only the ones provided are changed."""
    name: Optional[str] = None
    contact: Optional[str] = None
    latitude: Optional[float] = Field(default=None, ge=-90.0, le=90.0)
    longitude: Optional[float] = Field(default=None, ge=-180.0, le=180.0)

class PoliceStationResponse(BaseModel):
    id: uuid.UUID
    name: Optional[str] = None
    contact: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class IncidentActionReason(BaseModel):
    """Optional short reason, used by reject/needs-review actions."""
    reason: Optional[str] = None

class DispatchResponse(BaseModel):
    status: str  # "dispatched" | "no_available_constable"
    incident_id: uuid.UUID
    constable_id: Optional[uuid.UUID] = None
    assignment_id: Optional[uuid.UUID] = None
    primary_station: Optional[StationSummaryResponse] = None
    backup_station: Optional[StationSummaryResponse] = None

class AssignmentResponse(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    constable_id: uuid.UUID
    status: AssignmentStatus
    assigned_at: datetime
    responded_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class AssignmentActionResponse(BaseModel):
    status: str
    assignment_id: uuid.UUID
    assignment_status: AssignmentStatus

class ConstableIncidentResponse(BaseModel):
    """One row of GET /constables/me/incidents -- incident + the calling
    constable's own assignment status for it."""
    incident_id: uuid.UUID
    display_id: Optional[str] = None
    incident_status: IncidentStatus
    location: Optional[str] = None
    created_at: datetime
    assignment_id: uuid.UUID
    assignment_status: AssignmentStatus
    assigned_at: datetime

class ConstableMeResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    badge_number: Optional[str] = None
    phone: Optional[str] = None
    status: ConstableStatus
    station_id: Optional[uuid.UUID] = None
    battery_level: Optional[int] = None
    last_location_at: Optional[datetime] = None
    is_active: bool

class ConstableMeLocationUpdate(BaseModel):
    """Body for POST /constables/me/location -- deliberately distinct from
    the legacy ConstableLocationUpdate (location_lon/location_lat) used by
    the existing admin-facing POST /constables/{id}/location, matching the
    field names the Flutter app will actually send."""
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)
    accuracy: Optional[float] = Field(default=None, ge=0.0)

class ConstableLocationResponse(BaseModel):
    status: str
    constable_id: uuid.UUID
    latitude: float
    longitude: float
    accuracy: Optional[float] = None
    timestamp: datetime

class ConstableStatusUpdateRequest(BaseModel):
    status: str  # validated against a restricted allow-list in the router, not the full AssignmentStatus/IncidentStatus enum

# ---------------------------------------------------------------------------
# Phase 5: Audit log schemas
# ---------------------------------------------------------------------------

class AuditLogResponse(BaseModel):
    """
    Safe, API-facing view of an AuditLog row. `details` is parsed from the
    JSON-serialized string stored in the DB back into a dict; never
    contains passwords/JWTs/file paths (enforced at write time by
    app/services/audit.py, not by this schema).
    """
    id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    action: str
    details: Optional[dict] = None
    incident_id: Optional[uuid.UUID] = None
    evidence_id: Optional[uuid.UUID] = None
    ip_address: Optional[str] = None
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_audit_log(cls, entry) -> "AuditLogResponse":
        import json
        parsed_details = None
        if entry.details:
            try:
                parsed_details = json.loads(entry.details)
            except (ValueError, TypeError):
                parsed_details = {"raw": entry.details}
        return cls(
            id=entry.id,
            user_id=entry.user_id,
            action=entry.action,
            details=parsed_details,
            incident_id=entry.incident_id,
            evidence_id=entry.evidence_id,
            ip_address=entry.ip_address,
            timestamp=entry.timestamp,
        )


# ---------------------------------------------------------------------------
# Phase 1 (body-camera system): Device / Heartbeat / Battery schemas
# ---------------------------------------------------------------------------

class DeviceRegisterRequest(BaseModel):
    device_identifier: str = Field(..., min_length=1, max_length=255)
    platform: Optional[str] = None
    app_version: Optional[str] = None
    device_model: Optional[str] = None

class DeviceHeartbeatRequest(BaseModel):
    """
    Battery/liveness only. Location is intentionally NOT part of this
    payload -- POST /constables/me/location already exists and is reused
    as-is (see routers/devices.py) rather than creating a second,
    competing source of location truth.
    """
    device_identifier: str
    battery_percent: Optional[int] = Field(default=None, ge=0, le=100)
    is_charging: Optional[bool] = None

class DeviceBatteryReportRequest(BaseModel):
    device_identifier: str
    battery_percent: int = Field(..., ge=0, le=100)
    is_charging: Optional[bool] = None

class BatteryReadingResponse(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    battery_percent: int
    is_charging: Optional[bool] = None
    recorded_at: datetime
    model_config = ConfigDict(from_attributes=True)

class DeviceResponse(BaseModel):
    """
    Safe, API-facing device view. `status` is the EFFECTIVE status
    (computed at request time from last_heartbeat_at + configurable
    thresholds -- see compute_effective_status in routers/devices.py),
    not necessarily the raw stored column, since no background process
    exists yet to proactively flip stale/offline devices.
    """
    id: uuid.UUID
    constable_id: Optional[uuid.UUID] = None
    device_identifier: str
    platform: Optional[str] = None
    app_version: Optional[str] = None
    device_model: Optional[str] = None
    status: DeviceStatus
    last_heartbeat_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    battery_percent: Optional[int] = None
    is_charging: Optional[bool] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_updated_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Phase 2 (body-camera system): RecordingSession / VideoChunk schemas
# ---------------------------------------------------------------------------

class RecordingStartRequest(BaseModel):
    device_identifier: str = Field(..., min_length=1)
    trigger_type: RecordingTriggerType = RecordingTriggerType.manual
    incident_id: Optional[uuid.UUID] = None

class RecordingSessionResponse(BaseModel):
    id: uuid.UUID
    constable_id: uuid.UUID
    device_id: uuid.UUID
    trigger_type: RecordingTriggerType
    status: RecordingStatus
    started_at: datetime
    ended_at: Optional[datetime] = None
    incident_id: Optional[uuid.UUID] = None
    created_at: datetime
    chunk_count: int = 0
    highest_chunk_number: Optional[int] = None
    missing_chunk_numbers: List[int] = []
    model_config = ConfigDict(from_attributes=True)

class VideoChunkResponse(BaseModel):
    """Never exposes storage_key/filesystem paths -- see routers/recordings.py."""
    id: uuid.UUID
    recording_session_id: uuid.UUID
    chunk_number: int
    file_size: Optional[int] = None
    duration_seconds: Optional[float] = None
    file_hash: Optional[str] = None
    mime_type: Optional[str] = None
    is_last_chunk: bool
    upload_status: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class RecordingManifestResponse(BaseModel):
    """
    Ordered chunk manifest -- NOT a live stream. Chunks are always ordered
    by chunk_number regardless of upload arrival order (see
    services/chunk_manifest.py). `missing_chunk_numbers` reflects gaps in
    the contiguous sequence up to the highest received chunk (or, if the
    recording is completed, up to the last chunk actually marked
    is_last_chunk) -- see that service for the exact, documented semantics.
    """
    recording_session_id: uuid.UUID
    status: RecordingStatus
    chunks: List[VideoChunkResponse]
    highest_chunk_number: Optional[int] = None
    missing_chunk_numbers: List[int] = []
    is_complete: bool


# ---------------------------------------------------------------------------
# Phase 3 (body-camera system): RemoteCommand + Alert response schemas
# ---------------------------------------------------------------------------

class RemoteCommandCreateRequest(BaseModel):
    command_type: RemoteCommandType

class RemoteCommandResultRequest(BaseModel):
    success: bool
    failure_reason: Optional[str] = None

class RemoteCommandResponse(BaseModel):
    """Never exposes issuer contact info beyond the user_id, and never any storage/internal details."""
    id: uuid.UUID
    device_id: uuid.UUID
    issued_by: uuid.UUID
    command_type: RemoteCommandType
    status: RemoteCommandStatus
    created_at: datetime
    sent_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class AlertResponse(BaseModel):
    id: uuid.UUID
    type: AlertType
    severity: AlertSeverity
    constable_id: Optional[uuid.UUID] = None
    device_id: Optional[uuid.UUID] = None
    message: Optional[str] = None
    status: AlertStatus
    acknowledged_by: Optional[uuid.UUID] = None
    resolved_by: Optional[uuid.UUID] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ---------------------------------------------------------------------------
# Live camera streaming (ephemeral only -- see app/models.py::LiveStreamSession
# and app/routers/live_stream.py).
# ---------------------------------------------------------------------------

class LiveStreamStartRequest(BaseModel):
    triggering_command_id: Optional[uuid.UUID] = None

class LiveStreamSessionResponse(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    constable_id: uuid.UUID
    room_name: str
    status: LiveStreamStatus
    started_by: LiveStreamStartedBy
    triggering_command_id: Optional[uuid.UUID] = None
    started_at: datetime
    ended_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class LiveStreamTokenResponse(BaseModel):
    """Never includes the LiveKit API secret -- only a short-lived, single-purpose signed join token."""
    session: LiveStreamSessionResponse
    livekit_url: str
    token: str
    identity: str
    can_publish: bool
