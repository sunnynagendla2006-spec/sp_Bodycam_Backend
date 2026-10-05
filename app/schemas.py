from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List
import uuid
from datetime import datetime
from .models import UserRole, UserStatus, ConstableStatus, IncidentStatus, MediaType, UploadStatus, AssignmentStatus, DeviceStatus, AlertType, AlertSeverity, AlertStatus, RecordingTriggerType, RecordingStatus, RemoteCommandType, RemoteCommandStatus, LiveStreamStatus, LiveStreamStartedBy, CCTVProviderType, CCTVStreamProtocol, CCTVCameraStatus, CCTVStreamSessionStatus, CCTVCapabilities, AccessPointStatus, PresenceConnectionStatus, PresenceEventSource, DeploymentStatus

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
    Safe, API-facing view of an AuditLog row. `details` is a native
    embedded document -- never contains passwords/JWTs/file paths
    (enforced at write time by app/services/audit.py, not by this schema).
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
        return cls(
            id=entry.id,
            user_id=entry.user_id,
            action=entry.action,
            details=entry.details,
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
    # "front" | "back" -- validated in routers/recordings.py::start_recording
    # (a plain Optional[str] here rather than a Literal so an unrecognized
    # value is a clean, explicit 422 instead of a Pydantic-internal one).
    # Defaults to "back" when omitted, matching the mobile app's own
    # existing RecordingEngine default and every pre-existing caller that
    # doesn't send this field at all.
    camera_lens_direction: Optional[str] = None

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
    # "not_ready" | "building" | "ready" | "failed" -- see
    # recordings.py::_try_build_playable_recording. Never the storage_key
    # itself (same "no raw paths" rule as everything else here) -- a
    # client fetches the actual media via GET /recordings/{id}/play once
    # this is "ready".
    playable_status: str = "not_ready"
    camera_lens_direction: str = "back"
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
    # Real GPS fix as of this segment, or null if genuinely unavailable at
    # capture time -- see models.py::VideoChunk. Also burned directly into
    # the chunk's video frames (routers/recordings.py::_burn_watermark_best_effort);
    # exposed here too as queryable metadata, not a replacement for that.
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    recorded_at: Optional[datetime] = None
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
    # Set only once LiveKit Egress's webhook confirms a real, completed
    # recording exists for this session (see
    # live_stream.py::_handle_egress_ended) -- null the entire time the
    # session is live, and stays null forever if egress was never
    # available/failed. When set, GET /recordings/{recording_session_id}
    # and .../play work exactly like any other recording.
    recording_session_id: Optional[uuid.UUID] = None
    model_config = ConfigDict(from_attributes=True)

class LiveStreamTokenResponse(BaseModel):
    """Never includes the LiveKit API secret -- only a short-lived, single-purpose signed join token."""
    session: LiveStreamSessionResponse
    livekit_url: str
    token: str
    identity: str
    can_publish: bool


# ---------------------------------------------------------------------------
# Authorized CCTV monitoring (admin + control_room only -- see
# app/routers/cctv.py). See app/models.py::CCTVCamera for why this is a
# separate domain from Device/RecordingSession.
# ---------------------------------------------------------------------------

class CCTVCameraCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    camera_code: str = Field(..., min_length=1, max_length=64)
    description: Optional[str] = None
    # Informational only -- see models.CCTVCamera's docstring; never
    # selects a different code path than provider_type does.
    manufacturer: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    station_id: Optional[uuid.UUID] = None
    zone: Optional[str] = None
    address: Optional[str] = None
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)

    provider_type: CCTVProviderType = CCTVProviderType.rtsp
    stream_protocol: CCTVStreamProtocol = CCTVStreamProtocol.rtsp
    # Plain connection-target fields, never a single credentialed URL --
    # see models.CCTVCamera's docstring. stream_host accepts a hostname or
    # bare IP; it is NOT a URL and must not contain a scheme or userinfo.
    stream_host: str = Field(..., min_length=1)
    stream_port: int = Field(default=554, ge=1, le=65535)
    stream_path: Optional[str] = None
    management_url: Optional[str] = None

    username: Optional[str] = None
    # Plaintext ONLY as API input, for exactly as long as it takes to
    # encrypt it (see services/cctv_security.py::encrypt_secret). Never
    # stored, logged, or echoed back as plaintext anywhere.
    secret: Optional[str] = None

    is_demo: bool = False
    metadata: Optional[dict] = None


class CCTVCameraUpdateRequest(BaseModel):
    """All fields optional -- only the ones provided are changed. camera_code is intentionally not updatable here (stable natural key, same convention as Device.device_identifier)."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    manufacturer: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    station_id: Optional[uuid.UUID] = None
    zone: Optional[str] = None
    address: Optional[str] = None
    latitude: Optional[float] = Field(default=None, ge=-90.0, le=90.0)
    longitude: Optional[float] = Field(default=None, ge=-180.0, le=180.0)

    provider_type: Optional[CCTVProviderType] = None
    stream_protocol: Optional[CCTVStreamProtocol] = None
    stream_host: Optional[str] = Field(default=None, min_length=1)
    stream_port: Optional[int] = Field(default=None, ge=1, le=65535)
    stream_path: Optional[str] = None
    management_url: Optional[str] = None

    username: Optional[str] = None
    secret: Optional[str] = None
    clear_secret: bool = False  # explicit -- omitting `secret` always means "leave it unchanged", never "clear it"

    is_demo: Optional[bool] = None
    metadata: Optional[dict] = None


class CCTVCameraResponse(BaseModel):
    """
    Safe, API-facing camera view. NEVER includes `encrypted_secret` or any
    derived plaintext of it -- only `credentials_configured`. See the
    module docstring on app/routers/cctv.py.
    """
    id: uuid.UUID
    name: str
    camera_code: str
    description: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    capabilities: CCTVCapabilities
    station_id: Optional[uuid.UUID] = None
    zone: Optional[str] = None
    address: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    provider_type: CCTVProviderType
    stream_protocol: CCTVStreamProtocol
    stream_host: str
    stream_port: int
    stream_path: Optional[str] = None
    management_url: Optional[str] = None

    username: Optional[str] = None
    credentials_configured: bool

    enabled: bool
    status: CCTVCameraStatus
    last_seen_at: Optional[datetime] = None
    last_status_check_at: Optional[datetime] = None
    last_error: Optional[str] = None
    is_demo: bool

    created_at: datetime
    updated_at: datetime
    created_by: Optional[uuid.UUID] = None
    updated_by: Optional[uuid.UUID] = None
    metadata: Optional[dict] = None


class CCTVCameraTestResponse(BaseModel):
    camera_id: uuid.UUID
    status: CCTVCameraStatus
    checked_at: datetime
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    # Set from the REAL probe result for the camera's configured
    # provider_type -- never inferred from manufacturer/model. Unset
    # (None) when the probe didn't produce a capability determination
    # (e.g. the provider raised NotImplementedError).
    capabilities: Optional[CCTVCapabilities] = None


class CCTVDiscoveredDeviceResponse(BaseModel):
    """One WS-Discovery ProbeMatch -- a CANDIDATE, never an auto-registered camera. See cctv_discovery.py."""
    address: str
    xaddrs: List[str]
    scopes: List[str]
    types: List[str]


class CCTVNearbyCameraResponse(BaseModel):
    id: uuid.UUID
    name: str
    camera_code: str
    station_id: Optional[uuid.UUID] = None
    latitude: float
    longitude: float
    distance_meters: float
    status: CCTVCameraStatus
    enabled: bool


class CCTVStreamSessionResponse(BaseModel):
    """`stream_reference` is an opaque gateway-side id (e.g. a room/ingress name), never a raw or credentialed URL."""
    id: uuid.UUID
    camera_id: uuid.UUID
    requested_by: uuid.UUID
    provider: CCTVProviderType
    protocol: CCTVStreamProtocol
    gateway: Optional[str] = None
    stream_reference: Optional[str] = None
    status: CCTVStreamSessionStatus
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    viewer_count: int
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class CCTVStreamStartResponse(BaseModel):
    """Never includes a LiveKit API secret -- only a short-lived signed viewer token, when a media gateway actually produced one (see CCTVProvider.start_stream)."""
    session: CCTVStreamSessionResponse
    livekit_url: Optional[str] = None
    token: Optional[str] = None
    identity: Optional[str] = None
    can_publish: bool = False


# ---------------------------------------------------------------------------
# AP-based police presence / movement handoff. See app/models.py's module
# docstring above AccessPoint for why this is three separate models, and
# app/services/presence.py for the single business-logic path every
# caller (today: only the authenticated constable-device endpoint) goes
# through.
# ---------------------------------------------------------------------------

class AccessPointCreateRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=32)
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1000)
    zone: Optional[str] = None
    deployment: Optional[str] = None
    station_id: Optional[uuid.UUID] = None
    latitude: Optional[float] = Field(default=None, ge=-90.0, le=90.0)
    longitude: Optional[float] = Field(default=None, ge=-180.0, le=180.0)
    coverage_radius_m: Optional[float] = Field(default=None, gt=0)
    edge_node_id: Optional[str] = Field(default=None, max_length=128)
    is_demo: bool = False


class AccessPointUpdateRequest(BaseModel):
    """All fields optional -- only the ones provided are changed. `code` is not updatable here (stable natural key, same convention as Device.device_identifier / CCTVCamera.camera_code)."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1000)
    zone: Optional[str] = None
    deployment: Optional[str] = None
    station_id: Optional[uuid.UUID] = None
    latitude: Optional[float] = Field(default=None, ge=-90.0, le=90.0)
    longitude: Optional[float] = Field(default=None, ge=-180.0, le=180.0)
    coverage_radius_m: Optional[float] = Field(default=None, gt=0)
    edge_node_id: Optional[str] = Field(default=None, max_length=128)
    is_demo: Optional[bool] = None


class AccessPointResponse(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    description: Optional[str] = None
    zone: Optional[str] = None
    deployment: Optional[str] = None
    station_id: Optional[uuid.UUID] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    coverage_radius_m: Optional[float] = None
    edge_node_id: Optional[str] = None
    enabled: bool
    status: AccessPointStatus
    is_demo: bool
    created_at: datetime
    updated_at: datetime
    # Populated only by GET /access-points (list), which already has to
    # scan current presence rows to answer "how many officers are here" --
    # left unset (None) on single-camera-style reads that don't compute it.
    associated_device_count: Optional[int] = None


class PresenceAssociationRequest(BaseModel):
    """
    `device_identifier` (not device_id) matches the existing convention in
    schemas.DeviceHeartbeatRequest -- the caller identifies the device by
    its client-known identifier, never a server-side UUID it was never
    given. `source` is deliberately NOT a field here -- see
    models.PresenceEventSource's docstring: it is always server-set to
    REAL for this endpoint.
    """
    device_identifier: str = Field(..., min_length=1)
    access_point_code: str = Field(..., min_length=1)
    event_id: Optional[str] = Field(default=None, max_length=128)
    occurred_at: Optional[datetime] = None


class PresenceHandoffResponse(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    constable_id: uuid.UUID
    previous_access_point_id: Optional[uuid.UUID] = None
    access_point_id: uuid.UUID
    event_id: Optional[str] = None
    source: PresenceEventSource
    occurred_at: datetime
    model_config = ConfigDict(from_attributes=True)


class PresenceStateResponse(BaseModel):
    """
    `status` is the EFFECTIVE status (computed at request time from
    last_seen_at + configurable thresholds -- see
    services/presence.py::compute_effective_presence_status), exactly the
    same pattern as schemas.DeviceResponse.status.
    """
    device_id: uuid.UUID
    constable_id: uuid.UUID
    current_access_point_id: Optional[uuid.UUID] = None
    current_access_point_code: Optional[str] = None
    current_zone: Optional[str] = None
    status: PresenceConnectionStatus
    location_source: str
    last_seen_at: Optional[datetime] = None
    handoff_count: int
    current_zone_since: Optional[datetime] = None
    updated_at: datetime


class PresenceAssociationResponse(BaseModel):
    status: str  # "connected" | "handoff" | "duplicate_ignored"
    handoff_created: bool
    presence: PresenceStateResponse
    handoff: Optional[PresenceHandoffResponse] = None


# ---------------------------------------------------------------------------
# Virtual AP / zone / deployment layer -- see app/models.py::Deployment's
# docstring for why zones are a derived view, not a stored entity, and
# app/services/ap_association.py for the provider abstraction these
# schemas front.
# ---------------------------------------------------------------------------

class DeploymentCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    description: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    is_demo: bool = False


class DeploymentUpdateRequest(BaseModel):
    description: Optional[str] = None
    status: Optional[DeploymentStatus] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class DeploymentResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str] = None
    status: DeploymentStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    is_demo: bool
    created_at: datetime
    updated_at: datetime
    zone_count: Optional[int] = None
    access_point_count: Optional[int] = None


class ZoneSummaryResponse(BaseModel):
    """A zone is a derived grouping of AccessPoint.zone within one deployment -- never a stored row. See Deployment's docstring."""
    zone: str
    deployment: Optional[str] = None
    access_point_codes: List[str]
    enabled: bool  # true iff at least one AP in this zone is enabled
    police_count: int
    moving_count: int


class PresenceAssociationVirtualRequest(BaseModel):
    """
    Identical shape to PresenceAssociationRequest -- kept as a distinct
    schema (not reused) so the virtual-only endpoint's OpenAPI docs are
    self-explanatory and so a future field divergence doesn't require
    touching the real-association contract. `source` is still never
    client-settable here either -- see routers/presence.py::associate_virtual.
    """
    device_identifier: str = Field(..., min_length=1)
    access_point_code: str = Field(..., min_length=1)
    event_id: Optional[str] = Field(default=None, max_length=128)


class PresenceMovingPingRequest(BaseModel):
    """
    Pure WebSocket passthrough -- see routers/presence.py::moving_ping.
    NEVER persisted to MongoDB (no model, no collection): this is exactly
    the "don't store every animation frame" requirement. `progress` is
    the simulator's own client-side animation progress, 0-100, purely
    informational for the admin's live view.
    """
    device_identifier: str = Field(..., min_length=1)
    target_access_point_code: str = Field(..., min_length=1)
    progress: int = Field(..., ge=0, le=100)


class NearestAccessPointResponse(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    zone: Optional[str] = None
    distance_meters: float


class ZoneAlertRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=500)


class ZoneAlertResponse(BaseModel):
    zone: str
    message: str
    targeted_constable_ids: List[uuid.UUID]
    targeted_device_count: int
