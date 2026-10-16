"""
API schemas for Bodycam <-> site (Network Hopping) video transport:
site assignments, device authorizations, offline grants, receivers, receiver->control-room ingestion,
and the phone's site-configuration endpoint. No response model ever carries a stored secret, token hash,
storage path or raw client identifier.
"""
import re
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from .models import RecordingStatus, RecordingTriggerType
from .schemas_network import Code

_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _http_endpoints_allowed() -> bool:
    return os.getenv("ALLOW_HTTP_RECEIVER_ENDPOINTS", "false").strip().lower() in ("1", "true", "yes")


def _validate_url(v: Optional[str], *, allow_http: bool = True) -> Optional[str]:
    if v is None or not v.strip():
        return None
    v = v.strip().rstrip("/")
    parsed = urlparse(v)
    if parsed.scheme not in ("https", "http") or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("must be an http(s) URL without credentials, query or fragment")
    if parsed.scheme == "http" and not (allow_http and _http_endpoints_allowed()):
        raise ValueError("must be https:// (plain http is refused; ALLOW_HTTP_RECEIVER_ENDPOINTS=true is for an isolated development lab only)")
    return v


def _validate_endpoint(v: Optional[str]) -> Optional[str]:
    """Receiver address that phones will send grants and video to: https only unless the dev-lab flag is set."""
    parsed = urlparse(v.strip()) if v and v.strip() else None
    if parsed is not None and parsed.path not in ("", "/"):
        raise ValueError("must be just scheme, host and port")
    return _validate_url(v)


# ===========================================================================
# Assignments, device authorizations, grants (admin)
# ===========================================================================

class AssignmentIn(BaseModel):
    constable_id: uuid.UUID
    zone_id: Optional[uuid.UUID] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    notes: Optional[str] = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _window(self):
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class AssignmentOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    constable_id: uuid.UUID
    constable_label: Optional[str] = None  # badge number; never a phone number
    zone_id: Optional[uuid.UUID] = None
    building_id: Optional[uuid.UUID] = None
    floor_id: Optional[uuid.UUID] = None
    status: str
    valid_from: datetime
    valid_until: Optional[datetime] = None
    notes: Optional[str] = None
    created_at: datetime
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None


class ReasonIn(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=200)


class DeviceAuthorizationIn(BaseModel):
    device_id: uuid.UUID
    valid_until: Optional[datetime] = None


class DeviceAuthorizationOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    device_id: uuid.UUID
    device_identifier: Optional[str] = None
    constable_id: uuid.UUID
    constable_label: Optional[str] = None
    status: str
    authorized_at: datetime
    valid_until: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None
    last_seen_by_receiver_at: Optional[str] = None


class GrantIssueIn(BaseModel):
    device_id: uuid.UUID
    operations: Optional[List[Literal["session", "upload", "live"]]] = None


class GrantOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    constable_id: uuid.UUID
    device_id: uuid.UUID
    issued_at: datetime
    expires_at: datetime
    operations: List[str]
    key_id: Optional[str] = None
    revoked: bool
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None
    state: str  # valid | expired | revoked


class GrantIssuedOut(BaseModel):
    """Contains the signed grant. It is returned ONCE to the caller; only metadata is stored."""
    grant: GrantOut
    token: str


# ===========================================================================
# Receivers (admin)
# ===========================================================================

class ReceiverIn(BaseModel):
    code: Code
    name: str = Field(..., min_length=1, max_length=255)
    endpoint_url: Optional[str] = None
    local_live_enabled: bool = False
    local_live_url: Optional[str] = None

    @field_validator("endpoint_url")
    @classmethod
    def _endpoint(cls, v):
        return _validate_endpoint(v)

    @field_validator("local_live_url")
    @classmethod
    def _url(cls, v):
        return _validate_url(v)


class ReceiverPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    endpoint_url: Optional[str] = None
    clear_endpoint_url: bool = False
    local_live_enabled: Optional[bool] = None
    local_live_url: Optional[str] = None
    active: Optional[bool] = None

    @field_validator("endpoint_url")
    @classmethod
    def _endpoint(cls, v):
        return _validate_endpoint(v)

    @field_validator("local_live_url")
    @classmethod
    def _url(cls, v):
        return _validate_url(v)


class ReceiverCommandIn(BaseModel):
    type: Literal["retry_quarantined", "resync", "retry_recording"]
    recording_id: Optional[uuid.UUID] = None

    @model_validator(mode="after")
    def _needs(self):
        if self.type == "retry_recording" and self.recording_id is None:
            raise ValueError("retry_recording needs recording_id")
        return self


class ReceiverOut(BaseModel):
    id: uuid.UUID
    site_id: uuid.UUID
    code: str
    name: str
    endpoint_url: Optional[str] = None
    local_live_enabled: bool
    local_live_url: Optional[str] = None
    active: bool
    revoked: bool
    token_hint: Optional[str] = None
    token_version: int
    version: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    state: str  # online | stale | offline | unknown
    last_seen_at: Optional[datetime] = None
    last_sync_at: Optional[datetime] = None
    last_central_ack_at: Optional[datetime] = None
    last_local_upload_at: Optional[datetime] = None
    disk_total_bytes: Optional[int] = None
    disk_free_bytes: Optional[int] = None
    disk_used_pct: Optional[float] = None
    min_free_bytes: Optional[int] = None
    accepting_uploads: Optional[bool] = None
    pending_chunks: int = 0
    syncing_chunks: int = 0
    quarantined_chunks: int = 0
    received_chunks_total: int = 0
    failures: List[Dict[str, Any]] = Field(default_factory=list)
    pending_commands: int = 0
    alerts: List[str] = Field(default_factory=list)


class ReceiverCredentialOut(BaseModel):
    """The ONLY response that contains a receiver credential: shown once."""
    receiver: ReceiverOut
    token: str
    note: str = "Store this token in the receiver's secret store now. It is not shown again."


# ===========================================================================
# Receiver -> control room
# ===========================================================================

class ReceiverHeartbeat(BaseModel):
    site_code: Optional[str] = Field(default=None, max_length=64)  # cross-check only; the site comes from the credential
    version: Optional[str] = Field(default=None, max_length=64)
    capabilities: List[str] = Field(default_factory=list, max_length=32)
    disk_total_bytes: Optional[int] = Field(default=None, ge=0)
    disk_free_bytes: Optional[int] = Field(default=None, ge=0)
    min_free_bytes: Optional[int] = Field(default=None, ge=0)
    accepting_uploads: Optional[bool] = None
    pending_chunks: int = Field(default=0, ge=0)
    syncing_chunks: int = Field(default=0, ge=0)
    quarantined_chunks: int = Field(default=0, ge=0)
    received_chunks_total: int = Field(default=0, ge=0)
    last_local_upload_at: Optional[datetime] = None
    last_central_ack_at: Optional[datetime] = None
    recent_devices: Dict[str, str] = Field(default_factory=dict)
    failures: List[Dict[str, Any]] = Field(default_factory=list, max_length=20)
    completed_command_ids: List[str] = Field(default_factory=list, max_length=50)
    # Recordings the receiver still holds that are not fully confirmed centrally (bounded; summary fields only).
    local_recordings: List[Dict[str, Any]] = Field(default_factory=list, max_length=50)

    @field_validator("local_recordings")
    @classmethod
    def _local(cls, v):
        keep = ("recording_id", "status", "constable_id", "device_identifier", "started_at", "created_at", "expected_chunks", "central_registered",
                "central_completed", "last_error", "chunks_received", "chunks_synced", "chunks_quarantined")
        return [{k: (str(r.get(k))[:200] if r.get(k) is not None else None) for k in keep} for r in v[:50]]

    @field_validator("recent_devices")
    @classmethod
    def _bounded(cls, v):
        if len(v) > 200:
            raise ValueError("too many recent_devices")
        return {str(k)[:128]: str(val)[:40] for k, val in v.items()}

    @field_validator("failures")
    @classmethod
    def _failures(cls, v):
        # Free text from a remote service is length-bounded before it is stored or shown.
        out = []
        for f in v[:20]:
            out.append({k: (str(val)[:200] if val is not None else None) for k, val in list(f.items())[:8]})
        return out


class ReceiverSyncOut(BaseModel):
    server_time: datetime
    site_id: uuid.UUID
    site_code: str
    revoked_grant_ids: List[uuid.UUID]
    commands: List[Dict[str, Any]]
    grant_issuer: str
    grant_key_id: Optional[str] = None


class ReceiverRecordingIn(BaseModel):
    site_id: Optional[uuid.UUID] = None
    constable_id: uuid.UUID
    device_id: uuid.UUID
    grant_id: Optional[uuid.UUID] = None
    trigger_type: RecordingTriggerType = RecordingTriggerType.manual
    camera_lens_direction: Literal["front", "back"] = "back"
    started_at: datetime
    ended_at: Optional[datetime] = None
    status: Literal["recording", "completed", "cancelled"] = "recording"


class ReceiverRecordingOut(BaseModel):
    recording_id: uuid.UUID
    status: RecordingStatus
    created: bool
    chunk_numbers: List[int]
    flags: List[str] = Field(default_factory=list)


class ReceiverChunkAck(BaseModel):
    chunk_id: uuid.UUID
    recording_id: uuid.UUID
    chunk_number: int
    original_hash: str
    duplicate: bool
    stored_at: datetime


class ReceiverCompleteIn(BaseModel):
    ended_at: Optional[datetime] = None
    chunk_count: Optional[int] = Field(default=None, ge=0)


class ReceiverCompleteOut(BaseModel):
    recording_id: uuid.UUID
    status: RecordingStatus
    missing_chunk_numbers: List[int]


class ManifestItem(BaseModel):
    chunk_id: uuid.UUID
    chunk_number: int
    original_hash: Optional[str] = None


class ReceiverManifestOut(BaseModel):
    recording_id: uuid.UUID
    status: RecordingStatus
    chunks: List[ManifestItem]


# ===========================================================================
# Dashboard (control room)
# ===========================================================================

class SiteRecordingChunkOut(BaseModel):
    chunk_id: uuid.UUID
    chunk_number: int
    file_size: Optional[int] = None
    original_hash: Optional[str] = None
    derived_hash: Optional[str] = None
    has_original: bool
    received_via: str
    site_received_at: Optional[datetime] = None
    created_at: datetime
    processing: List[Dict[str, Any]] = Field(default_factory=list)


class SiteRecordingOut(BaseModel):
    id: uuid.UUID
    site_id: Optional[uuid.UUID] = None
    receiver_id: Optional[uuid.UUID] = None
    origin: str
    constable_id: uuid.UUID
    constable_label: Optional[str] = None
    device_id: uuid.UUID
    device_identifier: Optional[str] = None
    status: RecordingStatus
    started_at: datetime
    ended_at: Optional[datetime] = None
    chunk_count: int
    missing_chunk_numbers: List[int]
    flags: List[str] = Field(default_factory=list)
    sync_state: str  # local_only | partial | incomplete | central | online
    created_at: datetime


class SiteRecordingDetail(SiteRecordingOut):
    chunks: List[SiteRecordingChunkOut]


class SiteRecordingPage(BaseModel):
    items: List[SiteRecordingOut]
    total: int
    limit: int
    offset: int


class BodycamOverview(BaseModel):
    site_id: uuid.UUID
    receivers: List[ReceiverOut]
    active_assignments: int
    authorized_devices: int
    active_grants: int
    recordings_total: int
    recordings_via_receiver: int
    recordings_in_progress: int
    receiver_pending_chunks: int
    receiver_quarantined_chunks: int
    alerts: List[str]


class AuditEntryOut(BaseModel):
    id: uuid.UUID
    action: str
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None


# ===========================================================================
# Phone configuration
# ===========================================================================

class PhoneReceiverOut(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    endpoint_url: Optional[str] = None
    local_live_enabled: bool = False
    configured: bool = True  # False: the receiver has no address yet and must not be used as an upload destination


class PhoneGrantKey(BaseModel):
    kid: Optional[str] = None
    pem: str


class PhoneSiteConfig(BaseModel):
    site_id: uuid.UUID
    site_code: str
    site_name: str
    organization: Optional[str] = None
    assignment_id: uuid.UUID
    zone_id: Optional[uuid.UUID] = None
    eligible: bool
    reason: Optional[str] = None  # stable code when not eligible
    receivers: List[PhoneReceiverOut] = Field(default_factory=list)
    grant: Optional[str] = None
    grant_id: Optional[uuid.UUID] = None
    grant_expires_at: Optional[datetime] = None


class PhoneNetworkHoppingConfig(BaseModel):
    server_time: datetime
    device_id: uuid.UUID
    grant_lifetime_hours: int
    constable_id: Optional[uuid.UUID] = None
    grant_issuer: Optional[str] = None
    grant_public_keys: List[PhoneGrantKey] = Field(default_factory=list)  # PUBLIC keys only
    sites: List[PhoneSiteConfig]


class ReceiverLocalRecordingOut(BaseModel):
    recording_id: uuid.UUID
    status: Optional[str] = None
    constable_label: Optional[str] = None
    device_identifier: Optional[str] = None
    started_at: Optional[str] = None
    created_at: Optional[str] = None
    expected_chunks: Optional[int] = None  # None = unknown (the phone has not said how many chunks to expect)
    chunks_received: int = 0
    chunks_synced: int = 0
    chunks_quarantined: int = 0
    central_registered: bool = False
    central_completed: bool = False
    last_error: Optional[str] = None
    registered_centrally: bool = False  # the control room already has a record with this id


class ReceiverLocalRecordingsOut(BaseModel):
    receiver_id: uuid.UUID
    reported_at: Optional[datetime] = None
    stale: bool = True
    items: List[ReceiverLocalRecordingOut] = Field(default_factory=list)
