"""
Physical AP Telemetry Service & Adapters (Stage 2B).

Provides vendor-independent normalization, replay protection, identity
resolution, and ingestion of real Wi-Fi access point association telemetry
from authorized edge controllers, RADIUS accounting, or syslog collectors.
"""
import datetime
import os
import re
import uuid
from typing import Dict, List, Optional, Tuple

from fastapi import HTTPException, status
from pymongo.errors import DuplicateKeyError

from .. import models, schemas
from . import events, movement_state
from . import presence as presence_service

MAX_SKEW_SECONDS = int(os.getenv("EDGE_CONTROLLER_MAX_SKEW_SECONDS", "300").strip())


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ===========================================================================
# Adapters Layer
# ===========================================================================

class BaseAPTelemetryAdapter:
    """Base class for normalizing vendor-specific event payloads into standard schema."""

    def normalize(self, raw_data: dict) -> schemas.EdgeAPTelemetryEventRequest:
        raise NotImplementedError


class GenericEdgeTelemetryAdapter(BaseAPTelemetryAdapter):
    """Direct normalized JSON payload from edge collector."""

    def normalize(self, raw_data: dict) -> schemas.EdgeAPTelemetryEventRequest:
        return schemas.EdgeAPTelemetryEventRequest.model_validate(raw_data)


class SyslogTelemetryAdapter(BaseAPTelemetryAdapter):
    """
    Parses enterprise controller syslog messages (Cisco / Aruba / UniFi / MikroTik).
    Example formats:
      - Cisco: "%DOT11-6-ASSOC: Client 00:11:22:33:44:55 associated to AP AP-GATE-01 on SSID AP_POLICE_SECURE"
      - Aruba: "station 00:11:22:33:44:55 associated to bssid aa:bb:cc:dd:ee:01 essid AP_POLICE_SECURE ap-name AP-GATE-01"
      - UniFi: "hostapd: ath0: STA 00:11:22:33:44:55 IEEE 802.11: associated"
    """

    # Common patterns
    ASSOC_PATTERN = re.compile(
        r"(?:associated to (?:AP|bssid)?\s*([A-Za-z0-9_\-\:]+)|STA\s+([A-Za-z0-9_\:]+).*associated)",
        re.IGNORECASE,
    )
    DISASSOC_PATTERN = re.compile(
        r"(?:disassociated|deauthenticated|left AP)",
        re.IGNORECASE,
    )
    MAC_PATTERN = re.compile(
        r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
    )
    AP_NAME_PATTERN = re.compile(
        r"(?:AP\s+|ap-name\s+|AP-NAME\s+)([A-Za-z0-9_\-]+)",
        re.IGNORECASE,
    )

    def normalize(self, raw_data: dict) -> schemas.EdgeAPTelemetryEventRequest:
        syslog_line = raw_data.get("message", "").strip()
        controller_id = raw_data.get("controller_id", "syslog-collector").strip()
        event_id = raw_data.get("event_id") or str(uuid.uuid4())
        occurred_at = raw_data.get("occurred_at") or _utcnow()
        if isinstance(occurred_at, str):
            occurred_at = datetime.datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))

        mac_match = self.MAC_PATTERN.search(syslog_line)
        station_mac = mac_match.group(1).lower() if mac_match else None

        client_pattern = re.compile(r"Client\s+([A-Za-z0-9_\-\:]+)", re.IGNORECASE)
        client_match = client_pattern.search(syslog_line)
        device_identifier = None
        if client_match:
            candidate = client_match.group(1).strip()
            if self.MAC_PATTERN.match(candidate):
                station_mac = candidate.lower()
            else:
                device_identifier = candidate

        ap_match = self.AP_NAME_PATTERN.search(syslog_line)
        ap_code = ap_match.group(1).upper() if ap_match else raw_data.get("ap_code")

        if self.DISASSOC_PATTERN.search(syslog_line):
            event_type = schemas.EdgeAPEventType.disassociation
        elif "roam" in syslog_line.lower():
            event_type = schemas.EdgeAPEventType.roam
        else:
            event_type = schemas.EdgeAPEventType.association

        return schemas.EdgeAPTelemetryEventRequest(
            controller_event_id=event_id,
            controller_id=controller_id,
            ap_code=ap_code,
            event_type=event_type,
            occurred_at=occurred_at,
            device_identifier=device_identifier,
            station_mac=station_mac,
            source_metadata={"raw_syslog": syslog_line},
        )



class RadiusAccountingTelemetryAdapter(BaseAPTelemetryAdapter):
    """
    Parses RFC 2866 RADIUS Accounting attributes:
      - Acct-Status-Type: 1=Start, 2=Stop, 3=Interim-Update
      - Calling-Station-Id: Station MAC
      - Called-Station-Id: AP BSSID / SSID
      - User-Name: Authenticated 802.1X identity / badge / phone
      - NAS-Identifier: Controller / Gateway ID
    """

    def normalize(self, raw_data: dict) -> schemas.EdgeAPTelemetryEventRequest:
        status_type = int(raw_data.get("Acct-Status-Type", 1))
        station_mac = raw_data.get("Calling-Station-Id", "").strip().lower() or None
        called_station = raw_data.get("Called-Station-Id", "").strip()
        username = raw_data.get("User-Name", "").strip() or None
        controller_id = raw_data.get("NAS-Identifier", raw_data.get("NAS-IP-Address", "radius-nas")).strip()
        event_id = raw_data.get("Acct-Session-Id") or raw_data.get("event_id") or str(uuid.uuid4())
        occurred_at = raw_data.get("occurred_at") or _utcnow()

        ap_code = None
        ap_bssid = None
        if ":" in called_station:
            # Often formatted as "AA-BB-CC-DD-EE-FF:SSID" or "AP-CODE:SSID"
            parts = called_station.split(":")
            if len(parts) >= 1:
                first = parts[0].strip()
                if re.match(r"^[0-9a-fA-F]{2}[:-]", first):
                    ap_bssid = first.lower()
                else:
                    ap_code = first

        if status_type == 2:
            event_type = schemas.EdgeAPEventType.disassociation
        elif status_type == 3:
            event_type = schemas.EdgeAPEventType.roam
        else:
            event_type = schemas.EdgeAPEventType.association

        return schemas.EdgeAPTelemetryEventRequest(
            controller_event_id=event_id,
            controller_id=controller_id,
            ap_code=ap_code,
            ap_bssid=ap_bssid,
            event_type=event_type,
            occurred_at=occurred_at,
            authenticated_identity=username,
            station_mac=station_mac,
            source_metadata={"radius_attributes": raw_data},
        )


# ===========================================================================
# Ingestion & Resolution Logic
# ===========================================================================

def validate_timestamp_skew(occurred_at: datetime.datetime, max_skew_seconds: int = MAX_SKEW_SECONDS) -> None:
    """Rejects timestamps too far in the future or severely aged to prevent replay attacks."""
    now = _utcnow()
    # Normalize timezone
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=datetime.timezone.utc)
    delta = (now - occurred_at).total_seconds()
    if delta < -max_skew_seconds:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Event timestamp is {abs(delta):.0f}s in the future (max allowed skew: {max_skew_seconds}s)",
        )
    if delta > 86400:  # Older than 24 hours
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Event timestamp is older than 24 hours; stale historical replay rejected",
        )


async def resolve_access_point(
    ap_code: Optional[str], ap_bssid: Optional[str]
) -> Optional[models.AccessPoint]:
    """Resolves AccessPoint by code, edge_node_id, or natural key."""
    if ap_code:
        ap = await models.AccessPoint.find_one(models.AccessPoint.code == ap_code)
        if ap:
            return ap
    if ap_bssid:
        # Match edge_node_id if set
        ap = await models.AccessPoint.find_one(models.AccessPoint.edge_node_id == ap_bssid)
        if ap:
            return ap
        # Or match code if bssid matches code
        ap = await models.AccessPoint.find_one(models.AccessPoint.code == ap_bssid)
        if ap:
            return ap
    return None


async def resolve_enrolled_officer_and_device(
    device_identifier: Optional[str],
    authenticated_identity: Optional[str],
    station_mac: Optional[str],
) -> Tuple[Optional[models.Device], Optional[models.Constable]]:
    """
    Maps telemetry event to an enrolled police bodycam device and assigned constable.
    Never invents or auto-provisions devices.
    Prioritizes:
      1. Explicit enrolled device_identifier
      2. Authenticated 802.1X / captive portal identity (constable badge or phone)
      3. Station MAC matching device identifier if configured
    """
    device = None
    constable = None

    if device_identifier:
        device = await models.Device.find_one(models.Device.device_identifier == device_identifier)

    if not device and authenticated_identity:
        # Check if authenticated_identity is a constable's badge_number or phone
        constable = await models.Constable.find_one(
            {"$or": [{"badge_number": authenticated_identity}, {"phone": authenticated_identity}]}
        )
        if constable:
            device = await models.Device.find_one(models.Device.constable_id == constable.id)

    if not device and station_mac:
        # Correlate station_mac if device has that MAC in device_identifier or metadata
        device = await models.Device.find_one(models.Device.device_identifier == station_mac)

    if device and not constable and device.constable_id:
        constable = await models.Constable.get(device.constable_id)

    return device, constable


async def process_edge_telemetry_event(
    event: schemas.EdgeAPTelemetryEventRequest,
    controller_info: dict,
) -> schemas.EdgeAPTelemetryResponse:
    """
    Main ingestion engine for real AP telemetry.
    Validates clock skew, enforces deduplication / replay protection, resolves
    target AP and enrolled officer, and delegates to PresenceService.
    """
    now = _utcnow()

    # 1. Timestamp validation
    validate_timestamp_skew(event.occurred_at)

    # 2. Replay protection: check controller_event_id
    existing_log = await models.EdgeControllerEventLog.find_one(
        models.EdgeControllerEventLog.controller_event_id == event.controller_event_id
    )
    if existing_log:
        return schemas.EdgeAPTelemetryResponse(
            status="duplicate_ignored",
            event_id=event.controller_event_id,
            processed_at=now,
            handoff_created=False,
            device_identifier=existing_log.device_identifier,
            access_point_code=existing_log.ap_code,
            message="Duplicate controller event ID already processed",
        )

    # 3. Access Point resolution
    access_point = await resolve_access_point(event.ap_code, event.ap_bssid)
    if not access_point:
        # Log unmapped AP and reject with 404
        log_entry = models.EdgeControllerEventLog(
            controller_event_id=event.controller_event_id,
            controller_id=event.controller_id,
            ap_code=event.ap_code,
            ap_bssid=event.ap_bssid,
            device_identifier=event.device_identifier,
            station_mac=event.station_mac,
            authenticated_identity=event.authenticated_identity,
            event_type=event.event_type.value,
            occurred_at=event.occurred_at,
            server_received_at=now,
            status="unmapped_ap",
            details=event.source_metadata,
        )
        try:
            await log_entry.insert()
        except DuplicateKeyError:
            pass
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Access point '{event.ap_code or event.ap_bssid}' not found in registry",
        )

    # 4. Enrolled Device and Officer resolution
    device, constable = await resolve_enrolled_officer_and_device(
        event.device_identifier, event.authenticated_identity, event.station_mac
    )

    if not device or not constable:
        # Log unmapped device telemetry
        log_entry = models.EdgeControllerEventLog(
            controller_event_id=event.controller_event_id,
            controller_id=event.controller_id,
            ap_code=access_point.code,
            ap_bssid=event.ap_bssid,
            device_identifier=event.device_identifier,
            station_mac=event.station_mac,
            authenticated_identity=event.authenticated_identity,
            event_type=event.event_type.value,
            occurred_at=event.occurred_at,
            server_received_at=now,
            status="unmapped_device",
            details=event.source_metadata,
        )
        try:
            await log_entry.insert()
        except DuplicateKeyError:
            pass

        return schemas.EdgeAPTelemetryResponse(
            status="unmapped_device",
            event_id=event.controller_event_id,
            processed_at=now,
            handoff_created=False,
            device_identifier=event.device_identifier,
            access_point_code=access_point.code,
            message="Telemetry identity does not match any enrolled officer/device",
        )

    # 5. Handle Disassociation
    if event.event_type == schemas.EdgeAPEventType.disassociation:
        presence = await models.PolicePresence.find_one(models.PolicePresence.device_id == device.id)
        if presence and presence.current_access_point_id == access_point.id:
            old_status = presence.status.value if presence.status else None
            presence.status = models.PresenceConnectionStatus.disconnected
            presence.last_seen_at = event.occurred_at
            await presence.save()
            await events.publish_presence_status_changed(
                presence, old_status, models.PresenceConnectionStatus.disconnected.value, constable.station_id
            )

        log_entry = models.EdgeControllerEventLog(
            controller_event_id=event.controller_event_id,
            controller_id=event.controller_id,
            ap_code=access_point.code,
            ap_bssid=event.ap_bssid,
            device_identifier=device.device_identifier,
            station_mac=event.station_mac,
            authenticated_identity=event.authenticated_identity,
            event_type=event.event_type.value,
            occurred_at=event.occurred_at,
            server_received_at=now,
            status="disassociated",
            details=event.source_metadata,
        )
        try:
            await log_entry.insert()
        except DuplicateKeyError:
            pass

        return schemas.EdgeAPTelemetryResponse(
            status="disassociated",
            event_id=event.controller_event_id,
            processed_at=now,
            handoff_created=False,
            device_identifier=device.device_identifier,
            access_point_code=access_point.code,
            message="Disassociation processed",
        )

    # 6. Handle Association & Roam
    try:
        result = await presence_service.process_association(
            device=device,
            constable=constable,
            access_point=access_point,
            event_id=event.controller_event_id,
            occurred_at=event.occurred_at,
            source=models.PresenceEventSource.controller,
        )
    except presence_service.PresenceError as exc:
        if exc.code == "access_point_disabled":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.message)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message)

    movement_state.clear_moving(str(device.id))

    # Log successful ingestion
    log_entry = models.EdgeControllerEventLog(
        controller_event_id=event.controller_event_id,
        controller_id=event.controller_id,
        ap_code=access_point.code,
        ap_bssid=event.ap_bssid,
        device_identifier=device.device_identifier,
        station_mac=event.station_mac,
        authenticated_identity=event.authenticated_identity,
        event_type=event.event_type.value,
        occurred_at=event.occurred_at,
        server_received_at=now,
        status="accepted" if not result.duplicate_event else "duplicate_ignored",
        details={
            "rssi_dbm": event.rssi_dbm,
            "handoff_created": result.handoff_created,
            "is_first": result.is_first_association,
        },
    )
    try:
        await log_entry.insert()
    except DuplicateKeyError:
        pass

    # Publish WebSocket notifications
    station_id = constable.station_id
    if result.is_first_association:
        await events.publish_presence_connected(result.presence, access_point, station_id)
    elif result.handoff_created and result.handoff:
        from_ap = None
        if result.handoff.previous_access_point_id:
            from_ap = await models.AccessPoint.get(result.handoff.previous_access_point_id)
        await events.publish_presence_handoff(result.presence, result.handoff, from_ap, access_point, station_id)

    status_str = "duplicate_ignored" if result.duplicate_event else "accepted"
    return schemas.EdgeAPTelemetryResponse(
        status=status_str,
        event_id=event.controller_event_id,
        processed_at=now,
        handoff_created=result.handoff_created,
        device_identifier=device.device_identifier,
        access_point_code=access_point.code,
        message="Handoff recorded" if result.handoff_created else "Association recorded",
    )
