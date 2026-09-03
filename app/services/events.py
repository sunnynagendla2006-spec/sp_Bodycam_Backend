"""
Small event-publishing helpers used by incidents.py / constables.py /
media.py to notify the right WebSocket room(s) about a meaningful
operational event -- never a raw global broadcast, and never every
database change (see Phase 5 report Part 8).

Routing rules encoded here (see Phase 5 report Parts 8-9 for the full
rationale):
  - Incident/assignment events go to `control_room` + the incident's
    RESPONSIBLE station (`Incident.station_id`), plus the specific
    constable for assignment-level events.
  - Constable location updates go to `control_room` + that constable's
    OWN station (`Constable.station_id` -- a constable's home station,
    which is intentionally a different field from an incident's
    responsible station) -- and NEVER to any other constable.
  - Citizen personal information is never included in a payload a
    constable or station room can see.

Every publish function is a thin wrapper around
`websocket.manager.send_to_*`, which already swallows any per-connection
send failure internally (see ConnectionManager._send_to_all) -- so a
WebSocket delivery problem can never raise up into the caller and can
never affect whether the database transaction that triggered it commits.
"""
import uuid
from typing import Optional

from .. import models
from ..routers.websocket import manager, build_event


def _incident_summary(incident: models.Incident) -> dict:
    return {
        "incident_id": str(incident.id),
        "display_id": incident.display_id,
        "status": incident.status.value if incident.status else None,
    }


async def publish_incident_verified(incident: models.Incident):
    event = build_event("incident.verified", _incident_summary(incident))
    await manager.send_to_control_room(event)
    await manager.send_to_station(incident.station_id, event)


async def publish_incident_rejected(incident: models.Incident):
    event = build_event("incident.rejected", _incident_summary(incident))
    await manager.send_to_control_room(event)
    await manager.send_to_station(incident.station_id, event)


async def publish_incident_needs_review(incident: models.Incident):
    event = build_event("incident.needs_review", _incident_summary(incident))
    await manager.send_to_control_room(event)
    await manager.send_to_station(incident.station_id, event)


async def publish_incident_dispatched(
    incident: models.Incident,
    constable_id: Optional[uuid.UUID],
    assignment_id: Optional[uuid.UUID],
):
    """
    Control room + responsible station receive the dispatch event; ONLY the
    assigned constable receives their own assignment event (never other
    constables). No citizen personal information is included.
    """
    control_and_station_payload = dict(_incident_summary(incident))
    control_and_station_payload["constable_id"] = str(constable_id) if constable_id else None
    control_and_station_payload["assignment_id"] = str(assignment_id) if assignment_id else None
    event = build_event("incident.dispatched", control_and_station_payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(incident.station_id, event)

    if constable_id:
        assignment_payload = {
            "incident_id": str(incident.id),
            "display_id": incident.display_id,
            "assignment_id": str(assignment_id) if assignment_id else None,
            "status": "pending",
        }
        await manager.send_to_constable(constable_id, build_event("assignment.created", assignment_payload))


async def publish_assignment_accepted(assignment: models.IncidentAssignment, incident: models.Incident):
    payload = {
        "incident_id": str(incident.id),
        "display_id": incident.display_id,
        "assignment_id": str(assignment.id),
        "constable_id": str(assignment.constable_id),
        "status": assignment.status.value,
    }
    event = build_event("assignment.accepted", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(incident.station_id, event)


async def publish_assignment_rejected(assignment: models.IncidentAssignment, incident: models.Incident):
    payload = {
        "incident_id": str(incident.id),
        "display_id": incident.display_id,
        "assignment_id": str(assignment.id),
        "constable_id": str(assignment.constable_id),
        "status": assignment.status.value,
    }
    event = build_event("assignment.rejected", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(incident.station_id, event)


async def publish_assignment_status_changed(assignment: models.IncidentAssignment, incident: models.Incident):
    payload = {
        "incident_id": str(incident.id),
        "display_id": incident.display_id,
        "assignment_id": str(assignment.id),
        "constable_id": str(assignment.constable_id),
        "status": assignment.status.value,
    }
    event = build_event("assignment.status_changed", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(incident.station_id, event)


async def publish_evidence_uploaded(evidence: models.Evidence, station_id: Optional[uuid.UUID]):
    """Control room + the responsible station (if known) are notified that new evidence exists -- never the raw file, never other constables."""
    payload = {
        "evidence_id": str(evidence.id),
        "incident_id": str(evidence.incident_id),
        "type": evidence.type.value if evidence.type else None,
        "upload_status": evidence.upload_status.value if evidence.upload_status else None,
    }
    event = build_event("evidence.uploaded", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


def _evidence_lifecycle_payload(evidence: models.Evidence) -> dict:
    payload = {
        "evidence_id": str(evidence.id),
        "incident_id": str(evidence.incident_id),
        "upload_status": evidence.upload_status.value if evidence.upload_status else None,
    }
    if evidence.rejection_reason:
        payload["reason"] = evidence.rejection_reason
    return payload


async def publish_evidence_verified(evidence: models.Evidence, station_id: Optional[uuid.UUID]):
    """Same routing as publish_evidence_uploaded -- control_room + the evidence's responsible station only. No constable/citizen room ever receives this (see events routing notes above)."""
    event = build_event("evidence.verified", _evidence_lifecycle_payload(evidence))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


async def publish_evidence_rejected(evidence: models.Evidence, station_id: Optional[uuid.UUID]):
    event = build_event("evidence.rejected", _evidence_lifecycle_payload(evidence))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


async def publish_evidence_archived(evidence: models.Evidence, station_id: Optional[uuid.UUID]):
    event = build_event("evidence.archived", _evidence_lifecycle_payload(evidence))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


async def publish_police_station_event(action: str, station_id: uuid.UUID, name: Optional[str] = None):
    """
    Station configuration CRUD is administrative/operational awareness for
    Control Room -- not routed to any station room (a station doesn't need
    to be told about its own record being edited via this channel, and
    routing station-CRUD events INTO the station's own room would be an
    odd inversion of who this information is "about" vs "for").
    """
    payload = {"station_id": str(station_id)}
    if name is not None:
        payload["name"] = name
    await manager.send_to_control_room(build_event(f"police_station.{action}", payload))


async def publish_constable_location_updated(
    constable_id: uuid.UUID,
    station_id: Optional[uuid.UUID],
    latitude: float,
    longitude: float,
    accuracy: Optional[float],
):
    """
    Goes to control_room + the constable's OWN station only -- never to any
    other constable. This is the one event type explicitly called out in
    Part 9 as never-broadcast-globally.
    """
    payload = {
        "constable_id": str(constable_id),
        "latitude": latitude,
        "longitude": longitude,
        "accuracy": accuracy,
    }
    event = build_event("constable.location_updated", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


# ---------------------------------------------------------------------------
# Phase 1 (body-camera system): device / battery / alert events.
# Same routing rule as everything else in this file: control_room + the
# device's own station (via its constable's Constable.station_id), and for
# alerts additionally the specific constable's own room -- never any other
# constable.
# ---------------------------------------------------------------------------

def _device_summary(device: models.Device) -> dict:
    return {
        "device_id": str(device.id),
        "constable_id": str(device.constable_id) if device.constable_id else None,
        "device_identifier": device.device_identifier,
        "status": device.status.value if device.status else None,
    }


async def publish_device_registered(device: models.Device, station_id: Optional[uuid.UUID]):
    event = build_event("device.registered", _device_summary(device))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


async def publish_device_heartbeat(device: models.Device, station_id: Optional[uuid.UUID], effective_status: str):
    payload = _device_summary(device)
    payload["status"] = effective_status
    event = build_event("device.heartbeat", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


async def publish_device_status_changed(device: models.Device, station_id: Optional[uuid.UUID], old_status: str, new_status: str):
    payload = _device_summary(device)
    payload["status"] = new_status
    payload["previous_status"] = old_status
    event_name = {
        "online": "device.online",
        "stale": "device.stale",
        "offline": "device.offline",
    }.get(new_status, "device.status_changed")
    event = build_event(event_name, payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


async def publish_battery_updated(device: models.Device, station_id: Optional[uuid.UUID], battery_percent: int, is_charging: Optional[bool]):
    payload = _device_summary(device)
    payload["battery_percent"] = battery_percent
    payload["is_charging"] = is_charging
    event = build_event("battery.updated", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


async def publish_battery_alert(
    alert: models.Alert,
    device: models.Device,
    station_id: Optional[uuid.UUID],
    battery_percent: int,
    threshold: int,
):
    """
    Publishes BOTH the generic `alert.created`/`alert.updated` event AND
    the more specific `battery.warning`/`battery.critical` event -- the
    specific event is what a dashboard would actually filter on; the
    generic one keeps a single consistent "something alert-worthy
    happened" channel for a future unified Alerts page.
    """
    specific_event_name = "battery.critical" if alert.severity == models.AlertSeverity.critical else "battery.warning"
    payload = {
        "alert_id": str(alert.id),
        "device_id": str(device.id),
        "constable_id": str(device.constable_id) if device.constable_id else None,
        "battery_percent": battery_percent,
        "threshold": threshold,
        "severity": alert.severity.value,
        "status": alert.status.value,
    }
    specific_event = build_event(specific_event_name, payload)
    generic_event = build_event("alert.created" if alert.status == models.AlertStatus.open else "alert.updated", payload)

    await manager.send_to_control_room(specific_event)
    await manager.send_to_control_room(generic_event)
    await manager.send_to_station(station_id, specific_event)
    await manager.send_to_station(station_id, generic_event)
    if device.constable_id:
        await manager.send_to_constable(device.constable_id, specific_event)


# ---------------------------------------------------------------------------
# Phase 2 (body-camera system): recording lifecycle events. Same routing
# rule as Phase 1's device events -- control_room + the recording
# constable's own station + the constable's own room (recordings are
# personal to the constable making them, unlike device state which is
# more "operational awareness").
# ---------------------------------------------------------------------------

def _recording_summary(session: models.RecordingSession) -> dict:
    return {
        "recording_session_id": str(session.id),
        "constable_id": str(session.constable_id),
        "device_id": str(session.device_id),
        "status": session.status.value if session.status else None,
        "trigger_type": session.trigger_type.value if session.trigger_type else None,
    }


async def publish_recording_started(session: models.RecordingSession, station_id: Optional[uuid.UUID]):
    event = build_event("recording.started", _recording_summary(session))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(session.constable_id, event)


async def publish_recording_chunk_uploaded(session: models.RecordingSession, station_id: Optional[uuid.UUID], chunk_number: int, is_last_chunk: bool):
    payload = _recording_summary(session)
    payload["chunk_number"] = chunk_number
    payload["is_last_chunk"] = is_last_chunk
    event = build_event("recording.chunk_uploaded", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(session.constable_id, event)


async def publish_recording_completed(session: models.RecordingSession, station_id: Optional[uuid.UUID], missing_chunk_numbers: list):
    payload = _recording_summary(session)
    payload["missing_chunk_numbers"] = missing_chunk_numbers
    event = build_event("recording.completed", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(session.constable_id, event)


async def publish_recording_cancelled(session: models.RecordingSession, station_id: Optional[uuid.UUID]):
    event = build_event("recording.cancelled", _recording_summary(session))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(session.constable_id, event)


async def publish_recording_failed(session: models.RecordingSession, station_id: Optional[uuid.UUID], reason: Optional[str] = None):
    payload = _recording_summary(session)
    if reason:
        payload["reason"] = reason
    event = build_event("recording.failed", payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(session.constable_id, event)


# ---------------------------------------------------------------------------
# Phase 3 (body-camera system): command lifecycle + generic alert events.
# ---------------------------------------------------------------------------

def _command_summary(command: models.RemoteCommand) -> dict:
    return {
        "command_id": str(command.id),
        "device_id": str(command.device_id),
        "command_type": command.command_type.value if command.command_type else None,
        "status": command.status.value if command.status else None,
    }


async def publish_command_sent(command: models.RemoteCommand, constable_id: Optional[uuid.UUID], station_id: Optional[uuid.UUID]):
    """The target constable's own device is the primary audience -- this is what the future mobile client actually listens for."""
    event = build_event("command.sent", _command_summary(command))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(constable_id, event)


async def publish_command_acknowledged(command: models.RemoteCommand, constable_id: Optional[uuid.UUID], station_id: Optional[uuid.UUID]):
    event = build_event("command.acknowledged", _command_summary(command))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(constable_id, event)


async def publish_command_result(command: models.RemoteCommand, constable_id: Optional[uuid.UUID], station_id: Optional[uuid.UUID]):
    """command.executed or command.failed, chosen from command.status."""
    event_name = "command.executed" if command.status == models.RemoteCommandStatus.executed else "command.failed"
    payload = _command_summary(command)
    if command.failure_reason:
        payload["failure_reason"] = command.failure_reason
    event = build_event(event_name, payload)
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(constable_id, event)


async def publish_command_cancelled(command: models.RemoteCommand, constable_id: Optional[uuid.UUID], station_id: Optional[uuid.UUID]):
    event = build_event("command.cancelled", _command_summary(command))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    await manager.send_to_constable(constable_id, event)


def _alert_summary(alert: models.Alert) -> dict:
    return {
        "alert_id": str(alert.id),
        "device_id": str(alert.device_id) if alert.device_id else None,
        "constable_id": str(alert.constable_id) if alert.constable_id else None,
        "type": alert.type.value if alert.type else None,
        "severity": alert.severity.value if alert.severity else None,
        "status": alert.status.value if alert.status else None,
        "message": alert.message,
    }


async def publish_generic_alert_event(alert: models.Alert, station_id: Optional[uuid.UUID], event_name: str):
    """event_name is one of alert.created / alert.updated / alert.resolved, plus the specific device.stale / device.offline / recording.device_offline event where applicable -- see routers/devices.py and routers/recordings.py callers for exact usage."""
    event = build_event(event_name, _alert_summary(alert))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
    if alert.constable_id:
        await manager.send_to_constable(alert.constable_id, event)


def _live_stream_summary(session: models.LiveStreamSession) -> dict:
    return {
        "session_id": str(session.id),
        "device_id": str(session.device_id),
        "constable_id": str(session.constable_id),
        "room_name": session.room_name,
        "started_by": session.started_by.value if session.started_by else None,
    }


async def publish_live_stream_started(session: models.LiveStreamSession, station_id: Optional[uuid.UUID]):
    event = build_event("live_stream.started", _live_stream_summary(session))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)


async def publish_live_stream_ended(session: models.LiveStreamSession, station_id: Optional[uuid.UUID]):
    event = build_event("live_stream.ended", _live_stream_summary(session))
    await manager.send_to_control_room(event)
    await manager.send_to_station(station_id, event)
