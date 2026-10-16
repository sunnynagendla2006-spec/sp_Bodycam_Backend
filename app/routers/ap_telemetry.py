"""
Physical AP Telemetry Ingestion Router (Stage 2B).

Dedicated ingestion endpoints for real Wi-Fi access point controllers,
edge aggregators, syslog agents, and RADIUS accounting collectors.
Authenticated via dedicated edge credentials (never constable JWTs).
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status

from .. import models, schemas
from ..auth.deps import get_current_edge_controller, require_role
from ..services import ap_telemetry

router = APIRouter(prefix="/telemetry", tags=["AP Telemetry"])

_syslog_adapter = ap_telemetry.SyslogTelemetryAdapter()
_radius_adapter = ap_telemetry.RadiusAccountingTelemetryAdapter()


@router.post(
    "/ap-events",
    response_model=schemas.EdgeAPTelemetryResponse,
    status_code=status.HTTP_200_OK,
)
async def ingest_ap_event(
    event: schemas.EdgeAPTelemetryEventRequest,
    controller_info: dict = Depends(get_current_edge_controller),
):
    """
    Ingest a single normalized AP association/disassociation/roam telemetry event.
    Requires edge controller authentication via X-Edge-Controller-Key header.
    """
    return await ap_telemetry.process_edge_telemetry_event(event, controller_info)


@router.post(
    "/ap-events/batch",
    response_model=schemas.EdgeAPTelemetryBatchResponse,
    status_code=status.HTTP_200_OK,
)
async def ingest_ap_events_batch(
    batch: schemas.EdgeAPTelemetryBatchRequest,
    controller_info: dict = Depends(get_current_edge_controller),
):
    """
    Batch ingestion for high-throughput edge collectors (up to 50 events).
    """
    results = []
    accepted = 0
    duplicate = 0
    unmapped = 0
    errors = 0

    for item in batch.events:
        try:
            res = await ap_telemetry.process_edge_telemetry_event(item, controller_info)
            results.append(res)
            if res.status == "accepted" or res.status == "disassociated":
                accepted += 1
            elif res.status == "duplicate_ignored":
                duplicate += 1
            elif res.status == "unmapped_device":
                unmapped += 1
            else:
                accepted += 1
        except Exception as exc:
            errors += 1
            results.append(
                schemas.EdgeAPTelemetryResponse(
                    status="error",
                    event_id=item.controller_event_id,
                    processed_at=ap_telemetry._utcnow(),
                    handoff_created=False,
                    message=str(exc),
                )
            )

    return schemas.EdgeAPTelemetryBatchResponse(
        total=len(batch.events),
        accepted=accepted,
        duplicate=duplicate,
        unmapped=unmapped,
        errors=errors,
        results=results,
    )


@router.post(
    "/ap-events/syslog",
    response_model=schemas.EdgeAPTelemetryResponse,
    status_code=status.HTTP_200_OK,
)
async def ingest_syslog_ap_event(
    raw_payload: dict,
    controller_info: dict = Depends(get_current_edge_controller),
):
    """
    Convenience ingestion endpoint for syslog collectors parsing controller lines.
    Translates syslog messages into normalized telemetry events.
    """
    normalized = _syslog_adapter.normalize(raw_payload)
    return await ap_telemetry.process_edge_telemetry_event(normalized, controller_info)


@router.post(
    "/ap-events/radius",
    response_model=schemas.EdgeAPTelemetryResponse,
    status_code=status.HTTP_200_OK,
)
async def ingest_radius_ap_event(
    raw_payload: dict,
    controller_info: dict = Depends(get_current_edge_controller),
):
    """
    Convenience ingestion endpoint for RADIUS accounting webhooks / proxies.
    Translates RADIUS accounting attributes into normalized telemetry events.
    """
    normalized = _radius_adapter.normalize(raw_payload)
    return await ap_telemetry.process_edge_telemetry_event(normalized, controller_info)


@router.get(
    "/events",
    response_model=List[models.EdgeControllerEventLog],
    status_code=status.HTTP_200_OK,
)
async def list_telemetry_event_logs(
    controller_id: Optional[str] = Query(None, description="Filter by edge controller ID"),
    device_identifier: Optional[str] = Query(None, description="Filter by device identifier"),
    limit: int = Query(50, ge=1, le=200),
    _current_user: models.User = Depends(require_role("admin", "control_room")),
):
    """
    Audit log of ingested physical AP events. Restricted to admin / control_room.
    """
    query = {}
    if controller_id:
        query["controller_id"] = controller_id
    if device_identifier:
        query["device_identifier"] = device_identifier

    logs = (
        await models.EdgeControllerEventLog.find(query)
        .sort(-models.EdgeControllerEventLog.server_received_at)
        .limit(limit)
        .to_list()
    )
    return logs
