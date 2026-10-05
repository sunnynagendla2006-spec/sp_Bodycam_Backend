"""
Event deployment management (e.g. "JATARA-DEMO-001"). See
app/models.py::Deployment's docstring for why this is deliberately thin
metadata (name/status/time-window) rather than a scheduling system, and
why zones are NOT a stored entity here -- see
app/routers/access_points.py::list_zones for the derived zone view.
"""
import datetime
import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.errors import DuplicateKeyError

from .. import models, schemas
from ..auth.deps import require_role
from ..services.audit import log_action

router = APIRouter(prefix="/deployments", tags=["Deployments"])


async def _counts_for(deployment_name: str) -> tuple:
    aps = await models.AccessPoint.find(models.AccessPoint.deployment == deployment_name).to_list()
    zones = {a.zone for a in aps if a.zone}
    return len(zones), len(aps)


def _to_response(d: models.Deployment, zone_count=None, access_point_count=None) -> schemas.DeploymentResponse:
    return schemas.DeploymentResponse(
        id=d.id, name=d.name, description=d.description, status=d.status,
        start_time=d.start_time, end_time=d.end_time, is_demo=d.is_demo,
        created_at=d.created_at, updated_at=d.updated_at,
        zone_count=zone_count, access_point_count=access_point_count,
    )


@router.post("/", response_model=schemas.DeploymentResponse)
async def create_deployment(
    payload: schemas.DeploymentCreateRequest,
    current_user: models.User = Depends(require_role("admin")),
):
    deployment = models.Deployment(
        name=payload.name, description=payload.description, start_time=payload.start_time,
        end_time=payload.end_time, is_demo=payload.is_demo, created_by=current_user.id,
    )
    try:
        await deployment.insert()
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"A deployment named '{payload.name}' already exists")

    await log_action(user_id=current_user.id, action="deployment_created", details={"deployment_id": str(deployment.id), "name": deployment.name})
    return _to_response(deployment, zone_count=0, access_point_count=0)


@router.get("/", response_model=List[schemas.DeploymentResponse])
async def list_deployments(
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    deployments = await models.Deployment.find_all().sort(-models.Deployment.created_at).to_list()
    results = []
    for d in deployments:
        zc, apc = await _counts_for(d.name)
        results.append(_to_response(d, zone_count=zc, access_point_count=apc))
    return results


@router.get("/{deployment_id}", response_model=schemas.DeploymentResponse)
async def get_deployment(
    deployment_id: uuid.UUID,
    current_user: models.User = Depends(require_role("admin", "control_room")),
):
    d = await models.Deployment.get(deployment_id)
    if not d:
        raise HTTPException(status_code=404, detail="Deployment not found")
    zc, apc = await _counts_for(d.name)
    return _to_response(d, zone_count=zc, access_point_count=apc)


@router.patch("/{deployment_id}", response_model=schemas.DeploymentResponse)
async def update_deployment(
    deployment_id: uuid.UUID,
    payload: schemas.DeploymentUpdateRequest,
    current_user: models.User = Depends(require_role("admin")),
):
    d = await models.Deployment.get(deployment_id)
    if not d:
        raise HTTPException(status_code=404, detail="Deployment not found")

    if payload.description is not None:
        d.description = payload.description
    if payload.status is not None:
        d.status = payload.status
    if payload.start_time is not None:
        d.start_time = payload.start_time
    if payload.end_time is not None:
        d.end_time = payload.end_time

    d.updated_at = datetime.datetime.now(datetime.timezone.utc)
    await d.save()

    await log_action(user_id=current_user.id, action="deployment_updated", details={"deployment_id": str(deployment_id)})
    zc, apc = await _counts_for(d.name)
    return _to_response(d, zone_count=zc, access_point_count=apc)
