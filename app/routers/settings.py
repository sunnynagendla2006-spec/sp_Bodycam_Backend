from fastapi import APIRouter, Depends
from pydantic import BaseModel
import json
import os

from .. import models
from ..auth.deps import require_role
from ..services.audit import log_action

router = APIRouter(prefix="/settings", tags=["Settings"])

SETTINGS_FILE = "/app/settings.json"

class SystemSettings(BaseModel):
    chunk_size_mb: int
    geofence_threshold_m: int
    audio_alerts: bool
    battery_warning_threshold: int = 20
    battery_critical_threshold: int = 10
    device_stale_seconds: int = 120
    device_offline_seconds: int = 600
    max_websocket_connections_per_room: int = 200
    # AP-based presence: same stale/offline-after-N-seconds pattern as
    # device_stale_seconds/device_offline_seconds above, applied to
    # PolicePresence.last_seen_at instead of Device.last_seen_at -- see
    # app/services/presence.py::compute_effective_presence_status.
    presence_stale_seconds: int = 120
    presence_offline_seconds: int = 600

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {
        "chunk_size_mb": 5,
        "geofence_threshold_m": 50,
        "audio_alerts": True,
        "battery_warning_threshold": 20,
        "battery_critical_threshold": 10,
        "device_stale_seconds": 120,
        "device_offline_seconds": 600,
        "max_websocket_connections_per_room": 200,
        "presence_stale_seconds": 120,
        "presence_offline_seconds": 600,
    }

# These values (chunk size, geofence threshold, audio alert toggle) are
# operational config, not secrets -- but they are still administrative
# system configuration and were previously world-readable/world-writable
# with no auth at all. Read access is opened slightly wider than write
# access since control_room may reasonably need to see current operational
# config; only admin may change it.

@router.get("/", response_model=SystemSettings)
def get_settings(current_user: models.User = Depends(require_role("admin", "control_room"))):
    return load_settings()

@router.post("/")
async def update_settings(
    settings: SystemSettings,
    current_user: models.User = Depends(require_role("admin")),
):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings.model_dump(), f)

    await log_action(
        user_id=current_user.id,
        action="settings.updated",
        details=settings.model_dump(),
    )

    return {"status": "updated"}
