from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
import json
import os

from .. import database, models
from ..auth.deps import require_role
from ..services.audit import log_action

router = APIRouter(prefix="/settings", tags=["Settings"])

SETTINGS_FILE = "/app/settings.json"

class SystemSettings(BaseModel):
    chunk_size_mb: int
    geofence_threshold_m: int
    audio_alerts: bool
    # Phase 1 (body-camera system) additions. Defaulted so an existing
    # settings.json written before this phase still loads/validates fine
    # (pydantic fills these in) without needing any migration -- settings
    # are file-based, not a DB table.
    battery_warning_threshold: int = 20
    battery_critical_threshold: int = 10
    device_stale_seconds: int = 120
    device_offline_seconds: int = 600

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
def update_settings(
    settings: SystemSettings,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_role("admin")),
):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings.model_dump(), f)

    log_action(
        db,
        user_id=current_user.id,
        action="settings.updated",
        details=settings.model_dump(),
    )
    db.commit()

    return {"status": "updated"}
