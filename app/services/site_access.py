"""
Who may see a monitored site.

* admin: every site.
* control_room: every site whose access_mode is "all_control_room", and
  "restricted" sites only when the user is listed in viewer_user_ids.
* every other role: none (enforced by the routers' role dependencies).

The same predicate scopes WebSocket delivery, so a restricted site's live
updates never reach users who cannot open it.
"""
import uuid
from typing import Callable

from .. import models


def can_view(site: models.MonitoredSite, user_id: uuid.UUID, role: str) -> bool:
    if role == models.UserRole.admin.value:
        return True
    if role != models.UserRole.control_room.value:
        return False
    return site.access_mode != "restricted" or user_id in (site.viewer_user_ids or [])


def can_view_user(site: models.MonitoredSite, user: models.User) -> bool:
    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    return can_view(site, user.id, role)


def ws_predicate(site: models.MonitoredSite) -> Callable[[uuid.UUID, str], bool]:
    return lambda user_id, role: can_view(site, user_id, role)
