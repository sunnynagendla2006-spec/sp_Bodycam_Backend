"""
FastAPI dependencies for authentication and role-based authorization.

Usage:

    from ..auth.deps import get_current_user, require_role

    @router.get("/something")
    def handler(user: models.User = Depends(get_current_user)):
        ...

    @router.post("/admin-only")
    def handler(user: models.User = Depends(require_role("admin"))):
        ...

    @router.post("/control-room-or-admin")
    def handler(user: models.User = Depends(require_role("admin", "control_room"))):
        ...

Notes:
  - The role used for authorization is ALWAYS re-read from the database via
    `user.role`, never trusted from the JWT/client in isolation. The JWT
    `role` claim is included for convenience/debugging and for stateless
    checks where a DB round trip isn't desired, but `get_current_user`
    re-loads the user row so a role change or deactivation takes effect
    immediately on the next request, without waiting for the token to expire.
  - This module intentionally does NOT add these dependencies to any
    existing router (incidents/constables/media/settings/websocket). That is
    scoped for a later phase.
"""
import uuid
from typing import Iterable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from .. import models
from .security import decode_access_token

# Using HTTPBearer (rather than OAuth2PasswordBearer's form-encoded flow)
# because /auth/login accepts a JSON body, not OAuth2 form data. HTTPBearer
# still renders a proper "Bearer" security scheme in the OpenAPI docs and
# provides the "Authorize" button in /docs.
bearer_scheme = HTTPBearer(auto_error=False)

_AUTH_FAILED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> models.User:
    """
    Extract and validate the Bearer token, then load and return the
    authoritative User record from the database.

    Fails with 401 for: missing token, malformed/invalid token, bad
    signature, expired token, unknown user, or inactive user.
    """
    if credentials is None or not credentials.credentials:
        raise _AUTH_FAILED

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise _AUTH_FAILED

    try:
        user_id = uuid.UUID(payload.sub) if isinstance(payload.sub, str) else payload.sub
    except (ValueError, AttributeError, TypeError):
        raise _AUTH_FAILED

    user = await models.User.get(user_id)
    if user is None:
        raise _AUTH_FAILED

    if user.status != models.UserStatus.active:
        raise _AUTH_FAILED

    return user


def require_role(*allowed_roles: str):
    """
    Returns a FastAPI dependency that first authenticates the caller (via
    get_current_user) and then verifies their DATABASE-loaded role is one of
    `allowed_roles`. Role values may be passed as plain strings (e.g.
    "admin") or UserRole enum members.

    - Unauthenticated / invalid token -> 401 (raised by get_current_user)
    - Authenticated but wrong role    -> 403
    """
    allowed_values = {
        (r.value if hasattr(r, "value") else str(r)) for r in allowed_roles
    }

    def dependency(user: models.User = Depends(get_current_user)) -> models.User:
        user_role_value = user.role.value if hasattr(user.role, "value") else str(user.role)
        if user_role_value not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return user

    return dependency


# ===========================================================================
# Physical Edge Controller Authentication (Task 2)
# ===========================================================================

import os
import secrets
from fastapi import Header

EDGE_CONTROLLER_API_KEY = os.getenv("EDGE_CONTROLLER_API_KEY", "edge-controller-dev-key").strip()


async def get_current_edge_controller(
    x_edge_controller_key: str = Header(default="", alias="X-Edge-Controller-Key"),
    x_edge_controller_id: str = Header(default="", alias="X-Edge-Controller-Id"),
    authorization: str = Header(default="", alias="Authorization"),
) -> dict:
    """
    Dedicated edge controller authentication -- MUST NEVER reuse constable JWTs.
    Requires matching X-Edge-Controller-Key or dedicated Edge Bearer token.
    Uses constant-time comparison to prevent timing side-channels.
    """
    candidate_key = x_edge_controller_key.strip()
    if not candidate_key and authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() in ("bearer", "edgekey"):
            candidate_key = parts[1]

    if not candidate_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing edge controller credentials (X-Edge-Controller-Key required)",
            headers={"WWW-Authenticate": "EdgeKey"},
        )

    # Constant-time comparison
    if not secrets.compare_digest(candidate_key, EDGE_CONTROLLER_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid edge controller credentials",
            headers={"WWW-Authenticate": "EdgeKey"},
        )

    controller_id = x_edge_controller_id.strip() or "edge-collector-default"
    return {
        "controller_id": controller_id,
        "authenticated": True,
        "source": models.PresenceEventSource.controller.value,
    }

