"""
MediaMTX media-gateway integration for fixed CCTV cameras.

Flow:  NVR/IP camera --RTSP(S) over VPN/tunnel--> MediaMTX --WebRTC (WHEP)--> browser

* The backend registers one MediaMTX *path* per camera (`cctv-<camera id>`)
  through MediaMTX's control API, with `sourceOnDemand`: MediaMTX only
  connects to the camera while someone is watching and drops it shortly
  after the last viewer leaves. Nothing streams permanently.
* The credential-bearing RTSP URL is sent from this process to the
  gateway's internal API only. It is never logged and never returned to a client.
* Browsers authenticate to the gateway with a short-lived signed playback
  token (query parameter `token`). MediaMTX forwards that to
  POST /cctv/gateway/auth (routers/cctv_streaming.py), which verifies
  signature, expiry and that the token was minted for exactly that path.
* The gateway control API is internal-only (see deploy/mediamtx/mediamtx.yml).

Uses only the standard library (urllib in a worker thread), matching the
hand-rolled style of cctv_providers.py -- no new dependency.

NOT VERIFIED AT RUNTIME: no MediaMTX instance was available when this was
written. The control-API request shapes follow MediaMTX v1.x's documented
`/v3/config/paths/*` and `/v3/paths/list` endpoints; verify against the
pinned version in deploy/docker-compose.cctv.yml before relying on it.
"""
import asyncio
import datetime
import hashlib
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Dict, Optional, Set, Tuple

from jose import JWTError, jwt

from ..auth import security as auth_security

logger = logging.getLogger("cctv_gateway")

PATH_PREFIX = "cctv-"
TOKEN_TYPE = "cctv_playback"
_API_TIMEOUT_SECONDS = 5.0


class GatewayError(Exception):
    """A gateway failure with a message that is safe to show an operator (no URLs, credentials or response bodies)."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


# ---------------------------------------------------------------------------
# Configuration (read at call time so deployments/tests can change env)
# ---------------------------------------------------------------------------

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def api_url() -> str:
    return _env("CCTV_GATEWAY_API_URL").rstrip("/")


def public_url() -> str:
    return _env("CCTV_GATEWAY_PUBLIC_URL").rstrip("/")


def auth_key() -> str:
    return _env("CCTV_GATEWAY_AUTH_KEY")


def is_configured() -> bool:
    """True only when the backend can both control the gateway and tell browsers where to play from."""
    return bool(api_url() and public_url() and auth_key())


def playback_ttl_seconds() -> int:
    try:
        return max(15, int(_env("CCTV_PLAYBACK_TOKEN_TTL_SECONDS", "120")))
    except ValueError:
        return 120


def max_concurrent_streams() -> int:
    try:
        return max(1, int(_env("CCTV_MAX_CONCURRENT_STREAMS", "16")))
    except ValueError:
        return 16


def rotation_seconds() -> int:
    try:
        return max(2, int(_env("CCTV_ROTATION_SECONDS", "5")))
    except ValueError:
        return 5


def prefetch_next_enabled() -> bool:
    return _env("CCTV_PREFETCH_NEXT", "false").lower() in ("1", "true", "yes")


def path_name(camera_id: uuid.UUID) -> str:
    return f"{PATH_PREFIX}{camera_id.hex}"


# ---------------------------------------------------------------------------
# Playback tokens
# ---------------------------------------------------------------------------

def _token_secret() -> str:
    """Separate signing key: derived from (not equal to) the access-token secret, so a login JWT can never be replayed as a playback token or vice versa."""
    base = _env("CCTV_PLAYBACK_TOKEN_SECRET") or auth_security.JWT_SECRET_KEY
    return hashlib.sha256(f"cctv-playback:{base}".encode()).hexdigest()


def mint_playback_token(user_id: uuid.UUID, camera_id: uuid.UUID) -> Tuple[str, datetime.datetime]:
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=playback_ttl_seconds())
    claims = {
        "typ": TOKEN_TYPE,
        "sub": str(user_id),
        "cam": str(camera_id),
        "path": path_name(camera_id),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(claims, _token_secret(), algorithm="HS256"), expires_at


def verify_playback_token(token: str, expected_path: Optional[str] = None) -> Optional[dict]:
    """Returns the claims if the token is valid, unexpired, of the right type and (when given) minted for `expected_path`; otherwise None."""
    try:
        claims = jwt.decode(token, _token_secret(), algorithms=["HS256"])
    except JWTError:
        return None
    if claims.get("typ") != TOKEN_TYPE:
        return None
    if expected_path is not None and claims.get("path") != expected_path:
        return None
    return claims


# ---------------------------------------------------------------------------
# Control API client
# ---------------------------------------------------------------------------

# name -> sha256 of the source URL last registered by THIS process. Only used
# to avoid redundant replaces; never contains the URL itself.
_registered: Dict[str, str] = {}


def _request_blocking(method: str, path: str, body: Optional[dict] = None) -> Tuple[int, dict]:
    base = api_url()
    if not base:
        raise GatewayError("gateway_not_configured", "The CCTV media gateway is not configured (CCTV_GATEWAY_API_URL)")
    url = base + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_API_TIMEOUT_SECONDS) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except Exception:
            payload = {}
        return exc.code, payload if isinstance(payload, dict) else {}
    except (urllib.error.URLError, OSError, TimeoutError):
        # Deliberately generic: the underlying message can contain the gateway host.
        raise GatewayError("gateway_unreachable", "The CCTV media gateway is unreachable")


async def _request(method: str, path: str, body: Optional[dict] = None) -> Tuple[int, dict]:
    return await asyncio.to_thread(_request_blocking, method, path, body)


def _path_config(source_url: str) -> dict:
    return {
        "source": source_url,
        "sourceOnDemand": True,
        "sourceOnDemandStartTimeout": "10s",
        "sourceOnDemandCloseAfter": "10s",
        "rtspTransport": "tcp",
    }


async def ensure_path(name: str, source_url: str) -> None:
    """Idempotently makes sure the gateway has `name` pointing at `source_url`. Raises GatewayError."""
    fingerprint = hashlib.sha256(source_url.encode()).hexdigest()
    quoted = urllib.parse.quote(name, safe="")
    status, payload = await _request("POST", f"/v3/config/paths/add/{quoted}", _path_config(source_url))
    if status == 200:
        _registered[name] = fingerprint
        return
    already_exists = status == 400 and "exist" in str(payload.get("error", "")).lower()
    if already_exists:
        if _registered.get(name) == fingerprint:
            return
        if name in _registered:
            # We registered it earlier with different settings: update in place.
            status, _payload = await _request("POST", f"/v3/config/paths/replace/{quoted}", _path_config(source_url))
            if status == 200:
                _registered[name] = fingerprint
                return
            raise GatewayError("gateway_error", "The CCTV media gateway rejected the stream configuration")
        # Registered by another backend instance or an earlier run: trust it. Config
        # changes always call delete_path() first, so a stale entry cannot persist.
        _registered[name] = fingerprint
        return
    raise GatewayError("gateway_error", "The CCTV media gateway rejected the stream configuration")


async def delete_path(name: str) -> None:
    """Removes the path (and disconnects its viewers). A missing path is not an error. Never raises for an unconfigured gateway."""
    _registered.pop(name, None)
    if not api_url():
        return
    quoted = urllib.parse.quote(name, safe="")
    try:
        await _request("POST", f"/v3/config/paths/delete/{quoted}")
    except GatewayError as exc:
        logger.warning("could not delete gateway path %s: %s", name, exc.code)


async def active_viewer_paths() -> Optional[Set[str]]:
    """Names of CCTV paths that currently have at least one reader, or None if the gateway cannot be asked (callers must then fail open, not closed: capacity is a soft limit)."""
    try:
        status, payload = await _request("GET", "/v3/paths/list?itemsPerPage=1000&page=0")
    except GatewayError:
        return None
    if status != 200:
        return None
    active: Set[str] = set()
    for item in payload.get("items", []) or []:
        name = item.get("name", "")
        if name.startswith(PATH_PREFIX) and item.get("readers"):
            active.add(name)
    return active


def whep_url(name: str) -> str:
    return f"{public_url()}/{urllib.parse.quote(name, safe='')}/whep"
