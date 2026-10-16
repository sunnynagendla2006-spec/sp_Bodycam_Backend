"""
Camera source resolution: turns a CCTVCamera (+ its Building, if any) into
the concrete, validated connection target the media gateway should pull.

Two connection modes (models.CCTVConnectionMode):

  * nvr        -- ONE recorder endpoint per building; each camera is a
                  channel on it. The RTSP path comes from an EXPLICIT vendor
                  preset or an admin-written template containing `{channel}`.
                  No vendor URL format is guessed for `custom`.
  * direct_ip  -- each camera has its own host/port/path (the camera's own
                  fields, exactly as before buildings existed).

Credential handling: plaintext secrets exist only inside `ResolvedSource`
and `gateway_source_url()`'s return value, both of which are consumed only
by services/cctv_gateway.py. Nothing here logs, and nothing returned to an
API client ever contains them.
"""
import dataclasses
import ipaddress
import re
from typing import List, Optional
from urllib.parse import quote

from .. import models
from . import cctv_security

# Explicit, labelled presets -- the two NVR families whose channel path
# format is well known. Anything else must use `custom` with an explicit template.
PRESET_TEMPLATES = {
    models.CCTVVendorPreset.hikvision: "/Streaming/Channels/{channel}01",
    models.CCTVVendorPreset.dahua: "/cam/realmonitor?channel={channel}&subtype=0",
}

MIN_CHANNEL = 1
MAX_CHANNEL = 512

# Conservative path charset (no whitespace, control chars, '#', '\\', '@').
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/\-?&=%:+,]*$")
_TEMPLATE_RE = re.compile(r"^/[A-Za-z0-9._~/\-?&=%:+,{}]*$")


class SourceError(Exception):
    """A camera cannot be resolved to a usable source (configuration problem, never a bug). `code` is stable for API/UI use."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclasses.dataclass
class ResolvedSource:
    protocol: str
    host: str
    port: int
    path: str
    username: Optional[str]
    secret: Optional[str]  # plaintext -- gateway client only

    def __repr__(self) -> str:  # never leak the secret via repr/log formatting
        return f"ResolvedSource(protocol={self.protocol!r}, host={self.host!r}, port={self.port}, path={self.path!r}, credentials={'yes' if self.secret else 'no'})"


def validate_path(path: Optional[str]) -> str:
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    if ".." in path or not _PATH_RE.match(path):
        raise ValueError("stream path contains unsupported characters")
    return path


def validate_path_template(template: Optional[str]) -> Optional[str]:
    """A template may contain only the `{channel}` placeholder."""
    if template is None or template == "":
        return None
    if not template.startswith("/"):
        template = "/" + template
    if ".." in template or not _TEMPLATE_RE.match(template):
        raise ValueError("path template contains unsupported characters")
    leftovers = template.replace("{channel}", "")
    if "{" in leftovers or "}" in leftovers:
        raise ValueError("path template may only use the {channel} placeholder")
    return template


def template_for(building: models.Building) -> Optional[str]:
    preset = PRESET_TEMPLATES.get(building.recorder_vendor)
    return preset or building.stream_path_template


def networks_for_building(building: Optional[models.Building]) -> List:
    """The building's admin-authorized networks plus its own public IP (a /32 or /128): the admin typed it on an admin-only endpoint, so it is an explicit authorization of exactly that address."""
    if building is None:
        return []
    nets = []
    try:
        nets.extend(cctv_security.parse_authorized_networks(building.authorized_networks or []))
    except ValueError:
        # Stored values were validated on write; a bad one means manual DB edits. Fail closed for the bad entries only.
        for raw in building.authorized_networks or []:
            try:
                nets.extend(cctv_security.parse_authorized_networks([raw]))
            except ValueError:
                continue
    if building.public_ip:
        try:
            nets.append(ipaddress.ip_network(building.public_ip, strict=False))
        except ValueError:
            pass
    return nets


def resolve_source(camera: models.CCTVCamera, building: Optional[models.Building]) -> ResolvedSource:
    """Pure configuration -> target mapping; performs no network I/O. Raises SourceError for anything unusable."""
    if building is not None and building.connection_mode == models.CCTVConnectionMode.nvr:
        if not building.recorder_host:
            raise SourceError("recorder_not_configured", "The building's recorder (NVR/DVR) host is not configured")
        if camera.channel is None or not (MIN_CHANNEL <= camera.channel <= MAX_CHANNEL):
            raise SourceError("channel_missing", "This camera has no valid NVR channel number")
        template = template_for(building)
        if not template:
            raise SourceError("path_template_missing", "No stream path template is configured for this recorder")
        path = template.replace("{channel}", str(camera.channel))
        try:
            path = validate_path(path)
        except ValueError as exc:
            raise SourceError("invalid_path", str(exc))
        username = camera.username or building.recorder_username
        encrypted = camera.encrypted_secret or building.recorder_encrypted_secret
        host, port, protocol = building.recorder_host, building.recorder_port, building.recorder_protocol.value
    else:
        try:
            path = validate_path(camera.stream_path)
        except ValueError as exc:
            raise SourceError("invalid_path", str(exc))
        username, encrypted = camera.username, camera.encrypted_secret
        host, port, protocol = camera.stream_host, camera.stream_port, camera.stream_protocol.value

    secret = None
    if encrypted:
        try:
            secret = cctv_security.decrypt_secret(encrypted)
        except Exception:
            raise SourceError("credentials_unreadable", "Stored camera credentials could not be decrypted (was CCTV_SECRET_KEY changed?)")
    return ResolvedSource(protocol=protocol, host=host, port=port, path=path, username=username, secret=secret)


def gateway_source_url(source: ResolvedSource, pinned_ip: Optional[str] = None) -> str:
    """
    The credential-bearing URL handed to the media gateway ONLY. Connects to
    `pinned_ip` (an address already validated by
    cctv_security.resolve_and_validate) instead of the hostname, so a DNS
    answer cannot change between validation and connection. Never log or return this value.
    """
    host = pinned_ip or source.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    auth = ""
    if source.username:
        auth = quote(source.username, safe="")
        if source.secret:
            auth += ":" + quote(source.secret, safe="")
        auth += "@"
    return f"{source.protocol}://{auth}{host}:{source.port}{source.path}"
