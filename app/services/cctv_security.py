"""
CCTV-specific security helpers: secret-at-rest encryption and SSRF
protection for camera stream targets.

Kept separate from app/auth/security.py (which is JWT/password-hashing --
a different trust boundary) and from the generic storage/audit services --
this module exists specifically because CCTV introduces a NEW kind of
user-influenced network destination (a camera's host:port) that nothing
else in this backend has: every other outbound-ish operation (LiveKit,
S3, evidence storage) talks to infrastructure the deployer configured via
environment variables, never to a destination an admin enters through the
API. That makes this the one place in the codebase that needs real SSRF
handling.
"""
import contextlib
import contextvars
import ipaddress
import os
import socket
import warnings
from typing import Iterable, List, Optional

from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# Subsystem toggle
# ---------------------------------------------------------------------------
CCTV_ENABLED = os.getenv("CCTV_ENABLED", "true").strip().lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Secret-at-rest encryption
# ---------------------------------------------------------------------------
# Mirrors app/auth/security.py's JWT_SECRET_KEY pattern exactly: required
# (hard failure) in production *when the CCTV subsystem is actually
# enabled*, insecure-but-functional fallback with a loud warning otherwise.
# The fallback key is generated fresh per process and never persisted --
# any secret encrypted under it becomes unreadable after a restart, which
# is a deliberately safe failure mode for a throwaway dev key (never a
# silent data-loss risk for anything that matters).
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
_DEV_FALLBACK_CCTV_KEY = Fernet.generate_key().decode()
CCTV_SECRET_KEY = os.getenv("CCTV_SECRET_KEY")

if CCTV_ENABLED and not CCTV_SECRET_KEY:
    if ENVIRONMENT == "production":
        raise RuntimeError(
            "CCTV_SECRET_KEY environment variable is required when "
            "ENVIRONMENT=production and CCTV_ENABLED is true. Refusing to "
            "start with no durable key for encrypting camera credentials."
        )
    warnings.warn(
        "CCTV_SECRET_KEY is not set. Using an ephemeral, process-local "
        "encryption key -- any camera secret encrypted now becomes "
        "unreadable after a restart. This is NOT safe for production use.",
        RuntimeWarning,
    )
    CCTV_SECRET_KEY = _DEV_FALLBACK_CCTV_KEY

_fernet = Fernet(CCTV_SECRET_KEY.encode()) if CCTV_SECRET_KEY else None


def encrypt_secret(plaintext: str) -> str:
    """Encrypts a camera password/secret for storage. Never call this with anything that should ever be logged or returned as-is."""
    if _fernet is None:
        raise RuntimeError("CCTV encryption is not configured (CCTV_ENABLED is false)")
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    """Decrypts a stored camera secret. Raises cryptography.fernet.InvalidToken if the key changed or the ciphertext is corrupt -- callers must not swallow that silently into a fake 'empty' secret."""
    if _fernet is None:
        raise RuntimeError("CCTV encryption is not configured (CCTV_ENABLED is false)")
    return _fernet.decrypt(token.encode()).decode()


# ---------------------------------------------------------------------------
# SSRF protection for camera stream targets
# ---------------------------------------------------------------------------
# Deliberately NOT a blanket "block all private IPs" policy -- authorized
# CCTV overwhelmingly lives on private station/campus networks. Instead:
# certain ranges are blocked unconditionally (cloud metadata endpoints,
# multicast, unspecified/broadcast -- nothing legitimate ever needs these
# for a camera), and everything else -- including private/loopback ranges
# -- must be explicitly allow-listed via CCTV_ALLOWED_NETWORKS. No
# allowlist configured means no camera target can ever validate: fail
# closed, not fail open.
_BLOCKED_ALWAYS: List[ipaddress._BaseNetwork] = [
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP/Azure IMDS
    ipaddress.ip_network("169.254.170.2/32"),  # AWS ECS task metadata
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDSv2 (IPv6)
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),  # unspecified IPv6
]


def _allowed_networks() -> List:
    raw = os.getenv("CCTV_ALLOWED_NETWORKS", "")
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue  # malformed entry -- never let a typo widen the allowlist, just skip it
    return nets


def get_allowed_networks() -> List:
    """Public accessor for CCTV_ALLOWED_NETWORKS, parsed -- used by cctv_discovery.py to restrict WS-Discovery scanning to the same operator-authorized subnets as validate_stream_target(), fail-closed (empty list = scan nothing)."""
    return _allowed_networks()


# Per-building authorization (see models.Building.authorized_networks). The
# global CCTV_ALLOWED_NETWORKS allowlist stays in force and is never widened
# for other callers: a building's extra networks apply ONLY inside the
# `extra_networks()` context of an operation on that building's cameras, and
# the permanently blocked ranges below still win over everything.
_extra_networks_var: contextvars.ContextVar = contextvars.ContextVar("cctv_extra_networks", default=())

# Widest network an admin may authorize for a single building. A building
# authorizing e.g. 0.0.0.0/0 would silently disable the SSRF policy.
_MIN_IPV4_PREFIX = 16
_MIN_IPV6_PREFIX = 48


def parse_authorized_networks(values: Iterable[str]) -> List:
    """Strictly parses admin-supplied CIDRs for a building. Raises ValueError (never skips silently, unlike the env parser) on a malformed, over-broad or permanently blocked entry."""
    nets = []
    for raw in values:
        raw = (raw or "").strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError(f"'{raw}' is not a valid IP address or CIDR")
        min_prefix = _MIN_IPV4_PREFIX if net.version == 4 else _MIN_IPV6_PREFIX
        if net.prefixlen < min_prefix:
            raise ValueError(f"'{raw}' is too broad; a building may authorize at most a /{min_prefix} network")
        for blocked in _BLOCKED_ALWAYS:
            if net.version == blocked.version and net.overlaps(blocked):
                raise ValueError(f"'{raw}' overlaps a permanently blocked range")
        nets.append(net)
    return nets


@contextlib.contextmanager
def extra_networks(networks: Optional[Iterable]):
    """Temporarily adds a building's already-parsed authorized networks to the allowlist for the current task only."""
    token = _extra_networks_var.set(tuple(networks or ()))
    try:
        yield
    finally:
        _extra_networks_var.reset(token)


def resolve_and_validate(host: str, port: int) -> List[str]:
    """
    Raises ValueError if `host:port` is not a permitted camera network
    destination; otherwise returns the validated IP address strings the
    host resolved to. Callers that hand the destination to ANOTHER process
    (the media gateway) should connect to one of these literal addresses
    rather than re-resolving the name, which closes the DNS-rebinding gap
    between "checked here" and "connected there".
    """
    if not host or not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("invalid host/port")

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve host '{host}': {exc}")

    allowed = _allowed_networks() + list(_extra_networks_var.get())
    if not allowed:
        raise ValueError(
            "CCTV_ALLOWED_NETWORKS is not configured and the building has no "
            "authorized networks -- refusing all camera network targets "
            "(fail-closed; see .env.example)"
        )

    resolved: List[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        for blocked in _BLOCKED_ALWAYS:
            if ip in blocked:
                raise ValueError(f"resolved address {ip} is in a permanently blocked range ({blocked})")
        if not any(ip in net for net in allowed):
            raise ValueError(f"resolved address {ip} is not within any authorized network")
        if str(ip) not in resolved:
            resolved.append(str(ip))
    return resolved


def validate_stream_target(host: str, port: int) -> None:
    """Raises ValueError if `host:port` is not a permitted camera network destination. Resolves the hostname and checks the RESOLVED address(es), so a DNS name pointing at a blocked/unlisted address is caught too. See resolve_and_validate()."""
    resolve_and_validate(host, port)
