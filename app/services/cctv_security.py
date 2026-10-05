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
import ipaddress
import os
import socket
import warnings
from typing import List

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


def validate_stream_target(host: str, port: int) -> None:
    """
    Raises ValueError (never returns a reason code -- callers always treat
    this as "rejected") if `host:port` is not a permitted camera network
    destination. Resolves the hostname and checks the RESOLVED address
    (not just the string the client typed), so a DNS name that resolves to
    a blocked/unlisted address is caught too, not just a literal IP.
    """
    if not host or not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("invalid host/port")

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve host '{host}': {exc}")

    allowed = _allowed_networks()
    if not allowed:
        raise ValueError(
            "CCTV_ALLOWED_NETWORKS is not configured -- refusing all camera "
            "network targets (fail-closed; see .env.example)"
        )

    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        for blocked in _BLOCKED_ALWAYS:
            if ip in blocked:
                raise ValueError(f"resolved address {ip} is in a permanently blocked range ({blocked})")
        if not any(ip in net for net in allowed):
            raise ValueError(f"resolved address {ip} is not within any CCTV_ALLOWED_NETWORKS entry")
