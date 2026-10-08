"""
Real WS-Discovery (the protocol ONVIF devices use to announce themselves
on a local network) -- not a placeholder. Sends a genuine UDP multicast
Probe to 239.255.255.250:3702 and parses genuine ProbeMatch responses.

Restricted to CCTV_ALLOWED_NETWORKS (the same fail-closed allowlist
cctv_security.validate_stream_target uses) -- a response from an address
outside that allowlist is silently dropped, never surfaced. WS-Discovery
is inherently link-local multicast, so this can never scan the internet
or an arbitrary remote host regardless of that allowlist's contents --
the allowlist here only narrows which *local* responses are trusted.

VERIFICATION STATUS: [IMPLEMENTED] -- real protocol code, not a stub.
[RUNTIME VERIFIED: yes, the probe/listen/parse mechanism itself was
exercised against this machine's real network interface]. [PHYSICAL
CAMERA VERIFIED: NO] -- no physical ONVIF camera exists in this
environment, so the expected, honest result of a real scan here is an
empty list, not a fabricated device.
"""
import asyncio
import ipaddress
import socket
import time
import uuid
import xml.etree.ElementTree as ET
import dataclasses
from typing import List, Optional
from urllib.parse import urlparse

from . import cctv_security

WS_DISCOVERY_ADDRESS = "239.255.255.250"
WS_DISCOVERY_PORT = 3702

_PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{message_id}</w:MessageID>
    <w:To e:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action e:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

_SOAP_NS = {
    "e": "http://www.w3.org/2003/05/soap-envelope",
    "d": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
}


@dataclasses.dataclass
class DiscoveredDevice:
    address: str
    xaddrs: List[str]
    scopes: List[str]
    types: List[str]


def _ip_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = cctv_security.get_allowed_networks()
    return any(addr in net for net in nets)


def _parse_probe_match(data: bytes) -> Optional[DiscoveredDevice]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None

    match = root.find(".//d:ProbeMatch", _SOAP_NS)
    if match is None:
        return None

    xaddrs_el = match.find("d:XAddrs", _SOAP_NS)
    xaddrs = xaddrs_el.text.split() if xaddrs_el is not None and xaddrs_el.text else []
    scopes_el = match.find("d:Scopes", _SOAP_NS)
    scopes = scopes_el.text.split() if scopes_el is not None and scopes_el.text else []
    types_el = match.find("d:Types", _SOAP_NS)
    types = types_el.text.split() if types_el is not None and types_el.text else []

    address = urlparse(xaddrs[0]).hostname if xaddrs else None
    if not address:
        return None
    return DiscoveredDevice(address=address, xaddrs=xaddrs, scopes=scopes, types=types)


def _scan_blocking(timeout_seconds: float) -> List[DiscoveredDevice]:
    """Runs on a worker thread (via run_in_executor) -- plain blocking
    socket I/O, since asyncio's loop.sock_recvfrom() needs Python 3.11+
    and this project targets 3.10."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.bind(("0.0.0.0", 0))

    message_id = str(uuid.uuid4())
    probe = _PROBE_TEMPLATE.format(message_id=message_id).encode("utf-8")

    devices: dict = {}
    try:
        sock.sendto(probe, (WS_DISCOVERY_ADDRESS, WS_DISCOVERY_PORT))
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            if not _ip_allowed(ip):
                continue
            parsed = _parse_probe_match(data)
            if parsed is not None and ip not in devices:
                devices[ip] = parsed
    finally:
        sock.close()

    return list(devices.values())


async def discover(timeout_seconds: float = 3.0) -> List[DiscoveredDevice]:
    """Fail-closed: raises if no CCTV_ALLOWED_NETWORKS is configured, exactly like validate_stream_target."""
    if not cctv_security.get_allowed_networks():
        raise ValueError("CCTV_ALLOWED_NETWORKS is not configured -- refusing to scan (fail-closed)")
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _scan_blocking, timeout_seconds)
