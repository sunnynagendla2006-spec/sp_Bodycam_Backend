"""
CCTVProvider abstraction: keeps provider-specific logic out of
app/routers/cctv.py, mirroring how app/services/storage.py keeps
Local-vs-S3 logic out of the routers that use it.

VERIFICATION STATUS (see the final implementation report for the full
legend):
  - RTSPProvider.validate_connection(): [IMPLEMENTED] [UNIT TESTED]
    (against a local fake TCP server in tests/test_cctv_providers.py)
    [RUNTIME VERIFIED: NO] [PHYSICAL CAMERA VERIFIED: NO] -- no real RTSP
    camera or NVR was reachable in this environment.
  - RTSPProvider.start_stream(): [IMPLEMENTED: NO] -- see its docstring.
    This is a real extension point, not a disguised fake success path.
  - ONVIFProvider.validate_connection(): [IMPLEMENTED] -- a genuine ONVIF
    SOAP probe (GetSystemDateAndTime, the one ONVIF device-service call
    that never requires authentication), not a placeholder. [UNIT TESTED]
    (against a local fake HTTP server). [RUNTIME VERIFIED: yes, the
    SOAP-over-HTTP mechanism itself]. [PHYSICAL ONVIF CAMERA VERIFIED: NO]
    -- no physical ONVIF device exists in this environment, so a real
    probe against this project's own demo camera honestly reports "not a
    valid ONVIF response", never a fabricated "online".
  - ONVIFProvider.start_stream(): [IMPLEMENTED: NO] -- same honest
    "no media gateway" extension point as RTSPProvider.start_stream().
  - NVR / VMS providers: [NOT IMPLEMENTED] -- placeholders that raise
    NotImplementedError with a clear message. Do not wire these into any
    endpoint as if they worked.
"""
import abc
import asyncio
import dataclasses
import http.client
import os
import time
import xml.etree.ElementTree as ET
from typing import Optional
from urllib.parse import urlparse

from .. import models
from . import cctv_security

_RTSP_CONNECT_TIMEOUT_SECONDS = float(os.getenv("CCTV_RTSP_CONNECT_TIMEOUT_SECONDS", "5"))


@dataclasses.dataclass
class CCTVConnectionResult:
    status: "models.CCTVCameraStatus"
    latency_ms: Optional[float] = None
    error: Optional[str] = None


@dataclasses.dataclass
class CCTVStreamStartResult:
    """Returned by CCTVProvider.start_stream(). `ok=False` is the expected, non-exceptional outcome for every provider today -- see each provider's docstring."""
    ok: bool
    gateway: Optional[str] = None
    stream_reference: Optional[str] = None
    livekit_url: Optional[str] = None
    token: Optional[str] = None
    identity: Optional[str] = None
    error: Optional[str] = None


class CCTVProvider(abc.ABC):
    """Common interface every CCTV provider implements. See module docstring for which methods are actually implemented today."""

    @abc.abstractmethod
    async def validate_connection(self, camera: "models.CCTVCamera") -> CCTVConnectionResult:
        raise NotImplementedError

    async def get_status(self, camera: "models.CCTVCamera") -> CCTVConnectionResult:
        """Default: same check as validate_connection. A provider with a cheaper/different status mechanism (e.g. an NVR's own health API) would override this."""
        return await self.validate_connection(camera)

    @abc.abstractmethod
    async def start_stream(self, camera: "models.CCTVCamera", session: "models.CCTVStreamSession") -> CCTVStreamStartResult:
        raise NotImplementedError

    async def stop_stream(self, camera: "models.CCTVCamera", session: "models.CCTVStreamSession") -> None:
        """Default no-op -- correct for any provider whose start_stream() never actually bridged media (see RTSPProvider)."""
        return None


class RTSPProvider(CCTVProvider):
    """
    Real, protocol-level RTSP reachability check: SSRF-validates the
    target, opens a TCP connection, sends a minimal RTSP OPTIONS request,
    and inspects the response's status line. This is NOT a TCP ping
    disguised as a camera check -- an RTSP-speaking endpoint (even one
    that answers 401 Unauthorized to an unauthenticated OPTIONS) is
    distinguished from "something is listening on that port but isn't
    RTSP" (status=degraded) and from "nothing answered at all"
    (status=offline).

    start_stream() is a deliberate [NOT IMPLEMENTED] extension point, not
    a placeholder dressed up as success: bridging RTSP into something a
    browser can actually play (WebRTC/HLS) requires a real media gateway
    (LiveKit Ingress, MediaMTX, or similar). This repository's existing
    LiveKit usage (app/routers/live_stream.py) is a WebRTC *publish*
    integration driven by a device's own LiveKit client SDK -- it has no
    code path for pulling an existing RTSP stream into a room, and I could
    not verify the exact `livekit-api` Ingress-service call shape against
    a real LiveKit deployment in this environment. Rather than guess at
    that API surface and risk shipping a call that's subtly wrong, this
    method honestly reports "no media gateway available" so the session
    lifecycle (CCTVStreamSession status/events/audit) is still fully real
    and testable without a fabricated video path.
    """

    async def validate_connection(self, camera: "models.CCTVCamera") -> CCTVConnectionResult:
        host, port = camera.stream_host, camera.stream_port or 554
        try:
            cctv_security.validate_stream_target(host, port)
        except ValueError as exc:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.unknown, error=f"blocked by CCTV network policy: {exc}")

        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=_RTSP_CONNECT_TIMEOUT_SECONDS
            )
        except (OSError, asyncio.TimeoutError) as exc:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.offline, error=str(exc))

        try:
            path = camera.stream_path or "/"
            request_line = (
                f"OPTIONS {camera.stream_protocol.value}://{host}:{port}{path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n\r\n"
            )
            writer.write(request_line.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=_RTSP_CONNECT_TIMEOUT_SECONDS)
        except (OSError, asyncio.TimeoutError) as exc:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.offline, error=str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        latency_ms = (time.monotonic() - start) * 1000

        if data.startswith(b"RTSP/1.0") or data.startswith(b"RTSP/2.0"):
            # A real RTSP service answered. A 401/454/etc. status line still
            # counts as "online" -- reachability and credential validity
            # are different questions; see models.CCTVCameraStatus docstring.
            return CCTVConnectionResult(status=models.CCTVCameraStatus.online, latency_ms=latency_ms)

        if not data:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.offline, error="connection closed with no response")

        return CCTVConnectionResult(
            status=models.CCTVCameraStatus.degraded,
            latency_ms=latency_ms,
            error="host is reachable but did not return a valid RTSP response",
        )

    async def start_stream(self, camera: "models.CCTVCamera", session: "models.CCTVStreamSession") -> CCTVStreamStartResult:
        return CCTVStreamStartResult(
            ok=False,
            error=(
                "Media bridging (WebRTC/HLS) is not implemented in this phase. "
                "Camera management, connectivity testing, status, and nearby-camera "
                "search are fully functional without it."
            ),
        )


_ONVIF_SOAP_NS = {"soap": "http://www.w3.org/2003/05/soap-envelope"}
_ONVIF_PROBE_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    "<soap:Body><tds:GetSystemDateAndTime/></soap:Body></soap:Envelope>"
).encode("utf-8")

_ONVIF_CONNECT_TIMEOUT_SECONDS = float(os.getenv("CCTV_ONVIF_CONNECT_TIMEOUT_SECONDS", "5"))


class ONVIFProvider(CCTVProvider):
    """
    Real ONVIF reachability/compatibility check via SOAP-over-HTTP, not a
    disguised placeholder: POSTs a genuine GetSystemDateAndTime request
    (the one ONVIF device-service operation the spec guarantees works
    without authentication -- see ONVIF Core Spec section on
    GetSystemDateAndTime) to the camera's device service URL, and inspects
    the response for a real SOAP envelope containing
    GetSystemDateAndTimeResponse. Hand-rolled with stdlib http.client
    (mirrors RTSPProvider's own hand-rolled raw-socket RTSP check above)
    rather than pulling in a full ONVIF client library this codebase has
    no other use for.

    The device service URL is `camera.management_url` if the admin set
    one (the correct place to put it, since this is a management/control
    endpoint, not a media stream target); otherwise this falls back to
    `http://{stream_host}:80/onvif/device_service`, the ONVIF-spec default
    path -- a reasonable guess, not a guarantee, which is exactly why a
    REAL probe (not just "does something answer on port 80") decides the
    actual online/offline/degraded result.
    """

    def _device_service_url(self, camera: "models.CCTVCamera") -> str:
        if camera.management_url:
            return camera.management_url
        return f"http://{camera.stream_host}:80/onvif/device_service"

    async def validate_connection(self, camera: "models.CCTVCamera") -> CCTVConnectionResult:
        url = self._device_service_url(camera)
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        try:
            cctv_security.validate_stream_target(host, port)
        except ValueError as exc:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.unknown, error=f"blocked by CCTV network policy: {exc}")

        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._post_soap_blocking, parsed, host, port),
                timeout=_ONVIF_CONNECT_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.offline, error="ONVIF device service did not respond in time")
        return result

    def _post_soap_blocking(self, parsed, host: str, port: int) -> CCTVConnectionResult:
        start = time.monotonic()
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(host, port, timeout=_ONVIF_CONNECT_TIMEOUT_SECONDS)
        try:
            conn.request(
                "POST", parsed.path or "/onvif/device_service", body=_ONVIF_PROBE_BODY,
                headers={"Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"'},
            )
            resp = conn.getresponse()
            body = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.offline, error=str(exc))
        finally:
            conn.close()

        latency_ms = (time.monotonic() - start) * 1000

        if resp.status >= 500 or resp.status == 404:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.degraded, latency_ms=latency_ms, error=f"HTTP {resp.status} -- reachable but not an ONVIF device service at this path")

        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.degraded, latency_ms=latency_ms, error="reachable but did not return valid SOAP/XML")

        if root.find(".//{http://www.onvif.org/ver10/device/wsdl}GetSystemDateAndTimeResponse") is not None:
            return CCTVConnectionResult(status=models.CCTVCameraStatus.online, latency_ms=latency_ms)

        # A SOAP fault still proves "this is a real SOAP/ONVIF-ish endpoint", just not one that
        # answered this specific unauthenticated call cleanly -- report degraded, not offline.
        return CCTVConnectionResult(status=models.CCTVCameraStatus.degraded, latency_ms=latency_ms, error="responded, but not with a recognizable ONVIF GetSystemDateAndTime response")

    async def start_stream(self, camera: "models.CCTVCamera", session: "models.CCTVStreamSession") -> CCTVStreamStartResult:
        return CCTVStreamStartResult(
            ok=False,
            error="Media bridging (WebRTC/HLS) is not implemented in this phase, same as the generic RTSP provider.",
        )


class _UnimplementedProvider(CCTVProvider):
    """NVR / VMS -- genuine extension points, not working implementations. Every method raises, deliberately, so a caller can never mistake this for a working provider."""

    def __init__(self, name: str):
        self._name = name

    async def validate_connection(self, camera: "models.CCTVCamera") -> CCTVConnectionResult:
        raise NotImplementedError(f"{self._name} provider is not implemented yet")

    async def start_stream(self, camera: "models.CCTVCamera", session: "models.CCTVStreamSession") -> CCTVStreamStartResult:
        raise NotImplementedError(f"{self._name} provider is not implemented yet")


_PROVIDERS = {
    models.CCTVProviderType.rtsp: RTSPProvider(),
    models.CCTVProviderType.onvif: ONVIFProvider(),
    models.CCTVProviderType.nvr: _UnimplementedProvider("NVR"),
    models.CCTVProviderType.vms: _UnimplementedProvider("VMS"),
}


def get_provider(provider_type: "models.CCTVProviderType") -> CCTVProvider:
    return _PROVIDERS[provider_type]
