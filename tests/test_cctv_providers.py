"""
Unit tests for the CCTV SSRF validator and RTSP provider.

The cctv_security tests (SSRF allowlist, encrypt/decrypt) are genuinely
MongoDB-free -- confirmed by actually running this file: those passed
with no `mongo_db` fixture at all. The RTSP-provider tests, however,
construct a `models.CCTVCamera`/`CCTVStreamSession` instance directly,
and running this file for real surfaced something the earlier static
review missed: Beanie's `Document.__init__` calls
`get_motor_collection()` unconditionally, which raises
`CollectionWasNotInitialized` unless `init_beanie()` has already run at
least once in this process -- even just to build the object in memory,
with no actual query involved. So those specific tests DO need the
`mongo_db` fixture (and are skipped, not failed, when no MongoDB replica
set is reachable -- see tests/conftest.py's `requires_mongo`).
"""
import asyncio

import pytest

from app import models
from app.services import cctv_security


def test_validate_stream_target_rejects_cloud_metadata_ip(monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "0.0.0.0/0")  # even an "allow everything" policy must not override the hard block
    with pytest.raises(ValueError, match="permanently blocked"):
        cctv_security.validate_stream_target("169.254.169.254", 80)


def test_validate_stream_target_fails_closed_with_no_allowlist(monkeypatch):
    monkeypatch.delenv("CCTV_ALLOWED_NETWORKS", raising=False)
    with pytest.raises(ValueError, match="not configured"):
        cctv_security.validate_stream_target("192.168.1.50", 554)


def test_validate_stream_target_allows_explicitly_listed_private_network(monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "192.168.1.0/24")
    cctv_security.validate_stream_target("192.168.1.50", 554)  # must not raise


def test_validate_stream_target_rejects_address_outside_allowlist(monkeypatch):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "192.168.1.0/24")
    with pytest.raises(ValueError, match="not within any"):
        cctv_security.validate_stream_target("10.0.0.5", 554)


def test_validate_stream_target_rejects_invalid_port():
    with pytest.raises(ValueError):
        cctv_security.validate_stream_target("127.0.0.1", 0)


def test_encrypt_decrypt_round_trip():
    ciphertext = cctv_security.encrypt_secret("super-secret-camera-password")
    assert ciphertext != "super-secret-camera-password"
    assert cctv_security.decrypt_secret(ciphertext) == "super-secret-camera-password"


async def _run_fake_rtsp_server(host: str, port: int, response: bytes):
    async def handle(reader, writer):
        await reader.read(4096)
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, host, port)
    return server


async def test_rtsp_provider_reports_online_for_a_real_rtsp_response(monkeypatch, mongo_db):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    from app.services import cctv_providers

    server = await _run_fake_rtsp_server("127.0.0.1", 0, b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
    port = server.sockets[0].getsockname()[1]
    try:
        camera = models.CCTVCamera(name="t", camera_code="t", stream_host="127.0.0.1", stream_port=port)
        result = await cctv_providers.RTSPProvider().validate_connection(camera)
        assert result.status == models.CCTVCameraStatus.online
        assert result.latency_ms is not None
    finally:
        server.close()
        await server.wait_closed()


async def test_rtsp_provider_reports_degraded_for_a_non_rtsp_response(monkeypatch, mongo_db):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    from app.services import cctv_providers

    server = await _run_fake_rtsp_server("127.0.0.1", 0, b"HTTP/1.1 200 OK\r\n\r\n")
    port = server.sockets[0].getsockname()[1]
    try:
        camera = models.CCTVCamera(name="t", camera_code="t", stream_host="127.0.0.1", stream_port=port)
        result = await cctv_providers.RTSPProvider().validate_connection(camera)
        assert result.status == models.CCTVCameraStatus.degraded
    finally:
        server.close()
        await server.wait_closed()


async def test_rtsp_provider_reports_offline_when_nothing_is_listening(monkeypatch, mongo_db):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    from app.services import cctv_providers

    camera = models.CCTVCamera(name="t", camera_code="t", stream_host="127.0.0.1", stream_port=1)  # nothing listens on port 1
    result = await cctv_providers.RTSPProvider().validate_connection(camera)
    assert result.status == models.CCTVCameraStatus.offline


async def test_rtsp_provider_reports_unknown_when_blocked_by_ssrf_policy(monkeypatch, mongo_db):
    monkeypatch.delenv("CCTV_ALLOWED_NETWORKS", raising=False)
    from app.services import cctv_providers

    camera = models.CCTVCamera(name="t", camera_code="t", stream_host="127.0.0.1", stream_port=554)
    result = await cctv_providers.RTSPProvider().validate_connection(camera)
    assert result.status == models.CCTVCameraStatus.unknown
    assert "blocked" in result.error


async def test_unimplemented_providers_raise_not_implemented(mongo_db):
    """ONVIF is excluded here -- it's a real, implemented provider now (see the dedicated ONVIF tests below)."""
    from app.services import cctv_providers

    for provider_type in (models.CCTVProviderType.nvr, models.CCTVProviderType.vms):
        provider = cctv_providers.get_provider(provider_type)
        camera = models.CCTVCamera(name="t", camera_code="t", stream_host="127.0.0.1", stream_port=554, provider_type=provider_type)
        with pytest.raises(NotImplementedError):
            await provider.validate_connection(camera)


async def test_rtsp_start_stream_honestly_reports_not_implemented(mongo_db):
    """See cctv_providers.py's module docstring: this must never fabricate a working media bridge."""
    from app.services import cctv_providers

    camera = models.CCTVCamera(name="t", camera_code="t", stream_host="127.0.0.1", stream_port=554)
    session = models.CCTVStreamSession(camera_id=camera.id, requested_by=camera.id, provider=camera.provider_type, protocol=camera.stream_protocol)
    result = await cctv_providers.RTSPProvider().start_stream(camera, session)
    assert result.ok is False
    assert result.error


# ===========================================================================
# ONVIFProvider -- real SOAP-over-HTTP probe, tested against a local fake
# HTTP server (no physical ONVIF camera exists in this environment -- see
# cctv_providers.py's module docstring for the honest verification status).
# ===========================================================================

_ONVIF_VALID_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nConnection: close\r\n\r\n"
    b'<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
    b'<soap:Body><tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    b"</tds:GetSystemDateAndTimeResponse></soap:Body></soap:Envelope>"
)


async def _run_fake_http_server(host: str, port: int, response: bytes):
    async def handle(reader, writer):
        await reader.read(4096)
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, host, port)
    return server


async def test_onvif_provider_reports_online_for_a_real_onvif_response(monkeypatch, mongo_db):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    from app.services import cctv_providers

    server = await _run_fake_http_server("127.0.0.1", 0, _ONVIF_VALID_RESPONSE)
    port = server.sockets[0].getsockname()[1]
    try:
        camera = models.CCTVCamera(
            name="t", camera_code="t", stream_host="127.0.0.1", stream_port=554,
            provider_type=models.CCTVProviderType.onvif, management_url=f"http://127.0.0.1:{port}/onvif/device_service",
        )
        result = await cctv_providers.ONVIFProvider().validate_connection(camera)
        assert result.status == models.CCTVCameraStatus.online
        assert result.latency_ms is not None
    finally:
        server.close()
        await server.wait_closed()


async def test_onvif_provider_reports_degraded_for_a_non_onvif_http_response(monkeypatch, mongo_db):
    """Confirms a real-but-wrong endpoint (reachable, speaks HTTP, but isn't ONVIF) is honestly distinguished from both 'online' and 'offline' -- this is the realistic result against this project's own demo RTSP camera, which has no ONVIF service at all."""
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    from app.services import cctv_providers

    server = await _run_fake_http_server("127.0.0.1", 0, b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n<html>not onvif</html>")
    port = server.sockets[0].getsockname()[1]
    try:
        camera = models.CCTVCamera(
            name="t", camera_code="t", stream_host="127.0.0.1", stream_port=554,
            provider_type=models.CCTVProviderType.onvif, management_url=f"http://127.0.0.1:{port}/onvif/device_service",
        )
        result = await cctv_providers.ONVIFProvider().validate_connection(camera)
        assert result.status == models.CCTVCameraStatus.degraded
    finally:
        server.close()
        await server.wait_closed()


async def test_onvif_provider_reports_offline_when_nothing_is_listening(monkeypatch, mongo_db):
    monkeypatch.setenv("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32")
    from app.services import cctv_providers

    camera = models.CCTVCamera(
        name="t", camera_code="t", stream_host="127.0.0.1", stream_port=554,
        provider_type=models.CCTVProviderType.onvif, management_url="http://127.0.0.1:1/onvif/device_service",
    )
    result = await cctv_providers.ONVIFProvider().validate_connection(camera)
    assert result.status == models.CCTVCameraStatus.offline


async def test_onvif_provider_reports_unknown_when_blocked_by_ssrf_policy(monkeypatch, mongo_db):
    monkeypatch.delenv("CCTV_ALLOWED_NETWORKS", raising=False)
    from app.services import cctv_providers

    camera = models.CCTVCamera(
        name="t", camera_code="t", stream_host="127.0.0.1", stream_port=554,
        provider_type=models.CCTVProviderType.onvif, management_url="http://127.0.0.1:80/onvif/device_service",
    )
    result = await cctv_providers.ONVIFProvider().validate_connection(camera)
    assert result.status == models.CCTVCameraStatus.unknown
    assert "blocked" in result.error


# ===========================================================================
# cctv_discovery.py -- real WS-Discovery UDP multicast, exercised against
# this machine's real network interface. No physical ONVIF camera exists
# in this environment, so the expected, honest result is an empty list --
# that is a passing test, not a failure of the discovery mechanism.
# ===========================================================================

async def test_discovery_fails_closed_with_no_allowlist(monkeypatch):
    monkeypatch.delenv("CCTV_ALLOWED_NETWORKS", raising=False)
    from app.services import cctv_discovery

    with pytest.raises(ValueError, match="not configured"):
        await cctv_discovery.discover(timeout_seconds=0.1)


async def test_discovery_real_scan_completes_without_error():
    """Real UDP multicast probe + listen, genuinely exercised. PHYSICAL ONVIF CAMERA VERIFIED: NO -- an empty result list is the honest outcome here, not a stub."""
    import os as _os
    _os.environ.setdefault("CCTV_ALLOWED_NETWORKS", "127.0.0.1/32,192.168.0.0/16,10.0.0.0/8")
    from app.services import cctv_discovery

    devices = await cctv_discovery.discover(timeout_seconds=1.0)
    assert isinstance(devices, list)  # genuinely ran; whether any device answered depends on the real local network
