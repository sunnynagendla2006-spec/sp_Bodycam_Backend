"""
Requirement 2: LiveKit Egress recording of a live stream's room. These
tests exercise the actual egress integration code in
app/routers/live_stream.py (_start_egress_best_effort, _stop_egress_best_effort,
_handle_egress_ended, and the /live-stream/egress-webhook endpoint) without
needing a real livekit-egress/Redis deployment -- LiveKitAPI itself is
monkeypatched (the same seam the real network call goes through), but the
webhook signature verification is exercised for real using LiveKit's own
TokenVerifier against a genuinely HS256-signed JWT, exactly like a real
LiveKit Egress webhook delivery would be authenticated.

Full end-to-end verification (a real phone publishing, egress actually
producing a playable MP4) can only happen against the real
redis+livekit-egress deployment -- see the physical test matrix in the
final report; that is NOT what these tests claim to cover.
"""
import base64
import hashlib
import json
import os
import time
import types

import pytest
from jose import jwt as jose_jwt
from livekit import api as lk_api

from app import models
from app.routers import live_stream as live_stream_module

LIVEKIT_API_KEY = live_stream_module.LIVEKIT_API_KEY
LIVEKIT_API_SECRET = live_stream_module.LIVEKIT_API_SECRET


def _register_device(full_client, headers, device_identifier="phone-ls001"):
    resp = full_client.post("/devices/register", json={"device_identifier": device_identifier, "platform": "android"}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


class _FakeEgressService:
    def __init__(self, start_result=None, start_exc=None):
        self._start_result = start_result
        self._start_exc = start_exc
        self.stop_calls = []
        self.start_calls = []

    async def start_room_composite_egress(self, req):
        self.start_calls.append(req)
        if self._start_exc:
            raise self._start_exc
        return self._start_result

    async def stop_egress(self, req):
        self.stop_calls.append(req.egress_id)


class _FakeLiveKitAPI:
    def __init__(self, egress_service):
        self.egress = egress_service

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _patch_livekit_api(monkeypatch, fake_service):
    monkeypatch.setattr(live_stream_module.lk_api, "LiveKitAPI", lambda *a, **kw: _FakeLiveKitAPI(fake_service))


def _sign_webhook_token(body: str, *, api_key=LIVEKIT_API_KEY, api_secret=LIVEKIT_API_SECRET) -> str:
    """Builds the same HS256 JWT shape lk_api.TokenVerifier.verify expects
    (see app/routers/live_stream.py::_webhook_receiver) -- iss=api_key,
    sha256=of the exact raw body, signed with api_secret. Mirrors what a
    real LiveKit Egress webhook delivery signs, without needing a real
    egress process to produce one."""
    sha256_b64 = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
    payload = {"iss": api_key, "sha256": sha256_b64, "exp": int(time.time()) + 60}
    return jose_jwt.encode(payload, api_secret, algorithm="HS256")


# ---------------------------------------------------------------------------
# Starting a live stream: egress recording is best-effort and must never
# block/break the stream itself.
# ---------------------------------------------------------------------------
def test_start_live_stream_succeeds_even_when_egress_start_fails(full_client, make_constable, auth_header, db_session, monkeypatch):
    make_constable(phone="l000000001")
    headers = auth_header("l000000001", "correct-horse-battery")
    device_id = _register_device(full_client, headers, "phone-ls001")

    fake_service = _FakeEgressService(start_exc=ConnectionError("egress infra unreachable"))
    _patch_livekit_api(monkeypatch, fake_service)

    resp = full_client.post(f"/devices/{device_id}/live-stream/start", json={}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["token"]

    session_id = resp.json()["session"]["id"]
    import uuid as uuid_module
    session = db_session.query(models.LiveStreamSession).filter(models.LiveStreamSession.id == uuid_module.UUID(session_id)).one()
    assert session.egress_id is None
    assert session.status == models.LiveStreamStatus.live  # the stream itself is unaffected


def test_start_live_stream_records_egress_id_on_success(full_client, make_constable, auth_header, db_session, monkeypatch):
    make_constable(phone="l000000002")
    headers = auth_header("l000000002", "correct-horse-battery")
    device_id = _register_device(full_client, headers, "phone-ls002")

    fake_service = _FakeEgressService(start_result=types.SimpleNamespace(egress_id="EG_fake123"))
    _patch_livekit_api(monkeypatch, fake_service)

    resp = full_client.post(f"/devices/{device_id}/live-stream/start", json={}, headers=headers)
    assert resp.status_code == 200

    session_id = resp.json()["session"]["id"]
    import uuid as uuid_module
    session = db_session.query(models.LiveStreamSession).filter(models.LiveStreamSession.id == uuid_module.UUID(session_id)).one()
    assert session.egress_id == "EG_fake123"

    # The actual egress request must target this session's real room, and
    # must carry a webhook pointing back at this backend.
    req = fake_service.start_calls[0]
    assert req.room_name == session.room_name
    assert req.webhooks[0].url.endswith("/live-stream/egress-webhook")


def test_stop_live_stream_stops_egress_when_it_was_recording(full_client, make_constable, auth_header, monkeypatch):
    make_constable(phone="l000000003")
    headers = auth_header("l000000003", "correct-horse-battery")
    device_id = _register_device(full_client, headers, "phone-ls003")

    fake_service = _FakeEgressService(start_result=types.SimpleNamespace(egress_id="EG_fake456"))
    _patch_livekit_api(monkeypatch, fake_service)

    start_resp = full_client.post(f"/devices/{device_id}/live-stream/start", json={}, headers=headers)
    session_id = start_resp.json()["session"]["id"]

    stop_resp = full_client.post(f"/live-stream/{session_id}/stop", headers=headers)
    assert stop_resp.status_code == 200
    assert fake_service.stop_calls == ["EG_fake456"]


def test_stop_live_stream_never_calls_stop_egress_when_it_was_never_recording(full_client, make_constable, auth_header, monkeypatch):
    make_constable(phone="l000000004")
    headers = auth_header("l000000004", "correct-horse-battery")
    device_id = _register_device(full_client, headers, "phone-ls004")

    fake_service = _FakeEgressService(start_exc=ConnectionError("egress infra unreachable"))
    _patch_livekit_api(monkeypatch, fake_service)

    start_resp = full_client.post(f"/devices/{device_id}/live-stream/start", json={}, headers=headers)
    session_id = start_resp.json()["session"]["id"]

    stop_resp = full_client.post(f"/live-stream/{session_id}/stop", headers=headers)
    assert stop_resp.status_code == 200
    assert fake_service.stop_calls == []


# ---------------------------------------------------------------------------
# _handle_egress_ended -- turning a completed egress into a real My
# Recordings entry, reusing Requirement 1's playable-recording pipeline.
# ---------------------------------------------------------------------------
@pytest.fixture
def live_session_with_pending_file(full_client, make_constable, auth_header, db_session):
    """A LiveStreamSession row plus a real file sitting where
    _handle_egress_ended expects to find a finished egress output."""
    from app import models as models_module
    from app.routers import media as media_module

    _user, constable = make_constable(phone="l000000005")
    headers = auth_header("l000000005", "correct-horse-battery")
    device_id = _register_device(full_client, headers, "phone-ls005")

    import uuid as uuid_module
    session = models_module.LiveStreamSession(
        device_id=uuid_module.UUID(device_id),
        constable_id=constable.id,
        room_name="device-test-room",
        status=models_module.LiveStreamStatus.ended,
        started_by=models_module.LiveStreamStartedBy.self,
        egress_id="EG_pending789",
    )
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)

    storage = media_module._get_storage_backend()
    pending_path = storage._abs_path(live_stream_module._pending_egress_rel_path(session.id))
    os.makedirs(os.path.dirname(pending_path), exist_ok=True)
    with open(pending_path, "wb") as f:
        f.write(b"fake mp4 bytes representing a real egress output file")

    return session


def test_handle_egress_ended_creates_recording_on_complete(db_session, live_session_with_pending_file):
    session = live_session_with_pending_file
    egress_info = lk_api.EgressInfo(egress_id=session.egress_id, status=lk_api.EgressStatus.EGRESS_COMPLETE)

    import asyncio
    asyncio.get_event_loop().run_until_complete(live_stream_module._handle_egress_ended(db_session, egress_info))

    db_session.refresh(session)
    assert session.recording_session_id is not None

    recording = db_session.query(models.RecordingSession).filter(models.RecordingSession.id == session.recording_session_id).one()
    assert recording.trigger_type == models.RecordingTriggerType.live_stream
    assert recording.status == models.RecordingStatus.completed
    assert recording.playable_status == "ready"
    assert recording.constable_id == session.constable_id
    assert recording.device_id == session.device_id

    from app.routers import media as media_module
    storage = media_module._get_storage_backend()
    assert storage.exists(recording.playable_storage_key)
    assert storage.get_size(recording.playable_storage_key) > 0


def test_handle_egress_ended_ignores_non_complete_status(db_session, live_session_with_pending_file):
    """A failed/aborted egress must never fabricate a fake recording entry."""
    session = live_session_with_pending_file
    egress_info = lk_api.EgressInfo(egress_id=session.egress_id, status=lk_api.EgressStatus.EGRESS_FAILED)

    import asyncio
    asyncio.get_event_loop().run_until_complete(live_stream_module._handle_egress_ended(db_session, egress_info))

    db_session.refresh(session)
    assert session.recording_session_id is None


def test_handle_egress_ended_is_idempotent_on_redelivery(db_session, live_session_with_pending_file):
    session = live_session_with_pending_file
    egress_info = lk_api.EgressInfo(egress_id=session.egress_id, status=lk_api.EgressStatus.EGRESS_COMPLETE)

    import asyncio
    asyncio.get_event_loop().run_until_complete(live_stream_module._handle_egress_ended(db_session, egress_info))
    db_session.refresh(session)
    first_recording_id = session.recording_session_id
    assert first_recording_id is not None

    # A webhook redelivery for the same egress_id must never create a second recording.
    asyncio.get_event_loop().run_until_complete(live_stream_module._handle_egress_ended(db_session, egress_info))
    db_session.refresh(session)
    assert session.recording_session_id == first_recording_id

    count = db_session.query(models.RecordingSession).filter(models.RecordingSession.id == first_recording_id).count()
    assert count == 1


# ---------------------------------------------------------------------------
# /live-stream/egress-webhook -- real signature verification.
# ---------------------------------------------------------------------------
def test_egress_webhook_rejects_invalid_signature(full_client):
    body = json.dumps({"event": "egress_ended"})
    resp = full_client.post(
        "/live-stream/egress-webhook",
        data=body,
        headers={"Authorization": "not-a-real-token", "Content-Type": "application/webhook+json"},
    )
    assert resp.status_code == 401


def test_egress_webhook_rejects_body_that_does_not_match_signature(full_client):
    body = json.dumps({"event": "egress_ended"})
    token = _sign_webhook_token('{"event": "something_else"}')  # signed over DIFFERENT body
    resp = full_client.post(
        "/live-stream/egress-webhook",
        data=body,
        headers={"Authorization": token, "Content-Type": "application/webhook+json"},
    )
    assert resp.status_code == 401


def test_egress_webhook_accepts_genuinely_signed_event_and_creates_recording(full_client, db_session, live_session_with_pending_file):
    session = live_session_with_pending_file
    from google.protobuf.json_format import MessageToJson
    event = lk_api.WebhookEvent(
        event="egress_ended",
        egress_info=lk_api.EgressInfo(egress_id=session.egress_id, status=lk_api.EgressStatus.EGRESS_COMPLETE),
    )
    body = MessageToJson(event)
    token = _sign_webhook_token(body)

    resp = full_client.post(
        "/live-stream/egress-webhook",
        data=body,
        headers={"Authorization": token, "Content-Type": "application/webhook+json"},
    )
    assert resp.status_code == 200

    db_session.refresh(session)
    assert session.recording_session_id is not None
