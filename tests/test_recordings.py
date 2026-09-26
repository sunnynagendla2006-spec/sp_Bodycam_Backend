"""
RecordingSession + embedded VideoChunk tests.
"""
import json
import subprocess
import tempfile
import os

import pytest

from app.models import UserRole, RecordingStatus, RecordingTriggerType

JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + (b"0123456789" * 10)
MP4_BYTES = b"\x00\x00\x00\x18ftypmp42" + (b"0123456789" * 20)  # minimal valid "ftyp box" prefix recognized by _sniff_mime_type


def _real_mp4_segment_bytes(index: int) -> bytes:
    """
    A real, ffmpeg-decodable MP4 (not just a fake ftyp-prefixed blob like
    MP4_BYTES above) -- needed to test _try_build_playable_recording's
    actual ffmpeg concat, which requires structurally valid MP4 input.
    Generated fresh per call via ffmpeg's lavfi test source so these tests
    don't depend on any checked-in binary fixture.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, f"seg{index}.mp4")
        result = subprocess.run(
            [
                "ffmpeg", "-y", "-f", "lavfi", "-i", f"color=c=blue:s=32x32:d=1:r=2",
                "-c:v", "mpeg4", "-pix_fmt", "yuv420p", out_path,
            ],
            capture_output=True,
        )
        if result.returncode != 0 or not os.path.exists(out_path):
            pytest.skip(f"ffmpeg unavailable/failed in this test environment: {result.stderr.decode(errors='replace')[-500:]}")
        with open(out_path, "rb") as f:
            return f.read()


async def _get_logs(action=None):
    from app import models
    if action:
        return await models.AuditLog.find(models.AuditLog.action == action).to_list()
    return await models.AuditLog.find_all().to_list()


async def _get_recording_session(recording_id: str):
    from app import models
    import uuid as uuid_module
    return await models.RecordingSession.get(uuid_module.UUID(recording_id))


async def _register_device(full_client, headers, device_identifier="phone-r001"):
    resp = await full_client.post("/devices/register", json={"device_identifier": device_identifier, "platform": "android"}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


async def _start_recording(full_client, headers, device_identifier="phone-r001", trigger_type="manual", incident_id=None):
    payload = {"device_identifier": device_identifier, "trigger_type": trigger_type}
    if incident_id:
        payload["incident_id"] = incident_id
    resp = await full_client.post("/recordings/start", json=payload, headers=headers)
    return resp


async def _upload_chunk(full_client, headers, recording_id, chunk_number, content=MP4_BYTES, is_last_chunk=False, duration=2.5):
    return await full_client.post(
        f"/recordings/{recording_id}/chunks",
        data={"chunk_number": str(chunk_number), "duration_seconds": str(duration), "is_last_chunk": str(is_last_chunk)},
        files={"file": (f"chunk{chunk_number}.mp4", content, "video/mp4")},
        headers=headers,
    )


# ---------------------------------------------------------------------------
# 1-3: Recording creation, trigger types, initial status
# ---------------------------------------------------------------------------
async def test_recording_creation_with_default_trigger_type(full_client, make_constable, auth_header):
    await make_constable(phone="r000000001")
    headers = await auth_header("r000000001", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r001")

    resp = await _start_recording(full_client, headers, "phone-r001")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "recording"
    assert body["trigger_type"] == "manual"
    assert body["incident_id"] is None
    assert body["chunk_count"] == 0


async def test_recording_creation_with_emergency_button_trigger(full_client, make_constable, auth_header):
    await make_constable(phone="r000000002")
    headers = await auth_header("r000000002", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r002")

    resp = await _start_recording(full_client, headers, "phone-r002", trigger_type="emergency_button")
    assert resp.status_code == 200
    assert resp.json()["trigger_type"] == "emergency_button"


async def test_recording_does_not_require_incident(full_client, make_constable, auth_header):
    """The core requirement: RecordingSession must exist without any Incident."""
    await make_constable(phone="r000000003")
    headers = await auth_header("r000000003", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r003")

    resp = await _start_recording(full_client, headers, "phone-r003")
    assert resp.status_code == 200
    assert resp.json()["incident_id"] is None


async def test_recording_can_optionally_link_to_existing_incident(full_client, make_constable, make_incident, auth_header):
    await make_constable(phone="r000000004")
    headers = await auth_header("r000000004", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r004")
    incident = await make_incident()

    resp = await _start_recording(full_client, headers, "phone-r004", incident_id=str(incident.id))
    assert resp.status_code == 200
    assert resp.json()["incident_id"] == str(incident.id)


async def test_recording_with_nonexistent_incident_id_rejected(full_client, make_constable, auth_header):
    import uuid
    await make_constable(phone="r000000005")
    headers = await auth_header("r000000005", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r005")

    resp = await _start_recording(full_client, headers, "phone-r005", incident_id=str(uuid.uuid4()))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4: Ownership authorization for starting a recording
# ---------------------------------------------------------------------------
async def test_cannot_start_recording_for_another_constables_device(full_client, make_constable, auth_header):
    await make_constable(phone="r000000006a")
    await make_constable(phone="r000000006b")
    headers_a = await auth_header("r000000006a", "correct-horse-battery")
    headers_b = await auth_header("r000000006b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-r006")

    resp = await _start_recording(full_client, headers_b, "phone-r006")
    assert resp.status_code == 403


async def test_only_constable_role_can_start_recording(full_client, make_user, auth_header):
    await make_user(phone="r000000007", password="pw", role=UserRole.admin)
    headers = await auth_header("r000000007", "pw")
    resp = await _start_recording(full_client, headers, "nonexistent-device")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 5-8: Chunk upload, hash, MIME, size validation
# ---------------------------------------------------------------------------
async def test_chunk_upload_success(full_client, make_constable, auth_header):
    await make_constable(phone="r000000008")
    headers = await auth_header("r000000008", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r008")
    recording_id = (await _start_recording(full_client, headers, "phone-r008")).json()["id"]

    resp = await _upload_chunk(full_client, headers, recording_id, 1)
    assert resp.status_code == 200
    body = resp.json()
    assert body["chunk_number"] == 1
    assert body["mime_type"] == "video/mp4"
    assert "storage_key" not in body  # never exposed
    assert "file_path" not in body

    session = await _get_recording_session(recording_id)
    assert len(session.chunks) == 1
    assert session.chunks[0].file_hash is not None
    assert len(session.chunks[0].file_hash) == 64  # sha256 hex digest length


async def test_chunk_upload_computes_correct_sha256_hash(full_client, make_constable, auth_header):
    import hashlib
    await make_constable(phone="r000000009")
    headers = await auth_header("r000000009", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r009")
    recording_id = (await _start_recording(full_client, headers, "phone-r009")).json()["id"]

    resp = await _upload_chunk(full_client, headers, recording_id, 1, content=MP4_BYTES)
    assert resp.status_code == 200
    assert resp.json()["file_hash"] == hashlib.sha256(MP4_BYTES).hexdigest()


async def test_chunk_upload_rejects_mismatched_mime(full_client, make_constable, auth_header):
    await make_constable(phone="r000000010")
    headers = await auth_header("r000000010", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r010")
    recording_id = (await _start_recording(full_client, headers, "phone-r010")).json()["id"]

    resp = await full_client.post(
        f"/recordings/{recording_id}/chunks",
        data={"chunk_number": "1", "is_last_chunk": "false"},
        files={"file": ("chunk1.mp4", JPEG_BYTES, "video/mp4")},  # declared mp4, actual jpeg bytes
        headers=headers,
    )
    assert resp.status_code == 400


async def test_chunk_upload_size_limit_enforced(full_client, make_constable, auth_header, monkeypatch):
    from app.routers import media as media_module
    await make_constable(phone="r000000011")
    headers = await auth_header("r000000011", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r011")
    recording_id = (await _start_recording(full_client, headers, "phone-r011")).json()["id"]

    monkeypatch.setattr(media_module, "MAX_EVIDENCE_SIZE_BYTES", 10)
    resp = await _upload_chunk(full_client, headers, recording_id, 1)
    assert resp.status_code == 413


async def test_chunk_upload_only_allowed_by_own_constable(full_client, make_constable, auth_header):
    await make_constable(phone="r000000012a")
    await make_constable(phone="r000000012b")
    headers_a = await auth_header("r000000012a", "correct-horse-battery")
    headers_b = await auth_header("r000000012b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-r012")
    recording_id = (await _start_recording(full_client, headers_a, "phone-r012")).json()["id"]

    resp = await _upload_chunk(full_client, headers_b, recording_id, 1)
    assert resp.status_code == 403


async def test_chunk_upload_rejected_when_recording_not_active(full_client, make_constable, auth_header):
    await make_constable(phone="r000000013")
    headers = await auth_header("r000000013", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r013")
    recording_id = (await _start_recording(full_client, headers, "phone-r013")).json()["id"]
    await full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)

    resp = await _upload_chunk(full_client, headers, recording_id, 1)
    assert resp.status_code == 409
    # The mobile app's ChunkUploader must be able to tell this apart from a
    # genuine "duplicate chunk, already accepted" 409 (see
    # test_duplicate_chunk_number_rejected below) -- conflating the two was
    # a real, physically-reproduced evidence-loss bug: a chunk rejected for
    # THIS reason was never accepted server-side and its local copy must
    # never be deleted, unlike a genuine duplicate.
    assert resp.headers["x-conflict-reason"] == "recording_not_active"


# ---------------------------------------------------------------------------
# 9: Duplicate chunk rejection (application-level fast path)
# ---------------------------------------------------------------------------
async def test_duplicate_chunk_number_rejected(full_client, make_constable, auth_header):
    await make_constable(phone="r000000014")
    headers = await auth_header("r000000014", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r014")
    recording_id = (await _start_recording(full_client, headers, "phone-r014")).json()["id"]

    first = await _upload_chunk(full_client, headers, recording_id, 1)
    assert first.status_code == 200
    second = await _upload_chunk(full_client, headers, recording_id, 1)
    assert second.status_code == 409
    # Distinct from the "recording not active" 409 above -- see that test's
    # comment. This one IS safe for the mobile client to treat as a
    # confirmed-success idempotent retry.
    assert second.headers["x-conflict-reason"] == "duplicate_chunk"

    session = await _get_recording_session(recording_id)
    assert len(session.chunks) == 1


# ---------------------------------------------------------------------------
# 10-11: Out-of-order chunks, manifest ordering
# ---------------------------------------------------------------------------
async def test_out_of_order_chunks_all_accepted(full_client, make_constable, auth_header):
    await make_constable(phone="r000000015")
    headers = await auth_header("r000000015", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r015")
    recording_id = (await _start_recording(full_client, headers, "phone-r015")).json()["id"]

    for n in (1, 3, 2, 5, 4):
        resp = await _upload_chunk(full_client, headers, recording_id, n)
        assert resp.status_code == 200, f"chunk {n} failed: {resp.text}"

    manifest = await full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    assert manifest.status_code == 200
    numbers = [c["chunk_number"] for c in manifest.json()["chunks"]]
    assert numbers == [1, 2, 3, 4, 5]  # numerically ordered regardless of upload order


async def test_manifest_never_exposes_storage_paths(full_client, make_constable, auth_header):
    await make_constable(phone="r000000016")
    headers = await auth_header("r000000016", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r016")
    recording_id = (await _start_recording(full_client, headers, "phone-r016")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1)

    manifest = await full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    body_text = json.dumps(manifest.json())
    assert "storage_key" not in body_text
    assert "/tmp/" not in body_text
    assert "recordings/" not in body_text  # storage_key prefix never leaked


# ---------------------------------------------------------------------------
# 12: Missing chunk detection
# ---------------------------------------------------------------------------
async def test_missing_chunk_detected_in_manifest(full_client, make_constable, auth_header):
    await make_constable(phone="r000000017")
    headers = await auth_header("r000000017", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r017")
    recording_id = (await _start_recording(full_client, headers, "phone-r017")).json()["id"]

    for n in (1, 2, 4, 5):  # chunk 3 deliberately never uploaded
        await _upload_chunk(full_client, headers, recording_id, n)

    manifest = await full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    assert manifest.status_code == 200
    body = manifest.json()
    assert body["missing_chunk_numbers"] == [3]
    assert body["highest_chunk_number"] == 5
    assert body["is_complete"] is False  # still 'recording' status, not completed


async def test_no_missing_chunks_reported_for_contiguous_sequence(full_client, make_constable, auth_header):
    await make_constable(phone="r000000018")
    headers = await auth_header("r000000018", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r018")
    recording_id = (await _start_recording(full_client, headers, "phone-r018")).json()["id"]

    for n in (1, 2, 3):
        await _upload_chunk(full_client, headers, recording_id, n)

    manifest = await full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    assert manifest.json()["missing_chunk_numbers"] == []


async def test_actively_recording_session_with_only_early_chunks_not_falsely_flagged_beyond_highest(full_client, make_constable, auth_header):
    """Chunk 4+ not yet uploaded is NOT reported as 'missing' -- only gaps WITHIN what's been received so far."""
    await make_constable(phone="r000000019")
    headers = await auth_header("r000000019", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r019")
    recording_id = (await _start_recording(full_client, headers, "phone-r019")).json()["id"]

    for n in (1, 2, 3):
        await _upload_chunk(full_client, headers, recording_id, n)

    manifest = await full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    assert manifest.json()["missing_chunk_numbers"] == []  # NOT [4, 5, 6, ...]


# ---------------------------------------------------------------------------
# 13-14: Recording completion, cancellation
# ---------------------------------------------------------------------------
async def test_recording_completion_success(full_client, make_constable, auth_header):
    await make_constable(phone="r000000020")
    headers = await auth_header("r000000020", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r020")
    recording_id = (await _start_recording(full_client, headers, "phone-r020")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, is_last_chunk=True)

    resp = await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["ended_at"] is not None
    assert body["missing_chunk_numbers"] == []


async def test_recording_completion_with_missing_chunks_still_succeeds_and_reports_gap(full_client, make_constable, auth_header):
    await make_constable(phone="r000000021")
    headers = await auth_header("r000000021", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r021")
    recording_id = (await _start_recording(full_client, headers, "phone-r021")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1)
    await _upload_chunk(full_client, headers, recording_id, 3)  # chunk 2 missing

    resp = await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 200  # completion is allowed even with a gap
    assert resp.json()["missing_chunk_numbers"] == [2]  # gap is never hidden


async def test_recording_cancellation_success(full_client, make_constable, auth_header):
    await make_constable(phone="r000000022")
    headers = await auth_header("r000000022", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r022")
    recording_id = (await _start_recording(full_client, headers, "phone-r022")).json()["id"]

    resp = await full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"


# ---------------------------------------------------------------------------
# 15: Invalid lifecycle transitions
# ---------------------------------------------------------------------------
async def test_cannot_complete_already_completed_recording(full_client, make_constable, auth_header):
    await make_constable(phone="r000000023")
    headers = await auth_header("r000000023", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r023")
    recording_id = (await _start_recording(full_client, headers, "phone-r023")).json()["id"]
    await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)

    resp = await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 409


async def test_cannot_cancel_already_cancelled_recording(full_client, make_constable, auth_header):
    await make_constable(phone="r000000024")
    headers = await auth_header("r000000024", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r024")
    recording_id = (await _start_recording(full_client, headers, "phone-r024")).json()["id"]
    await full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)

    resp = await full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)
    assert resp.status_code == 409


async def test_cannot_complete_a_cancelled_recording(full_client, make_constable, auth_header):
    await make_constable(phone="r000000025")
    headers = await auth_header("r000000025", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r025")
    recording_id = (await _start_recording(full_client, headers, "phone-r025")).json()["id"]
    await full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)

    resp = await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# 16: Audit
# ---------------------------------------------------------------------------
async def test_recording_lifecycle_is_audited(full_client, make_constable, auth_header):
    await make_constable(phone="r000000026")
    headers = await auth_header("r000000026", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r026")
    recording_id = (await _start_recording(full_client, headers, "phone-r026")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1)
    await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)

    assert len(await _get_logs("recording.started")) == 1
    assert len(await _get_logs("recording.chunk_uploaded")) == 1
    assert len(await _get_logs("recording.completed")) == 1


# ---------------------------------------------------------------------------
# 17: WebSocket event ordering / routing
# ---------------------------------------------------------------------------
from httpx_ws import aconnect_ws


async def _login(full_client, phone, pw):
    r = await full_client.post("/auth/login", json={"username": phone, "password": pw})
    assert r.status_code == 200
    return r.json()["access_token"]


async def test_recording_started_event_reaches_control_room(full_client, make_user, make_constable):
    await make_user(phone="r000000027cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="r000000027c")

    token_cr = await _login(full_client, "r000000027cr", "pw")
    token_c = await _login(full_client, "r000000027c", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_cr}", full_client) as ws_cr:
        headers = {"Authorization": f"Bearer {token_c}"}
        await _register_device(full_client, headers, "phone-r027")
        await ws_cr.receive_json()  # device.registered

        resp = await _start_recording(full_client, headers, "phone-r027")
        assert resp.status_code == 200

        msg = await ws_cr.receive_json()
        assert msg["event"] == "recording.started"


async def test_recording_events_reach_only_owning_constable(full_client, make_user, make_constable):
    await make_user(phone="r000000028cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="r000000028a")
    await make_constable(phone="r000000028b")

    token_a = await _login(full_client, "r000000028a", "correct-horse-battery")
    token_b = await _login(full_client, "r000000028b", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_a}", full_client) as ws_a:
        async with aconnect_ws(f"/ws/control_room?token={token_b}", full_client) as ws_b:
            headers_a = {"Authorization": f"Bearer {token_a}"}
            await _register_device(full_client, headers_a, "phone-r028")
            resp = await _start_recording(full_client, headers_a, "phone-r028")
            assert resp.status_code == 200

            msg_a = await ws_a.receive_json()
            assert msg_a["event"] == "recording.started"

            await ws_b.send_text("ping")
            msg_b = await ws_b.receive_json()
            assert msg_b["event"] == "ack"  # constable B never receives constable A's recording event


async def test_chunk_uploaded_and_completed_events_publish_in_order(full_client, make_user, make_constable):
    await make_user(phone="r000000029cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="r000000029c")

    token_cr = await _login(full_client, "r000000029cr", "pw")
    token_c = await _login(full_client, "r000000029c", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={token_cr}", full_client) as ws_cr:
        headers = {"Authorization": f"Bearer {token_c}"}
        await _register_device(full_client, headers, "phone-r029")
        await ws_cr.receive_json()  # device.registered

        recording_id = (await _start_recording(full_client, headers, "phone-r029")).json()["id"]
        await ws_cr.receive_json()  # recording.started

        await _upload_chunk(full_client, headers, recording_id, 1)
        msg = await ws_cr.receive_json()
        assert msg["event"] == "recording.chunk_uploaded"
        assert msg["data"]["chunk_number"] == 1

        await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
        msg = await ws_cr.receive_json()
        assert msg["event"] == "recording.completed"


# ---------------------------------------------------------------------------
# 18: Unauthorized recording access
# ---------------------------------------------------------------------------
async def test_unrelated_constable_cannot_view_another_constables_recording(full_client, make_constable, auth_header):
    await make_constable(phone="r000000030a")
    await make_constable(phone="r000000030b")
    headers_a = await auth_header("r000000030a", "correct-horse-battery")
    headers_b = await auth_header("r000000030b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-r030")
    recording_id = (await _start_recording(full_client, headers_a, "phone-r030")).json()["id"]

    resp = await full_client.get(f"/recordings/{recording_id}", headers=headers_b)
    assert resp.status_code == 403


async def test_citizen_cannot_access_recordings(full_client, make_user, make_constable, auth_header):
    await make_constable(phone="r000000031c")
    await make_user(phone="r000000031cit", password="pw", role=UserRole.citizen)
    headers_c = await auth_header("r000000031c", "correct-horse-battery")
    await _register_device(full_client, headers_c, "phone-r031")
    recording_id = (await _start_recording(full_client, headers_c, "phone-r031")).json()["id"]

    citizen_headers = await auth_header("r000000031cit", "pw")
    resp = await full_client.get(f"/recordings/{recording_id}", headers=citizen_headers)
    assert resp.status_code == 403


async def test_station_sees_only_own_stations_recordings(full_client, make_user, make_station, make_constable, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="r000000032s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = await make_constable(phone="r000000032a", station_id=station_a.id)
    _, constable_b = await make_constable(phone="r000000032b", station_id=station_b.id)
    headers_a = await auth_header("r000000032a", "correct-horse-battery")
    headers_b = await auth_header("r000000032b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-r032a")
    await _register_device(full_client, headers_b, "phone-r032b")
    recording_a = (await _start_recording(full_client, headers_a, "phone-r032a")).json()["id"]
    recording_b = (await _start_recording(full_client, headers_b, "phone-r032b")).json()["id"]

    station_headers = await auth_header("r000000032s", "pw")
    resp_a = await full_client.get(f"/recordings/{recording_a}", headers=station_headers)
    resp_b = await full_client.get(f"/recordings/{recording_b}", headers=station_headers)
    assert resp_a.status_code == 200
    assert resp_b.status_code == 403


async def test_admin_and_control_room_can_view_any_recording(full_client, make_user, make_constable, auth_header):
    await make_user(phone="r000000033admin", password="pw", role=UserRole.admin)
    await make_user(phone="r000000033cr", password="pw", role=UserRole.control_room)
    await make_constable(phone="r000000033c")
    headers_c = await auth_header("r000000033c", "correct-horse-battery")
    await _register_device(full_client, headers_c, "phone-r033")
    recording_id = (await _start_recording(full_client, headers_c, "phone-r033")).json()["id"]

    for phone in ("r000000033admin", "r000000033cr"):
        headers = await auth_header(phone, "pw")
        resp = await full_client.get(f"/recordings/{recording_id}", headers=headers)
        assert resp.status_code == 200


async def test_unauthenticated_recording_access_returns_401(full_client, make_constable, auth_header):
    await make_constable(phone="r000000034")
    headers = await auth_header("r000000034", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r034")
    recording_id = (await _start_recording(full_client, headers, "phone-r034")).json()["id"]

    resp = await full_client.get(f"/recordings/{recording_id}")
    assert resp.status_code == 401


async def test_get_recording_404_for_unknown_id(full_client, make_user, auth_header):
    import uuid
    await make_user(phone="r000000035", password="pw", role=UserRole.admin)
    headers = await auth_header("r000000035", "pw")
    resp = await full_client.get(f"/recordings/{uuid.uuid4()}", headers=headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Extra: device status integration (recording state surfaced, restored on completion)
# ---------------------------------------------------------------------------
async def test_device_status_shows_recording_while_active_and_reverts_on_completion(full_client, make_constable, auth_header):
    await make_constable(phone="r000000036")
    headers = await auth_header("r000000036", "correct-horse-battery")
    device_id = await _register_device(full_client, headers, "phone-r036")
    recording_id = (await _start_recording(full_client, headers, "phone-r036")).json()["id"]

    device_resp = await full_client.get(f"/devices/{device_id}", headers=headers)
    assert device_resp.json()["status"] == "recording"

    await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    device_resp = await full_client.get(f"/devices/{device_id}", headers=headers)
    assert device_resp.json()["status"] == "online"


async def test_heartbeat_during_recording_does_not_clear_recording_status(full_client, make_constable, auth_header):
    """Regression test for a real integration bug found and fixed in an earlier phase."""
    await make_constable(phone="r000000037")
    headers = await auth_header("r000000037", "correct-horse-battery")
    device_id = await _register_device(full_client, headers, "phone-r037")
    await _start_recording(full_client, headers, "phone-r037")

    await full_client.post("/devices/heartbeat", json={"device_identifier": "phone-r037", "battery_percent": 80}, headers=headers)

    device_resp = await full_client.get(f"/devices/{device_id}", headers=headers)
    assert device_resp.json()["status"] == "recording"


# ---------------------------------------------------------------------------
# Chunk playback (/{recording_id}/chunks/{chunk_number}/stream) -- lets the
# dashboard actually play back a recording instead of only listing chunk
# metadata. Mirrors test_media_streaming.py's coverage of the analogous
# evidence /stream endpoint (Range support, auth, audit).
# ---------------------------------------------------------------------------
async def test_stream_chunk_success_via_bearer_header(full_client, make_constable, auth_header):
    await make_constable(phone="r000000038")
    headers = await auth_header("r000000038", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r038")
    recording_id = (await _start_recording(full_client, headers, "phone-r038")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=MP4_BYTES)

    resp = await full_client.get(f"/recordings/{recording_id}/chunks/1/stream", headers=headers)
    assert resp.status_code == 200
    assert resp.content == MP4_BYTES
    assert resp.headers["content-type"] == "video/mp4"
    assert resp.headers["accept-ranges"] == "bytes"
    assert resp.headers["content-length"] == str(len(MP4_BYTES))


async def test_stream_chunk_success_via_query_token(full_client, make_constable, auth_header):
    """A <video> element can't set a custom Authorization header, so the
    token must also work as a query parameter (see recordings.py's
    _authenticate_stream_request)."""
    await make_constable(phone="r000000039")
    headers = await auth_header("r000000039", "correct-horse-battery")
    token = headers["Authorization"].split(" ")[1]
    await _register_device(full_client, headers, "phone-r039")
    recording_id = (await _start_recording(full_client, headers, "phone-r039")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=MP4_BYTES)

    resp = await full_client.get(f"/recordings/{recording_id}/chunks/1/stream?token={token}")
    assert resp.status_code == 200
    assert resp.content == MP4_BYTES


async def test_stream_chunk_range_request(full_client, make_constable, auth_header):
    await make_constable(phone="r000000040")
    headers = await auth_header("r000000040", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r040")
    recording_id = (await _start_recording(full_client, headers, "phone-r040")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=MP4_BYTES)

    resp = await full_client.get(
        f"/recordings/{recording_id}/chunks/1/stream",
        headers={**headers, "Range": "bytes=0-9"},
    )
    assert resp.status_code == 206
    assert resp.content == MP4_BYTES[0:10]
    assert resp.headers["content-range"] == f"bytes 0-9/{len(MP4_BYTES)}"


async def test_stream_chunk_no_token_returns_401(full_client, make_constable, auth_header):
    await make_constable(phone="r000000041")
    headers = await auth_header("r000000041", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r041")
    recording_id = (await _start_recording(full_client, headers, "phone-r041")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1)

    resp = await full_client.get(f"/recordings/{recording_id}/chunks/1/stream")
    assert resp.status_code == 401


async def test_stream_chunk_unauthorized_constable_gets_403(full_client, make_constable, auth_header):
    await make_constable(phone="r000000042a")
    headers_a = await auth_header("r000000042a", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-r042")
    recording_id = (await _start_recording(full_client, headers_a, "phone-r042")).json()["id"]
    await _upload_chunk(full_client, headers_a, recording_id, 1)

    await make_constable(phone="r000000042b")
    headers_b = await auth_header("r000000042b", "correct-horse-battery")
    resp = await full_client.get(f"/recordings/{recording_id}/chunks/1/stream", headers=headers_b)
    assert resp.status_code == 403


async def test_stream_chunk_admin_can_view_any_recording(full_client, make_user, make_constable, auth_header):
    await make_constable(phone="r000000043")
    headers = await auth_header("r000000043", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r043")
    recording_id = (await _start_recording(full_client, headers, "phone-r043")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=MP4_BYTES)

    await make_user(phone="r000000043admin", password="pw", role=UserRole.admin)
    admin_headers = await auth_header("r000000043admin", "pw")
    resp = await full_client.get(f"/recordings/{recording_id}/chunks/1/stream", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.content == MP4_BYTES


async def test_stream_nonexistent_chunk_returns_404(full_client, make_constable, auth_header):
    await make_constable(phone="r000000044")
    headers = await auth_header("r000000044", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r044")
    recording_id = (await _start_recording(full_client, headers, "phone-r044")).json()["id"]

    resp = await full_client.get(f"/recordings/{recording_id}/chunks/1/stream", headers=headers)
    assert resp.status_code == 404


async def test_stream_chunk_creates_audit_entry(full_client, make_constable, auth_header):
    await make_constable(phone="r000000045")
    headers = await auth_header("r000000045", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r045")
    recording_id = (await _start_recording(full_client, headers, "phone-r045")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1)

    await full_client.get(f"/recordings/{recording_id}/chunks/1/stream", headers=headers)

    logs = await _get_logs(action="recording.chunk_streamed")
    assert len(logs) == 1
    details = logs[0].details
    assert details["recording_id"] == recording_id
    assert details["chunk_number"] == 1


# ---------------------------------------------------------------------------
# Playable (server-side concatenated) recording -- /{id}/play.
# See app/routers/recordings.py::_try_build_playable_recording. Uses real,
# ffmpeg-decodable MP4 segments (not the fake MP4_BYTES blob used above,
# which has no valid container structure past the ftyp box) since the
# concat step genuinely shells out to ffmpeg.
# ---------------------------------------------------------------------------
async def test_playable_recording_becomes_ready_on_contiguous_completion(full_client, make_constable, auth_header):
    await make_constable(phone="r000000046")
    headers = await auth_header("r000000046", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r046")
    recording_id = (await _start_recording(full_client, headers, "phone-r046")).json()["id"]

    await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1))
    await _upload_chunk(full_client, headers, recording_id, 2, content=_real_mp4_segment_bytes(2), is_last_chunk=True)

    resp = await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["playable_status"] == "ready"

    session = await _get_recording_session(recording_id)
    assert session.playable_storage_key == f"recordings/{recording_id}/playable.mp4"


async def test_playable_recording_not_attempted_when_chunks_missing(full_client, make_constable, auth_header):
    await make_constable(phone="r000000047")
    headers = await auth_header("r000000047", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r047")
    recording_id = (await _start_recording(full_client, headers, "phone-r047")).json()["id"]

    await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1))
    await _upload_chunk(full_client, headers, recording_id, 3, content=_real_mp4_segment_bytes(3), is_last_chunk=True)  # chunk 2 missing

    resp = await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["missing_chunk_numbers"] == [2]
    assert resp.json()["playable_status"] == "not_ready"  # concat skipped -- gap would corrupt/fail it


async def test_play_endpoint_returns_video_after_ready(full_client, make_constable, auth_header):
    await make_constable(phone="r000000048")
    headers = await auth_header("r000000048", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r048")
    recording_id = (await _start_recording(full_client, headers, "phone-r048")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1), is_last_chunk=True)
    complete_resp = await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert complete_resp.json()["playable_status"] == "ready"

    resp = await full_client.get(f"/recordings/{recording_id}/play", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "video/mp4"
    assert resp.headers["accept-ranges"] == "bytes"
    assert len(resp.content) > 0


async def test_play_endpoint_supports_range_requests(full_client, make_constable, auth_header):
    await make_constable(phone="r000000049")
    headers = await auth_header("r000000049", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r049")
    recording_id = (await _start_recording(full_client, headers, "phone-r049")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1), is_last_chunk=True)
    await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)

    resp = await full_client.get(f"/recordings/{recording_id}/play", headers={**headers, "Range": "bytes=0-9"})
    assert resp.status_code == 206
    assert len(resp.content) == 10
    assert resp.headers["content-range"].startswith("bytes 0-9/")


async def test_play_endpoint_works_via_query_token(full_client, make_constable, auth_header):
    await make_constable(phone="r000000050")
    headers = await auth_header("r000000050", "correct-horse-battery")
    token = headers["Authorization"].split(" ")[1]
    await _register_device(full_client, headers, "phone-r050")
    recording_id = (await _start_recording(full_client, headers, "phone-r050")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1), is_last_chunk=True)
    await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)

    resp = await full_client.get(f"/recordings/{recording_id}/play?token={token}")
    assert resp.status_code == 200
    assert len(resp.content) > 0


async def test_play_endpoint_404_when_not_ready_yet(full_client, make_constable, auth_header):
    await make_constable(phone="r000000051")
    headers = await auth_header("r000000051", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r051")
    recording_id = (await _start_recording(full_client, headers, "phone-r051")).json()["id"]  # still recording, never completed

    resp = await full_client.get(f"/recordings/{recording_id}/play", headers=headers)
    assert resp.status_code == 404


async def test_play_endpoint_unrelated_constable_gets_403(full_client, make_constable, auth_header):
    """The core authorization requirement: a constable must never reach
    another constable's playable recording by editing the ID -- same
    _authorize_recording_access matrix as every other recording read."""
    await make_constable(phone="r000000052a")
    await make_constable(phone="r000000052b")
    headers_a = await auth_header("r000000052a", "correct-horse-battery")
    headers_b = await auth_header("r000000052b", "correct-horse-battery")
    await _register_device(full_client, headers_a, "phone-r052")
    recording_id = (await _start_recording(full_client, headers_a, "phone-r052")).json()["id"]
    await _upload_chunk(full_client, headers_a, recording_id, 1, content=_real_mp4_segment_bytes(1), is_last_chunk=True)
    await full_client.post(f"/recordings/{recording_id}/complete", headers=headers_a)

    resp = await full_client.get(f"/recordings/{recording_id}/play", headers=headers_b)
    assert resp.status_code == 403


async def test_play_endpoint_no_token_returns_401(full_client, make_constable, auth_header):
    await make_constable(phone="r000000053")
    headers = await auth_header("r000000053", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r053")
    recording_id = (await _start_recording(full_client, headers, "phone-r053")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1), is_last_chunk=True)
    await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)

    resp = await full_client.get(f"/recordings/{recording_id}/play")
    assert resp.status_code == 401


async def test_play_endpoint_creates_audit_entry(full_client, make_constable, auth_header):
    await make_constable(phone="r000000054")
    headers = await auth_header("r000000054", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-r054")
    recording_id = (await _start_recording(full_client, headers, "phone-r054")).json()["id"]
    await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1), is_last_chunk=True)
    await full_client.post(f"/recordings/{recording_id}/complete", headers=headers)

    await full_client.get(f"/recordings/{recording_id}/play", headers=headers)

    logs = await _get_logs(action="recording.played")
    assert len(logs) == 1
    details = logs[0].details
    assert details["recording_id"] == recording_id
