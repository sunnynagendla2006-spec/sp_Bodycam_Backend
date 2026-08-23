"""
Phase 5: End-to-end simulation of the future mobile (Android) client,
using ONLY real HTTP API calls through the FastAPI TestClient -- never
fabricating database rows directly. This proves the complete chain:

  authenticate -> register device -> heartbeat -> battery -> location
  -> start recording -> upload chunks (out of order) -> manifest
  -> missing-chunk detection -> duplicate rejection -> completion
  -> control-room visibility -> cross-role/cross-station denial

works as one real system, not as isolated unit tests.
"""
import hashlib

from app.models import UserRole

MP4_BYTES = b"\x00\x00\x00\x18ftypmp42" + (b"simulated-video-audio-chunk-bytes" * 30)


def _login(full_client, phone, pw):
    resp = full_client.post("/auth/login", json={"username": phone, "password": pw})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_full_mobile_device_lifecycle_end_to_end(full_client, make_constable, make_user, make_station, auth_header, db_session):
    """
    The complete simulated body-camera flow, step by step, using real API
    calls exactly as a future Android app would.
    """
    # --- Setup: a real station, a real constable, a real control-room observer ---
    station = make_station(name="Central")
    make_user(phone="sim000001cr", password="pw", role=UserRole.control_room)
    _, constable = make_constable(phone="sim000001c", station_id=station.id)

    # --- Step 1: authenticate (as the mobile app would on launch) ---
    device_token = _login(full_client, "sim000001c", "correct-horse-battery")
    device_headers = _auth(device_token)

    # --- Step 2: register device ---
    reg_resp = full_client.post(
        "/devices/register",
        json={"device_identifier": "sim-pixel-7", "platform": "android", "app_version": "1.0.0", "device_model": "Pixel 7"},
        headers=device_headers,
    )
    assert reg_resp.status_code == 200
    device_id = reg_resp.json()["id"]
    assert reg_resp.json()["status"] == "online"

    # --- Step 3: heartbeat ---
    hb_resp = full_client.post("/devices/heartbeat", json={"device_identifier": "sim-pixel-7", "battery_percent": 85}, headers=device_headers)
    assert hb_resp.status_code == 200
    assert hb_resp.json()["status"] == "online"

    # --- Step 4: battery report (standalone) ---
    batt_resp = full_client.post("/devices/battery", json={"device_identifier": "sim-pixel-7", "battery_percent": 82, "is_charging": False}, headers=device_headers)
    assert batt_resp.status_code == 200

    # --- Step 5: location report (reuses the existing constable-location endpoint) ---
    loc_resp = full_client.post("/constables/me/location", json={"latitude": 17.385, "longitude": 78.4867, "accuracy": 12.5}, headers=device_headers)
    assert loc_resp.status_code == 200

    # --- Step 6: start emergency recording (volume-button-triggered, per the real project) ---
    start_resp = full_client.post(
        "/recordings/start",
        json={"device_identifier": "sim-pixel-7", "trigger_type": "emergency_button"},
        headers=device_headers,
    )
    assert start_resp.status_code == 200
    recording = start_resp.json()
    recording_id = recording["id"]
    assert recording["status"] == "recording"
    assert recording["incident_id"] is None  # never required to exist

    # Device status must now reflect "recording" (Phase 2/3 integration point)
    device_after_start = full_client.get(f"/devices/{device_id}", headers=device_headers)
    assert device_after_start.json()["status"] == "recording"

    # --- Step 7/8: upload 5 chunks, deliberately OUT OF ORDER ---
    upload_order = [3, 1, 5, 2, 4]
    chunk_hashes = {}
    for n in upload_order:
        content = MP4_BYTES + str(n).encode()
        chunk_hashes[n] = hashlib.sha256(content).hexdigest()
        resp = full_client.post(
            f"/recordings/{recording_id}/chunks",
            data={"chunk_number": str(n), "duration_seconds": "2.0", "is_last_chunk": str(n == 5).lower()},
            files={"file": (f"chunk{n}.mp4", content, "video/mp4")},
            headers=device_headers,
        )
        assert resp.status_code == 200, f"chunk {n} failed: {resp.text}"
        assert resp.json()["chunk_number"] == n
        assert resp.json()["file_hash"] == chunk_hashes[n]
        assert "storage_key" not in resp.json()  # never exposed

    # --- Step 9: manifest must be numerically ordered regardless of upload order ---
    manifest_resp = full_client.get(f"/recordings/{recording_id}/chunks", headers=device_headers)
    assert manifest_resp.status_code == 200
    manifest = manifest_resp.json()
    assert [c["chunk_number"] for c in manifest["chunks"]] == [1, 2, 3, 4, 5]
    assert manifest["missing_chunk_numbers"] == []
    assert manifest["highest_chunk_number"] == 5

    # --- Step 10: duplicate chunk_number is rejected ---
    dup_resp = full_client.post(
        f"/recordings/{recording_id}/chunks",
        data={"chunk_number": "3", "is_last_chunk": "false"},
        files={"file": ("chunk3-dup.mp4", MP4_BYTES, "video/mp4")},
        headers=device_headers,
    )
    assert dup_resp.status_code == 409

    # --- Step 11: complete the recording ---
    complete_resp = full_client.post(f"/recordings/{recording_id}/complete", headers=device_headers)
    assert complete_resp.status_code == 200
    assert complete_resp.json()["status"] == "completed"
    assert complete_resp.json()["missing_chunk_numbers"] == []

    # Device must return to a non-recording state after completion
    device_after_complete = full_client.get(f"/devices/{device_id}", headers=device_headers)
    assert device_after_complete.json()["status"] == "online"

    # --- Step 12: control room can see the recording via the real listing endpoint ---
    cr_token = _login(full_client, "sim000001cr", "pw")
    cr_resp = full_client.get("/recordings/", headers=_auth(cr_token))
    assert cr_resp.status_code == 200
    assert any(r["id"] == recording_id for r in cr_resp.json())

    # Control room can also fetch the full manifest
    cr_manifest = full_client.get(f"/recordings/{recording_id}/chunks", headers=_auth(cr_token))
    assert cr_manifest.status_code == 200
    assert cr_manifest.json()["is_complete"] is True


def test_missing_chunk_detected_mid_recording(full_client, make_constable, auth_header):
    """1 -> 2 -> 4 -> complete: chunk 3 must be reported missing, completion must not hide the gap."""
    make_constable(phone="sim000002c")
    headers = auth_header("sim000002c", "correct-horse-battery")
    full_client.post("/devices/register", json={"device_identifier": "sim-device-002"}, headers=headers)
    recording_id = full_client.post(
        "/recordings/start", json={"device_identifier": "sim-device-002", "trigger_type": "manual"}, headers=headers
    ).json()["id"]

    for n in (1, 2, 4):
        full_client.post(
            f"/recordings/{recording_id}/chunks",
            data={"chunk_number": str(n), "is_last_chunk": "false"},
            files={"file": (f"chunk{n}.mp4", MP4_BYTES, "video/mp4")},
            headers=headers,
        )

    manifest = full_client.get(f"/recordings/{recording_id}/chunks", headers=headers).json()
    assert manifest["missing_chunk_numbers"] == [3]

    complete_resp = full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert complete_resp.status_code == 200  # completion allowed with a gap
    assert complete_resp.json()["missing_chunk_numbers"] == [3]  # gap never hidden


def test_cross_constable_cannot_access_anothers_recording(full_client, make_constable, auth_header):
    make_constable(phone="sim000003a")
    make_constable(phone="sim000003b")
    headers_a = auth_header("sim000003a", "correct-horse-battery")
    headers_b = auth_header("sim000003b", "correct-horse-battery")
    full_client.post("/devices/register", json={"device_identifier": "sim-device-003a"}, headers=headers_a)
    recording_id = full_client.post(
        "/recordings/start", json={"device_identifier": "sim-device-003a", "trigger_type": "manual"}, headers=headers_a
    ).json()["id"]

    resp = full_client.get(f"/recordings/{recording_id}", headers=headers_b)
    assert resp.status_code == 403

    upload_resp = full_client.post(
        f"/recordings/{recording_id}/chunks",
        data={"chunk_number": "1", "is_last_chunk": "false"},
        files={"file": ("chunk1.mp4", MP4_BYTES, "video/mp4")},
        headers=headers_b,
    )
    assert upload_resp.status_code == 403


def test_station_isolation_for_simulated_recording(full_client, make_user, make_station, make_constable, auth_header):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="sim000004s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = make_constable(phone="sim000004a", station_id=station_a.id)
    _, constable_b = make_constable(phone="sim000004b", station_id=station_b.id)
    headers_a = auth_header("sim000004a", "correct-horse-battery")
    headers_b = auth_header("sim000004b", "correct-horse-battery")
    full_client.post("/devices/register", json={"device_identifier": "sim-device-004a"}, headers=headers_a)
    full_client.post("/devices/register", json={"device_identifier": "sim-device-004b"}, headers=headers_b)
    rec_a = full_client.post("/recordings/start", json={"device_identifier": "sim-device-004a", "trigger_type": "manual"}, headers=headers_a).json()["id"]
    rec_b = full_client.post("/recordings/start", json={"device_identifier": "sim-device-004b", "trigger_type": "manual"}, headers=headers_b).json()["id"]

    station_headers = auth_header("sim000004s", "pw")
    resp_a = full_client.get(f"/recordings/{rec_a}", headers=station_headers)
    resp_b = full_client.get(f"/recordings/{rec_b}", headers=station_headers)
    assert resp_a.status_code == 200
    assert resp_b.status_code == 403


# ---------------------------------------------------------------------------
# Step 6: WebSocket validation -- real 4-connection isolation test covering
# the FULL recording event chain in one integrated scenario (existing
# tests in test_devices.py/test_commands.py already cover individual event
# types in isolation; this proves the whole chain together).
# ---------------------------------------------------------------------------
def test_full_recording_event_chain_with_real_websocket_isolation(full_client, make_user, make_station, make_constable):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="sim000005cr", password="pw", role=UserRole.control_room)
    make_user(phone="sim000005sa", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = make_constable(phone="sim000005a", station_id=station_a.id)
    _, constable_b = make_constable(phone="sim000005b", station_id=station_b.id)

    cr_token = _login(full_client, "sim000005cr", "pw")
    sa_token = _login(full_client, "sim000005sa", "pw")
    token_a = _login(full_client, "sim000005a", "correct-horse-battery")
    token_b = _login(full_client, "sim000005b", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={cr_token}") as ws_cr:
        with full_client.websocket_connect(f"/ws/control_room?token={sa_token}") as ws_station_a:
            with full_client.websocket_connect(f"/ws/control_room?token={token_a}") as ws_constable_a:
                with full_client.websocket_connect(f"/ws/control_room?token={token_b}") as ws_constable_b:
                    headers_a = _auth(token_a)
                    full_client.post("/devices/register", json={"device_identifier": "sim-device-005a"}, headers=headers_a)
                    ws_cr.receive_json()  # device.registered
                    ws_station_a.receive_json()  # device.registered (station A owns constable A)

                    recording_id = full_client.post(
                        "/recordings/start", json={"device_identifier": "sim-device-005a", "trigger_type": "emergency_button"}, headers=headers_a
                    ).json()["id"]

                    # recording.started: control_room + station A + constable A's own room
                    assert ws_cr.receive_json()["event"] == "recording.started"
                    assert ws_station_a.receive_json()["event"] == "recording.started"
                    assert ws_constable_a.receive_json()["event"] == "recording.started"

                    full_client.post(
                        f"/recordings/{recording_id}/chunks",
                        data={"chunk_number": "1", "is_last_chunk": "true"},
                        files={"file": ("chunk1.mp4", MP4_BYTES, "video/mp4")},
                        headers=headers_a,
                    )
                    assert ws_cr.receive_json()["event"] == "recording.chunk_uploaded"
                    assert ws_station_a.receive_json()["event"] == "recording.chunk_uploaded"
                    assert ws_constable_a.receive_json()["event"] == "recording.chunk_uploaded"

                    full_client.post(f"/recordings/{recording_id}/complete", headers=headers_a)
                    assert ws_cr.receive_json()["event"] == "recording.completed"
                    assert ws_station_a.receive_json()["event"] == "recording.completed"
                    assert ws_constable_a.receive_json()["event"] == "recording.completed"

                    # Constable B (different station, unrelated) must NEVER have received any of this.
                    ws_constable_b.send_text("ping")
                    msg_b = ws_constable_b.receive_json()
                    assert msg_b["event"] == "ack"
