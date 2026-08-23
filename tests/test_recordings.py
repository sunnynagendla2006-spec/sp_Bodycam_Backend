"""
Phase 2 (body-camera system) tests: RecordingSession + VideoChunk.
"""
import io
import json

from app.models import UserRole, RecordingStatus, RecordingTriggerType

JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + (b"0123456789" * 10)
MP4_BYTES = b"\x00\x00\x00\x18ftypmp42" + (b"0123456789" * 20)  # minimal valid "ftyp box" prefix recognized by _sniff_mime_type


def _get_logs(db_session, action=None):
    from app import models
    q = db_session.query(models.AuditLog)
    if action:
        q = q.filter(models.AuditLog.action == action)
    return q.all()


def _register_device(full_client, headers, device_identifier="phone-r001"):
    resp = full_client.post("/devices/register", json={"device_identifier": device_identifier, "platform": "android"}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _start_recording(full_client, headers, device_identifier="phone-r001", trigger_type="manual", incident_id=None):
    payload = {"device_identifier": device_identifier, "trigger_type": trigger_type}
    if incident_id:
        payload["incident_id"] = incident_id
    resp = full_client.post("/recordings/start", json=payload, headers=headers)
    return resp


def _upload_chunk(full_client, headers, recording_id, chunk_number, content=MP4_BYTES, is_last_chunk=False, duration=2.5):
    return full_client.post(
        f"/recordings/{recording_id}/chunks",
        data={"chunk_number": str(chunk_number), "duration_seconds": str(duration), "is_last_chunk": str(is_last_chunk)},
        files={"file": (f"chunk{chunk_number}.mp4", content, "video/mp4")},
        headers=headers,
    )


# ---------------------------------------------------------------------------
# 1-3: Recording creation, trigger types, initial status
# ---------------------------------------------------------------------------
def test_recording_creation_with_default_trigger_type(full_client, make_constable, auth_header):
    make_constable(phone="r000000001")
    headers = auth_header("r000000001", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r001")

    resp = _start_recording(full_client, headers, "phone-r001")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "recording"
    assert body["trigger_type"] == "manual"
    assert body["incident_id"] is None
    assert body["chunk_count"] == 0


def test_recording_creation_with_emergency_button_trigger(full_client, make_constable, auth_header):
    make_constable(phone="r000000002")
    headers = auth_header("r000000002", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r002")

    resp = _start_recording(full_client, headers, "phone-r002", trigger_type="emergency_button")
    assert resp.status_code == 200
    assert resp.json()["trigger_type"] == "emergency_button"


def test_recording_does_not_require_incident(full_client, make_constable, auth_header):
    """The core Phase 2 requirement: RecordingSession must exist without any Incident."""
    make_constable(phone="r000000003")
    headers = auth_header("r000000003", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r003")

    resp = _start_recording(full_client, headers, "phone-r003")
    assert resp.status_code == 200
    assert resp.json()["incident_id"] is None


def test_recording_can_optionally_link_to_existing_incident(full_client, make_constable, make_incident, auth_header):
    make_constable(phone="r000000004")
    headers = auth_header("r000000004", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r004")
    incident = make_incident()

    resp = _start_recording(full_client, headers, "phone-r004", incident_id=str(incident.id))
    assert resp.status_code == 200
    assert resp.json()["incident_id"] == str(incident.id)


def test_recording_with_nonexistent_incident_id_rejected(full_client, make_constable, auth_header):
    import uuid
    make_constable(phone="r000000005")
    headers = auth_header("r000000005", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r005")

    resp = _start_recording(full_client, headers, "phone-r005", incident_id=str(uuid.uuid4()))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4: Ownership authorization for starting a recording
# ---------------------------------------------------------------------------
def test_cannot_start_recording_for_another_constables_device(full_client, make_constable, auth_header):
    make_constable(phone="r000000006a")
    make_constable(phone="r000000006b")
    headers_a = auth_header("r000000006a", "correct-horse-battery")
    headers_b = auth_header("r000000006b", "correct-horse-battery")
    _register_device(full_client, headers_a, "phone-r006")

    resp = _start_recording(full_client, headers_b, "phone-r006")
    assert resp.status_code == 403


def test_only_constable_role_can_start_recording(full_client, make_user, auth_header):
    make_user(phone="r000000007", password="pw", role=UserRole.admin)
    headers = auth_header("r000000007", "pw")
    resp = _start_recording(full_client, headers, "nonexistent-device")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 5-8: Chunk upload, hash, MIME, size validation
# ---------------------------------------------------------------------------
def test_chunk_upload_success(full_client, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_constable(phone="r000000008")
    headers = auth_header("r000000008", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r008")
    recording_id = _start_recording(full_client, headers, "phone-r008").json()["id"]

    resp = _upload_chunk(full_client, headers, recording_id, 1)
    assert resp.status_code == 200
    body = resp.json()
    assert body["chunk_number"] == 1
    assert body["mime_type"] == "video/mp4"
    assert "storage_key" not in body  # never exposed
    assert "file_path" not in body

    chunk = db_session.query(models.VideoChunk).filter(models.VideoChunk.recording_session_id == uuid_module.UUID(recording_id)).one()
    assert chunk.file_hash is not None
    assert len(chunk.file_hash) == 64  # sha256 hex digest length


def test_chunk_upload_computes_correct_sha256_hash(full_client, make_constable, auth_header):
    import hashlib
    make_constable(phone="r000000009")
    headers = auth_header("r000000009", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r009")
    recording_id = _start_recording(full_client, headers, "phone-r009").json()["id"]

    resp = _upload_chunk(full_client, headers, recording_id, 1, content=MP4_BYTES)
    assert resp.status_code == 200
    assert resp.json()["file_hash"] == hashlib.sha256(MP4_BYTES).hexdigest()


def test_chunk_upload_rejects_mismatched_mime(full_client, make_constable, auth_header):
    make_constable(phone="r000000010")
    headers = auth_header("r000000010", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r010")
    recording_id = _start_recording(full_client, headers, "phone-r010").json()["id"]

    resp = full_client.post(
        f"/recordings/{recording_id}/chunks",
        data={"chunk_number": "1", "is_last_chunk": "false"},
        files={"file": ("chunk1.mp4", JPEG_BYTES, "video/mp4")},  # declared mp4, actual jpeg bytes
        headers=headers,
    )
    assert resp.status_code == 400


def test_chunk_upload_size_limit_enforced(full_client, make_constable, auth_header, monkeypatch):
    from app.routers import recordings as recordings_module
    from app.routers import media as media_module
    make_constable(phone="r000000011")
    headers = auth_header("r000000011", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r011")
    recording_id = _start_recording(full_client, headers, "phone-r011").json()["id"]

    monkeypatch.setattr(media_module, "MAX_EVIDENCE_SIZE_BYTES", 10)
    resp = _upload_chunk(full_client, headers, recording_id, 1)
    assert resp.status_code == 413


def test_chunk_upload_only_allowed_by_own_constable(full_client, make_constable, auth_header):
    make_constable(phone="r000000012a")
    make_constable(phone="r000000012b")
    headers_a = auth_header("r000000012a", "correct-horse-battery")
    headers_b = auth_header("r000000012b", "correct-horse-battery")
    _register_device(full_client, headers_a, "phone-r012")
    recording_id = _start_recording(full_client, headers_a, "phone-r012").json()["id"]

    resp = _upload_chunk(full_client, headers_b, recording_id, 1)
    assert resp.status_code == 403


def test_chunk_upload_rejected_when_recording_not_active(full_client, make_constable, auth_header):
    make_constable(phone="r000000013")
    headers = auth_header("r000000013", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r013")
    recording_id = _start_recording(full_client, headers, "phone-r013").json()["id"]
    full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)

    resp = _upload_chunk(full_client, headers, recording_id, 1)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# 9: Duplicate chunk rejection (application-level fast path)
# ---------------------------------------------------------------------------
def test_duplicate_chunk_number_rejected(full_client, make_constable, auth_header, db_session):
    import uuid as uuid_module
    from app import models
    make_constable(phone="r000000014")
    headers = auth_header("r000000014", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r014")
    recording_id = _start_recording(full_client, headers, "phone-r014").json()["id"]

    first = _upload_chunk(full_client, headers, recording_id, 1)
    assert first.status_code == 200
    second = _upload_chunk(full_client, headers, recording_id, 1)
    assert second.status_code == 409

    chunks = db_session.query(models.VideoChunk).filter(models.VideoChunk.recording_session_id == uuid_module.UUID(recording_id)).all()
    assert len(chunks) == 1


# ---------------------------------------------------------------------------
# 10-11: Out-of-order chunks, manifest ordering
# ---------------------------------------------------------------------------
def test_out_of_order_chunks_all_accepted(full_client, make_constable, auth_header):
    make_constable(phone="r000000015")
    headers = auth_header("r000000015", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r015")
    recording_id = _start_recording(full_client, headers, "phone-r015").json()["id"]

    for n in (1, 3, 2, 5, 4):
        resp = _upload_chunk(full_client, headers, recording_id, n)
        assert resp.status_code == 200, f"chunk {n} failed: {resp.text}"

    manifest = full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    assert manifest.status_code == 200
    numbers = [c["chunk_number"] for c in manifest.json()["chunks"]]
    assert numbers == [1, 2, 3, 4, 5]  # numerically ordered regardless of upload order


def test_manifest_never_exposes_storage_paths(full_client, make_constable, auth_header):
    make_constable(phone="r000000016")
    headers = auth_header("r000000016", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r016")
    recording_id = _start_recording(full_client, headers, "phone-r016").json()["id"]
    _upload_chunk(full_client, headers, recording_id, 1)

    manifest = full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    body_text = json.dumps(manifest.json())
    assert "storage_key" not in body_text
    assert "/tmp/" not in body_text
    assert "recordings/" not in body_text  # storage_key prefix never leaked


# ---------------------------------------------------------------------------
# 12: Missing chunk detection
# ---------------------------------------------------------------------------
def test_missing_chunk_detected_in_manifest(full_client, make_constable, auth_header):
    make_constable(phone="r000000017")
    headers = auth_header("r000000017", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r017")
    recording_id = _start_recording(full_client, headers, "phone-r017").json()["id"]

    for n in (1, 2, 4, 5):  # chunk 3 deliberately never uploaded
        _upload_chunk(full_client, headers, recording_id, n)

    manifest = full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    assert manifest.status_code == 200
    body = manifest.json()
    assert body["missing_chunk_numbers"] == [3]
    assert body["highest_chunk_number"] == 5
    assert body["is_complete"] is False  # still 'recording' status, not completed


def test_no_missing_chunks_reported_for_contiguous_sequence(full_client, make_constable, auth_header):
    make_constable(phone="r000000018")
    headers = auth_header("r000000018", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r018")
    recording_id = _start_recording(full_client, headers, "phone-r018").json()["id"]

    for n in (1, 2, 3):
        _upload_chunk(full_client, headers, recording_id, n)

    manifest = full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    assert manifest.json()["missing_chunk_numbers"] == []


def test_actively_recording_session_with_only_early_chunks_not_falsely_flagged_beyond_highest(full_client, make_constable, auth_header):
    """Chunk 4+ not yet uploaded is NOT reported as 'missing' -- only gaps WITHIN what's been received so far."""
    make_constable(phone="r000000019")
    headers = auth_header("r000000019", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r019")
    recording_id = _start_recording(full_client, headers, "phone-r019").json()["id"]

    for n in (1, 2, 3):
        _upload_chunk(full_client, headers, recording_id, n)

    manifest = full_client.get(f"/recordings/{recording_id}/chunks", headers=headers)
    assert manifest.json()["missing_chunk_numbers"] == []  # NOT [4, 5, 6, ...]


# ---------------------------------------------------------------------------
# 13-14: Recording completion, cancellation
# ---------------------------------------------------------------------------
def test_recording_completion_success(full_client, make_constable, auth_header):
    make_constable(phone="r000000020")
    headers = auth_header("r000000020", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r020")
    recording_id = _start_recording(full_client, headers, "phone-r020").json()["id"]
    _upload_chunk(full_client, headers, recording_id, 1, is_last_chunk=True)

    resp = full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["ended_at"] is not None
    assert body["missing_chunk_numbers"] == []


def test_recording_completion_with_missing_chunks_still_succeeds_and_reports_gap(full_client, make_constable, auth_header):
    make_constable(phone="r000000021")
    headers = auth_header("r000000021", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r021")
    recording_id = _start_recording(full_client, headers, "phone-r021").json()["id"]
    _upload_chunk(full_client, headers, recording_id, 1)
    _upload_chunk(full_client, headers, recording_id, 3)  # chunk 2 missing

    resp = full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 200  # completion is allowed even with a gap
    assert resp.json()["missing_chunk_numbers"] == [2]  # gap is never hidden


def test_recording_cancellation_success(full_client, make_constable, auth_header):
    make_constable(phone="r000000022")
    headers = auth_header("r000000022", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r022")
    recording_id = _start_recording(full_client, headers, "phone-r022").json()["id"]

    resp = full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"


# ---------------------------------------------------------------------------
# 15: Invalid lifecycle transitions
# ---------------------------------------------------------------------------
def test_cannot_complete_already_completed_recording(full_client, make_constable, auth_header):
    make_constable(phone="r000000023")
    headers = auth_header("r000000023", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r023")
    recording_id = _start_recording(full_client, headers, "phone-r023").json()["id"]
    full_client.post(f"/recordings/{recording_id}/complete", headers=headers)

    resp = full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 409


def test_cannot_cancel_already_cancelled_recording(full_client, make_constable, auth_header):
    make_constable(phone="r000000024")
    headers = auth_header("r000000024", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r024")
    recording_id = _start_recording(full_client, headers, "phone-r024").json()["id"]
    full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)

    resp = full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)
    assert resp.status_code == 409


def test_cannot_complete_a_cancelled_recording(full_client, make_constable, auth_header):
    make_constable(phone="r000000025")
    headers = auth_header("r000000025", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r025")
    recording_id = _start_recording(full_client, headers, "phone-r025").json()["id"]
    full_client.post(f"/recordings/{recording_id}/cancel", headers=headers)

    resp = full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# 16: Audit
# ---------------------------------------------------------------------------
def test_recording_lifecycle_is_audited(full_client, make_constable, auth_header, db_session):
    make_constable(phone="r000000026")
    headers = auth_header("r000000026", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r026")
    recording_id = _start_recording(full_client, headers, "phone-r026").json()["id"]
    _upload_chunk(full_client, headers, recording_id, 1)
    full_client.post(f"/recordings/{recording_id}/complete", headers=headers)

    assert len(_get_logs(db_session, "recording.started")) == 1
    assert len(_get_logs(db_session, "recording.chunk_uploaded")) == 1
    assert len(_get_logs(db_session, "recording.completed")) == 1


# ---------------------------------------------------------------------------
# 17: WebSocket event ordering / routing
# ---------------------------------------------------------------------------
def _login(full_client, phone, pw):
    r = full_client.post("/auth/login", json={"username": phone, "password": pw})
    assert r.status_code == 200
    return r.json()["access_token"]


def test_recording_started_event_reaches_control_room(full_client, make_user, make_constable):
    make_user(phone="r000000027cr", password="pw", role=UserRole.control_room)
    make_constable(phone="r000000027c")

    token_cr = _login(full_client, "r000000027cr", "pw")
    token_c = _login(full_client, "r000000027c", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={token_cr}") as ws_cr:
        headers = {"Authorization": f"Bearer {token_c}"}
        _register_device(full_client, headers, "phone-r027")
        ws_cr.receive_json()  # device.registered

        resp = _start_recording(full_client, headers, "phone-r027")
        assert resp.status_code == 200

        msg = ws_cr.receive_json()
        assert msg["event"] == "recording.started"


def test_recording_events_reach_only_owning_constable(full_client, make_user, make_constable):
    make_user(phone="r000000028cr", password="pw", role=UserRole.control_room)
    make_constable(phone="r000000028a")
    make_constable(phone="r000000028b")

    token_a = _login(full_client, "r000000028a", "correct-horse-battery")
    token_b = _login(full_client, "r000000028b", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={token_a}") as ws_a:
        with full_client.websocket_connect(f"/ws/control_room?token={token_b}") as ws_b:
            headers_a = {"Authorization": f"Bearer {token_a}"}
            _register_device(full_client, headers_a, "phone-r028")
            resp = _start_recording(full_client, headers_a, "phone-r028")
            assert resp.status_code == 200

            msg_a = ws_a.receive_json()
            assert msg_a["event"] == "recording.started"

            ws_b.send_text("ping")
            msg_b = ws_b.receive_json()
            assert msg_b["event"] == "ack"  # constable B never receives constable A's recording event


def test_chunk_uploaded_and_completed_events_publish_in_order(full_client, make_user, make_constable):
    make_user(phone="r000000029cr", password="pw", role=UserRole.control_room)
    make_constable(phone="r000000029c")

    token_cr = _login(full_client, "r000000029cr", "pw")
    token_c = _login(full_client, "r000000029c", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={token_cr}") as ws_cr:
        headers = {"Authorization": f"Bearer {token_c}"}
        _register_device(full_client, headers, "phone-r029")
        ws_cr.receive_json()  # device.registered

        recording_id = _start_recording(full_client, headers, "phone-r029").json()["id"]
        ws_cr.receive_json()  # recording.started

        _upload_chunk(full_client, headers, recording_id, 1)
        msg = ws_cr.receive_json()
        assert msg["event"] == "recording.chunk_uploaded"
        assert msg["data"]["chunk_number"] == 1

        full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
        msg = ws_cr.receive_json()
        assert msg["event"] == "recording.completed"


# ---------------------------------------------------------------------------
# 18: Unauthorized recording access
# ---------------------------------------------------------------------------
def test_unrelated_constable_cannot_view_another_constables_recording(full_client, make_constable, auth_header):
    make_constable(phone="r000000030a")
    make_constable(phone="r000000030b")
    headers_a = auth_header("r000000030a", "correct-horse-battery")
    headers_b = auth_header("r000000030b", "correct-horse-battery")
    _register_device(full_client, headers_a, "phone-r030")
    recording_id = _start_recording(full_client, headers_a, "phone-r030").json()["id"]

    resp = full_client.get(f"/recordings/{recording_id}", headers=headers_b)
    assert resp.status_code == 403


def test_citizen_cannot_access_recordings(full_client, make_user, make_constable, auth_header):
    make_constable(phone="r000000031c")
    make_user(phone="r000000031cit", password="pw", role=UserRole.citizen)
    headers_c = auth_header("r000000031c", "correct-horse-battery")
    _register_device(full_client, headers_c, "phone-r031")
    recording_id = _start_recording(full_client, headers_c, "phone-r031").json()["id"]

    citizen_headers = auth_header("r000000031cit", "pw")
    resp = full_client.get(f"/recordings/{recording_id}", headers=citizen_headers)
    assert resp.status_code == 403


def test_station_sees_only_own_stations_recordings(full_client, make_user, make_station, make_constable, auth_header):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="r000000032s", password="pw", role=UserRole.station, station_id=station_a.id)
    _, constable_a = make_constable(phone="r000000032a", station_id=station_a.id)
    _, constable_b = make_constable(phone="r000000032b", station_id=station_b.id)
    headers_a = auth_header("r000000032a", "correct-horse-battery")
    headers_b = auth_header("r000000032b", "correct-horse-battery")
    _register_device(full_client, headers_a, "phone-r032a")
    _register_device(full_client, headers_b, "phone-r032b")
    recording_a = _start_recording(full_client, headers_a, "phone-r032a").json()["id"]
    recording_b = _start_recording(full_client, headers_b, "phone-r032b").json()["id"]

    station_headers = auth_header("r000000032s", "pw")
    resp_a = full_client.get(f"/recordings/{recording_a}", headers=station_headers)
    resp_b = full_client.get(f"/recordings/{recording_b}", headers=station_headers)
    assert resp_a.status_code == 200
    assert resp_b.status_code == 403


def test_admin_and_control_room_can_view_any_recording(full_client, make_user, make_constable, auth_header):
    make_user(phone="r000000033admin", password="pw", role=UserRole.admin)
    make_user(phone="r000000033cr", password="pw", role=UserRole.control_room)
    make_constable(phone="r000000033c")
    headers_c = auth_header("r000000033c", "correct-horse-battery")
    _register_device(full_client, headers_c, "phone-r033")
    recording_id = _start_recording(full_client, headers_c, "phone-r033").json()["id"]

    for phone in ("r000000033admin", "r000000033cr"):
        headers = auth_header(phone, "pw")
        resp = full_client.get(f"/recordings/{recording_id}", headers=headers)
        assert resp.status_code == 200


def test_unauthenticated_recording_access_returns_401(full_client, make_constable, auth_header):
    make_constable(phone="r000000034")
    headers = auth_header("r000000034", "correct-horse-battery")
    _register_device(full_client, headers, "phone-r034")
    recording_id = _start_recording(full_client, headers, "phone-r034").json()["id"]

    resp = full_client.get(f"/recordings/{recording_id}")
    assert resp.status_code == 401


def test_get_recording_404_for_unknown_id(full_client, make_user, auth_header):
    import uuid
    make_user(phone="r000000035", password="pw", role=UserRole.admin)
    headers = auth_header("r000000035", "pw")
    resp = full_client.get(f"/recordings/{uuid.uuid4()}", headers=headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Extra: device status integration (recording state surfaced, restored on completion)
# ---------------------------------------------------------------------------
def test_device_status_shows_recording_while_active_and_reverts_on_completion(full_client, make_constable, auth_header):
    make_constable(phone="r000000036")
    headers = auth_header("r000000036", "correct-horse-battery")
    device_id = _register_device(full_client, headers, "phone-r036")
    recording_id = _start_recording(full_client, headers, "phone-r036").json()["id"]

    device_resp = full_client.get(f"/devices/{device_id}", headers=headers)
    assert device_resp.json()["status"] == "recording"

    full_client.post(f"/recordings/{recording_id}/complete", headers=headers)
    device_resp = full_client.get(f"/devices/{device_id}", headers=headers)
    assert device_resp.json()["status"] == "online"


def test_heartbeat_during_recording_does_not_clear_recording_status(full_client, make_constable, auth_header):
    """Regression test for the real integration bug found and fixed this phase."""
    make_constable(phone="r000000037")
    headers = auth_header("r000000037", "correct-horse-battery")
    device_id = _register_device(full_client, headers, "phone-r037")
    _start_recording(full_client, headers, "phone-r037")

    full_client.post("/devices/heartbeat", json={"device_identifier": "phone-r037", "battery_percent": 80}, headers=headers)

    device_resp = full_client.get(f"/devices/{device_id}", headers=headers)
    assert device_resp.json()["status"] == "recording"
