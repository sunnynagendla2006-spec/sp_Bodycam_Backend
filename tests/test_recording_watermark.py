"""
Body-camera GPS/timestamp/status watermark feature.

Two kinds of tests here, deliberately kept separate:
  1. API-level tests (camera_lens_direction persistence/validation,
     latitude/longitude/recorded_at stored on the embedded Chunk) --
     ordinary request/response assertions.
  2. MEDIA-LEVEL tests that actually inspect the bytes ffmpeg produced --
     extracting a real pixel from the stored, burned video file and
     asserting it is red where the recording indicator was drawn, and
     confirming the file is still a valid, ffprobe-parseable video. A
     Python-level claim that "the chunk was watermarked" is never trusted
     here without opening the actual resulting file, per the project's own
     explicit anti-fabrication rule for this feature.
"""
import hashlib
import subprocess

from test_recordings import _real_mp4_segment_bytes, _register_device, _start_recording, _upload_chunk


def _ffprobe_duration(path: str) -> float:
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", path],
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return float(result.stdout.decode().strip())


def _extract_pixel_rgb(video_abs_path: str, x: int, y: int) -> tuple:
    """Decodes frame 0 of video_abs_path and returns the (r, g, b) of the
    pixel at (x, y) -- a real, decoded-from-the-actual-file value, not a
    guess based on the ffmpeg command that (supposedly) produced it.
    Crops a 2x2 region (not 1x1): swscale's yuv420p->rgb24 conversion needs
    even width/height for the chroma planes, and a 1x1 crop of a yuv420p
    source hits that edge case and fails outright -- only the first
    pixel's 3 bytes are actually read below."""
    result = subprocess.run(
        ["ffmpeg", "-y", "-i", video_abs_path, "-vf", f"crop=2:2:{x}:{y}", "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", "-"],
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    data = result.stdout
    assert len(data) >= 3, f"expected at least 3 bytes of RGB pixel data, got {len(data)}"
    return data[0], data[1], data[2]


async def _get_chunk(recording_id, chunk_number=1):
    from app import models
    import uuid as uuid_module
    session = await models.RecordingSession.get(uuid_module.UUID(recording_id))
    return next(c for c in session.chunks if c.chunk_number == chunk_number)


def _abs_path_for(storage_key: str) -> str:
    from app.routers import media as media_module
    return media_module._get_storage_backend()._abs_path(storage_key)


# ---------------------------------------------------------------------------
# camera_lens_direction (recording_sessions)
# ---------------------------------------------------------------------------
async def test_camera_lens_direction_defaults_to_back_when_omitted(full_client, make_constable, auth_header):
    await make_constable(phone="w000000001")
    headers = await auth_header("w000000001", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w001")

    resp = await _start_recording(full_client, headers, "phone-w001")
    assert resp.status_code == 200
    assert resp.json()["camera_lens_direction"] == "back"


async def test_camera_lens_direction_front_is_persisted(full_client, make_constable, auth_header):
    await make_constable(phone="w000000002")
    headers = await auth_header("w000000002", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w002")

    resp = await full_client.post(
        "/recordings/start",
        json={"device_identifier": "phone-w002", "trigger_type": "manual", "camera_lens_direction": "front"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["camera_lens_direction"] == "front"


async def test_camera_lens_direction_rejects_invalid_value(full_client, make_constable, auth_header):
    await make_constable(phone="w000000003")
    headers = await auth_header("w000000003", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w003")

    resp = await full_client.post(
        "/recordings/start",
        json={"device_identifier": "phone-w003", "trigger_type": "manual", "camera_lens_direction": "sideways"},
        headers=headers,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# latitude/longitude/recorded_at (embedded Chunk)
# ---------------------------------------------------------------------------
async def test_chunk_upload_stores_real_gps_and_recorded_at(full_client, make_constable, auth_header):
    await make_constable(phone="w000000004")
    headers = await auth_header("w000000004", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w004")
    recording_id = (await _start_recording(full_client, headers, "phone-w004")).json()["id"]

    resp = await full_client.post(
        f"/recordings/{recording_id}/chunks",
        data={
            "chunk_number": "1", "duration_seconds": "1.0", "is_last_chunk": "false",
            "latitude": "16.5062", "longitude": "80.6480", "recorded_at": "2026-09-16T16:24:31+00:00",
        },
        files={"file": ("chunk1.mp4", _real_mp4_segment_bytes(1), "video/mp4")},
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["latitude"] == 16.5062
    assert body["longitude"] == 80.6480
    assert body["recorded_at"] is not None

    chunk = await _get_chunk(recording_id)
    assert chunk.latitude == 16.5062
    assert chunk.longitude == 80.6480
    assert chunk.recorded_at is not None


async def test_chunk_upload_without_gps_stores_null_never_a_fabricated_coordinate(full_client, make_constable, auth_header):
    await make_constable(phone="w000000005")
    headers = await auth_header("w000000005", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w005")
    recording_id = (await _start_recording(full_client, headers, "phone-w005")).json()["id"]

    resp = await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1))
    assert resp.status_code == 200
    assert resp.json()["latitude"] is None
    assert resp.json()["longitude"] is None

    chunk = await _get_chunk(recording_id)
    assert chunk.latitude is None
    assert chunk.longitude is None


# ---------------------------------------------------------------------------
# Media-level: the actual stored file must really be re-encoded with the
# overlay burned into its pixels -- never trusted from a Dart/Python claim
# alone.
# ---------------------------------------------------------------------------
async def test_watermark_burn_changes_stored_bytes_and_stays_a_valid_video(full_client, make_constable, auth_header):
    await make_constable(phone="w000000006")
    headers = await auth_header("w000000006", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w006")
    recording_id = (await _start_recording(full_client, headers, "phone-w006")).json()["id"]

    raw_bytes = _real_mp4_segment_bytes(1)
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()

    resp = await _upload_chunk(full_client, headers, recording_id, 1, content=raw_bytes)
    assert resp.status_code == 200
    stored_hash = resp.json()["file_hash"]

    # A real re-encode happened -- the stored bytes are NOT identical to
    # what was uploaded (drawtext/drawbox is a genuine pixel-level change,
    # confirmed here by the hash actually differing, not assumed).
    assert stored_hash != raw_hash

    chunk = await _get_chunk(recording_id)
    abs_path = _abs_path_for(chunk.storage_key)
    # Still a real, decodable video afterward -- burning the overlay must
    # never corrupt the file into something unplayable.
    duration = _ffprobe_duration(abs_path)
    assert duration > 0


async def test_watermark_red_recording_indicator_is_physically_present_in_the_stored_frame(full_client, make_constable, auth_header):
    """
    The single most important assertion in this whole feature: opens the
    ACTUAL stored video file with ffmpeg and decodes a real pixel from
    inside the drawbox region (x=10..32, y=10..32) -- proving the red
    recording-indicator square is genuinely burned into the frame, not
    just present in a Flutter widget or claimed by application code.
    """
    await make_constable(phone="w000000007")
    headers = await auth_header("w000000007", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w007")
    recording_id = (await _start_recording(full_client, headers, "phone-w007")).json()["id"]

    resp = await _upload_chunk(full_client, headers, recording_id, 1, content=_real_mp4_segment_bytes(1))
    assert resp.status_code == 200

    chunk = await _get_chunk(recording_id)
    abs_path = _abs_path_for(chunk.storage_key)

    r, g, b = _extract_pixel_rgb(abs_path, x=20, y=20)
    assert r > 120 and g < 100 and b < 100, f"expected a red pixel at (20,20) from the drawbox overlay, got rgb=({r},{g},{b})"


async def test_watermark_burn_failure_leaves_the_original_chunk_completely_intact(full_client, make_constable, auth_header, monkeypatch):
    """
    If ffmpeg genuinely fails/is unavailable (simulated here by making the
    subprocess launch itself raise, exactly like _burn_watermark_best_effort's
    own `except FileNotFoundError` branch), the chunk upload must still
    succeed with the ORIGINAL, un-watermarked-but-perfectly-valid bytes --
    never corrupted, never lost, never a 500. (A bad fontfile= path alone
    is NOT reliable for this: this build's fontconfig-enabled ffmpeg
    silently substitutes a fallback font instead of failing, so the burn
    would still succeed -- forcing the subprocess call itself to fail is
    the deterministic way to exercise this failure path.)
    """
    from app.routers import recordings as recordings_module

    async def _raise_ffmpeg_missing(*args, **kwargs):
        raise FileNotFoundError("ffmpeg is not installed in this environment")

    monkeypatch.setattr(recordings_module.asyncio, "create_subprocess_exec", _raise_ffmpeg_missing)

    await make_constable(phone="w000000008")
    headers = await auth_header("w000000008", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w008")
    recording_id = (await _start_recording(full_client, headers, "phone-w008")).json()["id"]

    raw_bytes = _real_mp4_segment_bytes(1)
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()

    resp = await _upload_chunk(full_client, headers, recording_id, 1, content=raw_bytes)
    assert resp.status_code == 200
    # Burn failed -- the ORIGINAL bytes/hash must be exactly what's stored.
    assert resp.json()["file_hash"] == raw_hash

    # The chunk is still fully streamable/valid evidence despite the failed burn.
    stream_resp = await full_client.get(f"/recordings/{recording_id}/chunks/1/stream", headers=headers)
    assert stream_resp.status_code == 200
    assert stream_resp.content == raw_bytes


async def test_watermark_burn_succeeds_even_with_gps_unavailable(full_client, make_constable, auth_header):
    """GPS-unavailable ("SIGNAL UNAVAILABLE" text) must not block the burn
    itself -- the video is still watermarked and still valid."""
    await make_constable(phone="w000000009")
    headers = await auth_header("w000000009", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w009")
    recording_id = (await _start_recording(full_client, headers, "phone-w009")).json()["id"]

    raw_bytes = _real_mp4_segment_bytes(1)
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    resp = await _upload_chunk(full_client, headers, recording_id, 1, content=raw_bytes)
    assert resp.status_code == 200
    assert resp.json()["file_hash"] != raw_hash  # still re-encoded/burned

    chunk = await _get_chunk(recording_id)
    abs_path = _abs_path_for(chunk.storage_key)
    assert _ffprobe_duration(abs_path) > 0


async def test_emergency_recording_watermark_still_burns_successfully(full_client, make_constable, auth_header):
    """Sanity check that the trigger_type='emergency_button' path (which
    changes the burned STATUS text to "EMERGENCY RECORDING") goes through
    the exact same successful burn pipeline as a normal recording."""
    await make_constable(phone="w000000010")
    headers = await auth_header("w000000010", "correct-horse-battery")
    await _register_device(full_client, headers, "phone-w010")
    resp = await _start_recording(full_client, headers, "phone-w010", trigger_type="emergency_button")
    recording_id = resp.json()["id"]

    raw_bytes = _real_mp4_segment_bytes(1)
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    upload_resp = await _upload_chunk(full_client, headers, recording_id, 1, content=raw_bytes, duration=1.0)
    assert upload_resp.status_code == 200
    assert upload_resp.json()["file_hash"] != raw_hash

    chunk = await _get_chunk(recording_id)
    abs_path = _abs_path_for(chunk.storage_key)
    assert _ffprobe_duration(abs_path) > 0
