"""
Production-ready evidence storage + playback tests: the storage
abstraction, the new authenticated /media/{id}/stream endpoint (HTTP Range
support), upload failure cleanup, and audit coverage for both
stream/download access.
"""
import os
import uuid as uuid_module

import pytest

from app.models import UserRole, MediaType, UploadStatus

JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + (b"0123456789" * 10)  # 100 bytes body, deterministic content
FULL_SIZE = len(JPEG_BYTES)


def _get_logs(db_session, action=None):
    from app import models
    q = db_session.query(models.AuditLog)
    if action:
        q = q.filter(models.AuditLog.action == action)
    return q.all()


# ---------------------------------------------------------------------------
# Basic stream access: authenticated success, unauthenticated, unauthorized
# ---------------------------------------------------------------------------
def test_authenticated_stream_success(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="s000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = auth_header("s000000001", "pw")

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 200
    assert resp.content == JPEG_BYTES
    assert resp.headers["content-type"] == "image/jpeg"
    assert resp.headers["accept-ranges"] == "bytes"
    assert resp.headers["content-length"] == str(FULL_SIZE)


def test_unauthenticated_stream_returns_401(full_client, make_incident, make_evidence):
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    resp = full_client.get(f"/media/{evidence.id}/stream")
    assert resp.status_code == 401


def test_unauthorized_user_gets_established_403(
    full_client, make_constable, make_incident, make_evidence, auth_header
):
    """
    Matches the pre-existing, already-tested authorization contract for
    /download (403 for a real-but-unowned evidence row, not a uniform 404)
    -- see _load_and_authorize_evidence's docstring on why this wasn't
    changed to a uniform anti-enumeration 404 in this phase.
    """
    _, constable_a = make_constable(phone="s000000003a")
    _, constable_b = make_constable(phone="s000000003b")
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, constable_id=constable_b.id)
    headers = auth_header("s000000003a", "correct-horse-battery")

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 403


def test_station_isolation_on_stream(
    full_client, make_user, make_station, make_incident, make_evidence, auth_header
):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="s000000004", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = make_incident(station_id=station_b.id)
    evidence_b = make_evidence(incident_id=incident_b.id)
    headers = auth_header("s000000004", "pw")

    resp = full_client.get(f"/media/{evidence_b.id}/stream", headers=headers)
    assert resp.status_code == 403


def test_constable_assignment_isolation_on_stream(
    full_client, make_constable, make_incident, make_assignment, make_evidence, auth_header
):
    _, constable_assigned = make_constable(phone="s000000005a")
    _, constable_unrelated = make_constable(phone="s000000005b")
    incident = make_incident()
    make_assignment(constable_id=constable_assigned.id, incident_id=incident.id)
    evidence = make_evidence(incident_id=incident.id)  # uploaded by neither, tied only to the incident

    headers_assigned = auth_header("s000000005a", "correct-horse-battery")
    resp_ok = full_client.get(f"/media/{evidence.id}/stream", headers=headers_assigned)
    assert resp_ok.status_code == 200

    headers_unrelated = auth_header("s000000005b", "correct-horse-battery")
    resp_denied = full_client.get(f"/media/{evidence.id}/stream", headers=headers_unrelated)
    assert resp_denied.status_code == 403


def test_citizen_ownership_isolation_on_stream(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    citizen_a = make_user(phone="s000000006a", password="pw", role=UserRole.citizen)
    citizen_b = make_user(phone="s000000006b", password="pw", role=UserRole.citizen)
    incident_b = make_incident(citizen_id=citizen_b.id)
    evidence_b = make_evidence(incident_id=incident_b.id)

    headers_a = auth_header("s000000006a", "pw")
    resp = full_client.get(f"/media/{evidence_b.id}/stream", headers=headers_a)
    assert resp.status_code == 403


def test_admin_and_control_room_can_stream_any_evidence(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    make_user(phone="s000000007admin", password="pw", role=UserRole.admin)
    make_user(phone="s000000007cr", password="pw", role=UserRole.control_room)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)

    for phone in ("s000000007admin", "s000000007cr"):
        headers = auth_header(phone, "pw")
        resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Full download (unchanged contract) + Range behavior
# ---------------------------------------------------------------------------
def test_full_file_download_unchanged(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="s000000008", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = auth_header("s000000008", "pw")

    resp = full_client.get(f"/media/{evidence.id}/download", headers=headers)
    assert resp.status_code == 200
    assert resp.content == JPEG_BYTES
    assert resp.headers["content-type"] == "image/jpeg"
    assert "attachment" in resp.headers["content-disposition"]


def test_normal_byte_range(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="s000000009", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = dict(auth_header("s000000009", "pw"))
    headers["Range"] = "bytes=10-19"

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 206
    assert resp.content == JPEG_BYTES[10:20]
    assert resp.headers["content-range"] == f"bytes 10-19/{FULL_SIZE}"
    assert resp.headers["content-length"] == "10"
    assert resp.headers["accept-ranges"] == "bytes"


def test_open_ended_range(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="s000000010", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = dict(auth_header("s000000010", "pw"))
    headers["Range"] = "bytes=90-"

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 206
    assert resp.content == JPEG_BYTES[90:]
    assert resp.headers["content-range"] == f"bytes 90-{FULL_SIZE - 1}/{FULL_SIZE}"


def test_suffix_range(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="s000000011", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = dict(auth_header("s000000011", "pw"))
    headers["Range"] = "bytes=-10"

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 206
    assert resp.content == JPEG_BYTES[-10:]
    assert resp.headers["content-range"] == f"bytes {FULL_SIZE - 10}-{FULL_SIZE - 1}/{FULL_SIZE}"


def test_invalid_range_returns_416(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="s000000012", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = dict(auth_header("s000000012", "pw"))
    headers["Range"] = f"bytes={FULL_SIZE + 100}-{FULL_SIZE + 200}"

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 416
    assert resp.headers["content-range"] == f"bytes */{FULL_SIZE}"


def test_multiple_ranges_explicitly_rejected(full_client, make_user, make_incident, make_evidence, auth_header):
    """
    Documented choice: multiple ranges in a single request are rejected
    with 416 rather than implemented as a multipart/byteranges response --
    see _parse_range_header's docstring in media.py.
    """
    make_user(phone="s000000013", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = dict(auth_header("s000000013", "pw"))
    headers["Range"] = "bytes=0-9,20-29"

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 416


# ---------------------------------------------------------------------------
# Path safety / missing object handling
# ---------------------------------------------------------------------------
def test_no_filesystem_path_leakage_in_stream_or_download_responses(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    make_user(phone="s000000014", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = auth_header("s000000014", "pw")

    for path in (f"/media/{evidence.id}/stream", f"/media/{evidence.id}/download"):
        resp = full_client.get(path, headers=headers)
        assert resp.status_code == 200
        for header_value in resp.headers.values():
            assert "/tmp/" not in header_value
            assert "sp_test_evidence_" not in header_value


def test_missing_storage_object_returns_404_not_500(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    make_user(phone="s000000015", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    # Simulate the physical object having disappeared from disk.
    os.remove(evidence.file_path)
    headers = auth_header("s000000015", "pw")

    for path in (f"/media/{evidence.id}/stream", f"/media/{evidence.id}/download"):
        resp = full_client.get(path, headers=headers)
        assert resp.status_code == 404


def test_traversal_style_evidence_id_is_rejected_by_routing(full_client, make_user, auth_header):
    """
    media_id is a path parameter typed as uuid.UUID -- FastAPI/Pydantic
    validation rejects anything that isn't a valid UUID before the handler
    body (and therefore any filesystem resolution) ever runs, so a
    traversal-style id like "../../etc/passwd" can't even reach
    _resolve_evidence_read_target.
    """
    make_user(phone="s000000016", password="pw", role=UserRole.admin)
    headers = auth_header("s000000016", "pw")

    resp = full_client.get("/media/../../etc/passwd/stream", headers=headers)
    assert resp.status_code in (404, 422)


def test_legacy_evidence_without_storage_key_still_streams(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    """Evidence rows created before storage_key existed (file_path only) must still work through /stream, not just /download."""
    make_user(phone="s000000017", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    assert evidence.storage_key is None  # confirms this is the legacy-path case
    headers = auth_header("s000000017", "pw")

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 200
    assert resp.content == JPEG_BYTES


# ---------------------------------------------------------------------------
# Auditing
# ---------------------------------------------------------------------------
def test_stream_creates_evidence_downloaded_audit_entry(
    full_client, make_user, make_incident, make_evidence, auth_header, db_session
):
    make_user(phone="s000000018", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("s000000018", "pw")

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 200

    entries = _get_logs(db_session, "evidence.downloaded")
    assert len(entries) == 1
    import json
    details = json.loads(entries[0].details)
    assert details["access_method"] == "stream"


def test_download_creates_evidence_downloaded_audit_entry(
    full_client, make_user, make_incident, make_evidence, auth_header, db_session
):
    make_user(phone="s000000019", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("s000000019", "pw")

    resp = full_client.get(f"/media/{evidence.id}/download", headers=headers)
    assert resp.status_code == 200

    entries = _get_logs(db_session, "evidence.downloaded")
    assert len(entries) == 1
    import json
    details = json.loads(entries[0].details)
    assert details["access_method"] == "download"


def test_failed_authorization_does_not_create_audit_entry(
    full_client, make_constable, make_incident, make_evidence, auth_header, db_session
):
    _, constable_a = make_constable(phone="s000000020a")
    _, constable_b = make_constable(phone="s000000020b")
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, constable_id=constable_b.id)
    headers = auth_header("s000000020a", "correct-horse-battery")

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 403

    entries = _get_logs(db_session, "evidence.downloaded")
    assert len(entries) == 0


def test_invalid_range_does_not_create_audit_entry(
    full_client, make_user, make_incident, make_evidence, auth_header, db_session
):
    make_user(phone="s000000021", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=JPEG_BYTES, mime_type="image/jpeg")
    headers = dict(auth_header("s000000021", "pw"))
    headers["Range"] = "bytes=99999-999999"

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 416

    entries = _get_logs(db_session, "evidence.downloaded")
    assert len(entries) == 0


# ---------------------------------------------------------------------------
# Upload failure cleanup
# ---------------------------------------------------------------------------
def test_upload_failure_cleans_up_partial_file_on_oversized_upload(
    full_client, make_constable, make_incident, make_assignment, auth_header, monkeypatch
):
    from app.routers import media as media_router_module

    _, constable = make_constable(phone="s000000022")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("s000000022", "correct-horse-battery")

    monkeypatch.setattr(media_router_module, "MAX_EVIDENCE_SIZE_BYTES", 10)

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("big.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 413

    # No partial object should remain anywhere under the test upload dir.
    upload_dir = media_router_module.UPLOAD_DIR
    leftover_files = []
    for root, _, files in os.walk(upload_dir):
        leftover_files.extend(files)
    assert leftover_files == []


def test_symlink_escape_attempt_via_storage_key_is_structurally_impossible(
    full_client, make_user, make_incident, auth_header, tmp_path
):
    """
    storage_key is always server-generated from UUIDs (see
    media.py::_build_storage_key) -- there is no code path where a client
    can influence storage_key content at all (it's never accepted as
    request input, only computed). This test demonstrates that even if
    something on disk under the upload root were a symlink pointing
    outside it, LocalFilesystemStorage's path construction
    (os.path.join(root, storage_key)) never involves any client-supplied
    segment, so there is nothing for a client to redirect via ".." or a
    symlink target -- the traversal-prevention guarantee comes from
    storage_key's provenance, not from filesystem-level symlink detection.
    """
    from app.routers import media as media_router_module

    make_user(phone="s000000024", password="pw", role=UserRole.admin)
    incident = make_incident()
    headers = auth_header("s000000024", "pw")

    # Create a file OUTSIDE the upload root, and a symlink INSIDE the
    # upload root pointing to it, then confirm the API still only ever
    # resolves paths via server-generated storage_key/evidence_id -- a
    # client cannot ask for "the symlink" because storage_key is never
    # client-suppliable in the first place.
    outside_secret = tmp_path / "outside_secret.txt"
    outside_secret.write_text("should never be reachable via the API")

    upload_dir = media_router_module.UPLOAD_DIR
    evidence_dir = os.path.join(upload_dir, "evidence", str(incident.id))
    os.makedirs(evidence_dir, exist_ok=True)
    symlink_path = os.path.join(evidence_dir, "innocuous.jpg")
    try:
        os.symlink(str(outside_secret), symlink_path)
    except (OSError, NotImplementedError):
        import pytest as _pytest
        _pytest.skip("symlinks not supported in this environment")

    # There is no endpoint that accepts a raw filename/storage_key from the
    # client -- confirm the normal upload+stream flow never even offers
    # that as an input, by checking the upload form contract itself has no
    # such field name reaching the filesystem layer unsanitized.
    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("innocuous.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200
    evidence_id = resp.json()["evidence_id"]

    # The uploaded evidence's OWN storage_key (a fresh UUID-based path) is
    # what gets served -- never the pre-existing symlink filename, which
    # was never referenced by any evidence row's storage_key at all.
    stream_resp = full_client.get(f"/media/{evidence_id}/stream", headers=headers)
    assert stream_resp.status_code == 200
    assert stream_resp.content == JPEG_BYTES  # the real upload, not the symlink target


def test_db_failure_after_write_cleans_up_physical_object(
    full_client, make_constable, make_incident, make_assignment, auth_header, monkeypatch
):
    """
    Simulates the DB commit failing AFTER the file was already written --
    the just-written object must be deleted, not left orphaned.
    """
    from app.routers import media as media_router_module

    _, constable = make_constable(phone="s000000023")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)

    # Get the auth header (this itself performs a login, which commits its
    # own audit row) BEFORE arming the commit-failure trap below, so the
    # trap only fires on the upload endpoint's own commit -- not on the
    # login's.
    headers = auth_header("s000000023", "correct-horse-battery")

    from sqlalchemy.orm import Session as OrmSession
    real_commit = OrmSession.commit
    state = {"armed": True}

    def _boom_commit(self):
        if state["armed"]:
            state["armed"] = False
            raise RuntimeError("simulated DB failure")
        return real_commit(self)

    monkeypatch.setattr(OrmSession, "commit", _boom_commit)

    with pytest.raises(RuntimeError, match="simulated DB failure"):
        full_client.post(
            "/media/upload",
            data={"incident_id": str(incident.id), "type": "photo"},
            files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
            headers=headers,
        )
    # The important assertion isn't the framework's exception-propagation
    # behavior under TestClient -- it's that the just-written physical
    # object was cleaned up despite the DB commit failing after it was
    # written (see upload_evidence's `except Exception:` cleanup block).

    upload_dir = media_router_module.UPLOAD_DIR
    leftover_files = []
    for root, _, files in os.walk(upload_dir):
        leftover_files.extend(files)
    assert leftover_files == []
