"""
Phase-3 evidence/database hardening tests: MIME validation, size limits,
path-traversal safety, SHA-256/file-size correctness, storage-key design,
and response-shape checks (no internal path leakage).
"""
import hashlib
import uuid as uuid_module

from app.models import UserRole
from app.routers import media as media_router_module


# Minimal valid magic-byte payloads for the sniffer in media.py
JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 64
MP4_BYTES = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + b"\x00" * 64
GARBAGE_BYTES = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 64  # looks like a Windows PE header


# ---------------------------------------------------------------------------
# 1. Valid video upload
# ---------------------------------------------------------------------------
def test_valid_video_upload(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = make_constable(phone="7000000001")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000001", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "video"},
        files={"file": ("bodycam.mp4", MP4_BYTES, "video/mp4")},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["upload_status"] == "uploaded"
    assert "evidence_id" in body


# ---------------------------------------------------------------------------
# 2. Valid image upload
# ---------------------------------------------------------------------------
def test_valid_image_upload(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = make_constable(phone="7000000002")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000002", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# 3. Invalid MIME type
# ---------------------------------------------------------------------------
def test_invalid_mime_type_rejected(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = make_constable(phone="7000000003")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000003", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "video"},
        files={"file": ("evidence.mp4", GARBAGE_BYTES, "application/octet-stream")},
        headers=headers,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 4. Oversized upload -> 413
# ---------------------------------------------------------------------------
def test_oversized_upload_rejected(full_client, make_constable, make_incident, make_assignment, auth_header, monkeypatch):
    _, constable = make_constable(phone="7000000004")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000004", "correct-horse-battery")

    # Shrink the limit for this test only, rather than actually sending
    # hundreds of MB.
    monkeypatch.setattr(media_router_module, "MAX_EVIDENCE_SIZE_BYTES", 50)

    oversized_content = JPEG_BYTES + (b"\x00" * 1000)  # well over 50 bytes
    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("big.jpg", oversized_content, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 413


# ---------------------------------------------------------------------------
# 5. Path traversal filename
# ---------------------------------------------------------------------------
def test_path_traversal_filename_is_neutralized(
    full_client, make_constable, make_incident, make_assignment, auth_header, db_session
):
    _, constable = make_constable(phone="7000000005")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000005", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("../../../etc/passwd.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    evidence_id = resp.json()["evidence_id"]

    from app import models as app_models
    stored = db_session.query(app_models.Evidence).filter(
        app_models.Evidence.id == uuid_module.UUID(evidence_id)
    ).first()

    # The sanitized display filename must not contain any path separators
    # or ".." traversal sequences.
    assert stored.original_filename is not None
    assert "/" not in stored.original_filename
    assert "\\" not in stored.original_filename
    assert ".." not in stored.original_filename

    # The actual storage key is built entirely from server-generated UUIDs,
    # never from the client filename at all.
    assert "etc" not in stored.storage_key
    assert "passwd" not in stored.storage_key
    assert str(incident.id) in stored.storage_key
    assert str(stored.id) in stored.storage_key

    # And the file must have landed inside the configured upload root, not escaped it.
    import os
    abs_path = os.path.join(media_router_module.UPLOAD_DIR, stored.storage_key)
    assert os.path.exists(abs_path)
    assert os.path.commonpath([os.path.abspath(media_router_module.UPLOAD_DIR), os.path.abspath(abs_path)]) == os.path.abspath(media_router_module.UPLOAD_DIR)


# ---------------------------------------------------------------------------
# 6. SHA-256 hash correctness
# ---------------------------------------------------------------------------
def test_sha256_hash_is_correct(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = make_constable(phone="7000000006")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000006", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200
    expected_hash = hashlib.sha256(JPEG_BYTES).hexdigest()
    assert resp.json()["hash"] == expected_hash


# ---------------------------------------------------------------------------
# 7. File size correctness
# ---------------------------------------------------------------------------
def test_file_size_recorded_correctly(
    full_client, make_constable, make_incident, make_assignment, auth_header, db_session
):
    _, constable = make_constable(phone="7000000007")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000007", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    evidence_id = resp.json()["evidence_id"]

    from app import models as app_models
    stored = db_session.query(app_models.Evidence).filter(
        app_models.Evidence.id == uuid_module.UUID(evidence_id)
    ).first()
    assert stored.file_size == len(JPEG_BYTES)


# ---------------------------------------------------------------------------
# 8 & 17. Original filename preserved only as metadata; no absolute path leaked
# ---------------------------------------------------------------------------
def test_response_never_exposes_filesystem_path(
    full_client, make_constable, make_incident, make_assignment, auth_header
):
    _, constable = make_constable(phone="7000000008")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000008", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    body = resp.json()
    assert "file_path" not in body
    assert "storage_key" not in body

    list_resp = full_client.get("/media/", headers=headers)
    assert list_resp.status_code == 200
    for item in list_resp.json():
        assert "file_path" not in item
        assert "storage_key" not in item
        # original_filename is present as plain metadata, never used as a path
        assert "original_filename" in item


# ---------------------------------------------------------------------------
# 9. Storage key does not contain raw client path (covered thoroughly in
#    test_path_traversal_filename_is_neutralized; this adds a plain-filename
#    sanity check for the common case)
# ---------------------------------------------------------------------------
def test_storage_key_shape(full_client, make_constable, make_incident, make_assignment, auth_header, db_session):
    _, constable = make_constable(phone="7000000009")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000009", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    evidence_id = resp.json()["evidence_id"]
    from app import models as app_models
    stored = db_session.query(app_models.Evidence).filter(
        app_models.Evidence.id == uuid_module.UUID(evidence_id)
    ).first()
    assert stored.storage_key == f"evidence/{incident.id}/{stored.id}.jpg"


# ---------------------------------------------------------------------------
# 10. Evidence references existing incident
# ---------------------------------------------------------------------------
def test_evidence_references_existing_incident(
    full_client, make_constable, make_incident, make_assignment, auth_header, db_session
):
    _, constable = make_constable(phone="7000000010")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000010", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    evidence_id = resp.json()["evidence_id"]
    from app import models as app_models
    stored = db_session.query(app_models.Evidence).filter(
        app_models.Evidence.id == uuid_module.UUID(evidence_id)
    ).first()
    assert stored.incident_id == incident.id


# ---------------------------------------------------------------------------
# 11. Nonexistent incident rejected
# ---------------------------------------------------------------------------
def test_upload_to_nonexistent_incident_returns_404(full_client, make_constable, auth_header):
    _, constable = make_constable(phone="7000000011")
    headers = auth_header("7000000011", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(uuid_module.uuid4()), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 13. Constable uploader identity comes from JWT
# ---------------------------------------------------------------------------
def test_uploader_identity_derived_from_jwt(
    full_client, make_constable, make_incident, make_assignment, auth_header, db_session
):
    user, constable = make_constable(phone="7000000013")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000013", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    evidence_id = resp.json()["evidence_id"]
    from app import models as app_models
    stored = db_session.query(app_models.Evidence).filter(
        app_models.Evidence.id == uuid_module.UUID(evidence_id)
    ).first()
    assert str(stored.uploader_id) == str(user.id)
    assert stored.uploader_role == UserRole.constable


# ---------------------------------------------------------------------------
# 14. Spoofed uploader/constable ID ignored (extra unrecognized form fields
#     have no effect; the only accepted spoof vector, constable_id, is
#     covered by the existing Phase-2 test and still passes -- see below)
# ---------------------------------------------------------------------------
def test_unrecognized_uploader_id_form_field_has_no_effect(
    full_client, make_constable, make_incident, make_assignment, auth_header, db_session
):
    user, constable = make_constable(phone="7000000014")
    other_user_id = uuid_module.uuid4()
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000014", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        # uploader_id is not a real accepted field at all -- FastAPI simply
        # ignores form fields that aren't declared parameters. Confirms
        # there is no way to influence uploader_id from the request.
        data={"incident_id": str(incident.id), "type": "photo", "uploader_id": str(other_user_id)},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200
    evidence_id = resp.json()["evidence_id"]
    from app import models as app_models
    stored = db_session.query(app_models.Evidence).filter(
        app_models.Evidence.id == uuid_module.UUID(evidence_id)
    ).first()
    assert str(stored.uploader_id) == str(user.id)
    assert str(stored.uploader_id) != str(other_user_id)


# ---------------------------------------------------------------------------
# 16. Uploaded evidence starts with status "uploaded"
# ---------------------------------------------------------------------------
def test_new_evidence_starts_uploaded(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = make_constable(phone="7000000016")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000016", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.json()["upload_status"] == "uploaded"


# ---------------------------------------------------------------------------
# 18. Evidence download still requires authorization (unauthenticated case;
#     ownership-denial cases are already covered by the Phase-2 tests and
#     continue to pass unmodified -- see test_authorization.py)
# ---------------------------------------------------------------------------
def test_download_still_requires_authentication(full_client, make_incident, make_evidence):
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    resp = full_client.get(f"/media/{evidence.id}/download")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GPS metadata: stored, but distinguished from server timestamp
# ---------------------------------------------------------------------------
def test_client_gps_metadata_is_stored_but_not_authoritative(
    full_client, make_constable, make_incident, make_assignment, auth_header, db_session
):
    _, constable = make_constable(phone="7000000020")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("7000000020", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={
            "incident_id": str(incident.id),
            "type": "photo",
            "latitude": "16.5062",
            "longitude": "80.6480",
            "accuracy": "8.5",
            "device_timestamp": "2026-08-21T10:00:00Z",
        },
        files={"file": ("scene.jpg", JPEG_BYTES, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200
    evidence_id = resp.json()["evidence_id"]
    from app import models as app_models
    stored = db_session.query(app_models.Evidence).filter(
        app_models.Evidence.id == uuid_module.UUID(evidence_id)
    ).first()
    assert stored.evidence_metadata["latitude"] == 16.5062
    assert stored.evidence_metadata["device_timestamp"] == "2026-08-21T10:00:00Z"
    # Server timestamp is a distinct, separately-generated column.
    assert stored.timestamp is not None
