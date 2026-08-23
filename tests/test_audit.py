"""
Phase 5 tests: audit logging (writing) and the GET /audit-logs API.
"""
import json

from app.models import UserRole, IncidentStatus, AssignmentStatus


def _get_logs(db_session, action=None):
    from app import models
    q = db_session.query(models.AuditLog)
    if action:
        q = q.filter(models.AuditLog.action == action)
    return q.all()


# ---------------------------------------------------------------------------
# 1. Successful login creates audit entry
# ---------------------------------------------------------------------------
def test_successful_login_creates_audit_entry(full_client, make_user, db_session):
    make_user(phone="a000000001", password="pw", role=UserRole.admin)
    resp = full_client.post("/auth/login", json={"username": "a000000001", "password": "pw"})
    assert resp.status_code == 200

    entries = _get_logs(db_session, "auth.login_success")
    assert len(entries) == 1
    assert entries[0].user_id is not None


# ---------------------------------------------------------------------------
# 2. Failed login creates a safe audit entry (no password stored)
# ---------------------------------------------------------------------------
def test_failed_login_creates_safe_audit_entry(full_client, make_user, db_session):
    make_user(phone="a000000002", password="correct-pw", role=UserRole.admin)
    resp = full_client.post("/auth/login", json={"username": "a000000002", "password": "wrong-pw"})
    assert resp.status_code == 401

    entries = _get_logs(db_session, "auth.login_failed")
    assert len(entries) == 1
    assert "wrong-pw" not in (entries[0].details or "")
    assert "correct-pw" not in (entries[0].details or "")


# ---------------------------------------------------------------------------
# 3. Incident verification audited
# ---------------------------------------------------------------------------
def test_incident_verification_audited(full_client, make_user, make_incident, auth_header, db_session):
    make_user(phone="a000000003", password="pw", role=UserRole.control_room)
    incident = make_incident(status_=IncidentStatus.new)
    headers = auth_header("a000000003", "pw")

    resp = full_client.post(f"/incidents/{incident.id}/verify", headers=headers)
    assert resp.status_code == 200

    entries = _get_logs(db_session, "incident.verified")
    assert len(entries) == 1
    assert str(entries[0].incident_id) == str(incident.id)


# ---------------------------------------------------------------------------
# 4. Incident rejection audited
# ---------------------------------------------------------------------------
def test_incident_rejection_audited(full_client, make_user, make_incident, auth_header, db_session):
    make_user(phone="a000000004", password="pw", role=UserRole.control_room)
    incident = make_incident(status_=IncidentStatus.new)
    headers = auth_header("a000000004", "pw")

    resp = full_client.post(f"/incidents/{incident.id}/reject", headers=headers, json={"reason": "duplicate"})
    assert resp.status_code == 200

    entries = _get_logs(db_session, "incident.rejected")
    assert len(entries) == 1
    details = json.loads(entries[0].details)
    assert details["reason"] == "duplicate"


# ---------------------------------------------------------------------------
# 5. Dispatch audited
# ---------------------------------------------------------------------------
def test_dispatch_audited(full_client, make_user, make_incident, make_constable, make_location, auth_header, db_session):
    make_user(phone="a000000005", password="pw", role=UserRole.control_room)
    incident = make_incident(status_=IncidentStatus.verified, longitude=78.9, latitude=20.5)
    _, constable = make_constable(phone="ac000000005")
    make_location(constable.id, longitude=78.9, latitude=20.5, age_seconds=5)
    headers = auth_header("a000000005", "pw")

    resp = full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "dispatched"

    entries = _get_logs(db_session, "incident.dispatched")
    assert len(entries) == 1
    details = json.loads(entries[0].details)
    assert details["constable_id"] == str(constable.id)


# ---------------------------------------------------------------------------
# 6. Assignment accept audited
# ---------------------------------------------------------------------------
def test_assignment_accept_audited(full_client, make_constable, make_incident, make_assignment, auth_header, db_session):
    _, constable = make_constable(phone="a000000006")
    incident = make_incident(status_=IncidentStatus.assigned)
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("a000000006", "correct-horse-battery")

    resp = full_client.post(f"/constables/me/incidents/{incident.id}/accept", headers=headers)
    assert resp.status_code == 200

    entries = _get_logs(db_session, "assignment.accepted")
    assert len(entries) == 1
    assert str(entries[0].incident_id) == str(incident.id)


# ---------------------------------------------------------------------------
# 7. Assignment reject audited
# ---------------------------------------------------------------------------
def test_assignment_reject_audited(full_client, make_constable, make_incident, make_assignment, auth_header, db_session):
    _, constable = make_constable(phone="a000000007")
    incident = make_incident(status_=IncidentStatus.assigned)
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("a000000007", "correct-horse-battery")

    resp = full_client.post(f"/constables/me/incidents/{incident.id}/reject", headers=headers, json={"reason": "sick"})
    assert resp.status_code == 200

    entries = _get_logs(db_session, "assignment.rejected")
    assert len(entries) == 1
    details = json.loads(entries[0].details)
    assert details["reason"] == "sick"


# ---------------------------------------------------------------------------
# 8. Assignment status change audited
# ---------------------------------------------------------------------------
def test_assignment_status_change_audited(
    full_client, make_constable, make_incident, make_assignment, auth_header, db_session
):
    _, constable = make_constable(phone="a000000008")
    incident = make_incident(status_=IncidentStatus.assigned)
    assignment = make_assignment(constable_id=constable.id, incident_id=incident.id)
    assignment.status = AssignmentStatus.accepted
    db_session.commit()
    headers = auth_header("a000000008", "correct-horse-battery")

    resp = full_client.put(f"/constables/me/incidents/{incident.id}/status", json={"status": "en_route"}, headers=headers)
    assert resp.status_code == 200

    entries = _get_logs(db_session, "assignment.status_changed")
    assert len(entries) == 1
    details = json.loads(entries[0].details)
    assert details["new_status"] == "en_route"


# ---------------------------------------------------------------------------
# 9. Location update audited
# ---------------------------------------------------------------------------
def test_location_update_audited(full_client, make_constable, auth_header, db_session):
    _, constable = make_constable(phone="a000000009")
    headers = auth_header("a000000009", "correct-horse-battery")

    resp = full_client.post(
        "/constables/me/location", json={"latitude": 16.0, "longitude": 80.0}, headers=headers
    )
    assert resp.status_code == 200

    entries = _get_logs(db_session, "constable.location_updated")
    assert len(entries) == 1


# ---------------------------------------------------------------------------
# 10. Evidence upload audited
# ---------------------------------------------------------------------------
def test_evidence_upload_audited(
    full_client, make_constable, make_incident, make_assignment, auth_header, db_session
):
    _, constable = make_constable(phone="a000000010")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("a000000010", "correct-horse-battery")

    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 64
    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", jpeg_bytes, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200

    entries = _get_logs(db_session, "evidence.uploaded")
    assert len(entries) == 1
    assert str(entries[0].incident_id) == str(incident.id)


# ---------------------------------------------------------------------------
# 11. Evidence download audited
# ---------------------------------------------------------------------------
def test_evidence_download_audited(full_client, make_user, make_incident, make_evidence, auth_header, db_session):
    make_user(phone="a000000011", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("a000000011", "pw")

    resp = full_client.get(f"/media/{evidence.id}/download", headers=headers)
    assert resp.status_code == 200

    entries = _get_logs(db_session, "evidence.downloaded")
    assert len(entries) == 1
    assert str(entries[0].evidence_id) == str(evidence.id)


# ---------------------------------------------------------------------------
# 12. Settings update audited
# ---------------------------------------------------------------------------
def test_settings_update_audited(full_client, make_user, auth_header, db_session):
    make_user(phone="a000000012", password="pw", role=UserRole.admin)
    headers = auth_header("a000000012", "pw")

    resp = full_client.post(
        "/settings/", json={"chunk_size_mb": 10, "geofence_threshold_m": 30, "audio_alerts": False}, headers=headers
    )
    assert resp.status_code == 200

    entries = _get_logs(db_session, "settings.updated")
    assert len(entries) == 1


# ---------------------------------------------------------------------------
# 13. Audit endpoint requires authentication
# ---------------------------------------------------------------------------
def test_audit_endpoint_requires_authentication(full_client):
    resp = full_client.get("/audit-logs/")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 14. Admin can read audit logs
# ---------------------------------------------------------------------------
def test_admin_can_read_audit_logs(full_client, make_user, auth_header):
    make_user(phone="a000000014", password="pw", role=UserRole.admin)
    headers = auth_header("a000000014", "pw")
    resp = full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 15. Control room can read audit logs
# ---------------------------------------------------------------------------
def test_control_room_can_read_audit_logs(full_client, make_user, auth_header):
    make_user(phone="a000000015", password="pw", role=UserRole.control_room)
    headers = auth_header("a000000015", "pw")
    resp = full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 16. Constable cannot read audit logs
# ---------------------------------------------------------------------------
def test_constable_cannot_read_audit_logs(full_client, make_constable, auth_header):
    make_constable(phone="a000000016")
    headers = auth_header("a000000016", "correct-horse-battery")
    resp = full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 17. Citizen cannot read audit logs
# ---------------------------------------------------------------------------
def test_citizen_cannot_read_audit_logs(full_client, make_user, auth_header):
    make_user(phone="a000000017", password="pw", role=UserRole.citizen)
    headers = auth_header("a000000017", "pw")
    resp = full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 18. Station gets a safely-scoped view, not a blanket denial (Phase 6:
#     previously station was denied entirely since there was no reliable
#     way to scope AuditLog to a station; now that Incident.station_id/
#     Evidence->Incident.station_id give a safe association path, station
#     gets a 200 with only the records associable with their own station --
#     see test_station_scoping.py for the exact scoping behavior).
# ---------------------------------------------------------------------------
def test_station_gets_scoped_audit_logs_not_denied(full_client, make_user, make_station, auth_header):
    station = make_station()
    make_user(phone="a000000018", password="pw", role=UserRole.station, station_id=station.id)
    headers = auth_header("a000000018", "pw")
    resp = full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 19. Passwords/tokens never appear in any audit details
# ---------------------------------------------------------------------------
def test_no_passwords_or_tokens_in_audit_details(full_client, make_user, auth_header, db_session):
    make_user(phone="a000000019", password="super-secret-pw", role=UserRole.admin)
    resp = full_client.post("/auth/login", json={"username": "a000000019", "password": "super-secret-pw"})
    token = resp.json()["access_token"]

    from app import models
    all_entries = db_session.query(models.AuditLog).all()
    for entry in all_entries:
        blob = entry.details or ""
        assert "super-secret-pw" not in blob
        assert token not in blob
        assert "hashed_password" not in blob
