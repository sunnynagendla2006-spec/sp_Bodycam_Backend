"""
Audit logging (writing) and the GET /audit-logs API.
"""
import json

from app.models import UserRole, IncidentStatus, AssignmentStatus


async def _get_logs(action=None):
    from app import models
    if action:
        return await models.AuditLog.find(models.AuditLog.action == action).to_list()
    return await models.AuditLog.find_all().to_list()


# ---------------------------------------------------------------------------
# 1. Successful login creates audit entry
# ---------------------------------------------------------------------------
async def test_successful_login_creates_audit_entry(full_client, make_user):
    await make_user(phone="a000000001", password="pw", role=UserRole.admin)
    resp = await full_client.post("/auth/login", json={"username": "a000000001", "password": "pw"})
    assert resp.status_code == 200

    entries = await _get_logs("auth.login_success")
    assert len(entries) == 1
    assert entries[0].user_id is not None


# ---------------------------------------------------------------------------
# 2. Failed login creates a safe audit entry (no password stored)
# ---------------------------------------------------------------------------
async def test_failed_login_creates_safe_audit_entry(full_client, make_user):
    await make_user(phone="a000000002", password="correct-pw", role=UserRole.admin)
    resp = await full_client.post("/auth/login", json={"username": "a000000002", "password": "wrong-pw"})
    assert resp.status_code == 401

    entries = await _get_logs("auth.login_failed")
    assert len(entries) == 1
    blob = json.dumps(entries[0].details or {})
    assert "wrong-pw" not in blob
    assert "correct-pw" not in blob


# ---------------------------------------------------------------------------
# 3. Incident verification audited
# ---------------------------------------------------------------------------
async def test_incident_verification_audited(full_client, make_user, make_incident, auth_header):
    await make_user(phone="a000000003", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.new)
    headers = await auth_header("a000000003", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/verify", headers=headers)
    assert resp.status_code == 200

    entries = await _get_logs("incident.verified")
    assert len(entries) == 1
    assert str(entries[0].incident_id) == str(incident.id)


# ---------------------------------------------------------------------------
# 4. Incident rejection audited
# ---------------------------------------------------------------------------
async def test_incident_rejection_audited(full_client, make_user, make_incident, auth_header):
    await make_user(phone="a000000004", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.new)
    headers = await auth_header("a000000004", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/reject", headers=headers, json={"reason": "duplicate"})
    assert resp.status_code == 200

    entries = await _get_logs("incident.rejected")
    assert len(entries) == 1
    assert entries[0].details["reason"] == "duplicate"


# ---------------------------------------------------------------------------
# 5. Dispatch audited
# ---------------------------------------------------------------------------
async def test_dispatch_audited(full_client, make_user, make_incident, make_constable, make_location, auth_header):
    await make_user(phone="a000000005", password="pw", role=UserRole.control_room)
    incident = await make_incident(status_=IncidentStatus.verified, longitude=78.9, latitude=20.5)
    _, constable = await make_constable(phone="ac000000005")
    await make_location(constable.id, longitude=78.9, latitude=20.5, age_seconds=5)
    headers = await auth_header("a000000005", "pw")

    resp = await full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "dispatched"

    entries = await _get_logs("incident.dispatched")
    assert len(entries) == 1
    assert entries[0].details["constable_id"] == str(constable.id)


# ---------------------------------------------------------------------------
# 6. Assignment accept audited
# ---------------------------------------------------------------------------
async def test_assignment_accept_audited(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = await make_constable(phone="a000000006")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = await auth_header("a000000006", "correct-horse-battery")

    resp = await full_client.post(f"/constables/me/incidents/{incident.id}/accept", headers=headers)
    assert resp.status_code == 200

    entries = await _get_logs("assignment.accepted")
    assert len(entries) == 1
    assert str(entries[0].incident_id) == str(incident.id)


# ---------------------------------------------------------------------------
# 7. Assignment reject audited
# ---------------------------------------------------------------------------
async def test_assignment_reject_audited(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = await make_constable(phone="a000000007")
    incident = await make_incident(status_=IncidentStatus.assigned)
    await make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = await auth_header("a000000007", "correct-horse-battery")

    resp = await full_client.post(f"/constables/me/incidents/{incident.id}/reject", headers=headers, json={"reason": "sick"})
    assert resp.status_code == 200

    entries = await _get_logs("assignment.rejected")
    assert len(entries) == 1
    assert entries[0].details["reason"] == "sick"


# ---------------------------------------------------------------------------
# 8. Assignment status change audited
# ---------------------------------------------------------------------------
async def test_assignment_status_change_audited(full_client, make_constable, make_incident, make_assignment, auth_header):
    from app import models

    _, constable = await make_constable(phone="a000000008")
    incident = await make_incident(status_=IncidentStatus.assigned)
    assignment = await make_assignment(constable_id=constable.id, incident_id=incident.id)

    incident_doc = await models.Incident.get(incident.id)
    for a in incident_doc.assignments:
        if a.id == assignment.id:
            a.status = AssignmentStatus.accepted
    await incident_doc.save()

    headers = await auth_header("a000000008", "correct-horse-battery")

    resp = await full_client.put(f"/constables/me/incidents/{incident.id}/status", json={"status": "en_route"}, headers=headers)
    assert resp.status_code == 200

    entries = await _get_logs("assignment.status_changed")
    assert len(entries) == 1
    assert entries[0].details["new_status"] == "en_route"


# ---------------------------------------------------------------------------
# 9. Location update audited
# ---------------------------------------------------------------------------
async def test_location_update_audited(full_client, make_constable, auth_header):
    _, constable = await make_constable(phone="a000000009")
    headers = await auth_header("a000000009", "correct-horse-battery")

    resp = await full_client.post(
        "/constables/me/location", json={"latitude": 16.0, "longitude": 80.0}, headers=headers
    )
    assert resp.status_code == 200

    entries = await _get_logs("constable.location_updated")
    assert len(entries) == 1


# ---------------------------------------------------------------------------
# 10. Evidence upload audited
# ---------------------------------------------------------------------------
async def test_evidence_upload_audited(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = await make_constable(phone="a000000010")
    incident = await make_incident()
    await make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = await auth_header("a000000010", "correct-horse-battery")

    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 64
    resp = await full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("scene.jpg", jpeg_bytes, "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200

    entries = await _get_logs("evidence.uploaded")
    assert len(entries) == 1
    assert str(entries[0].incident_id) == str(incident.id)


# ---------------------------------------------------------------------------
# 11. Evidence download audited
# ---------------------------------------------------------------------------
async def test_evidence_download_audited(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="a000000011", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("a000000011", "pw")

    resp = await full_client.get(f"/media/{evidence.id}/download", headers=headers)
    assert resp.status_code == 200

    entries = await _get_logs("evidence.downloaded")
    assert len(entries) == 1
    assert str(entries[0].evidence_id) == str(evidence.id)


# ---------------------------------------------------------------------------
# 12. Settings update audited
# ---------------------------------------------------------------------------
async def test_settings_update_audited(full_client, make_user, auth_header):
    await make_user(phone="a000000012", password="pw", role=UserRole.admin)
    headers = await auth_header("a000000012", "pw")

    resp = await full_client.post(
        "/settings/", json={"chunk_size_mb": 10, "geofence_threshold_m": 30, "audio_alerts": False}, headers=headers
    )
    assert resp.status_code == 200

    entries = await _get_logs("settings.updated")
    assert len(entries) == 1


# ---------------------------------------------------------------------------
# 13. Audit endpoint requires authentication
# ---------------------------------------------------------------------------
async def test_audit_endpoint_requires_authentication(full_client):
    resp = await full_client.get("/audit-logs/")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 14. Admin can read audit logs
# ---------------------------------------------------------------------------
async def test_admin_can_read_audit_logs(full_client, make_user, auth_header):
    await make_user(phone="a000000014", password="pw", role=UserRole.admin)
    headers = await auth_header("a000000014", "pw")
    resp = await full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 15. Control room can read audit logs
# ---------------------------------------------------------------------------
async def test_control_room_can_read_audit_logs(full_client, make_user, auth_header):
    await make_user(phone="a000000015", password="pw", role=UserRole.control_room)
    headers = await auth_header("a000000015", "pw")
    resp = await full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 16. Constable cannot read audit logs
# ---------------------------------------------------------------------------
async def test_constable_cannot_read_audit_logs(full_client, make_constable, auth_header):
    await make_constable(phone="a000000016")
    headers = await auth_header("a000000016", "correct-horse-battery")
    resp = await full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 17. Citizen cannot read audit logs
# ---------------------------------------------------------------------------
async def test_citizen_cannot_read_audit_logs(full_client, make_user, auth_header):
    await make_user(phone="a000000017", password="pw", role=UserRole.citizen)
    headers = await auth_header("a000000017", "pw")
    resp = await full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 18. Station gets a safely-scoped view, not a blanket denial -- see
#     test_station_scoping.py for the exact scoping behavior.
# ---------------------------------------------------------------------------
async def test_station_gets_scoped_audit_logs_not_denied(full_client, make_user, make_station, auth_header):
    station = await make_station()
    await make_user(phone="a000000018", password="pw", role=UserRole.station, station_id=station.id)
    headers = await auth_header("a000000018", "pw")
    resp = await full_client.get("/audit-logs/", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 19. Passwords/tokens never appear in any audit details
# ---------------------------------------------------------------------------
async def test_no_passwords_or_tokens_in_audit_details(full_client, make_user, auth_header):
    await make_user(phone="a000000019", password="super-secret-pw", role=UserRole.admin)
    resp = await full_client.post("/auth/login", json={"username": "a000000019", "password": "super-secret-pw"})
    token = resp.json()["access_token"]

    all_entries = await _get_logs()
    for entry in all_entries:
        blob = json.dumps(entry.details or {})
        assert "super-secret-pw" not in blob
        assert token not in blob
        assert "hashed_password" not in blob
