"""
Phase-2 authorization tests: real routers (incidents, constables, media,
settings), backed by the shared SQLite test schema from conftest.py.

These exercise the ACTUAL route functions in app/routers/*.py -- nothing
here is mocked business logic.
"""
from app.models import UserRole, IncidentStatus, ConstableStatus

# ---------------------------------------------------------------------------
# 1. Unauthenticated request to incidents -> 401
# ---------------------------------------------------------------------------
def test_unauthenticated_incidents_list_returns_401(full_client):
    resp = full_client.get("/incidents/")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 2. Unauthenticated request to media -> 401
# ---------------------------------------------------------------------------
def test_unauthenticated_media_list_returns_401(full_client):
    resp = full_client.get("/media/")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 3. Unauthenticated request to constable location -> 401
# ---------------------------------------------------------------------------
def test_unauthenticated_constable_location_returns_401(full_client, make_constable):
    _, constable = make_constable()
    resp = full_client.post(
        f"/constables/{constable.id}/location",
        json={"location_lon": 78.9, "location_lat": 20.5},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 4. Constable cannot modify another constable's location
# ---------------------------------------------------------------------------
def test_constable_cannot_update_another_constables_location(full_client, make_constable, auth_header):
    user_a, constable_a = make_constable(phone="7770001111")
    user_b, constable_b = make_constable(phone="7770002222")

    headers_a = auth_header("7770001111", "correct-horse-battery")

    # Constable A tries to POST a location update for Constable B.
    resp = full_client.post(
        f"/constables/{constable_b.id}/location",
        json={"location_lon": 78.9, "location_lat": 20.5},
        headers=headers_a,
    )
    assert resp.status_code == 403

    # Sanity check: Constable A CAN update their own location.
    resp_own = full_client.post(
        f"/constables/{constable_a.id}/location",
        json={"location_lon": 78.9, "location_lat": 20.5},
        headers=headers_a,
    )
    assert resp_own.status_code == 200


# ---------------------------------------------------------------------------
# 5. Constable cannot access another constable's task
#    (there is no GET endpoint for reading a specific constable's task list;
#    the actual protected surface is assign/unassign -- a constable must not
#    be able to call either, for themselves or anyone else)
# ---------------------------------------------------------------------------
def test_constable_cannot_assign_or_unassign_tasks(full_client, make_constable, make_incident, auth_header):
    user_a, constable_a = make_constable(phone="7770003333")
    incident = make_incident()
    headers_a = auth_header("7770003333", "correct-horse-battery")

    resp = full_client.post(
        f"/constables/{constable_a.id}/tasks",
        json={"incident_id": str(incident.id)},
        headers=headers_a,
    )
    assert resp.status_code == 403

    resp2 = full_client.delete(
        f"/constables/{constable_a.id}/tasks/{incident.id}",
        headers=headers_a,
    )
    assert resp2.status_code == 403


# ---------------------------------------------------------------------------
# 6. Constable cannot dispatch an incident
# ---------------------------------------------------------------------------
def test_constable_cannot_dispatch(full_client, make_constable, make_incident, auth_header):
    _, constable = make_constable(phone="7770004444")
    incident = make_incident()
    headers = auth_header("7770004444", "correct-horse-battery")

    resp = full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 7. Citizen cannot dispatch an incident
# ---------------------------------------------------------------------------
def test_citizen_cannot_dispatch(full_client, make_user, make_incident, auth_header):
    make_user(phone="6660001111", password="pw", role=UserRole.citizen)
    incident = make_incident()
    headers = auth_header("6660001111", "pw")

    resp = full_client.post(f"/incidents/{incident.id}/dispatch", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 8. Constable cannot access another user's evidence
# ---------------------------------------------------------------------------
def test_constable_cannot_download_another_constables_evidence(
    full_client, make_constable, make_incident, make_evidence, auth_header):
    _, constable_a = make_constable(phone="5550001111")
    _, constable_b = make_constable(phone="5550002222")
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, constable_id=constable_b.id)

    headers_a = auth_header("5550001111", "correct-horse-battery")
    resp = full_client.get(f"/media/{evidence.id}/download", headers=headers_a)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 9. Citizen cannot access another citizen's incident
# ---------------------------------------------------------------------------
def test_citizen_cannot_download_evidence_from_another_citizens_incident(
    full_client, make_user, make_incident, make_evidence, auth_header):
    citizen_a = make_user(phone="4440001111", password="pw", role=UserRole.citizen)
    citizen_b = make_user(phone="4440002222", password="pw", role=UserRole.citizen)
    incident_b = make_incident(citizen_id=citizen_b.id)
    evidence = make_evidence(incident_id=incident_b.id)

    headers_a = auth_header("4440001111", "pw")
    resp = full_client.get(f"/media/{evidence.id}/download", headers=headers_a)
    assert resp.status_code == 403


def test_citizen_incident_list_only_shows_own_incidents(full_client, make_user, make_incident, auth_header):
    citizen_a = make_user(phone="4440003333", password="pw", role=UserRole.citizen)
    citizen_b = make_user(phone="4440004444", password="pw", role=UserRole.citizen)
    incident_a = make_incident(citizen_id=citizen_a.id, description="A's incident")
    incident_b = make_incident(citizen_id=citizen_b.id, description="B's incident")

    headers_a = auth_header("4440003333", "pw")
    resp = full_client.get("/incidents/", headers=headers_a)
    assert resp.status_code == 200
    ids = [row["id"] for row in resp.json()]
    assert str(incident_a.id) in ids
    assert str(incident_b.id) not in ids


# ---------------------------------------------------------------------------
# 10. Admin can access authorized administrative endpoints
# ---------------------------------------------------------------------------
def test_admin_can_list_constables(full_client, make_user, make_constable, auth_header):
    make_user(phone="3330001111", password="pw", role=UserRole.admin)
    make_constable(phone="3330009999")
    headers = auth_header("3330001111", "pw")

    resp = full_client.get("/constables/", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 11. Control room can access authorized operational endpoints
# ---------------------------------------------------------------------------
def test_control_room_can_list_incidents(full_client, make_user, make_incident, auth_header):
    make_user(phone="3330002222", password="pw", role=UserRole.control_room)
    make_incident()
    headers = auth_header("3330002222", "pw")

    resp = full_client.get("/incidents/", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 12. Wrong role receives 403
# ---------------------------------------------------------------------------
def test_constable_creating_constable_gets_403(full_client, make_constable, auth_header):
    make_constable(phone="2220001111")
    headers = auth_header("2220001111", "correct-horse-battery")

    resp = full_client.post(
        "/constables/",
        json={"phone": "9999999999", "badge_number": "NEWBADGE"},
        headers=headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 13. Valid authenticated access still works
# ---------------------------------------------------------------------------
def test_citizen_can_create_own_incident(full_client, make_user, auth_header):
    make_user(phone="1110001111", password="pw", role=UserRole.citizen)
    headers = auth_header("1110001111", "pw")

    resp = full_client.post(
        "/incidents/",
        json={"location_lon": 78.9, "location_lat": 20.5, "description": "help"},
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["citizen_id"] is not None


# ---------------------------------------------------------------------------
# Additional targeted ownership checks
# ---------------------------------------------------------------------------
def test_constable_upload_requires_assignment_to_incident(full_client, make_constable, make_incident, auth_header):
    """A constable not assigned to the incident cannot upload evidence for it."""
    _, constable = make_constable(phone="9990009999")
    incident = make_incident()
    headers = auth_header("9990009999", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("evidence.jpg", b"fake bytes", "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 403


def test_constable_upload_succeeds_when_assigned(full_client, make_constable, make_incident, make_assignment, auth_header):
    _, constable = make_constable(phone="9990008888")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("9990008888", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={"incident_id": str(incident.id), "type": "photo"},
        files={"file": ("evidence.jpg", b"fake bytes", "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200


def test_upload_ignores_client_supplied_constable_id_for_constable_role(
    full_client, make_constable, make_incident, make_assignment, db_session, auth_header):
    """Even if a constable POSTs someone else's constable_id in the form, the
    stored evidence.constable_id must be THEIR OWN id, never the spoofed one."""
    _, constable_real = make_constable(phone="9990007777")
    _, constable_spoofed = make_constable(phone="9990006666")
    incident = make_incident()
    make_assignment(constable_id=constable_real.id, incident_id=incident.id)
    headers = auth_header("9990007777", "correct-horse-battery")

    resp = full_client.post(
        "/media/upload",
        data={
            "incident_id": str(incident.id),
            "type": "photo",
            "constable_id": str(constable_spoofed.id),  # attempted spoof
        },
        files={"file": ("evidence.jpg", b"fake bytes", "image/jpeg")},
        headers=headers,
    )
    assert resp.status_code == 200
    evidence_id = resp.json()["evidence_id"]

    from app import models as app_models
    import uuid as uuid_module
    stored = db_session.query(app_models.Evidence).filter(app_models.Evidence.id == uuid_module.UUID(evidence_id)).first()
    assert str(stored.constable_id) == str(constable_real.id)
    assert str(stored.constable_id) != str(constable_spoofed.id)


def test_settings_read_requires_admin_or_control_room(full_client, make_user, make_constable, auth_header):
    _, constable = make_constable(phone="1230001111")
    headers = auth_header("1230001111", "correct-horse-battery")
    resp = full_client.get("/settings/", headers=headers)
    assert resp.status_code == 403


def test_settings_write_requires_admin_not_control_room(full_client, make_user, auth_header):
    make_user(phone="1230002222", password="pw", role=UserRole.control_room)
    headers = auth_header("1230002222", "pw")
    resp = full_client.post(
        "/settings/",
        json={"chunk_size_mb": 10, "geofence_threshold_m": 25, "audio_alerts": False},
        headers=headers,
    )
    assert resp.status_code == 403


def test_settings_write_succeeds_for_admin(full_client, make_user, auth_header):
    make_user(phone="1230003333", password="pw", role=UserRole.admin)
    headers = auth_header("1230003333", "pw")
    resp = full_client.post(
        "/settings/",
        json={"chunk_size_mb": 10, "geofence_threshold_m": 25, "audio_alerts": False},
        headers=headers,
    )
    assert resp.status_code == 200


def test_constable_cannot_set_control_room_only_status(full_client, make_constable, make_incident, make_assignment, auth_header):
    """A constable assigned to an incident can move it to en_route, but not to 'verified'."""
    _, constable = make_constable(phone="1110002222")
    incident = make_incident()
    make_assignment(constable_id=constable.id, incident_id=incident.id)
    headers = auth_header("1110002222", "correct-horse-battery")

    resp_ok = full_client.put(
        f"/incidents/{incident.id}/status", params={"status": "en_route"}, headers=headers
    )
    assert resp_ok.status_code == 200

    resp_denied = full_client.put(
        f"/incidents/{incident.id}/status", params={"status": "verified"}, headers=headers
    )
    assert resp_denied.status_code == 403


def test_constable_cannot_update_status_of_unassigned_incident(full_client, make_constable, make_incident, auth_header):
    _, constable = make_constable(phone="1110003333")
    incident = make_incident()  # not assigned to this constable
    headers = auth_header("1110003333", "correct-horse-battery")

    resp = full_client.put(
        f"/incidents/{incident.id}/status", params={"status": "en_route"}, headers=headers
    )
    assert resp.status_code == 403
