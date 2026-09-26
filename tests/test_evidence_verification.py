"""
Evidence Verification workflow tests: POST /media/{id}/verify|reject|archive.
"""
import pytest

from app.models import UserRole, UploadStatus
from httpx_ws import aconnect_ws


async def _get_logs(action=None):
    from app import models
    if action:
        return await models.AuditLog.find(models.AuditLog.action == action).to_list()
    return await models.AuditLog.find_all().to_list()


async def _token(full_client, phone, password):
    resp = await full_client.post("/auth/login", json={"username": phone, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# AUTHORIZATION (1-7)
# ---------------------------------------------------------------------------
async def test_admin_can_verify(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="v000000001", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("v000000001", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["upload_status"] == "verified"


async def test_control_room_can_verify(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="v000000002", password="pw", role=UserRole.control_room)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("v000000002", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200


async def test_authorized_station_can_verify(full_client, make_user, make_station, make_incident, make_evidence, auth_header):
    station = await make_station()
    await make_user(phone="v000000003", password="pw", role=UserRole.station, station_id=station.id)
    incident = await make_incident(station_id=station.id)
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("v000000003", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200


async def test_unrelated_station_cannot_verify(full_client, make_user, make_station, make_incident, make_evidence, auth_header):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="v000000004", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = await make_incident(station_id=station_b.id)
    evidence_b = await make_evidence(incident_id=incident_b.id)
    headers = await auth_header("v000000004", "pw")

    resp = await full_client.post(f"/media/{evidence_b.id}/verify", headers=headers)
    assert resp.status_code == 403


async def test_constable_cannot_verify(full_client, make_constable, make_incident, make_evidence, auth_header):
    await make_constable(phone="v000000005")
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("v000000005", "correct-horse-battery")

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 403


async def test_citizen_cannot_verify(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="v000000006", password="pw", role=UserRole.citizen)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("v000000006", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 403


async def test_unauthenticated_verify_returns_401(full_client, make_incident, make_evidence):
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    resp = await full_client.post(f"/media/{evidence.id}/verify")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# STATE TRANSITIONS (8-17)
# ---------------------------------------------------------------------------
async def test_uploaded_to_verified_succeeds(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000001", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    assert evidence.upload_status == UploadStatus.uploaded
    headers = await auth_header("t000000001", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["upload_status"] == "verified"
    assert resp.json()["verified_at"] is not None


async def test_uploaded_to_rejected_succeeds(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000002", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000002", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/reject", json={"reason": "blurry"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["upload_status"] == "rejected"
    assert resp.json()["rejection_reason"] == "blurry"


async def test_verified_to_archived_succeeds(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000003", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000003", "pw")

    verify_resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert verify_resp.status_code == 200

    archive_resp = await full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    assert archive_resp.status_code == 200
    assert archive_resp.json()["upload_status"] == "archived"
    assert archive_resp.json()["archived_at"] is not None


async def test_uploaded_to_archived_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000004", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000004", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    assert resp.status_code == 409


async def test_verified_to_rejected_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000005", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000005", "pw")

    await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    resp = await full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    assert resp.status_code == 409


async def test_rejected_to_verified_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000006", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000006", "pw")

    await full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 409


async def test_archived_to_verified_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000007", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000007", "pw")

    await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    await full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 409


async def test_archived_to_rejected_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000008", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000008", "pw")

    await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    await full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    resp = await full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    assert resp.status_code == 409


async def test_already_verified_verification_is_rejected(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000009", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000009", "pw")

    await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 409


async def test_already_rejected_rejection_is_rejected(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="t000000010", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("t000000010", "pw")

    await full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    resp = await full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# AUDIT (18-21)
# ---------------------------------------------------------------------------
async def test_successful_verify_creates_audit_row(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="a000000001", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("a000000001", "pw")

    await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    entries = await _get_logs("evidence.verified")
    assert len(entries) == 1
    assert str(entries[0].evidence_id) == str(evidence.id)


async def test_successful_reject_creates_audit_row(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="a000000002", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("a000000002", "pw")

    await full_client.post(f"/media/{evidence.id}/reject", json={"reason": "irrelevant"}, headers=headers)
    entries = await _get_logs("evidence.rejected")
    assert len(entries) == 1
    assert entries[0].details["reason"] == "irrelevant"


async def test_successful_archive_creates_audit_row(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="a000000003", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("a000000003", "pw")

    await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    await full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    entries = await _get_logs("evidence.archived")
    assert len(entries) == 1


async def test_failed_transition_does_not_create_audit_row(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="a000000004", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("a000000004", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/archive", headers=headers)  # uploaded -> archived: invalid
    assert resp.status_code == 409

    entries = await _get_logs("evidence.archived")
    assert len(entries) == 0


# ---------------------------------------------------------------------------
# EVENTS (22-25)
# ---------------------------------------------------------------------------
async def test_authorized_station_receives_its_evidence_event(full_client, make_user, make_station, make_incident, make_evidence):
    station = await make_station()
    await make_user(phone="e000000001cr", password="pw", role=UserRole.control_room)
    await make_user(phone="e000000001s", password="pw", role=UserRole.station, station_id=station.id)
    incident = await make_incident(station_id=station.id)
    evidence = await make_evidence(incident_id=incident.id)

    cr_token = await _token(full_client, "e000000001cr", "pw")
    station_token = await _token(full_client, "e000000001s", "pw")

    async with aconnect_ws(f"/ws/control_room?token={station_token}", full_client) as station_ws:
        headers = {"Authorization": f"Bearer {cr_token}"}
        resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
        assert resp.status_code == 200

        msg = await station_ws.receive_json()
        assert msg["event"] == "evidence.verified"
        assert msg["data"]["evidence_id"] == str(evidence.id)


async def test_unrelated_station_does_not_receive_evidence_event(
    full_client, make_user, make_station, make_incident, make_evidence
):
    station_a = await make_station(name="A")
    station_b = await make_station(name="B")
    await make_user(phone="e000000002cr", password="pw", role=UserRole.control_room)
    await make_user(phone="e000000002b", password="pw", role=UserRole.station, station_id=station_b.id)
    incident_a = await make_incident(station_id=station_a.id)
    evidence_a = await make_evidence(incident_id=incident_a.id)

    cr_token = await _token(full_client, "e000000002cr", "pw")
    token_b = await _token(full_client, "e000000002b", "pw")

    async with aconnect_ws(f"/ws/control_room?token={token_b}", full_client) as ws_b:
        headers = {"Authorization": f"Bearer {cr_token}"}
        resp = await full_client.post(f"/media/{evidence_a.id}/verify", headers=headers)
        assert resp.status_code == 200

        await ws_b.send_text("ping")
        msg = await ws_b.receive_json()
        assert msg["event"] == "ack"  # never evidence.verified for station A's evidence


async def test_control_room_receives_evidence_event(full_client, make_user, make_incident, make_evidence):
    await make_user(phone="e000000003", password="pw", role=UserRole.control_room)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    cr_token = await _token(full_client, "e000000003", "pw")

    async with aconnect_ws(f"/ws/control_room?token={cr_token}", full_client) as cr_ws:
        headers = {"Authorization": f"Bearer {cr_token}"}
        resp = await full_client.post(f"/media/{evidence.id}/reject", headers=headers)
        assert resp.status_code == 200

        msg = await cr_ws.receive_json()
        assert msg["event"] == "evidence.rejected"


async def test_unrelated_constable_does_not_receive_evidence_event(
    full_client, make_user, make_constable, make_incident, make_evidence
):
    await make_user(phone="e000000004cr", password="pw", role=UserRole.control_room)
    _, constable = await make_constable(phone="e000000004c")
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)

    cr_token = await _token(full_client, "e000000004cr", "pw")
    c_token = await _token(full_client, "e000000004c", "correct-horse-battery")

    async with aconnect_ws(f"/ws/control_room?token={c_token}", full_client) as c_ws:
        headers = {"Authorization": f"Bearer {cr_token}"}
        resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
        assert resp.status_code == 200

        await c_ws.send_text("ping")
        msg = await c_ws.receive_json()
        assert msg["event"] == "ack"  # never evidence.verified for an unrelated constable


# ---------------------------------------------------------------------------
# API SECURITY (26-28)
# ---------------------------------------------------------------------------
async def test_response_never_exposes_file_path(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="sec000000001", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("sec000000001", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert "file_path" not in resp.json()


async def test_response_never_exposes_storage_key(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="sec000000002", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("sec000000002", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    assert resp.status_code == 200
    assert "storage_key" not in resp.json()


async def test_rejection_reason_stored_and_returned(full_client, make_user, make_incident, make_evidence, auth_header):
    await make_user(phone="sec000000003", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("sec000000003", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/reject", json={"reason": "chain of custody broken"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["rejection_reason"] == "chain of custody broken"

    # A verify response for a DIFFERENT, never-rejected evidence must not show a reason.
    evidence2 = await make_evidence(incident_id=incident.id)
    resp2 = await full_client.post(f"/media/{evidence2.id}/verify", headers=headers)
    assert resp2.json()["rejection_reason"] is None


# ---------------------------------------------------------------------------
# STORAGE (29-30)
# ---------------------------------------------------------------------------
async def test_verification_does_not_move_or_change_storage_object(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    await make_user(phone="st000000001", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id, content=b"original evidence bytes")
    original_path = evidence.file_path
    headers = await auth_header("st000000001", "pw")

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200

    # The physical object is untouched -- verification is a metadata-only transition.
    assert original_path == evidence.file_path
    with open(original_path, "rb") as f:
        assert f.read() == b"original evidence bytes"


async def test_archived_evidence_remains_streamable_per_current_access_policy(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    """
    The current codebase defines no rule gating /download or /stream on
    upload_status -- so archived evidence must remain retrievable exactly
    like any other evidence. This test locks in that documented decision.
    """
    await make_user(phone="st000000002", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id, content=b"archived but still retrievable")
    headers = await auth_header("st000000002", "pw")

    await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    await full_client.post(f"/media/{evidence.id}/archive", headers=headers)

    stream_resp = await full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert stream_resp.status_code == 200
    assert stream_resp.content == b"archived but still retrievable"

    download_resp = await full_client.get(f"/media/{evidence.id}/download", headers=headers)
    assert download_resp.status_code == 200


async def test_rejected_evidence_also_remains_streamable(full_client, make_user, make_incident, make_evidence, auth_header):
    """Same documented no-gate policy applies to rejected evidence."""
    await make_user(phone="st000000003", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id, content=b"rejected but still retrievable")
    headers = await auth_header("st000000003", "pw")

    await full_client.post(f"/media/{evidence.id}/reject", headers=headers)

    resp = await full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 200
    assert resp.content == b"rejected but still retrievable"


# ---------------------------------------------------------------------------
# CONCURRENCY (sequential-request coverage; see
# tests/test_evidence_verification_concurrency.py for the genuine
# concurrent-request test, and app/routers/media.py's
# _transition_evidence_status docstring for the exact atomic-update mechanism)
# ---------------------------------------------------------------------------
async def test_sequential_conflicting_transitions_second_call_rejected(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    """
    Demonstrates that a second call arriving after the first has already
    committed correctly sees the new state and is rejected by the
    transition table.
    """
    await make_user(phone="c000000001", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("c000000001", "pw")

    resp1 = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp1.status_code == 200

    # A second, later request attempting the same transition sees the
    # already-updated state and is correctly rejected -- not silently
    # allowed to "verify" an already-verified item twice.
    resp2 = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp2.status_code == 409


async def test_rollback_after_invalid_transition_does_not_corrupt_subsequent_requests(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    """
    Each request's atomic `find_one_and_update` is independent (there is no
    shared, mutable session/identity-map the way SQLAlchemy had, so there
    is nothing analogous to "leaked stale state" to worry about at the
    database layer) -- but this still confirms the user-facing guarantee
    end to end: a failed transition on evidence A must not corrupt or block
    a subsequent, unrelated, VALID transition on a different evidence item
    B, or on A itself afterward.
    """
    await make_user(phone="rb000000001", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence_a = await make_evidence(incident_id=incident.id)
    evidence_b = await make_evidence(incident_id=incident.id)
    headers = await auth_header("rb000000001", "pw")

    # Invalid transition on A.
    invalid_resp = await full_client.post(f"/media/{evidence_a.id}/archive", headers=headers)  # uploaded -> archived: illegal
    assert invalid_resp.status_code == 409

    # A itself must remain exactly as it was (still 'uploaded').
    still_uploaded_resp = await full_client.post(f"/media/{evidence_a.id}/archive", headers=headers)
    assert still_uploaded_resp.status_code == 409  # still illegal -- proves A's state wasn't corrupted into something else

    # An entirely separate evidence item B must be completely unaffected --
    # a valid transition on B must succeed normally right after A's failure.
    valid_resp = await full_client.post(f"/media/{evidence_b.id}/verify", headers=headers)
    assert valid_resp.status_code == 200
    assert valid_resp.json()["upload_status"] == "verified"

    # And a valid transition on A (verify, which IS legal from 'uploaded')
    # must also still work normally -- the earlier failed archive attempt
    # didn't leave A stuck in some broken state either.
    a_verify_resp = await full_client.post(f"/media/{evidence_a.id}/verify", headers=headers)
    assert a_verify_resp.status_code == 200
    assert a_verify_resp.json()["upload_status"] == "verified"


async def test_failed_audit_write_rolls_back_the_evidence_transition_and_never_publishes(
    full_client, make_user, make_incident, make_evidence, auth_header, monkeypatch
):
    """
    _transition_evidence_status wraps its atomic state-change update AND
    the audit-log write in one `database.transaction()` (see that
    function's docstring) specifically so they succeed or fail together.
    This simulates the audit write itself failing (the last thing that
    happens inside the transaction) and confirms:
      - the transaction genuinely rolled back: evidence is still
        'uploaded', verified_at/verified_by are still unset
      - no audit row exists
      - the caller (verify_evidence) never reached its own
        `events.publish_evidence_verified(...)` call, since
        _transition_evidence_status raised before returning
    """
    from app import models
    from app.routers import media as media_router_module

    await make_user(phone="ord000000001", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("ord000000001", "pw")

    publish_calls = []

    async def _fake_publish(*args, **kwargs):
        publish_calls.append((args, kwargs))

    monkeypatch.setattr(media_router_module.events, "publish_evidence_verified", _fake_publish)

    async def _boom_log_action(*args, **kwargs):
        raise RuntimeError("simulated audit write failure")

    monkeypatch.setattr(media_router_module, "log_action", _boom_log_action)

    with pytest.raises(RuntimeError, match="simulated audit write failure"):
        await full_client.post(f"/media/{evidence.id}/verify", headers=headers)

    assert publish_calls == []  # the event must NEVER have been published

    fresh = await models.Evidence.get(evidence.id)
    assert fresh.upload_status == UploadStatus.uploaded  # rolled back, not left half-verified
    assert fresh.verified_at is None
    assert fresh.verified_by is None

    entries = await _get_logs("evidence.verified")
    assert len(entries) == 0


async def test_successful_transition_publishes_exactly_one_event(
    full_client, make_user, make_incident, make_evidence, auth_header, monkeypatch
):
    from app.routers import media as media_router_module

    await make_user(phone="ord000000003", password="pw", role=UserRole.admin)
    incident = await make_incident()
    evidence = await make_evidence(incident_id=incident.id)
    headers = await auth_header("ord000000003", "pw")

    publish_calls = []

    async def _fake_publish(*args, **kwargs):
        publish_calls.append((args, kwargs))

    monkeypatch.setattr(media_router_module.events, "publish_evidence_verified", _fake_publish)

    resp = await full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert len(publish_calls) == 1
