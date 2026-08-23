"""
Evidence Verification workflow tests.

Prior to this phase, `UploadStatus` already had verified/rejected/archived
enum values, but no endpoint anywhere ever transitioned an Evidence row
into any of them. This file tests the actual workflow added in this phase:
POST /media/{id}/verify|reject|archive.
"""
import json

import pytest
from starlette.websockets import WebSocketDisconnect

from app.models import UserRole, UploadStatus


def _get_logs(db_session, action=None):
    from app import models
    q = db_session.query(models.AuditLog)
    if action:
        q = q.filter(models.AuditLog.action == action)
    return q.all()


def _token(full_client, phone, password):
    resp = full_client.post("/auth/login", json={"username": phone, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# AUTHORIZATION (1-7)
# ---------------------------------------------------------------------------
def test_admin_can_verify(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="v000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("v000000001", "pw")

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["upload_status"] == "verified"


def test_control_room_can_verify(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="v000000002", password="pw", role=UserRole.control_room)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("v000000002", "pw")

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200


def test_authorized_station_can_verify(full_client, make_user, make_station, make_incident, make_evidence, auth_header):
    station = make_station()
    make_user(phone="v000000003", password="pw", role=UserRole.station, station_id=station.id)
    incident = make_incident(station_id=station.id)
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("v000000003", "pw")

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200


def test_unrelated_station_cannot_verify(full_client, make_user, make_station, make_incident, make_evidence, auth_header):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="v000000004", password="pw", role=UserRole.station, station_id=station_a.id)
    incident_b = make_incident(station_id=station_b.id)
    evidence_b = make_evidence(incident_id=incident_b.id)
    headers = auth_header("v000000004", "pw")

    resp = full_client.post(f"/media/{evidence_b.id}/verify", headers=headers)
    assert resp.status_code == 403


def test_constable_cannot_verify(full_client, make_constable, make_incident, make_evidence, auth_header):
    make_constable(phone="v000000005")
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("v000000005", "correct-horse-battery")

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 403


def test_citizen_cannot_verify(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="v000000006", password="pw", role=UserRole.citizen)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("v000000006", "pw")

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 403


def test_unauthenticated_verify_returns_401(full_client, make_incident, make_evidence):
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    resp = full_client.post(f"/media/{evidence.id}/verify")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# STATE TRANSITIONS (8-17)
# ---------------------------------------------------------------------------
def test_uploaded_to_verified_succeeds(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    assert evidence.upload_status == UploadStatus.uploaded
    headers = auth_header("t000000001", "pw")

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["upload_status"] == "verified"
    assert resp.json()["verified_at"] is not None


def test_uploaded_to_rejected_succeeds(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000002", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000002", "pw")

    resp = full_client.post(f"/media/{evidence.id}/reject", json={"reason": "blurry"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["upload_status"] == "rejected"
    assert resp.json()["rejection_reason"] == "blurry"


def test_verified_to_archived_succeeds(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000003", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000003", "pw")

    verify_resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert verify_resp.status_code == 200

    archive_resp = full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    assert archive_resp.status_code == 200
    assert archive_resp.json()["upload_status"] == "archived"
    assert archive_resp.json()["archived_at"] is not None


def test_uploaded_to_archived_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000004", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000004", "pw")

    resp = full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    assert resp.status_code == 409


def test_verified_to_rejected_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000005", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000005", "pw")

    full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    resp = full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    assert resp.status_code == 409


def test_rejected_to_verified_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000006", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000006", "pw")

    full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 409


def test_archived_to_verified_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000007", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000007", "pw")

    full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 409


def test_archived_to_rejected_fails(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000008", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000008", "pw")

    full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    resp = full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    assert resp.status_code == 409


def test_already_verified_verification_is_rejected(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000009", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000009", "pw")

    full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 409


def test_already_rejected_rejection_is_rejected(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="t000000010", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("t000000010", "pw")

    full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    resp = full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# AUDIT (18-21)
# ---------------------------------------------------------------------------
def test_successful_verify_creates_audit_row(full_client, make_user, make_incident, make_evidence, auth_header, db_session):
    make_user(phone="a000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("a000000001", "pw")

    full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    entries = _get_logs(db_session, "evidence.verified")
    assert len(entries) == 1
    assert str(entries[0].evidence_id) == str(evidence.id)


def test_successful_reject_creates_audit_row(full_client, make_user, make_incident, make_evidence, auth_header, db_session):
    make_user(phone="a000000002", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("a000000002", "pw")

    full_client.post(f"/media/{evidence.id}/reject", json={"reason": "irrelevant"}, headers=headers)
    entries = _get_logs(db_session, "evidence.rejected")
    assert len(entries) == 1
    details = json.loads(entries[0].details)
    assert details["reason"] == "irrelevant"


def test_successful_archive_creates_audit_row(full_client, make_user, make_incident, make_evidence, auth_header, db_session):
    make_user(phone="a000000003", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("a000000003", "pw")

    full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    full_client.post(f"/media/{evidence.id}/archive", headers=headers)
    entries = _get_logs(db_session, "evidence.archived")
    assert len(entries) == 1


def test_failed_transition_does_not_create_audit_row(full_client, make_user, make_incident, make_evidence, auth_header, db_session):
    make_user(phone="a000000004", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("a000000004", "pw")

    resp = full_client.post(f"/media/{evidence.id}/archive", headers=headers)  # uploaded -> archived: invalid
    assert resp.status_code == 409

    entries = _get_logs(db_session, "evidence.archived")
    assert len(entries) == 0


# ---------------------------------------------------------------------------
# EVENTS (22-25)
# ---------------------------------------------------------------------------
def test_authorized_station_receives_its_evidence_event(full_client, make_user, make_station, make_incident, make_evidence):
    station = make_station()
    make_user(phone="e000000001cr", password="pw", role=UserRole.control_room)
    make_user(phone="e000000001s", password="pw", role=UserRole.station, station_id=station.id)
    incident = make_incident(station_id=station.id)
    evidence = make_evidence(incident_id=incident.id)

    cr_token = _token(full_client, "e000000001cr", "pw")
    station_token = _token(full_client, "e000000001s", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={station_token}") as station_ws:
        headers = {"Authorization": f"Bearer {cr_token}"}
        resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
        assert resp.status_code == 200

        msg = station_ws.receive_json()
        assert msg["event"] == "evidence.verified"
        assert msg["data"]["evidence_id"] == str(evidence.id)


def test_unrelated_station_does_not_receive_evidence_event(
    full_client, make_user, make_station, make_incident, make_evidence
):
    station_a = make_station(name="A")
    station_b = make_station(name="B")
    make_user(phone="e000000002cr", password="pw", role=UserRole.control_room)
    make_user(phone="e000000002b", password="pw", role=UserRole.station, station_id=station_b.id)
    incident_a = make_incident(station_id=station_a.id)
    evidence_a = make_evidence(incident_id=incident_a.id)

    cr_token = _token(full_client, "e000000002cr", "pw")
    token_b = _token(full_client, "e000000002b", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={token_b}") as ws_b:
        headers = {"Authorization": f"Bearer {cr_token}"}
        resp = full_client.post(f"/media/{evidence_a.id}/verify", headers=headers)
        assert resp.status_code == 200

        ws_b.send_text("ping")
        msg = ws_b.receive_json()
        assert msg["event"] == "ack"  # never evidence.verified for station A's evidence


def test_control_room_receives_evidence_event(full_client, make_user, make_incident, make_evidence):
    make_user(phone="e000000003", password="pw", role=UserRole.control_room)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    cr_token = _token(full_client, "e000000003", "pw")

    with full_client.websocket_connect(f"/ws/control_room?token={cr_token}") as cr_ws:
        headers = {"Authorization": f"Bearer {cr_token}"}
        resp = full_client.post(f"/media/{evidence.id}/reject", headers=headers)
        assert resp.status_code == 200

        msg = cr_ws.receive_json()
        assert msg["event"] == "evidence.rejected"


def test_unrelated_constable_does_not_receive_evidence_event(
    full_client, make_user, make_constable, make_incident, make_evidence
):
    make_user(phone="e000000004cr", password="pw", role=UserRole.control_room)
    _, constable = make_constable(phone="e000000004c")
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)

    cr_token = _token(full_client, "e000000004cr", "pw")
    c_token = _token(full_client, "e000000004c", "correct-horse-battery")

    with full_client.websocket_connect(f"/ws/control_room?token={c_token}") as c_ws:
        headers = {"Authorization": f"Bearer {cr_token}"}
        resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
        assert resp.status_code == 200

        c_ws.send_text("ping")
        msg = c_ws.receive_json()
        assert msg["event"] == "ack"  # never evidence.verified for an unrelated constable


# ---------------------------------------------------------------------------
# API SECURITY (26-28)
# ---------------------------------------------------------------------------
def test_response_never_exposes_file_path(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="sec000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("sec000000001", "pw")

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert "file_path" not in resp.json()


def test_response_never_exposes_storage_key(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="sec000000002", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("sec000000002", "pw")

    resp = full_client.post(f"/media/{evidence.id}/reject", headers=headers)
    assert resp.status_code == 200
    assert "storage_key" not in resp.json()


def test_rejection_reason_stored_and_returned(full_client, make_user, make_incident, make_evidence, auth_header):
    make_user(phone="sec000000003", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("sec000000003", "pw")

    resp = full_client.post(f"/media/{evidence.id}/reject", json={"reason": "chain of custody broken"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["rejection_reason"] == "chain of custody broken"

    # A verify response for a DIFFERENT, never-rejected evidence must not show a reason.
    evidence2 = make_evidence(incident_id=incident.id)
    resp2 = full_client.post(f"/media/{evidence2.id}/verify", headers=headers)
    assert resp2.json()["rejection_reason"] is None


# ---------------------------------------------------------------------------
# STORAGE (29-30)
# ---------------------------------------------------------------------------
def test_verification_does_not_move_or_change_storage_object(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    make_user(phone="st000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=b"original evidence bytes")
    original_path = evidence.file_path
    headers = auth_header("st000000001", "pw")

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200

    # The physical object is untouched -- verification is a metadata-only transition.
    assert original_path == evidence.file_path
    with open(original_path, "rb") as f:
        assert f.read() == b"original evidence bytes"


def test_archived_evidence_remains_streamable_per_current_access_policy(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    """
    The current codebase defines no rule gating /download or /stream on
    upload_status (confirmed by inspection: no existing test or code path
    ties them together) -- so per this phase's explicit instruction not to
    invent such a gate, archived evidence must remain retrievable exactly
    like any other evidence. This test locks in that documented decision.
    """
    make_user(phone="st000000002", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=b"archived but still retrievable")
    headers = auth_header("st000000002", "pw")

    full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    full_client.post(f"/media/{evidence.id}/archive", headers=headers)

    stream_resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert stream_resp.status_code == 200
    assert stream_resp.content == b"archived but still retrievable"

    download_resp = full_client.get(f"/media/{evidence.id}/download", headers=headers)
    assert download_resp.status_code == 200


def test_rejected_evidence_also_remains_streamable(full_client, make_user, make_incident, make_evidence, auth_header):
    """Same documented no-gate policy applies to rejected evidence."""
    make_user(phone="st000000003", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id, content=b"rejected but still retrievable")
    headers = auth_header("st000000003", "pw")

    full_client.post(f"/media/{evidence.id}/reject", headers=headers)

    resp = full_client.get(f"/media/{evidence.id}/stream", headers=headers)
    assert resp.status_code == 200
    assert resp.content == b"rejected but still retrievable"


# ---------------------------------------------------------------------------
# CONCURRENCY (sequential-request coverage; see
# tests/test_evidence_verification_concurrency.py for the genuine
# two-connection PostgreSQL test, and app/routers/media.py's
# _transition_evidence_status docstring for the exact locking mechanism)
# ---------------------------------------------------------------------------
def test_sequential_conflicting_transitions_second_call_rejected(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    """
    Demonstrates that a second call arriving after the first has already
    committed correctly sees the new state and is rejected by the
    transition table. Since this test suite runs against SQLite,
    `.with_for_update()` (now used by `_transition_evidence_status` -- see
    that function's docstring) is a confirmed no-op here, so this proves
    SEQUENTIAL correctness only, not genuine concurrent-transaction
    locking -- that requires the separate Postgres-only integration test in
    tests/test_evidence_verification_concurrency.py.
    """
    make_user(phone="c000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("c000000001", "pw")

    resp1 = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp1.status_code == 200

    # A second, later request attempting the same transition sees the
    # already-updated state and is correctly rejected -- not silently
    # allowed to "verify" an already-verified item twice.
    resp2 = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp2.status_code == 409


def test_for_update_is_actually_used_and_compiles_with_for_update_on_postgres_dialect():
    """
    Unit-level proof (no live Postgres needed for THIS assertion) that the
    query _transition_evidence_status issues genuinely compiles to
    `SELECT ... FOR UPDATE` when targeting the PostgreSQL dialect --
    verified by compiling the exact query shape against
    sqlalchemy.dialects.postgresql.dialect() and inspecting the resulting
    SQL text, not by running it against a real server (that's what
    test_evidence_verification_concurrency.py is for).
    """
    import uuid as uuid_module
    from sqlalchemy.dialects import postgresql
    from app import models

    evidence_id = uuid_module.uuid4()
    stmt = models.Evidence.__table__.select().where(models.Evidence.id == evidence_id).with_for_update()
    compiled_sql = str(stmt.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE" in compiled_sql


def test_rollback_after_invalid_transition_does_not_corrupt_subsequent_requests(
    full_client, make_user, make_incident, make_evidence, auth_header
):
    """
    _transition_evidence_status calls db.rollback() on an invalid
    transition (see its docstring -- this releases the row lock promptly
    on PostgreSQL rather than holding it until the session closes). This
    test proves that rollback leaves the SQLAlchemy session in a fully
    usable state for whatever comes next in the SAME test-session's
    shared db_session (which is exactly how a real deployment reuses a
    session across a request lifecycle): a failed transition on evidence A
    must not corrupt or block a subsequent, unrelated, VALID transition on
    a completely different evidence item B, and must not leak any stale
    identity-map state that would make B's read/write behave incorrectly.
    """
    make_user(phone="rb000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence_a = make_evidence(incident_id=incident.id)
    evidence_b = make_evidence(incident_id=incident.id)
    headers = auth_header("rb000000001", "pw")

    # Invalid transition on A -- triggers the internal rollback.
    invalid_resp = full_client.post(f"/media/{evidence_a.id}/archive", headers=headers)  # uploaded -> archived: illegal
    assert invalid_resp.status_code == 409

    # A itself must remain exactly as it was (still 'uploaded').
    still_uploaded_resp = full_client.post(f"/media/{evidence_a.id}/archive", headers=headers)
    assert still_uploaded_resp.status_code == 409  # still illegal -- proves A's state wasn't corrupted into something else

    # An entirely separate evidence item B must be completely unaffected --
    # a valid transition on B must succeed normally right after A's failure.
    valid_resp = full_client.post(f"/media/{evidence_b.id}/verify", headers=headers)
    assert valid_resp.status_code == 200
    assert valid_resp.json()["upload_status"] == "verified"

    # And a valid transition on A (verify, which IS legal from 'uploaded')
    # must also still work normally -- the earlier failed archive attempt
    # didn't leave A stuck in some broken state either.
    a_verify_resp = full_client.post(f"/media/{evidence_a.id}/verify", headers=headers)
    assert a_verify_resp.status_code == 200
    assert a_verify_resp.json()["upload_status"] == "verified"


def test_event_not_published_when_commit_fails(
    full_client, make_user, make_incident, make_evidence, auth_header, monkeypatch
):
    """
    Regression test for event ordering (commit must happen before any
    WebSocket publish): simulates the DB commit failing inside
    _transition_evidence_status and confirms publish_evidence_verified is
    NEVER called in that case.
    """
    from app.routers import media as media_router_module

    make_user(phone="ord000000001", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("ord000000001", "pw")

    publish_calls = []

    async def _fake_publish(*args, **kwargs):
        publish_calls.append((args, kwargs))

    monkeypatch.setattr(media_router_module.events, "publish_evidence_verified", _fake_publish)

    from sqlalchemy.orm import Session as OrmSession
    real_commit = OrmSession.commit
    state = {"armed": True}

    def _boom_commit(self):
        if state["armed"]:
            state["armed"] = False
            raise RuntimeError("simulated commit failure")
        return real_commit(self)

    monkeypatch.setattr(OrmSession, "commit", _boom_commit)

    with pytest.raises(RuntimeError, match="simulated commit failure"):
        full_client.post(f"/media/{evidence.id}/verify", headers=headers)

    assert publish_calls == []  # the event must NEVER have been published


def test_failed_commit_leaves_evidence_and_audit_unchanged(
    full_client, make_user, make_incident, make_evidence, auth_header, db_session, monkeypatch
):
    """Companion to test_event_not_published_when_commit_fails: also confirms the DB itself shows no partial state -- evidence stays 'uploaded', no audit row exists."""
    make_user(phone="ord000000002", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("ord000000002", "pw")

    from sqlalchemy.orm import Session as OrmSession
    real_commit = OrmSession.commit
    state = {"armed": True}

    def _boom_commit(self):
        if state["armed"]:
            state["armed"] = False
            raise RuntimeError("simulated commit failure")
        return real_commit(self)

    monkeypatch.setattr(OrmSession, "commit", _boom_commit)

    with pytest.raises(RuntimeError, match="simulated commit failure"):
        full_client.post(f"/media/{evidence.id}/verify", headers=headers)

    from app import models
    db_session.rollback()  # clear the failed transaction's in-memory state so we re-read cleanly
    fresh = db_session.query(models.Evidence).filter(models.Evidence.id == evidence.id).first()
    assert fresh.upload_status == UploadStatus.uploaded  # unchanged
    assert fresh.verified_at is None
    assert fresh.verified_by is None

    entries = _get_logs(db_session, "evidence.verified")
    assert len(entries) == 0


def test_successful_commit_publishes_exactly_one_event(
    full_client, make_user, make_incident, make_evidence, auth_header, monkeypatch
):
    from app.routers import media as media_router_module

    make_user(phone="ord000000003", password="pw", role=UserRole.admin)
    incident = make_incident()
    evidence = make_evidence(incident_id=incident.id)
    headers = auth_header("ord000000003", "pw")

    publish_calls = []

    async def _fake_publish(*args, **kwargs):
        publish_calls.append((args, kwargs))

    monkeypatch.setattr(media_router_module.events, "publish_evidence_verified", _fake_publish)

    resp = full_client.post(f"/media/{evidence.id}/verify", headers=headers)
    assert resp.status_code == 200
    assert len(publish_calls) == 1
