"""
Officer duty sessions, genuine location ingestion, freshness, zones, tracking
read model, location-history access control and retention.
"""
import asyncio
import datetime

import pytest

from app import models
from app.models import UserRole
from app.services import tracking, zones

pytestmark = pytest.mark.usefixtures("mongo_db")

PW = "correct-horse-battery"


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture()
def published(monkeypatch):
    """Records every constable.location_updated / zone_changed event the ingestion path publishes."""
    from app.services import events

    calls = {"location": [], "zone": []}

    async def _loc(**kw):
        calls["location"].append(kw)

    async def _zone(**kw):
        calls["zone"].append(kw)

    monkeypatch.setattr(events, "publish_constable_location_updated", _loc)
    monkeypatch.setattr(events, "publish_constable_zone_changed", _zone)
    return calls


async def _post(full_client, headers, body):
    return await full_client.post("/constables/me/location", json=body, headers=headers)


# ---------------------------------------------------------------------------
# Duty sessions & device enrolment
# ---------------------------------------------------------------------------
async def test_location_rejected_without_active_duty_session(full_client, make_constable, auth_header, fix):
    await make_constable(phone="t100000001")
    headers = await auth_header("t100000001", PW)
    resp = await _post(full_client, headers, fix(seq=1))
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "no_active_duty_session"


async def test_pending_device_cannot_start_duty(full_client, make_constable, auth_header):
    await make_constable(phone="t100000002")
    headers = await auth_header("t100000002", PW)
    reg = await full_client.post("/devices/register", json={"device_identifier": "DEV-PEND", "platform": "android"}, headers=headers)
    assert reg.json()["enrolment_status"] == "pending"
    resp = await full_client.post("/constables/me/duty-session/start", json={"device_identifier": "DEV-PEND"}, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "device_not_approved"


async def test_cannot_start_duty_on_someone_elses_or_unknown_device(full_client, make_constable, auth_header, go_on_duty):
    other = await go_on_duty(phone="t100000003")
    await make_constable(phone="t100000004")
    headers = await auth_header("t100000004", PW)
    resp = await full_client.post(
        "/constables/me/duty-session/start", json={"device_identifier": other["device"].device_identifier}, headers=headers
    )
    assert resp.status_code == 404
    resp = await full_client.post("/constables/me/duty-session/start", json={"device_identifier": "nope"}, headers=headers)
    assert resp.status_code == 404


async def test_start_duty_is_idempotent_and_single_device(full_client, go_on_duty):
    duty = await go_on_duty(phone="t100000005")
    again = await full_client.post(
        "/constables/me/duty-session/start", json={"device_identifier": duty["device"].device_identifier}, headers=duty["headers"]
    )
    assert again.status_code == 200 and again.json()["session"]["id"] == duty["session_id"]

    second = models.Device(constable_id=duty["constable"].id, device_identifier="DEV-SECOND", enrolment_status=models.EnrolmentStatus.approved)
    await second.insert()
    conflict = await full_client.post("/constables/me/duty-session/start", json={"device_identifier": "DEV-SECOND"}, headers=duty["headers"])
    assert conflict.status_code == 409
    assert await models.DutySession.find(models.DutySession.constable_id == duty["constable"].id).count() == 1


async def test_stop_duty_ends_tracking_and_is_idempotent(full_client, go_on_duty, fix):
    duty = await go_on_duty(phone="t100000006")
    assert (await _post(full_client, duty["headers"], fix(seq=1))).status_code == 200
    stop = await full_client.post("/constables/me/duty-session/stop", headers=duty["headers"])
    assert stop.status_code == 200 and stop.json()["on_duty"] is False and stop.json()["tracking_enabled"] is False
    assert (await full_client.post("/constables/me/duty-session/stop", headers=duty["headers"])).status_code == 200
    status_ = await full_client.get("/constables/me/duty-session", headers=duty["headers"])
    assert status_.json() == {"on_duty": False, "session": None, "tracking_enabled": False}

    resp = await _post(full_client, duty["headers"], fix(seq=2))
    assert resp.status_code == 409 and resp.json()["detail"]["code"] == "no_active_duty_session"


async def test_queued_fix_recorded_during_duty_is_accepted_after_stop_but_later_fix_is_not(full_client, go_on_duty, fix):
    duty = await go_on_duty(phone="t100000007")
    await full_client.post("/constables/me/duty-session/stop", headers=duty["headers"])
    sid = duty["session_id"]
    ok = await _post(full_client, duty["headers"], fix(seq=1, age_seconds=0.0, duty_session_id=sid))
    assert ok.status_code == 200  # recorded just now, i.e. inside the end-grace window
    # A fix recorded well after the session ended must be refused
    late = await _post(full_client, duty["headers"], fix(seq=2, age_seconds=-30.0, duty_session_id=sid))
    assert late.status_code in (409, 422)


async def test_cannot_post_into_another_officers_duty_session(full_client, go_on_duty, fix):
    a = await go_on_duty(phone="t100000008")
    b = await go_on_duty(phone="t100000009")
    resp = await _post(full_client, b["headers"], fix(seq=1, duty_session_id=a["session_id"]))
    assert resp.status_code == 404 and resp.json()["detail"]["code"] == "duty_session_not_found"


async def test_revoking_device_ends_duty(full_client, make_user, auth_header, go_on_duty, fix):
    duty = await go_on_duty(phone="t100000010")
    await make_user(phone="t1admin10", password="pw", role=UserRole.admin)
    admin = await auth_header("t1admin10", "pw")
    resp = await full_client.post(f"/devices/{duty['device'].id}/enrolment/revoke", headers=admin)
    assert resp.status_code == 200 and resp.json()["enrolment_status"] == "revoked"
    assert (await _post(full_client, duty["headers"], fix(seq=1))).status_code == 409
    session = await models.DutySession.get(duty["session_id"])
    assert session.status == models.DutySessionStatus.ended and session.end_reason == "device_revoked"


async def test_only_admin_can_approve_devices(full_client, make_user, make_constable, auth_header):
    await make_user(phone="t1cr11", password="pw", role=UserRole.control_room)
    _, c = await make_constable(phone="t100000011")
    dev = models.Device(constable_id=c.id, device_identifier="DEV-11", enrolment_status=models.EnrolmentStatus.pending)
    await dev.insert()
    cr = await auth_header("t1cr11", "pw")
    assert (await full_client.post(f"/devices/{dev.id}/enrolment/approve", headers=cr)).status_code == 403


# ---------------------------------------------------------------------------
# Ingestion validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "overrides,code",
    [
        ({"is_mock_provider": True}, "mock_location_rejected"),
        ({"lat": 0.0, "lon": 0.0}, "invalid_coordinates"),
        ({"age_seconds": -600.0}, "timestamp_in_future"),
        ({"age_seconds": 3 * 86400.0}, "fix_too_old"),
        ({"age_seconds": 3 * 3600.0}, "fix_before_duty_start"),
    ],
)
async def test_invalid_fixes_are_rejected_with_a_code(full_client, go_on_duty, fix, overrides, code):
    duty = await go_on_duty(phone="t100000012")
    resp = await _post(full_client, duty["headers"], fix(seq=1, **overrides))
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["code"] == code
    assert await models.ConstableLocation.find().count() == 0


@pytest.mark.parametrize("missing", ["accuracy", "recorded_at", "sequence_number"])
async def test_required_fields_cannot_be_omitted(full_client, go_on_duty, fix, missing):
    duty = await go_on_duty(phone="t100000013")
    body = fix(seq=1)
    body.pop(missing)
    assert (await _post(full_client, duty["headers"], body)).status_code == 422


async def test_fix_from_a_different_device_identifier_is_rejected(full_client, go_on_duty, fix):
    duty = await go_on_duty(phone="t100000014")
    resp = await _post(full_client, duty["headers"], fix(seq=1, device_identifier="SOME-OTHER-PHONE"))
    assert resp.status_code == 403 and resp.json()["detail"]["code"] == "device_mismatch"


async def test_unauthenticated_and_non_constable_cannot_post_location(full_client, make_user, auth_header, fix):
    assert (await full_client.post("/constables/me/location", json=fix(seq=1))).status_code == 401
    await make_user(phone="t1admin15", password="pw", role=UserRole.admin)
    admin = await auth_header("t1admin15", "pw")
    assert (await _post(full_client, admin, fix(seq=1))).status_code == 403


async def test_legacy_location_endpoints_are_retired(full_client, go_on_duty, make_user, auth_header):
    duty = await go_on_duty(phone="t100000016")
    body = {"location_lon": 80.0, "location_lat": 16.0}
    assert (await full_client.post(f"/constables/{duty['constable'].id}/location", json=body, headers=duty["headers"])).status_code == 410
    await make_user(phone="t1admin16", password="pw", role=UserRole.admin)
    admin = await auth_header("t1admin16", "pw")
    assert (await full_client.post(f"/constables/{duty['constable'].id}/location", json=body, headers=admin)).status_code == 410
    assert await models.ConstableLocation.find().count() == 0  # no way to inject a position for someone else


async def test_location_rate_limit(full_client, go_on_duty, fix, monkeypatch):
    monkeypatch.setenv("LOCATION_RATE_LIMIT_PER_MINUTE", "2")
    duty = await go_on_duty(phone="t100000017")
    codes = [(await _post(full_client, duty["headers"], fix(seq=i))).status_code for i in range(1, 4)]
    assert codes == [200, 200, 429]


# ---------------------------------------------------------------------------
# Exactly-once, ordering, buffering
# ---------------------------------------------------------------------------
async def test_duplicate_fix_is_idempotent(full_client, go_on_duty, fix, published):
    duty = await go_on_duty(phone="t100000018")
    body = fix(seq=7)
    first = await _post(full_client, duty["headers"], body)
    second = await _post(full_client, duty["headers"], body)
    assert first.json()["result"] == "accepted"
    assert second.status_code == 200 and second.json()["result"] == "duplicate"
    assert await models.ConstableLocation.find(models.ConstableLocation.constable_id == duty["constable"].id).count() == 1
    assert len(published["location"]) == 1  # a replay never emits a second live event


async def test_concurrent_duplicates_create_exactly_one_record(full_client, go_on_duty, fix, published):
    duty = await go_on_duty(phone="t100000019")
    body = fix(seq=3)
    results = await asyncio.gather(*[_post(full_client, duty["headers"], body) for _ in range(6)])
    assert all(r.status_code == 200 for r in results)
    assert sorted(r.json()["result"] for r in results).count("accepted") == 1
    assert await models.ConstableLocation.find().count() == 1
    assert len(published["location"]) == 1


async def test_late_older_fix_is_history_only_and_does_not_move_the_marker(full_client, go_on_duty, fix, published):
    duty = await go_on_duty(phone="t100000020")
    newer = await _post(full_client, duty["headers"], fix(seq=2, lat=16.50, lon=80.60, age_seconds=5))
    older = await _post(full_client, duty["headers"], fix(seq=1, lat=16.40, lon=80.50, age_seconds=60))
    assert newer.json()["projection_advanced"] is True
    assert older.json()["result"] == "accepted_history" and older.json()["projection_advanced"] is False

    c = await models.Constable.get(duty["constable"].id)
    assert c.last_location_point.coordinates == [80.60, 16.50]
    assert await models.ConstableLocation.find().count() == 2  # history keeps both
    assert len(published["location"]) == 1  # only the genuinely newer fix moved the officer


async def test_buffered_old_fix_is_never_live(full_client, make_user, auth_header, go_on_duty, fix):
    duty = await go_on_duty(phone="t100000021")
    resp = await _post(full_client, duty["headers"], fix(seq=1, age_seconds=400))  # sat in the phone's queue ~7 minutes
    assert resp.json()["buffered"] is True
    await make_user(phone="t1cr21", password="pw", role=UserRole.control_room)
    cr = await auth_header("t1cr21", "pw")
    snap = (await full_client.get("/tracking/officers", headers=cr)).json()
    row = next(o for o in snap["officers"] if o["constable_id"] == str(duty["constable"].id))
    assert row["tracking_state"] == "stale"  # judged on recorded_at, not on when the server got it
    assert row["position"]["buffered"] is True and row["position"]["age_seconds"] >= 399


async def test_batch_flush_reports_each_item_and_dedupes(full_client, go_on_duty, fix, published):
    duty = await go_on_duty(phone="t100000022")
    await _post(full_client, duty["headers"], fix(seq=1, age_seconds=120))
    batch = {"fixes": [
        fix(seq=1, age_seconds=120),                      # already ingested -> duplicate
        fix(seq=2, age_seconds=100),                      # new
        fix(seq=3, age_seconds=80),                       # new
        fix(seq=4, lat=0.0, lon=0.0, age_seconds=60),     # invalid -> rejected, must not block the rest
    ]}
    resp = await full_client.post("/constables/me/location/batch", json=batch, headers=duty["headers"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["total"], body["accepted"], body["duplicate"], body["rejected"]) == (4, 2, 1, 1)
    rejected = [r for r in body["results"] if r["result"] == "rejected"][0]
    assert rejected["sequence_number"] == 4 and rejected["code"] == "invalid_coordinates"
    c = await models.Constable.get(duty["constable"].id)
    assert c.last_location_sequence == 3  # projection ended on the newest fix


async def test_reconnect_recovery_does_not_duplicate_after_partial_batch(full_client, go_on_duty, fix):
    """Phone retries the whole queue after a dropped response: nothing is stored twice."""
    duty = await go_on_duty(phone="t100000023")
    batch = {"fixes": [fix(seq=i, age_seconds=100 - i * 10) for i in range(1, 6)]}
    first = await full_client.post("/constables/me/location/batch", json=batch, headers=duty["headers"])
    retry = await full_client.post("/constables/me/location/batch", json=batch, headers=duty["headers"])
    assert first.json()["accepted"] == 5
    assert retry.json()["duplicate"] == 5 and retry.json()["accepted"] == 0
    assert await models.ConstableLocation.find().count() == 5


# ---------------------------------------------------------------------------
# Freshness policy (pure)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "age,expected",
    [(5, "live"), (59, "live"), (120, "delayed"), (299, "delayed"), (600, "stale"), (1700, "stale"), (4000, "unavailable")],
)
def test_tracking_state_thresholds(age, expected):
    now = _now()
    st = tracking.compute_tracking_state(on_duty=True, recorded_at=now - datetime.timedelta(seconds=age), server_received_at=now, now=now)
    assert st.state == expected


def test_tracking_state_off_duty_and_no_fix_are_unavailable():
    now = _now()
    assert tracking.compute_tracking_state(on_duty=False, recorded_at=now, now=now).reason == "off_duty"
    st = tracking.compute_tracking_state(on_duty=True, recorded_at=None, now=now)
    assert (st.state, st.reason) == ("unavailable", "no_fix_yet")


# ---------------------------------------------------------------------------
# Zone transition policy (pure) -- boundary / accuracy / overlap cases
# ---------------------------------------------------------------------------
def _zone(code, lon0, lon1, priority=0):
    ring = [[lon0, 16.50], [lon1, 16.50], [lon1, 16.51], [lon0, 16.51], [lon0, 16.50]]
    return models.EventZone(code=code, name=code, polygon=models.GeoPolygon(coordinates=[ring]), priority=priority)


def _resolve(current, matched, lon, lat=16.505, acc=5.0, candidate=None, count=0, evaluated=True, all_zones=()):
    by_code = {z.code: z for z in list(all_zones) + list(matched)}
    return zones.resolve_zone_transition(
        current_zone=current, evaluated_before=evaluated, candidate=candidate, candidate_count=count,
        matched=matched, zones_by_code=by_code, longitude=lon, latitude=lat, accuracy=acc,
    )


def test_zone_requires_consecutive_confirmations():
    a, b = _zone("A", 80.600, 80.610), _zone("B", 80.620, 80.630)
    r1 = _resolve("A", [b], 80.625, all_zones=[a])
    assert (r1.zone_code, r1.status, r1.changed, r1.candidate_count) == ("A", "PENDING", False, 1)
    r2 = _resolve("A", [b], 80.625, candidate="B", count=1, all_zones=[a])
    assert (r2.zone_code, r2.status, r2.changed) == ("B", "CONFIRMED", True)


def test_zone_candidate_resets_when_fix_returns_to_current_zone():
    a, b = _zone("A", 80.600, 80.610), _zone("B", 80.620, 80.630)
    r = _resolve("A", [a], 80.605, candidate="B", count=1, all_zones=[b])
    assert (r.zone_code, r.changed, r.candidate, r.candidate_count) == ("A", False, None, 0)


def test_noisy_fix_right_on_a_shared_boundary_never_flips_zone():
    a, b = _zone("A", 80.600, 80.610), _zone("B", 80.610, 80.620)
    # 80.61004 is ~4 m inside B -- closer to the boundary than the margin
    for n in range(5):
        r = _resolve("A", [b], 80.61004, candidate="B", count=n, all_zones=[a])
        assert r.zone_code == "A" and r.changed is False and r.status == "PENDING"


def test_inaccurate_fix_never_changes_zone():
    a, b = _zone("A", 80.600, 80.610), _zone("B", 80.620, 80.630)
    r = _resolve("A", [b], 80.625, acc=120.0, candidate="B", count=5, all_zones=[a])
    assert (r.zone_code, r.status, r.changed) == ("A", "UNCERTAIN", False)
    r = _resolve("A", [b], 80.625, acc=None, all_zones=[a])
    assert r.status == "UNCERTAIN" and r.changed is False


def test_first_evaluation_is_accepted_immediately_and_outside_is_reported():
    a = _zone("A", 80.600, 80.610)
    r = _resolve(None, [a], 80.605, evaluated=False)
    assert (r.zone_code, r.status, r.changed) == ("A", "CONFIRMED", True)
    r = _resolve(None, [], 80.700, evaluated=False)
    assert (r.zone_code, r.status, r.changed) == (None, "OUTSIDE", False)


def test_leaving_all_zones_also_needs_confirmation():
    a = _zone("A", 80.600, 80.610)
    r = _resolve("A", [], 80.700, all_zones=[a])
    assert (r.zone_code, r.status, r.changed) == ("A", "PENDING", False)
    assert r.candidate == zones.OUTSIDE_CANDIDATE and r.candidate_count == 1
    r = _resolve("A", [], 80.700, candidate=zones.OUTSIDE_CANDIDATE, count=1, all_zones=[a])
    assert (r.zone_code, r.status, r.changed) == (None, "OUTSIDE", True)


def test_overlap_higher_priority_wins_but_only_after_confirmation():
    outer, inner = _zone("OUTER", 80.600, 80.620, 1), _zone("INNER", 80.605, 80.615, 9)
    r = _resolve("OUTER", [inner, outer], 80.610, all_zones=[outer])
    assert r.zone_code == "OUTER" and r.changed is False and r.raw_zone_code == "INNER"
    r = _resolve("OUTER", [inner, outer], 80.610, candidate="INNER", count=1, all_zones=[outer])
    assert r.zone_code == "INNER" and r.changed is True


# ---------------------------------------------------------------------------
# Tracking read model: authorisation, assigned vs detected zone, network honesty
# ---------------------------------------------------------------------------
async def test_tracking_snapshot_is_role_and_station_scoped(full_client, make_user, make_station, auth_header, go_on_duty, fix):
    st_a, st_b = await make_station(name="A"), await make_station(name="B")
    a = await go_on_duty(phone="t100000030", station_id=st_a.id)
    b = await go_on_duty(phone="t100000031", station_id=st_b.id)
    for d in (a, b):
        await _post(full_client, d["headers"], fix(seq=1))
    await make_user(phone="t1st30", password="pw", role=UserRole.station, station_id=st_a.id)
    await make_user(phone="t1cr30", password="pw", role=UserRole.control_room)
    await make_user(phone="t1ci30", password="pw", role=UserRole.citizen)

    station = await auth_header("t1st30", "pw")
    ids = {o["constable_id"] for o in (await full_client.get("/tracking/officers", headers=station)).json()["officers"]}
    assert ids == {str(a["constable"].id)}
    cr = await auth_header("t1cr30", "pw")
    ids = {o["constable_id"] for o in (await full_client.get("/tracking/officers", headers=cr)).json()["officers"]}
    assert ids == {str(a["constable"].id), str(b["constable"].id)}
    assert (await full_client.get("/tracking/officers", headers=a["headers"])).status_code == 403  # constables never
    assert (await full_client.get("/tracking/officers", headers=await auth_header("t1ci30", "pw"))).status_code == 403
    assert (await full_client.get("/tracking/officers")).status_code == 401
    assert (await full_client.get(f"/tracking/officers/{b['constable'].id}", headers=station)).status_code == 403


async def test_off_duty_officer_position_is_hidden(full_client, make_user, auth_header, go_on_duty, fix):
    duty = await go_on_duty(phone="t100000032")
    await _post(full_client, duty["headers"], fix(seq=1))
    await full_client.post("/constables/me/duty-session/stop", headers=duty["headers"])
    await make_user(phone="t1cr32", password="pw", role=UserRole.control_room)
    row = (await full_client.get(f"/tracking/officers/{duty['constable'].id}", headers=await auth_header("t1cr32", "pw"))).json()
    assert row["on_duty"] is False and row["position"] is None
    assert row["tracking_state"] == "unavailable" and row["unavailable_reason"] == "off_duty"


async def test_on_duty_officer_with_no_fix_is_unavailable_not_invented(full_client, make_user, auth_header, go_on_duty):
    duty = await go_on_duty(phone="t100000033")
    await make_user(phone="t1cr33", password="pw", role=UserRole.control_room)
    row = (await full_client.get(f"/tracking/officers/{duty['constable'].id}", headers=await auth_header("t1cr33", "pw"))).json()
    assert row["on_duty"] is True and row["position"] is None
    assert (row["tracking_state"], row["unavailable_reason"]) == ("unavailable", "no_fix_yet")


async def test_assigned_zone_is_separate_from_detected_zone(full_client, make_user, auth_header, go_on_duty, fix):
    await make_user(phone="t1admin34", password="pw", role=UserRole.admin)
    await make_user(phone="t1cr34", password="pw", role=UserRole.control_room)
    admin, cr = await auth_header("t1admin34", "pw"), await auth_header("t1cr34", "pw")
    ring = lambda lon0, lon1: [[[lon0, 16.50], [lon1, 16.50], [lon1, 16.51], [lon0, 16.51], [lon0, 16.50]]]
    for code, lon0, lon1 in (("Z-GATE", 80.600, 80.610), ("Z-TEMPLE", 80.620, 80.630)):
        r = await full_client.post("/event-zones/", json={"code": code, "name": code, "coordinates": ring(lon0, lon1)}, headers=admin)
        assert r.status_code == 200, r.text
    duty = await go_on_duty(phone="t100000034")
    cid = duty["constable"].id

    assert (await full_client.put(f"/tracking/officers/{cid}/assigned-zone", json={"zone_code": "Z-TEMPLE"}, headers=cr)).status_code == 403
    assert (await full_client.put(f"/tracking/officers/{cid}/assigned-zone", json={"zone_code": "NOPE"}, headers=admin)).status_code == 422
    ok = await full_client.put(f"/tracking/officers/{cid}/assigned-zone", json={"zone_code": "Z-TEMPLE"}, headers=admin)
    assert ok.status_code == 200 and ok.json()["assigned_zone_code"] == "Z-TEMPLE"

    await _post(full_client, duty["headers"], fix(seq=1, lon=80.605, lat=16.505))  # physically at the GATE
    row = (await full_client.get(f"/tracking/officers/{cid}", headers=cr)).json()
    assert row["assigned_zone_code"] == "Z-TEMPLE" and row["detected_zone_code"] == "Z-GATE"
    assert row["in_assigned_zone"] is False and row["zone_status"] == "CONFIRMED"
    audit = await models.AuditLog.find(models.AuditLog.action == "constable.assigned_zone_changed").to_list()
    assert len(audit) == 1


async def test_network_info_only_from_real_sources(full_client, make_user, auth_header, go_on_duty, fix, make_access_point):
    duty = await go_on_duty(phone="t100000035")
    await _post(full_client, duty["headers"], fix(seq=1))
    ap = await make_access_point(code="AP-N1")
    presence = models.PolicePresence(
        device_id=duty["device"].id, constable_id=duty["constable"].id, current_access_point_id=ap.id, current_zone="Z",
        status=models.PresenceConnectionStatus.connected, last_seen_at=_now(), source=models.PresenceEventSource.simulator,
    )
    await presence.insert()
    await make_user(phone="t1cr35", password="pw", role=UserRole.control_room)
    cr = await auth_header("t1cr35", "pw")
    url = f"/tracking/officers/{duty['constable'].id}"

    assert (await full_client.get(url, headers=cr)).json()["network"] is None  # simulator is never shown as telemetry
    presence.source = None  # legacy row of unknown origin
    await presence.save()
    assert (await full_client.get(url, headers=cr)).json()["network"] is None
    presence.source = models.PresenceEventSource.controller
    await presence.save()
    net = (await full_client.get(url, headers=cr)).json()["network"]
    assert net["access_point_code"] == "AP-N1" and net["verified_by_controller"] is True
    assert net["ap_verification_status"] == "registered"  # the AP record itself is still unverified inventory


# ---------------------------------------------------------------------------
# Location history: access control, audit, retention
# ---------------------------------------------------------------------------
async def test_location_history_access_control_and_audit(full_client, make_user, make_station, auth_header, go_on_duty, fix):
    st_a, st_b = await make_station(name="A"), await make_station(name="B")
    duty = await go_on_duty(phone="t100000036", station_id=st_b.id)
    for i in range(1, 4):
        await _post(full_client, duty["headers"], fix(seq=i, age_seconds=30 - i))
    cid = duty["constable"].id
    await make_user(phone="t1cr36", password="pw", role=UserRole.control_room)
    await make_user(phone="t1st36a", password="pw", role=UserRole.station, station_id=st_a.id)
    await make_user(phone="t1st36b", password="pw", role=UserRole.station, station_id=st_b.id)
    await make_user(phone="t1ci36", password="pw", role=UserRole.citizen)

    assert (await full_client.get(f"/tracking/officers/{cid}/history")).status_code == 401
    assert (await full_client.get(f"/tracking/officers/{cid}/history", headers=duty["headers"])).status_code == 403  # not even the officer
    assert (await full_client.get(f"/tracking/officers/{cid}/history", headers=await auth_header("t1ci36", "pw"))).status_code == 403
    assert (await full_client.get(f"/tracking/officers/{cid}/history", headers=await auth_header("t1st36a", "pw"))).status_code == 403
    assert await models.AuditLog.find(models.AuditLog.action == "location_history_viewed").count() == 0  # denied attempts return data to no one

    ok = await full_client.get(f"/tracking/officers/{cid}/history", headers=await auth_header("t1st36b", "pw"))
    assert ok.status_code == 200 and ok.json()["count"] == 3
    ok2 = await full_client.get(f"/tracking/officers/{cid}/history?limit=2", headers=await auth_header("t1cr36", "pw"))
    assert ok2.json()["count"] == 2 and ok2.json()["truncated"] is True

    logs = await models.AuditLog.find(models.AuditLog.action == "location_history_viewed").to_list()
    assert len(logs) == 2
    assert {l.details["constable_id"] for l in logs} == {str(cid)} and {l.details["role"] for l in logs} == {"station", "control_room"}


async def test_retention_purge_removes_only_expired_history(go_on_duty, full_client, fix, monkeypatch):
    from app.services import retention

    monkeypatch.setenv("LOCATION_RETENTION_DAYS", "30")
    duty = await go_on_duty(phone="t100000037")
    await _post(full_client, duty["headers"], fix(seq=1))
    old = models.ConstableLocation(
        constable_id=duty["constable"].id, location=models.GeoPoint(coordinates=[80.0, 16.0]),
        timestamp=_now() - datetime.timedelta(days=45),
    )
    await old.insert()
    assert await retention.purge_location_history() == 1
    assert await models.ConstableLocation.find().count() == 1


# ---------------------------------------------------------------------------
# Safety: tracking never touches emergency recording
# ---------------------------------------------------------------------------
async def test_duty_and_location_never_start_recording_or_streaming(full_client, go_on_duty, fix):
    duty = await go_on_duty(phone="t100000038")
    await _post(full_client, duty["headers"], fix(seq=1))
    assert await models.RecordingSession.find().count() == 0
    assert await models.LiveStreamSession.find().count() == 0
    assert await models.RemoteCommand.find().count() == 0
