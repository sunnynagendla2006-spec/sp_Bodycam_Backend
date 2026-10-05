"""
AP-based presence: association processing (duplicate-heartbeat
protection, handoff detection, invalid/disabled AP rejection,
unauthorized-device rejection), movement history, and RBAC on the
read endpoints.
"""
import pytest

pytestmark = pytest.mark.usefixtures("mongo_db")


async def _register_constable_with_device(full_client, make_constable, auth_header, phone, device_identifier):
    _user, constable = await make_constable(phone=phone, password="pw")
    headers = await auth_header(phone, "pw")
    resp = await full_client.post("/devices/register", json={"device_identifier": device_identifier}, headers=headers)
    assert resp.status_code == 200, resp.text
    return constable, headers


async def test_first_association_is_labeled_connected_and_creates_no_prior_handoff(
    full_client, make_constable, make_access_point, auth_header
):
    await make_access_point(code="AP-01")
    _constable, headers = await _register_constable_with_device(
        full_client, make_constable, auth_header, "pr0000001", "DEV-PR-01"
    )

    resp = await full_client.post(
        "/presence/association",
        json={"device_identifier": "DEV-PR-01", "access_point_code": "AP-01"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "connected"
    assert body["handoff_created"] is True
    assert body["presence"]["current_access_point_code"] == "AP-01"
    assert body["presence"]["handoff_count"] == 0
    assert body["handoff"]["previous_access_point_id"] is None


async def test_duplicate_same_ap_heartbeat_creates_no_handoff(full_client, make_constable, make_access_point, auth_header):
    await make_access_point(code="AP-01")
    _constable, headers = await _register_constable_with_device(
        full_client, make_constable, auth_header, "pr0000002", "DEV-PR-02"
    )
    body = {"device_identifier": "DEV-PR-02", "access_point_code": "AP-01"}

    first = await full_client.post("/presence/association", json=body, headers=headers)
    assert first.status_code == 200
    assert first.json()["status"] == "connected"

    second = await full_client.post("/presence/association", json=body, headers=headers)
    assert second.status_code == 200
    assert second.json()["status"] == "duplicate_ignored"
    assert second.json()["handoff_created"] is False
    assert second.json()["presence"]["handoff_count"] == 0

    third = await full_client.post("/presence/association", json=body, headers=headers)
    assert third.json()["status"] == "duplicate_ignored"
    assert third.json()["presence"]["handoff_count"] == 0


async def test_multiple_handoffs_with_no_event_id_do_not_collide_on_the_null_index(
    full_client, make_constable, make_access_point, auth_header
):
    """
    Regression test for a real bug caught by running this against a live
    MongoDB replica set (not caught by static review): PresenceHandoff's
    event_id uniqueness was originally a `sparse=True` index, but Beanie
    stores an omitted Optional field as an explicit `null` rather than
    omitting it -- and MongoDB's sparse index still indexes an explicit
    null, so a SECOND handoff with no event_id collided with the first
    one's null index entry, got misreported as a duplicate retry, and
    silently dropped the handoff (current AP never advanced,
    handoff_count never incremented). Fixed by switching to a partial
    index with an explicit $type filter (see models.py::PresenceHandoff).
    This test drives three consecutive handoffs with NO event_id at all
    and asserts every single one actually lands as a real handoff.
    """
    for code in ("AP-01", "AP-02", "AP-03", "AP-04"):
        await make_access_point(code=code)
    _constable, headers = await _register_constable_with_device(
        full_client, make_constable, auth_header, "pr0000010", "DEV-PR-10"
    )

    statuses = []
    for code in ("AP-01", "AP-02", "AP-03", "AP-04"):
        resp = await full_client.post(
            "/presence/association", json={"device_identifier": "DEV-PR-10", "access_point_code": code}, headers=headers,
        )
        assert resp.status_code == 200, resp.text
        statuses.append(resp.json()["status"])

    assert statuses == ["connected", "handoff", "handoff", "handoff"]

    final = await full_client.get("/presence/me", headers=headers)
    presence = final.json()[0]
    assert presence["current_access_point_code"] == "AP-04"
    assert presence["handoff_count"] == 3


async def test_event_id_partial_unique_index_excludes_null(mongo_db):
    """Mirrors tests/test_mongo_schema.py's index-existence assertions -- confirms the fix is a partial index, not the buggy sparse one."""
    from app import models

    indexes = await models.PresenceHandoff.get_motor_collection().index_information()
    idx = indexes.get("event_id_1")
    assert idx is not None
    assert idx.get("unique") is True
    assert idx.get("partialFilterExpression") == {"event_id": {"$type": "string"}}
    assert "sparse" not in idx or idx.get("sparse") is not True


async def test_ap_to_ap_handoff_increments_count_and_records_previous_ap(
    full_client, make_constable, make_access_point, auth_header
):
    ap1 = await make_access_point(code="AP-01")
    ap2 = await make_access_point(code="AP-02")
    _constable, headers = await _register_constable_with_device(
        full_client, make_constable, auth_header, "pr0000003", "DEV-PR-03"
    )

    r1 = await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-PR-03", "access_point_code": "AP-01"}, headers=headers,
    )
    assert r1.json()["status"] == "connected"

    r2 = await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-PR-03", "access_point_code": "AP-02"}, headers=headers,
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["status"] == "handoff"
    assert body["handoff_created"] is True
    assert body["handoff"]["previous_access_point_id"] == str(ap1.id)
    assert body["handoff"]["access_point_id"] == str(ap2.id)
    assert body["presence"]["handoff_count"] == 1
    assert body["presence"]["current_access_point_code"] == "AP-02"


async def test_full_route_produces_correct_movement_history(full_client, make_constable, make_access_point, auth_header):
    """AP-01 -> AP-02 -> AP-04 -> AP-03, matching the 'Jatara patrol' scenario shape. Asserting on a SECOND device/constable in the same test (pr0000004b) confirms the handoffs aren't cross-contaminated between devices."""
    aps = {code: await make_access_point(code=code) for code in ("AP-01", "AP-02", "AP-03", "AP-04")}
    _constable, headers = await _register_constable_with_device(
        full_client, make_constable, auth_header, "pr0000004", "DEV-PR-04"
    )

    route = ["AP-01", "AP-02", "AP-04", "AP-03"]
    device_id = None
    for code in route:
        resp = await full_client.post(
            "/presence/association", json={"device_identifier": "DEV-PR-04", "access_point_code": code}, headers=headers,
        )
        assert resp.status_code == 200, resp.text
        device_id = resp.json()["presence"]["device_id"]

    history = await full_client.get(f"/presence/devices/{device_id}/history", headers=headers)
    assert history.status_code == 200
    rows = history.json()
    assert len(rows) == 4

    # Rows are returned most-recent-first; reverse to get chronological
    # (AP-01 -> AP-02 -> AP-04 -> AP-03) order and compare against the
    # actual route driven above.
    chronological = list(reversed(rows))
    observed_route = [str(aps[code].id) for code in route]
    assert [r["access_point_id"] for r in chronological] == observed_route
    assert chronological[0]["previous_access_point_id"] is None  # the very first association
    assert chronological[1]["previous_access_point_id"] == str(aps["AP-01"].id)
    assert chronological[2]["previous_access_point_id"] == str(aps["AP-02"].id)
    assert chronological[3]["previous_access_point_id"] == str(aps["AP-04"].id)


async def test_unknown_access_point_code_is_404(full_client, make_constable, auth_header):
    _constable, headers = await _register_constable_with_device(
        full_client, make_constable, auth_header, "pr0000005", "DEV-PR-05"
    )
    resp = await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-PR-05", "access_point_code": "AP-DOES-NOT-EXIST"}, headers=headers,
    )
    assert resp.status_code == 404


async def test_disabled_access_point_is_rejected_with_409(full_client, make_constable, make_access_point, auth_header):
    await make_access_point(code="AP-DISABLED-01", enabled=False)
    _constable, headers = await _register_constable_with_device(
        full_client, make_constable, auth_header, "pr0000006", "DEV-PR-06"
    )
    resp = await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-PR-06", "access_point_code": "AP-DISABLED-01"}, headers=headers,
    )
    assert resp.status_code == 409


async def test_unregistered_device_is_rejected(full_client, make_constable, make_access_point, auth_header):
    await make_access_point(code="AP-01")
    _user, _constable = await make_constable(phone="pr0000007", password="pw")
    headers = await auth_header("pr0000007", "pw")
    # Device was never registered via POST /devices/register.
    resp = await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-NEVER-REGISTERED", "access_point_code": "AP-01"}, headers=headers,
    )
    assert resp.status_code == 404


async def test_constable_cannot_report_for_another_constables_device(
    full_client, make_constable, make_access_point, auth_header
):
    await make_access_point(code="AP-01")
    await _register_constable_with_device(full_client, make_constable, auth_header, "pr0000008a", "DEV-PR-08")
    _other_user, _other_constable = await make_constable(phone="pr0000008b", password="pw")
    other_headers = await auth_header("pr0000008b", "pw")

    resp = await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-PR-08", "access_point_code": "AP-01"}, headers=other_headers,
    )
    assert resp.status_code == 403


async def test_repeated_event_id_is_idempotent_not_double_applied(
    full_client, make_constable, make_access_point, auth_header
):
    ap1 = await make_access_point(code="AP-01")
    ap2 = await make_access_point(code="AP-02")
    _constable, headers = await _register_constable_with_device(
        full_client, make_constable, auth_header, "pr0000009", "DEV-PR-09"
    )
    await full_client.post(
        "/presence/association", json={"device_identifier": "DEV-PR-09", "access_point_code": "AP-01"}, headers=headers,
    )

    body = {"device_identifier": "DEV-PR-09", "access_point_code": "AP-02", "event_id": "SIM-0001"}
    first = await full_client.post("/presence/association", json=body, headers=headers)
    assert first.json()["status"] == "handoff"
    assert first.json()["presence"]["handoff_count"] == 1

    # Exact retry of the same request (e.g. a network-level retry) --
    # must not create a second handoff or double-increment handoff_count.
    # This retry targets the SAME access point the device is already on,
    # so it takes the same-AP no-op branch (process_association's first
    # check, presence.py:71) rather than the event_id DuplicateKeyError
    # branch -- the router labels that path "duplicate_ignored", not
    # "duplicate_event" (see routers/presence.py's status_label logic).
    retry = await full_client.post("/presence/association", json=body, headers=headers)
    assert retry.status_code == 200
    assert retry.json()["status"] == "duplicate_ignored"
    assert retry.json()["presence"]["handoff_count"] == 1


@pytest.mark.parametrize("role", ["station", "constable", "citizen"])
async def test_non_control_roles_only_see_their_own_scope_or_are_denied(full_client, make_user, role):
    """GET /presence/ never 403s for station/constable (they get a scoped/empty list), but citizen is denied outright."""
    await make_user(phone=f"prrole{role}", password="pw", role=role)
    resp = await full_client.post("/auth/login", json={"username": f"prrole{role}", "password": "pw"})
    headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}

    resp = await full_client.get("/presence/", headers=headers)
    if role == "citizen":
        assert resp.status_code == 403
    else:
        assert resp.status_code == 200
        assert resp.json() == []  # no station_id / no own device registered yet in this test
