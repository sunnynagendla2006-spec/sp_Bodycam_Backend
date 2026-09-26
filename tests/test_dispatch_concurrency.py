"""
Genuine concurrent-dispatch test for incident dispatch (see
app/routers/incidents.py::dispatch_incident) against a real MongoDB
replica set.

Two DIFFERENT incidents, both verified and at the same location, are
dispatched at essentially the same instant (synchronized via an
`asyncio.Barrier`, not an artificial sleep -- a genuine race, no
predetermined winner) while only ONE constable is available. Both dispatch
calls run as concurrent asyncio tasks on the SAME event loop (sharing the
same Motor client, as Motor requires) -- interleaving happens for real at
each `await` boundary, so this genuinely exercises the atomic
`find_one_and_update` compare-and-swap in dispatch_incident against the
real server, not merely single-threaded sequential calls.

Needs a reachable MongoDB replica set (see tests/conftest.py's
requires_mongo / TEST_MONGODB_URL) -- skips otherwise.
"""
import asyncio
import uuid as uuid_module

import pytest

from app import models
from app.routers.incidents import dispatch_incident
from conftest import requires_mongo

pytestmark = [pytest.mark.concurrency, requires_mongo]


async def test_two_simultaneous_dispatches_cannot_double_book_the_same_constable(mongo_db):
    """
    Expected outcome:
      - exactly one of the two dispatch calls returns status="dispatched"
        with that constable_id
      - the other returns status="no_available_constable"
      - exactly one active assignment exists for that constable across
        both incidents
      - the constable's final status is `busy`, not left inconsistent
      - exactly one `incident.dispatched` audit row exists (not two)
    """
    admin_user = models.User(
        phone=f"pgtest-dispatch-{uuid_module.uuid4().hex[:10]}",
        role=models.UserRole.admin,
        status=models.UserStatus.active,
    )
    await admin_user.insert()

    incident_a = models.Incident(location=models.GeoPoint(coordinates=[77.1, 28.6]), status=models.IncidentStatus.verified)
    incident_b = models.Incident(location=models.GeoPoint(coordinates=[77.1, 28.6]), status=models.IncidentStatus.verified)
    await incident_a.insert()
    await incident_b.insert()

    constable_user = models.User(
        phone=f"pgtest-dispatch-c-{uuid_module.uuid4().hex[:10]}",
        role=models.UserRole.constable,
        status=models.UserStatus.active,
    )
    await constable_user.insert()

    constable = models.Constable(
        user_id=constable_user.id,
        badge_number=f"BADGE-{uuid_module.uuid4().hex[:8]}",
        status=models.ConstableStatus.available,
        battery_level=100,
    )
    await constable.insert()

    await models.ConstableLocation(constable_id=constable.id, location=models.GeoPoint(coordinates=[77.1, 28.6])).insert()

    barrier = asyncio.Barrier(2)

    async def attempt(incident_id, key: str):
        await barrier.wait()  # both tasks reach dispatch_incident at essentially the same instant
        response = await dispatch_incident(incident_id, admin_user)
        return key, response

    outcomes = dict(await asyncio.gather(attempt(incident_a.id, "a"), attempt(incident_b.id, "b")))

    statuses = {outcomes["a"].status, outcomes["b"].status}
    assert statuses == {"dispatched", "no_available_constable"}, f"Unexpected outcome: {outcomes}"

    winner_key = "a" if outcomes["a"].status == "dispatched" else "b"
    assert outcomes[winner_key].constable_id == constable.id

    final_constable = await models.Constable.get(constable.id)
    assert final_constable.status == models.ConstableStatus.busy

    fresh_a = await models.Incident.get(incident_a.id)
    fresh_b = await models.Incident.get(incident_b.id)
    active_incidents = [inc for inc in (fresh_a, fresh_b) if inc.active_assignment_id is not None]
    assert len(active_incidents) == 1, f"Constable was double-booked: {[inc.id for inc in active_incidents]}"

    dispatched_audit = await models.AuditLog.find(
        models.AuditLog.action == "incident.dispatched",
        models.AuditLog.user_id == admin_user.id,
    ).to_list()
    assert len(dispatched_audit) == 1, f"Expected exactly one dispatch audit row, got {len(dispatched_audit)}"
