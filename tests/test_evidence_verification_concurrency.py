"""
Genuine concurrent-request test for evidence verification (see
app/routers/media.py::_transition_evidence_status), against a real MongoDB
replica set.

DESIGN NOTE: the old Postgres version of this file also proved
`SELECT ... FOR UPDATE` genuinely BLOCKS a second connection until the
first commits (a pessimistic-locking behavior). That has no analog here on
purpose: `_transition_evidence_status` now uses an atomic
`find_one_and_update` compare-and-swap, which never blocks at all -- a
losing concurrent request is rejected immediately (no lock-wait window to
measure), which is a strictly simpler and equally-safe guarantee. The
"two concurrent requests can never both win" property is what's tested
below; there is nothing left to prove about blocking/wait-time.

Needs a reachable MongoDB replica set (see tests/conftest.py's
requires_mongo / TEST_MONGODB_URL) -- skips otherwise.
"""
import asyncio
import uuid as uuid_module

import pytest

from conftest import requires_mongo

pytestmark = [pytest.mark.concurrency, requires_mongo]


async def test_genuine_simultaneous_race_verify_vs_reject_exactly_one_winner(mongo_db):
    """
    Both tasks call the real `_transition_evidence_status` for the SAME
    evidence document at essentially the same instant (synchronized via an
    `asyncio.Barrier`, not a sleep), one attempting uploaded->verified and
    the other uploaded->rejected. Whichever task's atomic
    `find_one_and_update` actually reaches the server first wins -- that is
    determined by MongoDB's own write ordering, not by anything this test
    controls. What IS asserted, and what actually matters:
      - both tasks run without raising anything other than the expected
        HTTPException(409) for the loser
      - exactly one of them is a real transition and the other is a 409
      - the final database state is EXACTLY ONE of verified/rejected, never
        both, never left at 'uploaded', never any other value
      - the loser produced NO audit row for its attempted action
    """
    from app import models
    from app.routers.media import _transition_evidence_status
    from fastapi import HTTPException

    admin_user = models.User(
        phone=f"pgtest-race-{uuid_module.uuid4().hex[:10]}",
        role=models.UserRole.admin,
        status=models.UserStatus.active,
    )
    await admin_user.insert()

    incident = models.Incident(location=models.GeoPoint(coordinates=[3, 3]), status=models.IncidentStatus.new)
    await incident.insert()

    evidence = models.Evidence(incident_id=incident.id, type=models.MediaType.photo, upload_status=models.UploadStatus.uploaded)
    await evidence.insert()

    barrier = asyncio.Barrier(2)

    async def attempt(target_status, action, key):
        await barrier.wait()  # both tasks proceed to their atomic update at essentially the same instant
        try:
            await _transition_evidence_status(evidence.id, target_status, admin_user, action)
            return key, "succeeded"
        except HTTPException as exc:
            return key, f"rejected_{exc.status_code}"

    outcomes = dict(await asyncio.gather(
        attempt(models.UploadStatus.verified, "evidence.verified", "verify"),
        attempt(models.UploadStatus.rejected, "evidence.rejected", "reject"),
    ))

    results = {outcomes.get("verify"), outcomes.get("reject")}
    # Exactly one side succeeded, the other was rejected with 409 -- never both, never neither.
    assert results == {"succeeded", "rejected_409"}, f"Unexpected race outcome: {outcomes}"

    final = await models.Evidence.get(evidence.id)
    assert final.upload_status.value in ("verified", "rejected")

    verified_audit = await models.AuditLog.find(
        models.AuditLog.evidence_id == evidence.id, models.AuditLog.action == "evidence.verified"
    ).to_list()
    rejected_audit = await models.AuditLog.find(
        models.AuditLog.evidence_id == evidence.id, models.AuditLog.action == "evidence.rejected"
    ).to_list()

    if final.upload_status == models.UploadStatus.verified:
        assert outcomes["verify"] == "succeeded"
        assert len(verified_audit) == 1
        assert len(rejected_audit) == 0  # the loser created no audit row
    else:
        assert outcomes["reject"] == "succeeded"
        assert len(rejected_audit) == 1
        assert len(verified_audit) == 0  # the loser created no audit row
