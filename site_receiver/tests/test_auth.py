"""Grant verification, session tokens, health minimality and unauthenticated rate limiting at the receiver."""
import time
import uuid

import pytest
from jose import jwt

from .conftest import DEVICE_IDENT, OTHER_PRIV, PRIV, PUB, SITE_ID, ISSUER, make_grant




async def test_valid_grant_gets_session_bound_to_grant(receiver):
    r = await receiver.session()
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["receiver"]["site_id"] == SITE_ID
    claims = jwt.get_unverified_claims(body["access_token"])
    assert claims["site"] == SITE_ID and claims["typ"] == "rcv"
    assert claims["exp"] <= claims["gexp"], "a session must never outlive its grant"


async def test_session_capped_at_grant_expiry(receiver):
    r = await receiver.session(make_grant(exp_in=30))
    assert r.status_code == 200 and r.json()["expires_in"] <= 30


async def test_signature_from_another_key_is_rejected(receiver):
    r = await receiver.session(make_grant(OTHER_PRIV))
    assert r.status_code == 401 and r.json()["error"]["code"] == "grant_invalid"


@pytest.mark.parametrize("alg", ["HS256"])
async def test_hmac_forged_with_public_key_is_rejected(receiver, alg):
    # classic algorithm confusion: sign HS256 using the PUBLIC key text as the secret
    import base64, hashlib, hmac, json
    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = b64(json.dumps({"iss": ISSUER, "sub": "x", "jti": "j", "site": SITE_ID, "dev": "d", "iat": int(time.time()), "exp": int(time.time()) + 600, "ops": ["session", "upload"]}).encode())
    sig = b64(hmac.new(PUB.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    forged = f"{head}.{body}.{sig}"
    r = await receiver.session(forged)
    assert r.status_code == 401


async def test_alg_none_is_rejected(receiver):
    import base64, json
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'iss': ISSUER, 'sub': 'x', 'jti': 'j', 'site': SITE_ID, 'dev': 'd', 'exp': int(time.time()) + 600, 'ops': ['session']})}."
    r = await receiver.session(token)
    assert r.status_code == 401


async def test_wrong_issuer_wrong_site_expired(receiver):
    assert (await receiver.session(make_grant(issuer="someone-else"))).status_code == 401
    r = await receiver.session(make_grant(site=str(uuid.uuid4())))
    assert r.status_code == 403 and r.json()["error"]["code"] == "grant_wrong_site"
    r = await receiver.session(make_grant(exp_in=-600))
    assert r.status_code == 401 and r.json()["error"]["code"] == "grant_expired"


async def test_pinned_key_id_is_enforced(env, tmp_path):
    from site_receiver import main as m

    env(RECEIVER_GRANT_KEY_ID="key-2026")
    app = m.create_app()
    async with app.router.lifespan_context(app):
        import httpx

        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://r")
        bad = await c.post("/v1/auth/session", json={"grant": make_grant(kid="key-OTHER")})
        none = await c.post("/v1/auth/session", json={"grant": make_grant()})
        good = await c.post("/v1/auth/session", json={"grant": make_grant(kid="key-2026")})
        await c.aclose()
    assert bad.status_code == 401 and none.status_code == 401 and good.status_code == 200


async def test_missing_session_operation_cannot_open_session(receiver):
    r = await receiver.session(make_grant(ops=("upload",)))
    assert r.status_code == 403 and r.json()["error"]["code"] == "operation_not_permitted"


async def test_upload_requires_upload_operation(receiver):
    h = await receiver.token(ops=("session", "live"))
    r = await receiver.client.post("/v1/recordings", headers=h, json={"recording_id": str(uuid.uuid4()), "started_at": "2026-01-01T00:00:00Z"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "operation_not_permitted"


async def test_device_identifier_must_match_grant(receiver):
    r = await receiver.session(make_grant(), device="a-different-phone")
    assert r.status_code == 403 and r.json()["error"]["code"] == "device_mismatch"


async def test_future_issued_grant_beyond_skew_is_rejected(receiver):
    # iat an hour in the future: clock-skew tolerance is minutes, not hours
    r = await receiver.session(make_grant(iat_offset=3600))
    assert r.status_code in (401, 403), "a grant issued in the future must not be accepted"


async def test_small_clock_skew_is_tolerated(receiver):
    assert (await receiver.session(make_grant(iat_offset=60))).status_code == 200
    assert (await receiver.session(make_grant(exp_in=-60))).status_code == 200, "an expiry 60 s ago is inside the 2-minute skew allowance"
    assert (await receiver.session(make_grant(exp_in=-300))).status_code == 401


async def test_revoked_grant_refused_and_existing_session_stops(receiver):
    jti = str(uuid.uuid4())
    h = await receiver.token(jti=jti)
    assert (await receiver.client.get("/v1/config", headers=h)).status_code == 200
    receiver.app.state.store.replace_revoked([jti])  # what a sync from the control room does
    r = await receiver.client.get("/v1/config", headers=h)
    assert r.status_code == 403 and r.json()["error"]["code"] == "grant_revoked"
    assert (await receiver.session(make_grant(jti=jti))).status_code == 403
    receiver.app.state.store.replace_revoked([])  # the control room's list is authoritative
    assert (await receiver.client.get("/v1/config", headers=h)).status_code == 200


async def test_session_token_signed_with_other_secret_is_rejected(receiver):
    now = int(time.time())
    forged = jwt.encode({"typ": "rcv", "sub": "s", "dev": "d", "site": SITE_ID, "gid": "g", "ops": ["session", "upload"], "iat": now, "exp": now + 600}, "another-secret", algorithm="HS256")
    r = await receiver.client.get("/v1/config", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


async def test_session_token_for_another_site_is_rejected(receiver):
    now = int(time.time())
    tok = jwt.encode({"typ": "rcv", "sub": "s", "dev": "d", "site": str(uuid.uuid4()), "gid": "g", "ops": ["upload"], "iat": now, "exp": now + 600}, "unit-test-session-secret-not-for-production", algorithm="HS256")
    r = await receiver.client.get("/v1/config", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401


async def test_missing_or_malformed_authorization(receiver):
    assert (await receiver.client.get("/v1/config")).status_code == 401
    assert (await receiver.client.get("/v1/config", headers={"Authorization": "Basic abc"})).status_code == 401
    assert (await receiver.client.get("/v1/config", headers={"Authorization": "Bearer not.a.jwt"})).status_code == 401


async def test_health_is_minimal_and_reveals_no_site(receiver):
    r = await receiver.client.get("/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"status", "service", "api", "ready"}
    assert SITE_ID not in r.text and "SITE-T" not in r.text


async def test_unauthenticated_flood_does_not_block_authorized_devices(receiver):
    h = await receiver.token()
    flood = receiver.other_client("203.0.113.9")
    codes = [(await flood.post("/v1/auth/session", json={"grant": "x.y.z" + "a" * 30})).status_code for _ in range(70)]
    assert 429 in codes, "failed session attempts from one address must be throttled"
    # the flooding address is throttled, but an authorized device and another address are not
    assert (await receiver.client.get("/v1/config", headers=h)).status_code == 200
    assert (await receiver.session()).status_code == 200
    await flood.aclose()


async def test_admin_key_required_and_failures_throttled_but_correct_key_never(receiver):
    c = receiver.other_client("198.51.100.7")
    assert (await c.get("/v1/admin/status")).status_code == 401
    for _ in range(15):
        await c.get("/v1/admin/status", headers={"X-Receiver-Admin-Key": "wrong"})
    assert (await c.get("/v1/admin/status", headers={"X-Receiver-Admin-Key": "wrong"})).status_code == 429
    ok = await c.get("/v1/admin/status", headers={"X-Receiver-Admin-Key": "unit-test-admin-key"})
    assert ok.status_code == 200, "the correct key must not be locked out by failed guesses"
    await c.aclose()
