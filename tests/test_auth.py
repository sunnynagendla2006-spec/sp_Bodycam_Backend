import pytest

from app.auth.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.models import UserRole


# ---------------------------------------------------------------------------
# 14. Password hash verification (unit-level, no HTTP, no DB)
# ---------------------------------------------------------------------------
def test_password_hash_and_verify_roundtrip():
    hashed = hash_password("correct-horse-battery")
    assert hashed != "correct-horse-battery"  # never store plaintext
    assert verify_password("correct-horse-battery", hashed) is True
    assert verify_password("wrong-password", hashed) is False


# ---------------------------------------------------------------------------
# 1. Valid login
# ---------------------------------------------------------------------------
async def test_valid_login_returns_token_and_user(client, make_user):
    await make_user(phone="9990001111", password="correct-horse-battery", role=UserRole.admin)

    resp = await client.post("/auth/login", json={"username": "9990001111", "password": "correct-horse-battery"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str) and len(body["access_token"]) > 0
    assert body["expires_in"] > 0
    assert body["user"]["phone"] == "9990001111"
    assert body["user"]["role"] == "admin"
    assert body["user"]["is_active"] is True
    # Never leak the password hash
    assert "hashed_password" not in body["user"]
    assert "password" not in body["user"]


# ---------------------------------------------------------------------------
# 2. Invalid password
# ---------------------------------------------------------------------------
async def test_login_wrong_password_returns_401_generic_message(client, make_user):
    await make_user(phone="9990002222", password="correct-horse-battery")

    resp = await client.post("/auth/login", json={"username": "9990002222", "password": "totally-wrong"})

    assert resp.status_code == 401
    assert resp.json()["detail"] == "Incorrect username or password"


# ---------------------------------------------------------------------------
# 3. Unknown user
# ---------------------------------------------------------------------------
async def test_login_unknown_user_returns_401_same_generic_message(client, make_user):
    await make_user(phone="9990003333", password="correct-horse-battery")

    resp = await client.post("/auth/login", json={"username": "no-such-user", "password": "whatever"})

    assert resp.status_code == 401
    # Must be identical to the wrong-password message -- no enumeration signal.
    assert resp.json()["detail"] == "Incorrect username or password"


# ---------------------------------------------------------------------------
# 4. Inactive user
# ---------------------------------------------------------------------------
async def test_login_inactive_user_returns_401(client, make_user):
    from app.models import UserStatus

    await make_user(phone="9990004444", password="correct-horse-battery", status=UserStatus.inactive)

    resp = await client.post("/auth/login", json={"username": "9990004444", "password": "correct-horse-battery"})

    assert resp.status_code == 401
    assert resp.json()["detail"] == "Incorrect username or password"


# ---------------------------------------------------------------------------
# 5. Valid JWT -> /auth/me works
# ---------------------------------------------------------------------------
async def test_valid_jwt_allows_auth_me(client, make_user):
    await make_user(phone="9990005555", password="correct-horse-battery")
    login_resp = await client.post("/auth/login", json={"username": "9990005555", "password": "correct-horse-battery"})
    token = login_resp.json()["access_token"]

    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["phone"] == "9990005555"
    assert body["is_active"] is True
    assert "hashed_password" not in body


# ---------------------------------------------------------------------------
# 6. Invalid JWT
# ---------------------------------------------------------------------------
async def test_invalid_jwt_returns_401(client):
    resp = await client.get("/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 7. Expired JWT
# ---------------------------------------------------------------------------
async def test_expired_jwt_returns_401(client, make_user):
    user = await make_user(phone="9990007777", password="correct-horse-battery")

    # Create a token that expired 1 minute ago.
    token, _ = create_access_token(subject=str(user.id), role="admin", expires_minutes=-1)

    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 8. Missing token
# ---------------------------------------------------------------------------
async def test_missing_token_returns_401(client):
    resp = await client.get("/auth/me")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 9. /auth/me with valid token (duplicate-named per spec item 9, kept
#    distinct from test_valid_jwt_allows_auth_me to check field shape)
# ---------------------------------------------------------------------------
async def test_auth_me_response_shape(client, make_user):
    await make_user(phone="9990009999", password="correct-horse-battery")
    login_resp = await client.post("/auth/login", json={"username": "9990009999", "password": "correct-horse-battery"})
    token = login_resp.json()["access_token"]

    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    body = resp.json()
    assert set(["id", "phone", "role", "is_active", "created_at"]).issubset(body.keys())


# ---------------------------------------------------------------------------
# 10. /auth/me without token (alias of test_missing_token_returns_401, kept
#     to mirror the requested test list explicitly)
# ---------------------------------------------------------------------------
async def test_auth_me_without_token_returns_401(client):
    resp = await client.get("/auth/me")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 11. Admin role authorization (allowed)
# ---------------------------------------------------------------------------
async def test_require_role_allows_matching_role(client, make_user):
    await make_user(phone="9990011111", password="correct-horse-battery", role=UserRole.admin)
    login_resp = await client.post("/auth/login", json={"username": "9990011111", "password": "correct-horse-battery"})
    token = login_resp.json()["access_token"]

    resp = await client.get("/__test__/admin-only", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 12. Constable role authorization (allowed)
# ---------------------------------------------------------------------------
async def test_require_role_allows_constable_on_constable_route(client, make_user):
    await make_user(phone="9990012222", password="correct-horse-battery", role=UserRole.constable)
    login_resp = await client.post("/auth/login", json={"username": "9990012222", "password": "correct-horse-battery"})
    token = login_resp.json()["access_token"]

    resp = await client.get("/__test__/constable-only", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 13. Forbidden role -> 403
# ---------------------------------------------------------------------------
async def test_require_role_rejects_wrong_role_with_403(client, make_user):
    await make_user(phone="9990013333", password="correct-horse-battery", role=UserRole.constable)
    login_resp = await client.post("/auth/login", json={"username": "9990013333", "password": "correct-horse-battery"})
    token = login_resp.json()["access_token"]

    # Constable hitting an admin-only route.
    resp = await client.get("/__test__/admin-only", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


async def test_require_role_rejects_unauthenticated_with_401_not_403(client):
    # No token at all -> should fail authentication (401), not authorization (403).
    resp = await client.get("/__test__/admin-only")
    assert resp.status_code == 401
