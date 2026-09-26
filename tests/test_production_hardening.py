"""
Production-hardening regression tests: login brute-force rate limiting and
CORS configuration (wildcard-origin + credentials was an invalid/insecure
combination).

The old main.py Alembic-migration-head safety check this file used to also
test (`_verify_database_at_expected_migration_head`, and the
`create_all()`-was-removed regression guard) no longer exists -- MongoDB/
Beanie has no migration tool or `alembic_version` table to check against;
see app/database.py::init_db() and app/main.py's startup event instead.
"""


# ---------------------------------------------------------------------------
# Login rate limiting
# ---------------------------------------------------------------------------
async def test_repeated_failed_logins_get_rate_limited(full_client, make_user):
    from app.models import UserRole

    await make_user(phone="rl000000001", password="correct-pw", role=UserRole.admin)
    for _ in range(10):
        resp = await full_client.post("/auth/login", json={"username": "rl000000001", "password": "wrong-pw"})
        assert resp.status_code == 401

    # The 11th attempt (still within the same 5-minute window) must be rate-limited.
    limited_resp = await full_client.post("/auth/login", json={"username": "rl000000001", "password": "wrong-pw"})
    assert limited_resp.status_code == 429


async def test_rate_limit_is_keyed_by_attempted_username_not_globally(full_client, make_user):
    """A different account is unaffected by another account being rate-limited."""
    from app.models import UserRole

    await make_user(phone="rl000000002a", password="pw", role=UserRole.admin)
    await make_user(phone="rl000000002b", password="pw", role=UserRole.admin)

    for _ in range(10):
        await full_client.post("/auth/login", json={"username": "rl000000002a", "password": "wrong-pw"})

    # Account "a" is now locked out...
    resp_a = await full_client.post("/auth/login", json={"username": "rl000000002a", "password": "wrong-pw"})
    assert resp_a.status_code == 429

    # ...but account "b" is completely unaffected.
    resp_b = await full_client.post("/auth/login", json={"username": "rl000000002b", "password": "pw"})
    assert resp_b.status_code == 200


async def test_successful_login_clears_rate_limit_counter(full_client, make_user):
    from app.models import UserRole

    await make_user(phone="rl000000003", password="correct-pw", role=UserRole.admin)

    for _ in range(5):
        resp = await full_client.post("/auth/login", json={"username": "rl000000003", "password": "wrong-pw"})
        assert resp.status_code == 401

    # A successful login clears the counter...
    success = await full_client.post("/auth/login", json={"username": "rl000000003", "password": "correct-pw"})
    assert success.status_code == 200

    # ...so the account isn't stuck partway toward lockout afterward.
    for _ in range(5):
        resp = await full_client.post("/auth/login", json={"username": "rl000000003", "password": "wrong-pw"})
        assert resp.status_code == 401
    still_ok = await full_client.post("/auth/login", json={"username": "rl000000003", "password": "wrong-pw"})
    # 11th total failed attempt SINCE the counter reset (5 + this one = 6) --
    # well under the 10-attempt threshold, so still a normal 401, not 429.
    assert still_ok.status_code == 401


async def test_rate_limiting_does_not_reveal_account_existence(full_client):
    """Rate limiting a nonexistent account behaves identically to a real one -- no oracle."""
    for _ in range(10):
        resp = await full_client.post("/auth/login", json={"username": "totally-nonexistent-phone", "password": "x"})
        assert resp.status_code == 401

    limited = await full_client.post("/auth/login", json={"username": "totally-nonexistent-phone", "password": "x"})
    assert limited.status_code == 429


# ---------------------------------------------------------------------------
# CORS configuration
# ---------------------------------------------------------------------------
def test_cors_does_not_combine_wildcard_origin_with_credentials():
    """
    The invalid/insecure combination (allow_origins=["*"] + allow_credentials=True)
    must never appear together -- browsers reject it anyway, but it should
    never be configured that way in the first place.
    """
    import importlib
    from app import main as main_module
    importlib.reload(main_module)

    cors_middleware = None
    for middleware in main_module.app.user_middleware:
        if "CORSMiddleware" in str(middleware.cls):
            cors_middleware = middleware
            break

    assert cors_middleware is not None, "CORSMiddleware is not registered"
    kwargs = cors_middleware.kwargs
    allow_credentials = kwargs.get("allow_credentials")
    allow_origins = kwargs.get("allow_origins")

    if allow_origins == ["*"]:
        assert allow_credentials is False, "Wildcard origin combined with allow_credentials=True is invalid and insecure"


def test_cors_origins_configurable_via_env_var(monkeypatch):
    """CORS_ALLOWED_ORIGINS overrides the default wildcard with an explicit origin list."""
    import importlib

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://dashboard.example.com,https://admin.example.com")
    from app import main as main_module
    importlib.reload(main_module)

    cors_middleware = None
    for middleware in main_module.app.user_middleware:
        if "CORSMiddleware" in str(middleware.cls):
            cors_middleware = middleware
            break
    assert cors_middleware is not None
    assert cors_middleware.kwargs.get("allow_origins") == [
        "https://dashboard.example.com", "https://admin.example.com"
    ]

    # Reload again without the env var so subsequent tests get the default back.
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    importlib.reload(main_module)
