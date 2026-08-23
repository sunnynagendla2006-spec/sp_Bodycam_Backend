"""
Production-hardening regression tests for issues found during the fresh
security audit: login brute-force rate limiting, CORS configuration
(wildcard-origin + credentials was an invalid/insecure combination), and
main.py's Alembic-migration-head safety check (replacing the removed
`Base.metadata.create_all()` call).
"""
import os

import pytest


# ---------------------------------------------------------------------------
# Login rate limiting
# ---------------------------------------------------------------------------
def test_repeated_failed_logins_get_rate_limited(full_client, make_user):
    from app.models import UserRole

    make_user(phone="rl000000001", password="correct-pw", role=UserRole.admin)
    for _ in range(10):
        resp = full_client.post("/auth/login", json={"username": "rl000000001", "password": "wrong-pw"})
        assert resp.status_code == 401

    # The 11th attempt (still within the same 5-minute window) must be rate-limited.
    limited_resp = full_client.post("/auth/login", json={"username": "rl000000001", "password": "wrong-pw"})
    assert limited_resp.status_code == 429


def test_rate_limit_is_keyed_by_attempted_username_not_globally(full_client, make_user):
    """A different account is unaffected by another account being rate-limited."""
    from app.models import UserRole

    make_user(phone="rl000000002a", password="pw", role=UserRole.admin)
    make_user(phone="rl000000002b", password="pw", role=UserRole.admin)

    for _ in range(10):
        full_client.post("/auth/login", json={"username": "rl000000002a", "password": "wrong-pw"})

    # Account "a" is now locked out...
    resp_a = full_client.post("/auth/login", json={"username": "rl000000002a", "password": "wrong-pw"})
    assert resp_a.status_code == 429

    # ...but account "b" is completely unaffected.
    resp_b = full_client.post("/auth/login", json={"username": "rl000000002b", "password": "pw"})
    assert resp_b.status_code == 200


def test_successful_login_clears_rate_limit_counter(full_client, make_user):
    from app.models import UserRole

    make_user(phone="rl000000003", password="correct-pw", role=UserRole.admin)

    for _ in range(5):
        resp = full_client.post("/auth/login", json={"username": "rl000000003", "password": "wrong-pw"})
        assert resp.status_code == 401

    # A successful login clears the counter...
    success = full_client.post("/auth/login", json={"username": "rl000000003", "password": "correct-pw"})
    assert success.status_code == 200

    # ...so the account isn't stuck partway toward lockout afterward.
    for _ in range(5):
        resp = full_client.post("/auth/login", json={"username": "rl000000003", "password": "wrong-pw"})
        assert resp.status_code == 401
    still_ok = full_client.post("/auth/login", json={"username": "rl000000003", "password": "wrong-pw"})
    # 11th total failed attempt SINCE the counter reset (5 + this one = 6) --
    # well under the 10-attempt threshold, so still a normal 401, not 429.
    assert still_ok.status_code == 401


def test_rate_limiting_does_not_reveal_account_existence(full_client):
    """Rate limiting a nonexistent account behaves identically to a real one -- no oracle."""
    for _ in range(10):
        resp = full_client.post("/auth/login", json={"username": "totally-nonexistent-phone", "password": "x"})
        assert resp.status_code == 401

    limited = full_client.post("/auth/login", json={"username": "totally-nonexistent-phone", "password": "x"})
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


# ---------------------------------------------------------------------------
# main.py migration-head safety check
# ---------------------------------------------------------------------------
def test_main_does_not_call_create_all_on_import():
    """
    Regression test for the removed `Base.metadata.create_all(bind=engine)`
    call -- confirms main.py's source no longer contains an ACTUAL CALL to
    create_all (checked via AST, not naive substring search, since the
    module's own comments legitimately mention "create_all" by name when
    explaining why it was removed). The real production initialization
    path is `alembic upgrade head`, run as an explicit deploy step; see
    Dockerfile.
    """
    import ast
    import inspect
    from app import main as main_module

    source = inspect.getsource(main_module)
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "create_all":
                pytest.fail(f"main.py still calls .create_all(...) at line {node.lineno}")


def test_migration_head_check_warns_in_development_when_db_missing_or_stale(monkeypatch, capsys):
    """
    In development (the default ENVIRONMENT), a database that isn't at the
    expected Alembic head produces a loud warning but does NOT raise --
    since this is exercised by every test run in this suite (SQLite, no
    alembic_version table at all), a hard failure here would break the
    entire test suite; verified directly by re-running the check function
    against the current (SQLite, migration-less) test database connection
    setup and confirming it only warns.
    """
    monkeypatch.delenv("ENVIRONMENT", raising=False)  # ensure default "development"
    from app.main import _verify_database_at_expected_migration_head

    with pytest.warns(RuntimeWarning):
        _verify_database_at_expected_migration_head()


def test_migration_head_check_raises_in_production_when_db_stale(monkeypatch):
    """In ENVIRONMENT=production, a database not at the expected head must fail loudly rather than silently starting up against the wrong schema."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    from app.main import _verify_database_at_expected_migration_head

    with pytest.raises(RuntimeError, match="(?i)not at the expected alembic migration head|could not resolve"):
        _verify_database_at_expected_migration_head()

    monkeypatch.delenv("ENVIRONMENT", raising=False)
