"""
Phase 7 (deployment hardening): configuration validation.

Since app/auth/security.py reads JWT_SECRET_KEY/ENVIRONMENT at MODULE
IMPORT time (not per-request), testing different environment combinations
requires fresh subprocesses -- a normal in-process monkeypatch can't
un-import an already-loaded module's constants. This mirrors the same
subprocess-based approach already used elsewhere in this project for
migration-behavior verification.
"""
import subprocess
import sys

import pytest


def _run_python(code: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd="/home/claude/project/backend",
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _base_env(**overrides) -> dict:
    import os
    env = {k: v for k, v in os.environ.items() if k not in ("JWT_SECRET_KEY", "ENVIRONMENT")}
    env.update(overrides)
    return env


def test_backend_starts_with_a_supplied_jwt_secret_key():
    """A real secret is honored -- no warning, no fallback, module imports cleanly."""
    env = _base_env(JWT_SECRET_KEY="a-real-explicit-secret-for-this-test", ENVIRONMENT="development")
    result = _run_python("from app.auth import security; print('OK:', security.JWT_SECRET_KEY)", env)
    assert result.returncode == 0, result.stderr
    assert "OK: a-real-explicit-secret-for-this-test" in result.stdout
    assert "insecure" not in result.stderr.lower()


def test_backend_refuses_to_start_in_production_without_jwt_secret_key():
    """Must NEVER silently run production with a guessable secret."""
    env = _base_env(ENVIRONMENT="production")
    env.pop("JWT_SECRET_KEY", None)
    result = _run_python("from app.auth import security", env)
    assert result.returncode != 0, "Expected a startup failure, but the process exited cleanly"
    assert "JWT_SECRET_KEY environment variable is required" in result.stderr


def test_backend_warns_but_still_starts_in_development_without_jwt_secret_key():
    """Development convenience is preserved -- this is a deliberate, documented fallback, not a bug to remove."""
    env = _base_env(ENVIRONMENT="development")
    env.pop("JWT_SECRET_KEY", None)
    result = _run_python("from app.auth import security; print('started')", env)
    assert result.returncode == 0, result.stderr
    assert "started" in result.stdout
    assert "insecure development secret" in result.stderr.lower()


def test_backend_does_not_silently_use_the_dev_fallback_secret_in_production():
    """Redundant-but-explicit: the insecure fallback string must never actually be used to sign a token when ENVIRONMENT=production."""
    env = _base_env(ENVIRONMENT="production")
    env.pop("JWT_SECRET_KEY", None)
    result = _run_python("from app.auth import security; print(security.JWT_SECRET_KEY)", env)
    assert result.returncode != 0  # never even reaches the print -- confirms no token could ever be signed with it


def test_jwt_tokens_remain_valid_within_the_same_configured_secret(monkeypatch):
    """A token created and decoded within one process (one fixed secret) round-trips correctly -- proves the fix didn't break token creation/verification for a real deployment secret."""
    import importlib
    from app.auth import security as security_module
    monkeypatch.setenv("JWT_SECRET_KEY", "consistent-test-secret-value")
    importlib.reload(security_module)
    try:
        token, expires_in = security_module.create_access_token(subject="user-id-123", role="admin")
        assert expires_in > 0
        payload = security_module.decode_access_token(token)
        assert payload.sub == "user-id-123"
        assert payload.role == "admin"
    finally:
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        importlib.reload(security_module)


def test_authentication_flow_still_works_end_to_end(full_client, make_user):
    """Full regression guard: the actual login flow (real endpoint, real password hash, real token) still works after these configuration changes."""
    from app.models import UserRole
    make_user(phone="deploy000001", password="pw", role=UserRole.admin)
    resp = full_client.post("/auth/login", json={"username": "deploy000001", "password": "pw"})
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    me_resp = full_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["phone"] == "deploy000001"


def test_env_example_documents_every_variable_the_backend_actually_reads():
    """Prevents .env.example from silently drifting out of sync with the real source -- every os.getenv() call in app/ must have a corresponding line in .env.example."""
    import re

    env_example_path = "/home/claude/project/backend/.env.example"
    with open(env_example_path) as f:
        documented = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", f.read(), re.MULTILINE))
        documented |= set(re.findall(r"^# ([A-Z_][A-Z0-9_]*)=", open(env_example_path).read(), re.MULTILINE))

    used_vars = set()
    import subprocess as sp
    result = sp.run(
        ["grep", "-rhoE", r'os\.getenv\("[A-Z_][A-Z0-9_]*"', "/home/claude/project/backend/app"],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        m = re.search(r'"([A-Z_][A-Z0-9_]*)"', line)
        if m:
            used_vars.add(m.group(1))

    missing = used_vars - documented
    assert not missing, f".env.example is missing documentation for: {missing}"
