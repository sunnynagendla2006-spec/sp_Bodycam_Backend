"""
Password handling for the development seed scripts (seed_demo.py, scripts/seed_*.py).

No seed script may embed a password. The password comes from SEED_PASSWORD, or
-- if unset -- is generated randomly for that run and printed once to the
terminal of whoever ran the script. Seeding is refused entirely when
ENVIRONMENT=production.
"""
import os
import secrets


def require_non_production() -> None:
    if os.getenv("ENVIRONMENT", "development").strip().lower() == "production":
        raise SystemExit("Refusing to run a demo/test seed script with ENVIRONMENT=production.")


def seed_password() -> str:
    require_non_production()
    pw = os.getenv("SEED_PASSWORD", "").strip()
    if pw:
        if len(pw) < 8:
            raise SystemExit("SEED_PASSWORD must be at least 8 characters.")
        return pw
    pw = secrets.token_urlsafe(12)
    print(f"[seed] SEED_PASSWORD not set; generated a one-time password for this run: {pw}")
    return pw
