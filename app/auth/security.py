"""
Password hashing and JWT helpers.

This module is the single source of truth for:
  - password hashing / verification (passlib + bcrypt)
  - JWT access token creation / decoding (python-jose)

Both `passlib[bcrypt]` and `python-jose[cryptography]` are already listed in
requirements.txt — no new dependencies are introduced here.
"""
import os
import warnings
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# There is no existing centralized settings module in this project (only a
# per-feature `settings.json` used by app/routers/settings.py for unrelated
# runtime config), so — consistent with the pattern already used in
# app/database.py (os.getenv with a local fallback) — configuration here is
# read directly from environment variables rather than introducing a second,
# competing settings system (e.g. pydantic-settings).

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()

_DEV_FALLBACK_SECRET = "dev-insecure-secret-key-change-me"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET_KEY:
    if ENVIRONMENT == "production":
        # Fail safely/loudly rather than silently running production with a
        # guessable secret.
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is required when "
            "ENVIRONMENT=production. Refusing to start with no secret."
        )
    warnings.warn(
        "JWT_SECRET_KEY is not set. Falling back to an insecure development "
        "secret. This is NOT safe for production use.",
        RuntimeWarning,
    )
    JWT_SECRET_KEY = _DEV_FALLBACK_SECRET

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password for storage. Never store plaintext passwords."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    if not password_hash:
        # No hash on record (e.g. SSO-only account) -> cannot verify a password login.
        return False
    try:
        return pwd_context.verify(plain_password, password_hash)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# JWT creation / decoding
# ---------------------------------------------------------------------------
def create_access_token(
    *,
    subject: str,
    role: str,
    expires_minutes: Optional[int] = None,
    extra_claims: Optional[dict[str, Any]] = None,
) -> tuple[str, int]:
    """
    Create a signed JWT access token.

    Returns a (token, expires_in_seconds) tuple so callers can report
    `expires_in` in the login response without re-deriving it.

    Claims:
      sub  - user id (subject)
      role - user's role at time of issuance (server-authoritative; the
             client must never be trusted to supply this)
      iat  - issued-at
      exp  - expiration
    """
    expires_minutes = expires_minutes or ACCESS_TOKEN_EXPIRE_MINUTES
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes)

    to_encode: dict[str, Any] = {
        "sub": str(subject),
        "role": str(role),
        "iat": int(now.timestamp()),
        "exp": expire,
    }
    if extra_claims:
        to_encode.update(extra_claims)

    token = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    expires_in = expires_minutes * 60
    return token, expires_in


class TokenPayload:
    """Lightweight container for decoded token claims."""

    def __init__(self, sub: str, role: str, iat: Optional[int], exp: Optional[int]):
        self.sub = sub
        self.role = role
        self.iat = iat
        self.exp = exp


def decode_access_token(token: str) -> TokenPayload:
    """
    Decode and validate a JWT.

    Raises jose.JWTError (or subclasses, e.g. ExpiredSignatureError) on any
    validation failure -- signature mismatch, malformed token, or expiry.
    Callers (deps.get_current_user) are responsible for translating that
    into an HTTP 401.
    """
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    sub = payload.get("sub")
    role = payload.get("role")
    if sub is None:
        raise JWTError("Token is missing required 'sub' claim")
    return TokenPayload(sub=sub, role=role, iat=payload.get("iat"), exp=payload.get("exp"))
