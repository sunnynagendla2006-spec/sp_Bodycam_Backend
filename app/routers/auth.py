from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import database, models, schemas
from ..auth.deps import get_current_user
from ..auth.security import create_access_token, verify_password
from ..auth import rate_limit
from ..services.audit import log_action

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Generic message for every "credentials didn't work" case. Do not
# distinguish "unknown user" vs "wrong password" vs "inactive user" in the
# response -- that distinction enables account enumeration.
_GENERIC_AUTH_FAILURE = "Incorrect username or password"
_RATE_LIMITED_MESSAGE = "Too many failed login attempts. Please try again later."


@router.post("/login", response_model=schemas.TokenResponse)
def login(creds: schemas.LoginRequest, request: Request, db: Session = Depends(database.get_db)):
    """
    Database-backed login.

    `username` is matched against User.phone (see schemas.LoginRequest for
    why). Verifies the bcrypt password hash, requires the user to be active,
    and issues a real, signed, expiring JWT.

    Phase 5: every login attempt (success or failure) is audited. The
    failure-path audit entry records the attempted phone and a generic
    failure reason -- never the submitted password -- and this has no
    bearing on the HTTP response, which stays identically generic either
    way (no account-enumeration signal is added by auditing).

    Rate limiting (see app/auth/rate_limit.py for exact, honestly-scoped
    behavior): checked BEFORE the database lookup, keyed purely by the
    submitted `username` string regardless of whether that account exists
    -- so the rate-limit response itself never reveals account existence
    either.
    """
    client_ip = request.client.host if request.client else None

    if rate_limit.is_rate_limited(creds.username):
        # Deliberately generic -- same for a real, locked-out account as
        # for a nonexistent one being hammered.
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_RATE_LIMITED_MESSAGE,
        )

    user = db.query(models.User).filter(models.User.phone == creds.username).first()

    # Same generic failure whether the user doesn't exist, the password is
    # wrong, or there's no password hash on record at all (e.g. an
    # SSO-only/citizen account with no password auth configured yet).
    if not user or not verify_password(creds.password, user.hashed_password or ""):
        rate_limit.record_failed_attempt(creds.username)
        log_action(
            db,
            user_id=user.id if user else None,
            action="auth.login_failed",
            details={"attempted_phone": creds.username, "reason": "invalid_credentials"},
            ip_address=client_ip,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_AUTH_FAILURE,
        )

    if user.status != models.UserStatus.active:
        rate_limit.record_failed_attempt(creds.username)
        log_action(
            db,
            user_id=user.id,
            action="auth.login_failed",
            details={"attempted_phone": creds.username, "reason": "inactive_user"},
            ip_address=client_ip,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_AUTH_FAILURE,
        )

    rate_limit.record_successful_login(creds.username)

    role_value = user.role.value if hasattr(user.role, "value") else str(user.role)
    access_token, expires_in = create_access_token(subject=str(user.id), role=role_value)

    log_action(
        db,
        user_id=user.id,
        action="auth.login_success",
        details={"role": role_value},
        ip_address=client_ip,
    )
    db.commit()

    return schemas.TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        user=schemas.UserPublic.from_user(user),
    )


@router.get("/me", response_model=schemas.UserPublic)
def read_current_user(current_user: models.User = Depends(get_current_user)):
    """Return the authenticated caller's own safe profile. Requires a valid Bearer token. Not audited -- see Phase 5 report (routine reads aren't logged)."""
    return schemas.UserPublic.from_user(current_user)
