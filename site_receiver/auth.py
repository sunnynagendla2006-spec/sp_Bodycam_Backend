"""
Authentication for the site receiver (no control-room database, no network call).

1. OFFLINE GRANT (what the phone gets from the control room while online): an ES256 JWS signed by the control room.
   The receiver verifies it with the control room's PUBLIC key: signature, expiry, issuer, key id (if pinned), that it
   is for THIS site, that it permits the operation, and that it has not been revoked (the revocation list arrives with
   each control-room sync; see the limitation below).
2. SESSION TOKEN (what the receiver gives the phone in exchange): a short-lived HS256 token signed with the receiver's
   own secret, bound to the same officer, device, site and grant, and never valid past the grant's expiry. Every request
   re-checks the grant against the revocation list.

Being on the site Wi-Fi proves nothing: every endpoint except /v1/health requires one of these.

LIMITATION: a receiver that cannot reach the control room cannot learn of a revocation made meanwhile. A revoked grant
stays usable here until it expires or the next successful sync. Keep GRANT_LIFETIME_HOURS short enough for your risk.
The receiver's clock must be correct (NTP) because expiry is checked locally.
"""
import time
from typing import Any, Dict

from jose import JWTError, jwt

from .config import Settings
from .store import Store

GRANT_ALGORITHMS = ["ES256"]  # explicit allow-list: no "alg" confusion, no unsigned tokens
CLOCK_SKEW_SECONDS = 120  # tolerated difference between the control room's clock and this receiver's (same policy as the phone)


class AuthError(Exception):
    def __init__(self, code: str, message: str, status: int = 401):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


def verify_grant(token: str, settings: Settings, store: Store) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise AuthError("grant_invalid", "The grant is malformed")
    if header.get("alg") not in GRANT_ALGORITHMS:
        raise AuthError("grant_invalid", "Unsupported grant algorithm")
    if settings.grant_key_id and header.get("kid") != settings.grant_key_id:
        raise AuthError("grant_key_unknown", "The grant was signed with an unknown key")
    try:
        claims = jwt.decode(token, settings.grant_public_key_pem, algorithms=GRANT_ALGORITHMS, issuer=settings.grant_issuer, options={"verify_aud": False, "leeway": CLOCK_SKEW_SECONDS})
    except jwt.ExpiredSignatureError:
        raise AuthError("grant_expired", "The grant has expired; renew it while connected to the control room")
    except JWTError:
        raise AuthError("grant_invalid", "The grant signature or claims are invalid")
    if claims.get("site") != str(settings.site_id):
        raise AuthError("grant_wrong_site", "The grant is for a different site", 403)
    for needed in ("sub", "jti", "dev", "exp"):
        if not claims.get(needed):
            raise AuthError("grant_invalid", f"The grant lacks '{needed}'")
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or iat > time.time() + CLOCK_SKEW_SECONDS:
        # A grant "issued in the future" means a wrong clock somewhere or a forged claim: never accepted beyond the skew allowance.
        raise AuthError("grant_invalid", "The grant was issued in the future (check the clocks)")
    if store.is_revoked(str(claims["jti"])):
        raise AuthError("grant_revoked", "The grant has been revoked", 403)
    return claims


def require_operation(claims: Dict[str, Any], operation: str) -> None:
    if operation not in (claims.get("ops") or []):
        raise AuthError("operation_not_permitted", f"The grant does not permit '{operation}'", 403)


def issue_session_token(claims: Dict[str, Any], settings: Settings) -> Dict[str, Any]:
    now = int(time.time())
    exp = min(now + settings.access_token_minutes * 60, int(claims["exp"]))
    payload = {
        "typ": "rcv", "sub": claims["sub"], "dev": claims["dev"], "devid": claims.get("devid"), "site": claims["site"], "gid": claims["jti"],
        "ops": claims.get("ops") or [], "iat": now, "exp": exp, "gexp": claims["exp"],
    }
    return {"access_token": jwt.encode(payload, settings.access_token_secret, algorithm="HS256"), "expires_in": max(0, exp - now)}


def verify_session_token(token: str, settings: Settings, store: Store) -> Dict[str, Any]:
    try:
        claims = jwt.decode(token, settings.access_token_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise AuthError("session_expired", "The session expired; open a new one with the grant")
    except JWTError:
        raise AuthError("session_invalid", "Invalid session token")
    if claims.get("typ") != "rcv" or claims.get("site") != str(settings.site_id):
        raise AuthError("session_invalid", "Invalid session token")
    if store.is_revoked(str(claims.get("gid"))):
        raise AuthError("grant_revoked", "The grant has been revoked", 403)
    return claims
