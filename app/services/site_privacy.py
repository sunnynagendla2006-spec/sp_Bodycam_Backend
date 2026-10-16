"""
Client-identifier privacy for the network monitoring platform.

* Client identifiers (usually MAC addresses) are turned into keyed
  PSEUDONYMS (HMAC-SHA256, per-site) the moment they enter the backend. The raw
  value is not stored, logged or returned unless the site policy explicitly
  allows it AND a raw-identifier key is configured (fail-closed otherwise).
* The pseudonym is per site: the same device at two sites is not linkable.
* Pseudonymization is NOT anonymization. Anyone holding CLIENT_ID_HMAC_KEY and a
  candidate MAC can recompute the pseudonym. Treat pseudonyms as personal data.
* Devices with randomized/rotating MACs yield a new pseudonym each time the MAC
  changes; counts of ASSOCIATIONS stay valid, unique-device counts do not.

Keys (environment only, never in source):
  CLIENT_ID_HMAC_KEY   required in production; a random per-process fallback is
                       used in development (pseudonyms then change on restart).
  CLIENT_RAW_ID_KEY    Fernet key; raw identifiers can only be stored (encrypted) when set.
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
import uuid
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("site_privacy")

_DEV_FALLBACK = secrets.token_hex(32)
_warned = False
_SEPARATORS = re.compile(r"[:\-.\s]")
_HEX12 = re.compile(r"^[0-9a-f]{12}$")


def _is_production() -> bool:
    return os.getenv("ENVIRONMENT", "development").strip().lower() == "production"


def _hmac_key() -> bytes:
    global _warned
    key = os.getenv("CLIENT_ID_HMAC_KEY", "").strip()
    if key:
        return key.encode()
    if _is_production():
        raise RuntimeError("CLIENT_ID_HMAC_KEY is required in production; refusing to pseudonymize with a fallback key")
    if not _warned:
        logger.warning("CLIENT_ID_HMAC_KEY is not set: using an ephemeral development key (pseudonyms change on restart)")
        _warned = True
    return _DEV_FALLBACK.encode()


def is_configured() -> bool:
    """True when pseudonymization will work (a key is set, or we are in development)."""
    return bool(os.getenv("CLIENT_ID_HMAC_KEY", "").strip()) or not _is_production()


def normalize_identifier(raw: str) -> str:
    """MAC-looking values collapse to 12 lowercase hex digits; anything else is just trimmed and lowercased."""
    value = (raw or "").strip().lower()
    collapsed = _SEPARATORS.sub("", value)
    return collapsed if _HEX12.match(collapsed) else value


def pseudonymize(site_id: uuid.UUID, raw_identifier: str) -> str:
    normalized = normalize_identifier(raw_identifier)
    if not normalized:
        raise ValueError("empty client identifier")
    digest = hmac.new(_hmac_key(), f"{site_id}:{normalized}".encode(), hashlib.sha256).hexdigest()
    return digest[:32]


def mask(pseudonym: Optional[str]) -> Optional[str]:
    """Short form for ordinary dashboard use."""
    return None if not pseudonym else f"{pseudonym[:8]}…"


# ---- optional encrypted raw storage ----------------------------------------

def _fernet() -> Optional[Fernet]:
    key = os.getenv("CLIENT_RAW_ID_KEY", "").strip()
    return Fernet(key.encode()) if key else None


def raw_storage_available() -> bool:
    try:
        return _fernet() is not None
    except Exception:
        return False


def encrypt_raw(raw_identifier: str) -> Optional[str]:
    f = _fernet()
    return f.encrypt(normalize_identifier(raw_identifier).encode()).decode() if f else None


def decrypt_raw(token: str) -> Optional[str]:
    f = _fernet()
    if not f:
        return None
    try:
        return f.decrypt(token.encode()).decode()
    except InvalidToken:
        return None
