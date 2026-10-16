"""
Access-point verification: the only code allowed to claim that an AP is real,
verified or reachable.

An administrator creating or editing an AccessPoint row proves nothing about
the hardware. An AP becomes `verified` only when one of these actually
happens:

  * CONTROLLER_API   -- the configured controller/NMS integration (below)
                        answers a live lookup for this AP's identifiers; or
  * EDGE_TELEMETRY   -- an authenticated edge collector reports an event
                        carrying this AP's BSSID (see record_edge_telemetry).

When no integration is configured the honest answer is "unconfigured": the
verify endpoint reports that and changes nothing, rather than guessing.

The shipped adapter (`HttpJsonController`) speaks a small, documented JSON
contract (docs/PHYSICAL_AP_INTEGRATION_GUIDE.md) that a site's controller or
a thin vendor bridge must implement. No vendor API is assumed or invented
here; adding a vendor-native adapter means implementing `APIntegration`.
Credentials come from the environment only and are never logged, stored on
an AP row, or returned by any endpoint.
"""
import dataclasses
import datetime
import logging
import os
from typing import Optional

from .. import models

logger = logging.getLogger(__name__)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def telemetry_stale_seconds() -> int:
    try:
        v = int(os.getenv("AP_TELEMETRY_STALE_SECONDS", "300"))
    except ValueError:
        v = 300
    return v if v > 0 else 300


class IntegrationError(Exception):
    """A failure talking to the controller. `message` is safe to show to an administrator (no URLs, tokens or response bodies)."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class IntegrationUnconfigured(Exception):
    pass


@dataclasses.dataclass
class APLookupResult:
    found: bool
    reachable: Optional[bool] = None
    serial_number: Optional[str] = None
    model: Optional[str] = None
    client_count: Optional[int] = None


class APIntegration:
    kind: str = "none"

    def is_configured(self) -> bool:
        return False

    async def lookup_ap(self, *, bssid: Optional[str], serial_number: Optional[str], management_ip: Optional[str]) -> APLookupResult:
        raise IntegrationUnconfigured()


class UnconfiguredIntegration(APIntegration):
    kind = "none"


class HttpJsonController(APIntegration):
    """
    GET {AP_CONTROLLER_URL}/access-points/lookup?bssid=&serial=&ip=
        Authorization: Bearer {AP_CONTROLLER_TOKEN}      (token optional)
    -> 200 {"found": bool, "reachable": bool|null, "serial_number": str|null,
            "model": str|null, "client_count": int|null}
    """
    kind = "http_json"

    def __init__(self, base_url: str, token: Optional[str], timeout: float):
        self._base_url = base_url.rstrip("/")
        self._token = token or None
        self._timeout = timeout

    def is_configured(self) -> bool:
        return bool(self._base_url)

    async def lookup_ap(self, *, bssid, serial_number, management_ip) -> APLookupResult:
        import httpx

        params = {k: v for k, v in {"bssid": bssid, "serial": serial_number, "ip": management_ip}.items() if v}
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(f"{self._base_url}/access-points/lookup", params=params, headers=headers)
        except httpx.TimeoutException:
            raise IntegrationError("The controller did not respond in time")
        except httpx.HTTPError:
            raise IntegrationError("The controller could not be reached")
        if resp.status_code in (401, 403):
            raise IntegrationError("The controller rejected the configured credentials")
        if resp.status_code != 200:
            raise IntegrationError(f"The controller returned HTTP {resp.status_code}")
        try:
            body = resp.json()
            return APLookupResult(
                found=bool(body["found"]),
                reachable=body.get("reachable"),
                serial_number=body.get("serial_number"),
                model=body.get("model"),
                client_count=body.get("client_count"),
            )
        except (ValueError, KeyError, TypeError):
            raise IntegrationError("The controller returned a response that does not match the integration contract")


def get_integration() -> APIntegration:
    url = os.getenv("AP_CONTROLLER_URL", "").strip()
    if not url:
        return UnconfiguredIntegration()
    try:
        timeout = float(os.getenv("AP_CONTROLLER_TIMEOUT_SECONDS", "5"))
    except ValueError:
        timeout = 5.0
    return HttpJsonController(url, os.getenv("AP_CONTROLLER_TOKEN", "").strip() or None, timeout)


def integration_status() -> dict:
    integ = get_integration()
    if not integ.is_configured():
        return {"configured": False, "kind": None, "message": "No AP controller integration is configured (AP_CONTROLLER_URL is unset). APs cannot be verified through a controller; they can still become verified through authorised edge telemetry that carries their BSSID."}
    return {"configured": True, "kind": integ.kind, "message": f"Controller integration '{integ.kind}' is configured."}


def derive_reachability(ap: models.AccessPoint, now: Optional[datetime.datetime] = None) -> str:
    """
    unknown               -> not verified (or no telemetry ever): nothing may be claimed
    reachable             -> verified AND real telemetry/controller report within the freshness window
    no_recent_telemetry   -> verified but silent for longer than the window
    unreachable           -> verified and the controller explicitly reported it down
    """
    now = now or _utcnow()
    if ap.verification_status != models.APVerificationStatus.verified or ap.last_seen_at is None:
        return "unknown"
    last = ap.last_seen_at if ap.last_seen_at.tzinfo else ap.last_seen_at.replace(tzinfo=datetime.timezone.utc)
    if ap.status == models.AccessPointStatus.offline:
        return "unreachable"
    if (now - last).total_seconds() <= telemetry_stale_seconds():
        return "reachable"
    return "no_recent_telemetry"


def legacy_status(reachability: str) -> models.AccessPointStatus:
    if reachability == "reachable":
        return models.AccessPointStatus.online
    if reachability == "unreachable":
        return models.AccessPointStatus.offline
    return models.AccessPointStatus.unknown


def add_history(ap: models.AccessPoint, *, by, action: str, changes: Optional[dict] = None) -> None:
    ap.config_history.append(models.APConfigChange(by=by, action=action, changes=changes or {}))
    if len(ap.config_history) > 200:
        ap.config_history = ap.config_history[-200:]


async def verify_via_integration(ap: models.AccessPoint, actor_id) -> models.AccessPoint:
    """
    Runs a live controller lookup and records the honest outcome. Raises
    IntegrationUnconfigured (nothing claimed, attempt noted) when there is no
    integration; IntegrationError when the controller call itself failed.
    """
    integ = get_integration()
    now = _utcnow()
    ap.last_verification_attempt_at = now

    if not integ.is_configured():
        ap.integration_health = models.APIntegrationHealth.unconfigured
        ap.integration_checked_at = now
        ap.last_verification_error = "No controller integration is configured"
        add_history(ap, by=actor_id, action="verification_attempted", changes={"outcome": "integration_unconfigured"})
        await ap.save()
        raise IntegrationUnconfigured()

    try:
        result = await integ.lookup_ap(bssid=ap.bssid, serial_number=ap.serial_number, management_ip=ap.management_ip)
    except IntegrationError as exc:
        ap.integration_health = models.APIntegrationHealth.error
        ap.integration_checked_at = now
        ap.last_verification_error = exc.message
        if ap.verification_status != models.APVerificationStatus.verified:
            ap.verification_status = models.APVerificationStatus.verification_failed
        add_history(ap, by=actor_id, action="verification_attempted", changes={"outcome": "integration_error", "error": exc.message})
        await ap.save()
        raise

    ap.integration_checked_at = now
    mismatch = None
    if result.found and ap.serial_number and result.serial_number and ap.serial_number.strip().lower() != result.serial_number.strip().lower():
        mismatch = "The controller reports a different serial number than the one registered"

    if not result.found or mismatch:
        ap.verification_status = models.APVerificationStatus.verification_failed
        ap.last_verification_error = mismatch or "The controller does not know an access point with these identifiers"
        ap.integration_health = models.APIntegrationHealth.healthy
        ap.status = models.AccessPointStatus.unknown
        add_history(ap, by=actor_id, action="verification_attempted", changes={"outcome": "not_verified", "reason": ap.last_verification_error})
    else:
        ap.verification_status = models.APVerificationStatus.verified
        ap.verification_source = "CONTROLLER_API"
        ap.verified_at = now
        ap.last_verification_error = None
        if result.reachable is True:
            ap.last_seen_at = now
            ap.status = models.AccessPointStatus.online
            ap.integration_health = models.APIntegrationHealth.healthy
        elif result.reachable is False:
            ap.status = models.AccessPointStatus.offline
            ap.integration_health = models.APIntegrationHealth.degraded
        else:
            ap.status = models.AccessPointStatus.unknown
            ap.integration_health = models.APIntegrationHealth.healthy
        add_history(ap, by=actor_id, action="verified", changes={"source": "CONTROLLER_API", "reachable": result.reachable})
    ap.updated_at = now
    await ap.save()
    return ap


async def record_edge_telemetry(
    ap: models.AccessPoint, *, event_bssid: Optional[str], occurred_at: datetime.datetime, controller_id: str
) -> None:
    """
    Called for every accepted event from an AUTHENTICATED edge collector that
    resolved to this AP. Always refreshes last_seen_at/integration health. It
    promotes the AP to `verified` only when the event carries a BSSID equal to
    the BSSID an administrator registered -- a code/name match alone is just
    the collector echoing our own label, not proof of the radio.
    """
    now = _utcnow()
    occurred_at = occurred_at if occurred_at.tzinfo else occurred_at.replace(tzinfo=datetime.timezone.utc)
    # Targeted $set/$push (not a whole-document save): this runs on every
    # telemetry event and must never clobber a concurrent administrator edit.
    updates: dict = {"integration_health": models.APIntegrationHealth.healthy.value, "integration_checked_at": now}
    current_seen = ap.last_seen_at
    if current_seen is not None and current_seen.tzinfo is None:
        current_seen = current_seen.replace(tzinfo=datetime.timezone.utc)
    if current_seen is None or occurred_at > current_seen:
        updates["last_seen_at"] = occurred_at

    from ..schemas import normalise_bssid

    try:
        bssid = normalise_bssid(event_bssid) if event_bssid else None
    except ValueError:
        bssid = None
    promote = bool(
        bssid and ap.bssid and bssid == ap.bssid and ap.verification_status != models.APVerificationStatus.verified
    )
    ops: dict = {}
    if promote:
        updates.update(
            verification_status=models.APVerificationStatus.verified.value,
            verification_source="EDGE_TELEMETRY",
            verified_at=now,
            last_verification_error=None,
        )
        entry = models.APConfigChange(by=None, action="verified", changes={"source": "EDGE_TELEMETRY", "controller_id": controller_id})
        ops["$push"] = {"config_history": {"$each": [entry.model_dump()], "$slice": -200}}
    if promote or ap.verification_status == models.APVerificationStatus.verified:
        updates["status"] = models.AccessPointStatus.online.value
    ops["$set"] = updates
    await models.AccessPoint.get_motor_collection().update_one({"_id": ap.id}, ops)
    # keep the in-memory copy coherent for the caller
    ap.last_seen_at = updates.get("last_seen_at", ap.last_seen_at)
    ap.integration_health = models.APIntegrationHealth.healthy
    if promote:
        ap.verification_status = models.APVerificationStatus.verified
        ap.verification_source = "EDGE_TELEMETRY"
        ap.verified_at = now
