"""HTTPS client for the backend's /collector/* API (standard library only)."""
import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional, Tuple

from .config import Config


class TransientError(Exception):
    """Network failure, timeout, 429 or 5xx: keep the data and retry later with back-off."""

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class AuthError(Exception):
    """401/403: the credential is wrong, revoked or not allowed for the site. Retrying will not help until an operator fixes it."""


class PermanentError(Exception):
    """400/413/422: the backend will never accept this payload as sent."""


class BackendClient:
    def __init__(self, cfg: Config):
        self._base = cfg.backend_url
        self._token = cfg.token
        self._timeout = cfg.http_timeout
        self._ctx = ssl.create_default_context(cafile=cfg.ca_file) if self._base.startswith("https://") else None

    def post(self, path: str, body: dict) -> Any:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self._base + path, data=data, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._token}", "User-Agent": "sp-collector"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            status = exc.code
            if status in (401, 403):
                raise AuthError(f"backend rejected the collector credential (HTTP {status})")
            if status == 429:
                try:
                    retry = float(exc.headers.get("Retry-After", "10"))
                except ValueError:
                    retry = 10.0
                raise TransientError("rate limited by backend", retry)
            if status in (400, 404, 409, 413, 422):
                detail = _short_detail(exc)
                raise PermanentError(f"HTTP {status}: {detail}")
            raise TransientError(f"backend error HTTP {status}")
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            # The reason can contain the host name; the type alone is enough for operators.
            raise TransientError(f"cannot reach backend ({type(exc).__name__})")


def _short_detail(exc: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(exc.read() or b"{}")
        detail = payload.get("detail", "")
        return (detail if isinstance(detail, str) else json.dumps(detail))[:200]
    except Exception:
        return "unparseable error body"
