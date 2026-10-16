"""
Request-body size limit enforced BEFORE the framework parses a multipart upload.

A size check inside a route handler runs after Starlette has already parsed (and spooled to a temporary file) the whole
multipart body, so it cannot protect against an oversized request. This ASGI middleware looks at the request first:

  * a declared Content-Length above the limit is refused with 413 before any body is read;
  * a body that does not declare its length (chunked transfer) or lies about it is counted as it is received and
    cut off with 413 as soon as it exceeds the limit.

It limits what THIS application will read. A reverse proxy in front should enforce the same limit (nginx
`client_max_body_size`, see docs/BODYCAM_OFFLINE_TRANSPORT.md), because the proxy can refuse the bytes before they reach
the host at all. Spooled multipart data goes to the system temporary directory (set TMPDIR to a volume with room).
"""
import json
from typing import Callable


class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    def __init__(self, app, limit_bytes: int, matches: Callable[[str, str], bool]):
        self.app, self.limit, self.matches = app, int(limit_bytes), matches

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.matches(scope.get("method", ""), scope.get("path", "")):
            return await self.app(scope, receive, send)

        declared = None
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = None
        if declared is not None and declared > self.limit:
            return await self._reject(send)

        seen = 0
        started = False
        exceeded = False
        replace_body = False

        async def counting_receive():
            nonlocal seen, exceeded
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.limit:
                    exceeded = True
                    raise _TooLarge()
            return message

        async def tracking_send(message):
            # Frameworks often turn the aborted read into their own "400 could not parse the body". The real cause is the
            # size, so whatever response the app produces after we cut the body off is rewritten to 413.
            nonlocal started, replace_body
            if exceeded and message["type"] == "http.response.start":
                started = True
                replace_body = True
                body = json.dumps({"detail": "Request body too large"}).encode()
                await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")]})
                return
            if replace_body and message["type"] == "http.response.body":
                await send({"type": "http.response.body", "body": json.dumps({"detail": "Request body too large"}).encode()})
                replace_body = False
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send)

    async def _reject(self, send):
        body = json.dumps({"detail": "Request body too large"}).encode()
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})
