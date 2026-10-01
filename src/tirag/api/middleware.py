"""Pure-ASGI middleware: request IDs, body-size limit, secure headers, access log + metrics."""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tirag.api.metrics import HTTP_LATENCY, HTTP_REQUESTS
from tirag.logging_setup import request_id_var

access_log = logging.getLogger("tirag.access")

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
]

# The interactive docs need to load their own assets; relax CSP for those paths only.
_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")
_DOCS_CSP = (
    b"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    b"script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
)


class BodyTooLarge(Exception):
    pass


class RequestContextMiddleware:
    """Assigns a request ID, enforces the body limit, adds headers, records metrics."""

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope["headers"])
        incoming = headers.get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _SAFE_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        status_holder = {"status": 500}
        path = scope["path"]

        declared = headers.get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_body_bytes:
            await self._reject_413(scope, send, request_id)
            request_id_var.reset(token)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise BodyTooLarge
            return message

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                existing = {k.lower() for k, _ in message.get("headers", [])}
                extra = [(k, v) for k, v in SECURITY_HEADERS if k not in existing]
                if path.startswith(_DOCS_PATHS):
                    extra = [(k, _DOCS_CSP if k == b"content-security-policy" else v) for k, v in extra]
                extra.append((b"x-request-id", request_id.encode()))
                message = {**message, "headers": [*message.get("headers", []), *extra]}
            await send(message)

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except BodyTooLarge:
            await self._reject_413(scope, send_wrapper, request_id)
        finally:
            elapsed = time.perf_counter() - started
            route = scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            HTTP_REQUESTS.labels(scope["method"], template, str(status_holder["status"])).inc()
            HTTP_LATENCY.labels(scope["method"], template).observe(elapsed)
            access_log.info(
                "request",
                extra={
                    "method": scope["method"],
                    "path": path,
                    "status": status_holder["status"],
                    "duration_ms": int(elapsed * 1000),
                    "client": (scope.get("client") or ("-", 0))[0],
                },
            )
            request_id_var.reset(token)

    @staticmethod
    async def _reject_413(scope: Scope, send: Send, request_id: str) -> None:
        body = (
            b'{"error":{"code":"payload_too_large","message":"request body too large","request_id":"'
            + request_id.encode()
            + b'"}}'
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
