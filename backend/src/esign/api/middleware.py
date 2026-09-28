"""Pure ASGI middleware: body size limits, security headers, one PHI-free access log line.

Pure ASGI rather than ``BaseHTTPMiddleware`` so a body is refused while it is still arriving, not
after it has been buffered, and so PDF responses stream straight through.
"""

from __future__ import annotations

import time
from typing import Any, Final

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from esign.api.errors import error_response
from esign.config import Settings
from esign.logging import get_logger

__all__ = ["API_CSP", "AccessLog", "BodySizeLimit", "SecurityHeaders", "SigningCors", "ui_csp"]

log = get_logger("esign.api.access")

#: JSON and PDF responses render nothing, load nothing and may be framed by nobody.
API_CSP: Final = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

_TEMPLATE_UPLOAD_SLACK: Final = 1024 * 1024  # multipart framing and the definitions JSON

#: Public library files a host page loads from another origin (Addendum 4). JSON and PDFs stay
#: ``same-origin``; these are the hashed worker, the IIFE, and its stylesheet.
_LIBRARY_FILES: Final = frozenset({"/esign-sdk.js", "/esign-sdk.css", "/esign-frontend.css"})


def _is_embeddable_library(path: str) -> bool:
    if path in _LIBRARY_FILES:
        return True
    return path.startswith("/assets/") and "pdf.worker" in path


def ui_csp(frame_ancestors: tuple[str, ...]) -> str:
    """The signing UI's policy. ``frame-ancestors`` is the host's allowed origins (SPEC section 9),
    or ``'none'`` when the host is unknown: the UI is then not embeddable at all."""
    ancestors = " ".join(frame_ancestors) if frame_ancestors else "'none'"
    return (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; "
        f"object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors {ancestors}"
    )


class _BodyTooLarge(Exception):
    pass


def _is_multipart(scope: Scope) -> bool:
    """Whether this request declares a multipart body, read from the raw ASGI headers.

    The limit is decided before anything reads the body, so there is no ``Request`` to ask yet.
    """
    for name, value in scope.get("headers") or []:
        if bytes(name).lower() == b"content-type":
            return bytes(value).split(b";", 1)[0].strip().lower() == b"multipart/form-data"
    return False


class BodySizeLimit:
    """413 for a body over the limit: by ``Content-Length`` up front, and by counting for a chunked
    body that never declared one. Template uploads get the template limit; everything else the
    request limit."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self._app = app
        self._default = settings.max_request_bytes
        self._templates = settings.max_template_bytes + _TEMPLATE_UPLOAD_SLACK
        #: Addendum 1 A: a filed scan is bounded by ``MAX_SCAN_BYTES``, not by the request limit
        #: (SPEC section 9). Image-only pages are large, and the route refuses the part itself as
        #: well, so this bound only has to leave room for the multipart framing and the JSON body.
        self._scans = settings.max_scan_bytes + _TEMPLATE_UPLOAD_SLACK
        #: Addendum 2: a host-supplied document arrives as a multipart ``POST /v1/envelopes`` and
        #: is bounded by ``MAX_SUPPLIED_DOCUMENT_BYTES`` (SPEC section 9). A 30-page generated
        #: report is bigger than the default request limit, and the JSON shape of the same route
        #: is not: the raise applies to the multipart shape alone.
        self._supplied = settings.max_supplied_document_bytes + _TEMPLATE_UPLOAD_SLACK

    def _limit(self, scope: Scope) -> int:
        path = str(scope.get("path", ""))
        if path.startswith("/v1/templates"):
            return self._templates
        if path.startswith("/v1/archives"):
            return self._scans
        if path == "/v1/envelopes" and str(scope.get("method", "")) == "POST" and _is_multipart(scope):
            return self._supplied
        return self._default

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        limit = self._limit(scope)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                too_large = int(declared) > limit
            except ValueError:
                too_large = True
            if too_large:
                await error_response(413, "payload_too_large")(scope, receive, send)
                return

        received = 0
        exceeded = False
        started = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if exceeded:
                # The framework turns an error while reading a body into its own 400. Whatever it
                # was about to say, the truth is 413: drop its response and send ours, once.
                if not started:
                    started = True
                    await error_response(413, "payload_too_large")(scope, _no_more_body, send)
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self._app(scope, counting_receive, tracking_send)
        except _BodyTooLarge:
            if not started:
                await error_response(413, "payload_too_large")(scope, _no_more_body, send)


async def _no_more_body() -> Message:
    return {"type": "http.disconnect"}


class SecurityHeaders:
    """Headers every response carries. A route that set its own CSP (the signing UI, whose
    ``frame-ancestors`` is per host) keeps it; everything else gets the locked-down API policy."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self._app = app
        self._hsts = settings.app_env == "prod"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        path = str(scope.get("path", ""))

        async def with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                present = {name.lower() for name, _ in headers}

                def put(name: bytes, value: str) -> None:
                    if name not in present:
                        headers.append((name, value.encode("latin-1")))

                put(b"x-content-type-options", "nosniff")
                put(b"referrer-policy", "no-referrer")
                put(b"permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()")
                if path.startswith("/v1/signing") or _is_embeddable_library(path):
                    # SDK-mode callers are on another origin; iframe same-origin still works.
                    put(b"cross-origin-resource-policy", "cross-origin")
                    if _is_embeddable_library(path):
                        # Classic scripts need CORP; the pdf.js module worker also needs CORS.
                        put(b"access-control-allow-origin", "*")
                else:
                    put(b"cross-origin-resource-policy", "same-origin")
                if b"content-security-policy" not in present:
                    put(b"content-security-policy", API_CSP)
                    put(b"x-frame-options", "DENY")
                if not path.startswith("/assets/") and not _is_embeddable_library(path):
                    # Nothing this service returns -- a PDF least of all -- belongs in a cache.
                    put(b"cache-control", "no-store")
                    put(b"pragma", "no-cache")
                if self._hsts:
                    put(b"strict-transport-security", "max-age=63072000; includeSubDomains")
                message = {**message, "headers": headers}
            await send(message)

        await self._app(scope, receive, with_headers)


class AccessLog:
    """One line per request: method, the *route template*, status, duration. Never the query
    string, never a header, never a body."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        began = time.perf_counter()
        status: dict[str, Any] = {"code": 500}

        async def capture(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = int(message["status"])
            await send(message)

        try:
            await self._app(scope, receive, capture)
        finally:
            route = scope.get("route")
            log.info(
                "api.request",
                method=str(scope.get("method", "")),
                route=str(getattr(route, "path", "") or "unmatched"),
                http_status=status["code"],
                duration_ms=int((time.perf_counter() - began) * 1000),
            )


_SIGNING_PREFIX = "/v1/signing"
_CORS_ALLOW_HEADERS = "Authorization, Content-Type, Idempotency-Key, X-Esign-Client"
_CORS_ALLOW_METHODS = "GET, POST, OPTIONS"


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or []:
        if bytes(key).lower() == name:
            raw = bytes(value).decode("latin-1").strip()
            return raw or None
    return None


def _cors_header_list(origin: str) -> list[tuple[bytes, bytes]]:
    return [
        (b"access-control-allow-origin", origin.encode("latin-1")),
        (b"access-control-allow-methods", _CORS_ALLOW_METHODS.encode("ascii")),
        (b"access-control-allow-headers", _CORS_ALLOW_HEADERS.encode("ascii")),
        (b"access-control-max-age", b"600"),
        (b"vary", b"Origin"),
    ]


class SigningCors:
    """CORS for ``/v1/signing/*`` only (Addendum 4).

    Preflight is answered when ``Origin`` is in any host's ``allowed_origins``. Actual requests
    from another origin are allowed only for an ``sdk`` session whose host listed that origin.
    Iframe sessions are unchanged: same-origin, no CORS headers.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        if not path.startswith(_SIGNING_PREFIX):
            await self._app(scope, receive, send)
            return

        origin = _header(scope, b"origin")
        method = str(scope.get("method", ""))
        rt = scope.get("app")
        runtime = None if rt is None else getattr(getattr(rt, "state", None), "runtime", None)

        if method == "OPTIONS":
            if origin is None or runtime is None or not _origin_known(runtime, origin):
                await error_response(403, "origin_not_allowed")(scope, receive, send)
                return
            await _preflight(origin)(scope, receive, send)
            return

        allow_origin: str | None = None
        if origin is not None and runtime is not None:
            decision = _actual_request(runtime, origin, _header(scope, b"authorization"))
            if decision == "deny":
                await error_response(403, "origin_not_allowed")(scope, receive, send)
                return
            if decision == "allow":
                allow_origin = origin

        async def with_cors(message: Message) -> None:
            if message["type"] == "http.response.start" and allow_origin is not None:
                headers: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                headers.extend(_cors_header_list(allow_origin))
                message = {**message, "headers": headers}
            await send(message)

        await self._app(scope, receive, with_cors)


def _origin_known(runtime: Any, origin: str) -> bool:
    from esign.identity.hosts import list_allowed_origins

    with runtime.new_session() as db:
        return origin in list_allowed_origins(db)


def _actual_request(runtime: Any, origin: str, authorization: str | None) -> str:
    """``allow`` (SDK + matching origin), ``pass`` (iframe / unauthenticated), or ``deny``."""
    from esign.contracts import Unauthorized
    from esign.identity.hosts import get_host

    if authorization is None:
        return "pass"
    try:
        with runtime.new_session() as db:
            session = runtime.identity.authenticate_session(db, authorization)
            if session.client_mode != "sdk":
                return "pass"
            host = get_host(db, session.host_id)
    except Unauthorized:
        return "pass"
    except Exception:
        return "deny"
    if origin not in host.allowed_origins:
        return "deny"
    return "allow"


def _preflight(origin: str) -> Any:
    from starlette.responses import Response

    headers = {name.decode("ascii"): value.decode("latin-1") for name, value in _cors_header_list(origin)}

    async def send_preflight(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response(status_code=204, headers=headers)
        await response(scope, receive, send)

    return send_preflight
