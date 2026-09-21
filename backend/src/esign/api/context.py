"""What the server knows about a request without asking the client: who connected, with which
credential, from where.

``RequestContext`` is built here and only here. The IP is the transport peer unless that peer is a
configured proxy (``TRUSTED_PROXY_CIDRS``), in which case the forwarded chain is walked; the user
agent is the header, bounded. Nothing in it comes from a JSON body.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

from fastapi import Request
from sqlalchemy.orm import Session

from esign.contracts import EsignError, Host, RequestContext, SessionInfo, Unauthorized
from esign.identity import RateLimits, client_ip, ip_key
from esign.runtime import Runtime

__all__ = ["authenticate_host", "authenticate_signer", "request_context", "runtime_of"]

_MAX_USER_AGENT = 512


def runtime_of(request: Request) -> Runtime:
    return cast(Runtime, request.app.state.runtime)


def request_context(request: Request, rt: Runtime) -> RequestContext:
    peer = request.client.host if request.client else None
    ip = client_ip(peer, request.headers.get("x-forwarded-for"), rt.settings.trusted_proxy_cidrs)
    agent = request.headers.get("user-agent")
    return RequestContext(ip=ip, user_agent=agent[:_MAX_USER_AGENT] if agent else None)


def _failed(rt: Runtime, ctx: RequestContext, exc: EsignError) -> EsignError:
    """Count a credential that did not authenticate, per IP. Past the limit the answer becomes
    429, which is what stops a guessing loop from being free."""
    limit = RateLimits.TOKEN_FAILURE
    try:
        rt.limiter.hit(ip_key("token_failure", ctx.ip), limit=limit.limit, window_seconds=limit.window_seconds)
    except EsignError as limited:
        return limited
    return exc


def authenticate_host(request: Request, rt: Runtime, db: Session) -> tuple[Host, RequestContext]:
    ctx = request_context(request, rt)
    try:
        host = rt.identity.authenticate_host(db, request.headers.get("authorization") or "")
    except Unauthorized as exc:
        raise _failed(rt, ctx, exc) from None
    return host, replace(ctx, auth_method="api_key")


def authenticate_signer(request: Request, rt: Runtime, db: Session) -> tuple[SessionInfo, RequestContext]:
    ctx = request_context(request, rt)
    try:
        session = rt.identity.authenticate_session(db, request.headers.get("authorization") or "")
    except Unauthorized as exc:
        raise _failed(rt, ctx, exc) from None
    # The context of a signer's action records how *they* authenticated, as the host attested it.
    return session, replace(ctx, auth_method=session.auth.method, session_id=session.id)
