"""The Signer API (SPEC section 9): the embedded UI, ``Authorization: Bearer est_...``.

The session token is the only credential and the only thing that says which signer and which
envelope a request is about: no route here takes an id. One transaction per request; the response
is built after the commit.

What the client may send is signature *inputs* and nothing else. It never supplies PDF bytes,
hashes, timestamps, identity or a ``date_signed`` value -- the request models forbid unknown keys,
so an attempt is a 422 rather than a value quietly ignored.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any, Final

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from esign.api import idempotency
from esign.api.context import authenticate_signer, runtime_of
from esign.api.schemas import (
    ConsentBody,
    DeclineBody,
    SignBody,
    ViewedBody,
    signer_ack_json,
    signing_session_json,
)
from esign.contracts import RequestContext, SessionInfo, ValidationFailed
from esign.identity import Limit, RateLimits, ip_key, session_key
from esign.runtime import Runtime
from esign.worker import claim_seal_job, seal_one

__all__ = ["router"]

router = APIRouter(prefix="/v1/signing", tags=["signer"])

_PDF_HEADERS = {"Cache-Control": "no-store", "Content-Disposition": 'inline; filename="document.pdf"'}


#: Which rule each limited scope uses. ``sign`` and ``consent`` are SPEC section 8's; ``present``
#: and ``copy`` cover the two GETs that append an audit event or re-hash a revision on every call.
_LIMITS: Final[dict[str, Limit]] = {
    "sign": RateLimits.SIGN,
    "consent": RateLimits.CONSENT,
    "present": RateLimits.PRESENT,
    "copy": RateLimits.COPY,
}


def _limit(rt: Runtime, scope: str, session: SessionInfo, ctx: RequestContext) -> None:
    """Per session and per IP, as SPEC section 8 asks for sign and consent."""
    limit = _LIMITS[scope]
    rt.limiter.hit(session_key(scope, session.id), limit=limit.limit, window_seconds=limit.window_seconds)
    # One clinic is one IP for many patients: the per-IP allowance is wider than the per-session one.
    rt.limiter.hit(ip_key(scope, ctx.ip), limit=limit.limit * 20, window_seconds=limit.window_seconds)


def _signer_ack(rt: Runtime, db: Session, session: SessionInfo) -> dict[str, Any]:
    """Ids and statuses, the same shape ``sign`` and ``decline`` answer with."""
    view = rt.envelopes.signing_view(db, session)
    return {
        "envelope": {"id": str(view.envelope_id), "status": view.envelope_status},
        "signer": {"id": str(view.signer.id), "status": view.signer.status},
    }


@router.get("/session")
def get_session(
    request: Request, locale: Annotated[str | None, Query(max_length=35, pattern=r"^[A-Za-z0-9-]+$")] = None
) -> JSONResponse:
    """Everything the UI needs. ``locale`` selects the disclosure language (falls back to the
    default locale); it is a language tag, never anything about the signer."""
    rt = runtime_of(request)
    with rt.transaction() as db:
        session, ctx = authenticate_signer(request, rt, db)
        # Cheap-looking but not cheap: ``signing_view`` fetches and parses the current revision to
        # count its pages.
        _limit(rt, "present", session, ctx)
        view = rt.envelopes.signing_view(db, session)
        consent = rt.identity.current_consent(db, locale or rt.settings.default_locale)
    return JSONResponse(signing_session_json(view, consent, session))


@router.get("/document")
def get_document(request: Request) -> Response:
    """The current revision. Serving it *is* the ``document.presented`` event: the hash recorded is
    the hash of the bytes in this response."""
    rt = runtime_of(request)
    with rt.transaction() as db:
        session, ctx = authenticate_signer(request, rt, db)
        # Serving the document appends an audit event, and there is no delete path for those.
        _limit(rt, "present", session, ctx)
        pdf = rt.envelopes.present(db, session, ctx)
    return Response(pdf, media_type="application/pdf", headers=_PDF_HEADERS)


@router.post("/viewed")
def post_viewed(request: Request, body: ViewedBody) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        session, ctx = authenticate_signer(request, rt, db)
        rt.envelopes.record_viewed(db, session, body.pages_viewed, ctx)
        ack = _signer_ack(rt, db, session)
    return JSONResponse(ack)


@router.post("/consent")
def post_consent(request: Request, body: ConsentBody) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        session, ctx = authenticate_signer(request, rt, db)
        _limit(rt, "consent", session, ctx)
        rt.envelopes.accept_consent(db, session, body.consent_version, ctx, locale=body.locale)
        ack = _signer_ack(rt, db, session)
    return JSONResponse(ack)


@router.post("/sign")
def post_sign(
    request: Request,
    body: SignBody,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=200)] = None,
) -> JSONResponse:
    """Apply this signer's marks. Idempotent: the same key and body replays the first response,
    the same key with a different body is a ``conflict``.

    When this was the last signature the envelope is ``completed_pending_seal`` and a seal job is
    queued in the same transaction. One sealing attempt is then made inline, *after* that commit
    and in a transaction of its own: if KMS, the timestamp authority or storage is down the
    signature still stands, the failure is recorded, and the worker retries. The response reports
    the state as of the signature, never "sealed" on the strength of an attempt.
    """
    rt = runtime_of(request)
    if idempotency_key is None:
        raise ValidationFailed("signing needs an Idempotency-Key", code="idempotency_key_required")
    with rt.transaction() as db:
        session, ctx = authenticate_signer(request, rt, db)
        scope = f"session:{session.id}"
        # The digest covers the captures, image included. Only the digest is kept.
        digest = idempotency.request_hash("POST", "/v1/signing/sign", body.model_dump(mode="json"))
        stored = idempotency.begin(
            db,
            scope=scope,
            key=idempotency_key,
            digest=digest,
            now=rt.clock.now(),
            ttl=timedelta(hours=rt.settings.idempotency_ttl_hours),
        )
        if stored is not None:
            return JSONResponse(stored.body, status_code=stored.status)
        # After the replay check: a retry of a signature that already succeeded must get its first
        # answer back, not a 429, however many times the connection drops.
        _limit(rt, "sign", session, ctx)
        view = rt.envelopes.sign(db, session, body.to_contract(rt.settings), ctx)
        ack = signer_ack_json(view, session.signer_id)
        idempotency.complete(db, scope=scope, key=idempotency_key, status=200, body=ack)
    if view.status == "completed_pending_seal":
        # Claim the job like any worker would, so a worker ticking right now does not make a second
        # attempt inside the backoff window if this one fails. If a worker got there first, it
        # seals. seal_one never raises for an expected failure; the job stays queued either way.
        claimed_at = rt.clock.now()
        with rt.transaction() as db:
            mine = claim_seal_job(db, view.id, now=claimed_at)
        if mine:
            seal_one(rt, view.id, claimed_at=claimed_at)
    return JSONResponse(ack)


@router.post("/decline")
def post_decline(request: Request, body: DeclineBody) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        session, ctx = authenticate_signer(request, rt, db)
        view = rt.envelopes.decline(db, session, body.reason_code, ctx)
    return JSONResponse(signer_ack_json(view, session.signer_id))


@router.get("/copy")
def get_copy(request: Request) -> Response:
    """The sealed PDF (recording ``document.downloaded``), or ``202 {"status": "sealing"}`` while
    the seal is pending. ``409 envelope_not_complete`` while other signers are outstanding. Nothing
    short of the sealed document is ever handed out as "your copy"."""
    rt = runtime_of(request)
    with rt.transaction() as db:
        session, ctx = authenticate_signer(request, rt, db)
        # Handing over the copy appends ``document.downloaded``; the UI polls this while sealing.
        _limit(rt, "copy", session, ctx)
        pdf = rt.envelopes.signer_copy(db, session, ctx)
    if pdf is None:
        return JSONResponse({"status": "sealing"}, status_code=202)
    headers = {**_PDF_HEADERS, "Content-Disposition": 'attachment; filename="signed-document.pdf"'}
    return Response(pdf, media_type="application/pdf", headers=headers)
