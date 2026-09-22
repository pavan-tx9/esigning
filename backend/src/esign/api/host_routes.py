"""The Host API (SPEC section 9): server to server, ``Authorization: Bearer esk_...``.

Every handler is one transaction (``rt.transaction()``): it commits when the block exits cleanly
and rolls back on any exception, and the response is built only after the commit -- a host is
never told something happened that did not. Every lookup is scoped to the authenticated host, so
another host's envelope, template or session is ``not_found`` (SPEC section 10).
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, File, Form, Header, Request, UploadFile
from fastapi.responses import JSONResponse, Response

from esign.api import idempotency
from esign.api.context import authenticate_host, runtime_of
from esign.api.schemas import (
    NewEnvelopeBody,
    ReauthBody,
    SessionBody,
    VoidBody,
    audit_event_json,
    envelope_json,
    template_json,
    timestamp,
)
from esign.api.template_service import TemplateService
from esign.contracts import (
    Actor,
    Conflict,
    EsignError,
    EventType,
    Host,
    NotFound,
    RequestContext,
    SignerView,
    ValidationFailed,
)
from esign.identity import RateLimits, host_key
from esign.logging import get_logger
from esign.runtime import Runtime
from esign.verification import Verifier

__all__ = ["router"]

log = get_logger(__name__)
router = APIRouter(prefix="/v1", tags=["host"])

_HOST_ACTOR = Actor(role="host")
_PDF_HEADERS = {"Cache-Control": "no-store", "Content-Disposition": 'attachment; filename="document.pdf"'}


def _templates(rt: Runtime) -> TemplateService:
    return TemplateService(rt.settings, rt.clock, audit=rt.audit, blobs=rt.blobs, documents=rt.documents)


def _read_upload(rt: Runtime, upload: UploadFile) -> bytes:
    data = upload.file.read(rt.settings.max_template_bytes + 1)
    if len(data) > rt.settings.max_template_bytes:
        raise ValidationFailed("the template PDF is too large", code="template_too_large")
    return data


def _parse_definitions(raw: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        raise ValidationFailed("definitions is not valid JSON", code="definitions_invalid") from None


# --------------------------------------------------------------------------- templates


@router.post("/templates", status_code=201)
def create_template(
    request: Request,
    pdf: Annotated[UploadFile, File()],
    definitions: Annotated[str, Form(max_length=2_000_000)],
) -> JSONResponse:
    """Multipart: ``pdf`` plus ``definitions``, a JSON document
    ``{key, name, document_type, fields, prefill_fields, signer_roles}``. Creates draft version 1."""
    rt = runtime_of(request)
    document = _parse_definitions(definitions)
    if not isinstance(document, dict):
        raise ValidationFailed("definitions must be an object", code="definitions_invalid")
    with rt.transaction() as db:
        host, _ctx = authenticate_host(request, rt, db)
        view = _templates(rt).create(
            db,
            host,
            key=str(document.get("key", "")),
            name=str(document.get("name", "")),
            document_type=str(document.get("document_type", "")),
            pdf=_read_upload(rt, pdf),
            definitions=document,
        )
    return JSONResponse(template_json(view), status_code=201)


@router.post("/templates/{key}/versions", status_code=201)
def create_template_version(
    request: Request,
    key: str,
    pdf: Annotated[UploadFile, File()],
    definitions: Annotated[str, Form(max_length=2_000_000)],
) -> JSONResponse:
    rt = runtime_of(request)
    document = _parse_definitions(definitions)
    with rt.transaction() as db:
        host, _ctx = authenticate_host(request, rt, db)
        view = _templates(rt).add_version(db, host, key, pdf=_read_upload(rt, pdf), definitions=document)
    return JSONResponse(template_json(view), status_code=201)


@router.post("/templates/{key}/versions/{version}/publish")
def publish_template_version(request: Request, key: str, version: int) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, ctx = authenticate_host(request, rt, db)
        view = _templates(rt).publish(db, host, key, version, ctx)
    return JSONResponse(template_json(view))


@router.post("/templates/{key}/versions/{version}/retire")
def retire_template_version(request: Request, key: str, version: int) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, ctx = authenticate_host(request, rt, db)
        view = _templates(rt).retire(db, host, key, version, ctx)
    return JSONResponse(template_json(view))


@router.get("/templates")
def list_templates(request: Request) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, _ctx = authenticate_host(request, rt, db)
        views = _templates(rt).list(db, host)
    return JSONResponse({"templates": [template_json(v, detail=False) for v in views]})


@router.get("/templates/{key}")
def get_template(request: Request, key: str) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, _ctx = authenticate_host(request, rt, db)
        view = _templates(rt).get(db, host, key)
    return JSONResponse(template_json(view))


# --------------------------------------------------------------------------- envelopes


@router.post("/envelopes", status_code=201)
def create_envelope(
    request: Request,
    body: NewEnvelopeBody,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=200)] = None,
) -> JSONResponse:
    """Create an envelope from a published template version. With an ``Idempotency-Key`` a retry
    returns the same envelope instead of creating a second one. The stored replay is the envelope's
    *id*, not the response body -- the body carries display names and there is no reason to keep
    a second copy of those -- so a replay shows that envelope as it is now."""
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, ctx = authenticate_host(request, rt, db)
        scope = f"host:{host.id}"
        if idempotency_key is not None:
            digest = idempotency.request_hash("POST", "/v1/envelopes", body.model_dump(mode="json"))
            stored = idempotency.begin(
                db,
                scope=scope,
                key=idempotency_key,
                digest=digest,
                now=rt.clock.now(),
                ttl=timedelta(hours=rt.settings.idempotency_ttl_hours),
            )
            if stored is not None:
                view = rt.envelopes.get(db, host, UUID(str(stored.body["envelope_id"])))
                return JSONResponse(envelope_json(view), status_code=stored.status)
        view = rt.envelopes.create(db, host, body.to_contract(), ctx)
        if idempotency_key is not None:
            idempotency.complete(db, scope=scope, key=idempotency_key, status=201, body={"envelope_id": str(view.id)})
    return JSONResponse(envelope_json(view), status_code=201)


@router.get("/envelopes/{envelope_id}")
def get_envelope(request: Request, envelope_id: UUID) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, _ctx = authenticate_host(request, rt, db)
        view = rt.envelopes.get(db, host, envelope_id)
    return JSONResponse(envelope_json(view))


@router.post("/envelopes/{envelope_id}/void")
def void_envelope(request: Request, envelope_id: UUID, body: VoidBody) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, ctx = authenticate_host(request, rt, db)
        view = rt.envelopes.void(db, host, envelope_id, body.reason_code, ctx)
    return JSONResponse(envelope_json(view))


def _record_rejection(
    rt: Runtime, envelope_id: UUID, signer: SignerView, ctx: RequestContext, reason_code: str
) -> None:
    """``session.rejected``, in a transaction of its own: the refused request's transaction has
    been rolled back, and the refusal is evidence that has to survive that."""
    try:
        with rt.transaction() as db:
            rt.audit.append(
                db,
                stream_type="envelope",
                stream_id=envelope_id,
                event_type=EventType.SESSION_REJECTED,
                actor=_HOST_ACTOR,
                ctx=ctx,
                data={"signer_id": signer.id, "role_key": signer.role_key, "reason_code": reason_code},
            )
    except Exception:
        log.error("session.rejection_unrecorded", envelope_id=envelope_id, signer_id=signer.id, reason_code=reason_code)


@router.post("/envelopes/{envelope_id}/signers/{signer_id}/sessions", status_code=201)
def create_session(request: Request, envelope_id: UUID, signer_id: UUID, body: SessionBody) -> JSONResponse:
    rt = runtime_of(request)
    known: tuple[Host, RequestContext, SignerView] | None = None
    try:
        with rt.transaction() as db:
            host, ctx = authenticate_host(request, rt, db)
            limit = RateLimits.SESSION_CREATE
            rt.limiter.hit(host_key("session_create", host.id), limit=limit.limit, window_seconds=limit.window_seconds)
            view = rt.envelopes.get(db, host, envelope_id)  # not_found for another host's envelope
            signer = next((s for s in view.signers if s.id == signer_id), None)
            if signer is None:
                raise NotFound("no such signer", code="not_found")
            known = (host, ctx, signer)
            rt.envelopes.assert_signer_may_start(db, host, envelope_id, signer_id)
            kiosk = body.kiosk_context()
            token, info = rt.identity.create_session(
                db, signer_id=signer_id, auth=body.auth.to_contract(), kiosk=kiosk, ctx=ctx
            )
            rt.audit.append(
                db,
                stream_type="envelope",
                stream_id=envelope_id,
                event_type=EventType.SESSION_CREATED,
                actor=_HOST_ACTOR,
                ctx=RequestContext(ip=ctx.ip, user_agent=ctx.user_agent, auth_method="api_key", session_id=info.id),
                data={
                    "signer_id": signer_id,
                    "role_key": signer.role_key,
                    "auth_method": info.auth.method,
                    "auth_time": info.auth.auth_time,
                    "expires_at": info.expires_at,
                    "kiosk": info.kiosk is not None,
                    "kiosk_staff_user_id": info.kiosk.staff_user_id if info.kiosk else None,
                    "kiosk_identity_check": info.kiosk.identity_check if info.kiosk else None,
                },
            )
    except (Conflict, ValidationFailed) as exc:
        if known is not None:
            _record_rejection(rt, envelope_id, known[2], known[1], exc.code)
        raise
    # The token appears here, once, and nowhere else: not in a log line, not in the database.
    return JSONResponse(
        {"token": token, "session_id": str(info.id), "expires_at": timestamp(info.expires_at)}, status_code=201
    )


@router.post("/sessions/{session_id}/reauth")
def attest_reauth(request: Request, session_id: UUID, body: ReauthBody) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, ctx = authenticate_host(request, rt, db)
        limit = RateLimits.REAUTH
        rt.limiter.hit(host_key("reauth", host.id), limit=limit.limit, window_seconds=limit.window_seconds)
        info = rt.identity.attest_reauth(db, host=host, session_id=session_id, auth=body.to_contract())
        # The identity module only knows the session is live, and the session a signer signed from
        # stays live for the copy download. Only the envelope service can say whether an
        # attestation could still belong to a signature: it takes the envelope row lock and checks
        # the signer has not finished and the role re-authenticates at all.
        rt.envelopes.assert_reauth_allowed(db, info.envelope_id, info.signer_id)
        rt.audit.append(
            db,
            stream_type="envelope",
            stream_id=info.envelope_id,
            event_type=EventType.REAUTH_ATTESTED,
            actor=_HOST_ACTOR,
            ctx=RequestContext(ip=ctx.ip, user_agent=ctx.user_agent, auth_method="api_key", session_id=info.id),
            data={"signer_id": info.signer_id, "method": body.method, "auth_time": body.auth_time},
        )
        valid_until = body.auth_time + timedelta(seconds=rt.settings.reauth_max_age_seconds)
    return JSONResponse({"session_id": str(info.id), "reauth_valid_until": timestamp(valid_until)})


@router.get("/envelopes/{envelope_id}/document")
def get_sealed_document(request: Request, envelope_id: UUID) -> Response:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, ctx = authenticate_host(request, rt, db)
        pdf = rt.envelopes.sealed_document(db, host, envelope_id, ctx)  # 409 not_sealed until it is
    return Response(pdf, media_type="application/pdf", headers=_PDF_HEADERS)


@router.get("/envelopes/{envelope_id}/audit")
def get_audit_trail(request: Request, envelope_id: UUID) -> JSONResponse:
    rt = runtime_of(request)
    with rt.transaction() as db:
        host, _ctx = authenticate_host(request, rt, db)
        rt.envelopes.get(db, host, envelope_id)  # host scoping
        events = rt.audit.list(db, "envelope", envelope_id)
    return JSONResponse({"envelope_id": str(envelope_id), "events": [audit_event_json(e) for e in events]})


@router.get("/envelopes/{envelope_id}/verification")
def verify_envelope(request: Request, envelope_id: UUID) -> JSONResponse:
    """Run the checks now and return the report. Always 200 when the envelope exists: a failed
    verification is a finding to be read, not a transport error."""
    rt = runtime_of(request)
    verifier = Verifier(audit=rt.audit, blobs=rt.blobs, sealer=rt.sealer)
    with rt.transaction() as db:
        host, ctx = authenticate_host(request, rt, db)
        # Every call re-hashes every revision, validates the seal with pyHanko and appends
        # ``verification.performed`` to an append-only trail that has no delete path.
        limit = RateLimits.VERIFY
        rt.limiter.hit(host_key("verify", host.id), limit=limit.limit, window_seconds=limit.window_seconds)
        report = verifier.verify_envelope(db, envelope_id, host=host, actor=_HOST_ACTOR, ctx=ctx)
    return JSONResponse(report.to_json())


# --------------------------------------------------------------------------- out of scope (SPEC section 1)


def _out_of_scope() -> EsignError:
    return ValidationFailed("out of scope", code="out_of_scope")


@router.post("/envelopes/bulk", include_in_schema=False)
@router.post("/envelopes/{envelope_id}/email-links", include_in_schema=False)
@router.post("/envelopes/{envelope_id}/documents", include_in_schema=False)
def out_of_scope() -> JSONResponse:
    """Bulk send, email-link signing and uploaded PDFs at signing time are refused with a clear
    code rather than approximated."""
    raise _out_of_scope()
