"""``POST /v1/archives`` (Addendum 1 A, SPEC section 9): filing a scan of a paper-signed document.

One route, in the Host API's style: one transaction, host-scoped, the response built after the
commit. It is multipart rather than JSON because the scan is a file -- ``scan`` plus ``body``, a
JSON document that is exactly ``NewArchive``. Converting a photograph or a TIFF into a PDF is the
host's job: this route takes a PDF and says so, rather than guessing at an image.

Like the last signature, the seal is attempted once inline after the commit and in a transaction
of its own. If KMS, the timestamp authority or storage is down the archive still exists, the
failure is recorded, and the worker retries; the response reports the state as of filing and never
says "sealed" on the strength of an attempt.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, File, Form, Header, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from esign.api import idempotency
from esign.api.context import authenticate_host, runtime_of
from esign.api.schemas import envelope_json
from esign.contracts import (
    Attestation,
    AttestationStatement,
    Capacity,
    NewArchive,
    OriginalDisposition,
    PaperSigner,
    ValidationFailed,
)
from esign.identity import RateLimits, host_key
from esign.logging import get_logger
from esign.runtime import Runtime
from esign.worker import claim_seal_job, seal_one

__all__ = ["router"]

log = get_logger(__name__)
router = APIRouter(prefix="/v1", tags=["host"])


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PaperSignerBody(_Body):
    display_name: str = Field(max_length=200)
    capacity: Capacity


class AttestationBody(_Body):
    """What the staff member filing the scan says about it.

    ``statement`` is a closed vocabulary of one: there is exactly one thing this service records a
    staff member as attesting to, and "this is a true copy" is it. A second statement would be a
    second legal meaning, and it would have to be written down before it could be claimed.
    """

    staff_user_id: str = Field(max_length=128)
    staff_display_name: str = Field(max_length=200)
    statement: AttestationStatement
    original_disposition: OriginalDisposition
    paper_signers: list[PaperSignerBody] = Field(min_length=1, max_length=20)

    def to_contract(self) -> Attestation:
        return Attestation(
            staff_user_id=self.staff_user_id,
            staff_display_name=self.staff_display_name,
            statement=self.statement,
            original_disposition=self.original_disposition,
            paper_signers=tuple(
                PaperSigner(display_name=s.display_name, capacity=s.capacity) for s in self.paper_signers
            ),
        )


class NewArchiveBody(_Body):
    """The ``body`` part of the multipart request: ``NewArchive`` on the wire.

    Unknown keys are refused here as everywhere else. A host that sends ``template_key``,
    ``signers``, a hash or a timestamp is told so rather than having it quietly dropped: a paper
    archive has no template and no signers, and a client that thinks otherwise has a bug worth
    hearing about.
    """

    patient_ref: str = Field(max_length=128)
    document_type: str = Field(max_length=64)
    host_document_ref: str | None = Field(default=None, max_length=200)
    paper_signed_on: date
    attestation: AttestationBody
    supersedes_envelope_id: UUID | None = None

    def to_contract(self) -> NewArchive:
        return NewArchive(
            patient_ref=self.patient_ref,
            document_type=self.document_type,
            host_document_ref=self.host_document_ref,
            paper_signed_on=self.paper_signed_on,
            attestation=self.attestation.to_contract(),
            supersedes_envelope_id=self.supersedes_envelope_id,
        )


def _parse_body(raw: str) -> NewArchiveBody:
    """``body`` as a ``NewArchiveBody``, or 422. Pydantic's own message quotes the input, so it
    never leaves this function -- the code is what the host reads (SPEC section 9)."""
    try:
        document = json.loads(raw)
    except ValueError:
        raise ValidationFailed("body is not valid JSON", code="validation_failed") from None
    if not isinstance(document, dict):
        raise ValidationFailed("body must be an object", code="validation_failed")
    try:
        return NewArchiveBody.model_validate(document)
    except ValidationError:
        raise ValidationFailed("body is not a valid archive", code="validation_failed") from None


def _read_scan(rt: Runtime, upload: UploadFile) -> bytes:
    """The scan, refused by size before anything tries to parse it.

    The middleware caps the whole request at ``MAX_SCAN_BYTES`` plus multipart overhead; this
    catches the part itself, so a host that sends one enormous part inside a legal request gets
    ``scan_too_large`` rather than a 413 about the envelope around it.
    """
    data = upload.file.read(rt.settings.max_scan_bytes + 1)
    if len(data) > rt.settings.max_scan_bytes:
        raise ValidationFailed("the scan is too large", code="scan_too_large")
    return data


@router.post("/archives", status_code=201)
def create_archive(
    request: Request,
    scan: Annotated[UploadFile, File()],
    body: Annotated[str, Form(max_length=100_000)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=200)] = None,
) -> JSONResponse:
    """File a scan of a document signed in ink. Returns an ``EnvelopeView`` with
    ``kind: "paper_archive"``, as of filing (``completed_pending_seal``)."""
    rt = runtime_of(request)
    parsed = _parse_body(body)
    data = _read_scan(rt, scan)
    with rt.transaction() as db:
        host, ctx = authenticate_host(request, rt, db)
        # Filing a scan stores a blob, appends two audit events and queues a seal job, none of
        # which has a delete path. Metered on the host, like the other calls that create evidence.
        limit = RateLimits.SESSION_CREATE
        rt.limiter.hit(host_key("archive_create", host.id), limit=limit.limit, window_seconds=limit.window_seconds)
        scope = f"host:{host.id}"
        if idempotency_key is not None:
            # The digest covers the scan as well as the body: the same key with a different
            # document is a different request, and must not replay this one's answer.
            digest = idempotency.request_hash(
                "POST",
                "/v1/archives",
                {**parsed.model_dump(mode="json"), "scan_sha256": hashlib.sha256(data).hexdigest()},
            )
            stored = idempotency.begin(
                db,
                scope=scope,
                key=idempotency_key,
                digest=digest,
                now=rt.clock.now(),
                ttl=timedelta(hours=rt.settings.idempotency_ttl_hours),
            )
            if stored is not None:
                # As for ``POST /v1/envelopes``: what is stored is the envelope's id, so a replay
                # shows that archive as it is now rather than a second copy of the first answer.
                replayed = rt.envelopes.get(db, host, UUID(str(stored.body["envelope_id"])))
                return JSONResponse(envelope_json(replayed), status_code=stored.status)
        view = rt.envelopes.create_archive(db, host, parsed.to_contract(), data, ctx)
        if idempotency_key is not None:
            idempotency.complete(db, scope=scope, key=idempotency_key, status=201, body={"envelope_id": str(view.id)})
    if view.status == "completed_pending_seal":
        # Claim the job like a worker would, so a worker ticking right now does not make a second
        # attempt inside the backoff window if this one fails. ``seal_one`` never raises for an
        # expected failure; the job stays queued either way.
        claimed_at = rt.clock.now()
        with rt.transaction() as db:
            mine = claim_seal_job(db, view.id, now=claimed_at)
        if mine:
            seal_one(rt, view.id, claimed_at=claimed_at)
    return JSONResponse(envelope_json(view), status_code=201)
