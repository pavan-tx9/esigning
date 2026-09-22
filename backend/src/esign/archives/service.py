"""Filing a scan of a paper-signed document (Addendum 1 A, SPEC section 3 "Paper archives").

One method, one transaction: check what the host said, check the scan is a plain PDF, store it
write-once as revision 1, insert the envelope, record who attested to it, and hand it to the
ordinary seal path. From ``completed_pending_seal`` onwards a paper archive is an envelope like
any other -- the seal job, the certificate, the webhooks, the verification report and the void
rules are the base spec's, with the cover page and the archive certificate as the only difference.

What the seal will prove, and what it will not: that the scan has not changed since it was filed,
and who filed and attested to it. Not that the ink is genuine. The cover page and the certificate
say so in plain words; this module's job is to make sure the record behind those words is true.

PHI discipline as everywhere else: the staff member and the paper signers are named in the
database and inside the sealed PDF. ``archive.created`` and ``archive.attested`` carry the opaque
staff id, the closed vocabularies and counts, and nothing else -- not a name, not the signing date.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any, Final, get_args
from uuid import UUID

from sqlalchemy.orm import Session

from esign.archives import repository as repo
from esign.clock import Clock
from esign.config import Settings
from esign.contracts import (
    Actor,
    Attestation,
    AuditLog,
    BlobService,
    Capacity,
    Conflict,
    DocumentService,
    EventType,
    Host,
    NewArchive,
    NotFound,
    OriginalDisposition,
    PaperSigner,
    RequestContext,
    TemplatePdfInfo,
    ValidationFailed,
    is_opaque_id,
)
from esign.ids import new_id
from esign.logging import get_logger

__all__ = ["ArchiveService", "build_archive_service"]

log = get_logger(__name__)

#: A display name printed on the cover page and the certificate. The same bound the envelope
#: service puts on a signer's display name, for the same reason: it ends up in sealed bytes.
_MAX_NAME_CHARS: Final[int] = 200

#: More paper signers than an envelope may have electronic ones would be a mis-filed document.
_MAX_PAPER_SIGNERS: Final[int] = 20

_CAPACITIES: Final[frozenset[str]] = frozenset(get_args(Capacity))
_DISPOSITIONS: Final[frozenset[str]] = frozenset(get_args(OriginalDisposition))


class ArchiveService:
    """Creation of ``kind = paper_archive`` envelopes. ``EnvelopeService.create_archive``
    delegates here; everything after ``completed_pending_seal`` is the envelope service's."""

    def __init__(
        self,
        settings: Settings,
        clock: Clock,
        *,
        audit_log: AuditLog,
        blob_service: BlobService,
        document_service: DocumentService,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._audit = audit_log
        self._blobs = blob_service
        self._documents = document_service

    def create(self, db: Session, host: Host, spec: NewArchive, scan: bytes, ctx: RequestContext) -> UUID:
        """File ``scan`` as a paper archive and return the new envelope's id.

        Everything happens in the caller's transaction: the blob, the envelope, the revision, both
        audit events and the seal job commit together or not at all.
        """
        now = self._clock.now()
        document_type = self._approved(spec.document_type)
        patient_ref = _require_opaque(spec.patient_ref, "patient_ref_invalid")
        attestation = _check_attestation(spec.attestation)
        paper_signed_on = _check_signing_date(spec.paper_signed_on, now)
        info = self._inspect(scan)
        superseded = self._lock_superseded(db, host, spec.supersedes_envelope_id)

        retain_until = self._settings.retain_until(document_type, now)
        blob = self._blobs.put(db, scan, kind="scan_pdf", retain_until=retain_until)

        envelope_id = new_id()
        repo.insert_archive_envelope(
            db,
            envelope_id=envelope_id,
            host_id=host.id,
            document_type=document_type,
            patient_ref=patient_ref,
            host_document_ref=spec.host_document_ref,
            scan_sha256=blob.sha256,
            paper_signed_on=paper_signed_on,
            attestation=repo.attestation_json(attestation),
            attested_at=now,
            supersedes_envelope_id=None if superseded is None else superseded.id,
            expires_at=self._settings.default_expiry(now),
            created_at=now,
        )
        repo.insert_scan_revision(db, revision_id=new_id(), envelope_id=envelope_id, sha256=blob.sha256, created_at=now)

        self._append(
            db,
            envelope_id,
            EventType.ARCHIVE_CREATED,
            actor=Actor(user_id=None, role="host"),
            ctx=ctx,
            document_sha256=blob.sha256,
            data={
                "host_id": host.id,
                "document_type": document_type,
                "page_count": info.page_count,
                "size_bytes": blob.size_bytes,
                "scan_sha256": blob.sha256,
                "supersedes_envelope_id": None if superseded is None else superseded.id,
            },
        )
        self._append(
            db,
            envelope_id,
            EventType.ARCHIVE_ATTESTED,
            # The staff member who says this is a true copy -- by opaque id, as an actor, exactly
            # as a kiosk staff member appears. The signature on the paper is not theirs and the
            # trail never says it is; what they attest to is the scan.
            actor=Actor(user_id=attestation.staff_user_id, role="staff"),
            ctx=ctx,
            data={
                "staff_user_id": attestation.staff_user_id,
                "statement": attestation.statement,
                "original_disposition": attestation.original_disposition,
                "paper_signer_count": len(attestation.paper_signers),
            },
        )
        if superseded is not None:
            self._append(
                db,
                superseded.id,
                EventType.ENVELOPE_SUPERSEDED,
                actor=Actor(user_id=None, role="host"),
                ctx=ctx,
                data={"superseded_by_envelope_id": envelope_id},
            )

        # Nobody signs an archive, so filing it completes it. The seal job is queued in this same
        # transaction; the route attempts it once inline afterwards, exactly as the last signature
        # does, and the worker retries on any failure.
        repo.mark_pending_seal(db, envelope_id, now)
        repo.enqueue_seal_job(db, envelope_id, now)

        log.info(
            "archive.created",
            envelope_id=envelope_id,
            host_id=host.id,
            document_type=document_type,
            page_count=info.page_count,
            document_sha256=blob.sha256,
            size_bytes=blob.size_bytes,
        )
        return envelope_id

    # ----------------------------------------------------------------- checks

    def _approved(self, document_type: str) -> str:
        """Compliance owns the list; a scan of anything else is not filed here (SPEC section 9)."""
        value = (document_type or "").strip()
        if not self._settings.is_approved_document_type(value):
            raise ValidationFailed("document type is not approved here", code="document_type_not_approved")
        return value

    def _inspect(self, scan: bytes) -> TemplatePdfInfo:
        """The template hygiene rules under the scan bounds (``DocumentService.inspect_scan_pdf``).

        Image-only pages are expected and fine; anything active, encrypted or already signed is
        not, and the document service answers with ``scan_`` codes.
        """
        return self._documents.inspect_scan_pdf(scan)

    def _lock_superseded(self, db: Session, host: Host, envelope_id: UUID | None) -> repo.SupersededRow | None:
        """The same rule ``EnvelopeService.create`` applies: only a sealed envelope of this host,
        of either kind, and only once."""
        if envelope_id is None:
            return None
        old = repo.lock_envelope(db, envelope_id)
        if old is None or old.host_id != host.id:
            # Another host's envelope and no envelope look the same on purpose (SPEC section 10).
            raise NotFound("no such envelope", code="not_found")
        if old.status != "sealed":
            raise Conflict("only a sealed envelope can be superseded", code="supersedes_not_sealed")
        if repo.superseded_by(db, envelope_id) is not None:
            raise Conflict("that envelope has already been superseded", code="already_superseded")
        return old

    # ----------------------------------------------------------------- audit

    def _append(
        self,
        db: Session,
        stream_id: UUID,
        event_type: EventType,
        *,
        actor: Actor,
        ctx: RequestContext,
        document_sha256: bytes | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        payload = {key: value for key, value in (data or {}).items() if value is not None}
        self._audit.append(
            db,
            stream_type="envelope",
            stream_id=stream_id,
            event_type=event_type,
            actor=actor,
            ctx=ctx,
            document_sha256=document_sha256,
            data=payload,
        )


# --------------------------------------------------------------------------- validation helpers


def _require_opaque(value: str, code: str = "host_user_id_invalid") -> str:
    """Host-chosen identifiers reach the audit trail, so they must not be facts about a person.
    The codes are the ones ``EnvelopeService.create`` uses: ``patient_ref_invalid`` for the
    patient reference, ``host_user_id_invalid`` for a person's id."""
    text_value = (value or "").strip()
    if not is_opaque_id(text_value):
        raise ValidationFailed("an identifier must be opaque: no spaces, not a name or a date", code=code)
    return text_value


def _require_name(value: str) -> str:
    text_value = (value or "").strip()
    if not text_value or len(text_value) > _MAX_NAME_CHARS:
        raise ValidationFailed("a required value is missing or too long", code="attestation_invalid")
    return text_value


def _check_attestation(attestation: Attestation) -> Attestation:
    """What the staff member says, checked before it is stored and printed.

    The wire types already close the two vocabularies; they are re-checked here because this
    method is also reachable from the CLI and the tests, and because the schema's CHECK would
    otherwise be the only thing between a bad value and a driver error with no usable code.
    """
    if attestation.statement != "true_copy":
        raise ValidationFailed("unknown attestation statement", code="attestation_invalid")
    if attestation.original_disposition not in _DISPOSITIONS:
        raise ValidationFailed("unknown disposition of the original", code="attestation_invalid")
    if not attestation.paper_signers:
        raise ValidationFailed("a paper document has at least one signer", code="attestation_invalid")
    if len(attestation.paper_signers) > _MAX_PAPER_SIGNERS:
        raise ValidationFailed("too many paper signers", code="attestation_invalid")
    for signer in attestation.paper_signers:
        if signer.capacity not in _CAPACITIES:
            raise ValidationFailed("unknown capacity for a paper signer", code="attestation_invalid")
        _require_name(signer.display_name)
    return Attestation(
        staff_user_id=_require_opaque(attestation.staff_user_id),
        staff_display_name=_require_name(attestation.staff_display_name),
        statement=attestation.statement,
        original_disposition=attestation.original_disposition,
        paper_signers=tuple(
            PaperSigner(display_name=_require_name(signer.display_name), capacity=signer.capacity)
            for signer in attestation.paper_signers
        ),
    )


def _check_signing_date(paper_signed_on: date, now: datetime) -> date:
    """The date on the paper. It cannot be in the future: a document signed tomorrow was not."""
    if not isinstance(paper_signed_on, date) or isinstance(paper_signed_on, datetime):
        # A ``datetime`` is a ``date``, and storing one here would put a time of day on the
        # cover page that the paper does not carry.
        raise ValidationFailed("paper_signed_on is a date", code="paper_signed_on_invalid")
    if paper_signed_on > now.astimezone(UTC).date():
        raise ValidationFailed("paper_signed_on is in the future", code="paper_signed_on_in_future")
    return paper_signed_on


def build_archive_service(
    settings: Settings,
    clock: Clock,
    *,
    audit_log: AuditLog,
    blob_service: BlobService,
    document_service: DocumentService,
) -> ArchiveService:
    """The module's one factory (SPEC section 2). ``esign.runtime`` is the only caller."""
    return ArchiveService(
        settings,
        clock,
        audit_log=audit_log,
        blob_service=blob_service,
        document_service=document_service,
    )
