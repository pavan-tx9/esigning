"""``DocumentService``: the implementation the rest of the system talks to.

Every method is a thin, typed front for one focused module, so this file stays readable and the
interesting logic stays testable on its own. Nothing here touches the database, the clock or the
network: given the same inputs it returns the same bytes, which is what lets a revision hash mean
something.

Logging deliberately carries counts, hashes, page counts and error codes -- never a prefill value,
a display name, a typed signature or PDF bytes. See ``esign.logging``.
"""

from __future__ import annotations

from pypdf import PdfWriter

from esign.config import Settings
from esign.contracts import (
    CERTIFICATE_OF_COMPLETION_FILENAME,
    ArchiveCoverSummary,
    Capture,
    CertificateSummary,
    Clock,
    FieldDef,
    PrefillFieldDef,
    SignerRoleDef,
    SignerStamp,
    TemplatePdfInfo,
    ValidationFailed,
)
from esign.documents import archive_cover as archive_cover_module
from esign.documents import certificate as certificate_module
from esign.documents import definitions as definitions_module
from esign.documents import images, inspection, stamping, supplied
from esign.documents.fonts import ensure_fonts_registered
from esign.documents.pdfutil import open_reader, sanitize_document, sanitized_bytes, to_bytes, writer_from_bytes
from esign.logging import get_logger

__all__ = ["PdfDocumentService"]

log = get_logger(__name__)


def _sanitized_writer(writer: PdfWriter) -> PdfWriter:
    """The writer ``sanitized_bytes`` would write, still open so a file can be attached.

    ``sanitize_document`` removes ``/Names``. An attachment added before this step would be
    deleted with it, so callers attach afterwards and write with ``to_bytes`` directly.
    """
    sanitize_document(writer)
    reborn = writer_from_bytes(to_bytes(writer))
    sanitize_document(reborn, flatten_annotations=False)
    return reborn


def _recoded(code: str, kind: str) -> str:
    """``template_too_many_pages`` -> ``<kind>_too_many_pages``, ``pdf_encrypted`` -> ``<kind>_encrypted``.

    The hygiene rules are one implementation under three sets of bounds, so a host uploading a scan
    or supplying a report would otherwise read ``template_too_large`` about a file that is not a
    template. Only the prefix changes; the reason does not.
    """
    for prefix in ("template_", "pdf_"):
        if code.startswith(prefix):
            return f"{kind}_{code[len(prefix) :]}"
    return code


class PdfDocumentService:
    """pypdf + reportlab + Pillow implementation of ``esign.contracts.DocumentService``."""

    def __init__(self, settings: Settings, clock: Clock | None = None) -> None:
        self._settings = settings
        # Kept for factory symmetry with the other modules. This service never reads a clock: every
        # timestamp it prints arrives inside a ``SignerStamp`` or ``CertificateSummary`` that the
        # envelope service already took from ``Clock``. Reading the wall clock here would let two
        # renderings of the same evidence disagree.
        self._clock = clock
        ensure_fonts_registered()

    # ------------------------------------------------------------------ templates

    def inspect_template_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        info = inspection.inspect_template(pdf, self._settings)
        log.info(
            "documents.template_inspected",
            page_count=info.page_count,
            sha256=info.sha256,
            size_bytes=len(pdf),
        )
        return info

    def inspect_scan_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        """The template hygiene rules under the scan bounds (Addendum 1 A).

        Rasterised pages are larger than rendered text and a paper consent packet has more of
        them, so the bounds differ; nothing else does. The codes are the template ones with their
        prefix changed, so a host reading them knows they are about the file it just sent.
        """
        bounds = self._settings.model_copy(
            update={
                "max_template_bytes": self._settings.max_scan_bytes,
                "max_template_pages": self._settings.max_scan_pages,
            }
        )
        try:
            info = inspection.inspect_template(pdf, bounds)
        except ValidationFailed as exc:
            raise ValidationFailed("the scan was refused", code=_recoded(exc.code, "scan")) from None
        log.info("documents.scan_inspected", page_count=info.page_count, sha256=info.sha256, size_bytes=len(pdf))
        return info

    # ------------------------------------------------------------------ host-supplied documents

    def inspect_supplied_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        """The template hygiene rules under the supplied-document bounds (Addendum 2).

        A generated report is 20 to 30 pages where a template is one to five, so the bounds differ;
        one rule differs too. Widgets are still allowed through here on purpose -- they are how
        ``resolve_named_fields`` finds the signature block -- and ``flatten_supplied`` removes them
        before the bytes become revision 1. A widget carrying JavaScript, in ``/AA`` or anywhere
        else, is still refused: ``inspection`` walks the whole object graph, AcroForm included.

        Any *other* visible annotation is refused here and not on the template path, because
        ``flatten_supplied`` drops annotations without drawing them: accepting a ``/FreeText``
        "AMENDED" note would store a revision 1 the host's reader shows and ours does not.
        """
        bounds = self._settings.model_copy(
            update={
                "max_template_bytes": self._settings.max_supplied_document_bytes,
                "max_template_pages": self._settings.max_supplied_document_pages,
            }
        )
        try:
            info = inspection.inspect_template(pdf, bounds, reject_inked_annotations=True)
        except ValidationFailed as exc:
            raise ValidationFailed("the supplied document was refused", code=_recoded(exc.code, "supplied")) from None
        log.info("documents.supplied_inspected", page_count=info.page_count, sha256=info.sha256, size_bytes=len(pdf))
        return info

    def resolve_named_fields(self, pdf: bytes, signer_roles: list[SignerRoleDef]) -> list[FieldDef]:
        fields = supplied.resolve_named_fields(pdf, signer_roles)
        # Counts, never names: a widget name in a generated report is host text of unknown
        # provenance, and the role keys are already logged by the envelope service.
        log.info("documents.named_fields_resolved", field_count=len(fields), signer_count=len(signer_roles))
        return fields

    def flatten_supplied(self, pdf: bytes) -> bytes:
        out = supplied.flatten_supplied(pdf)
        log.info("documents.supplied_flattened", size_bytes=len(out))
        return out

    def validate_definitions(
        self,
        info: TemplatePdfInfo,
        fields: list[FieldDef],
        prefill_fields: list[PrefillFieldDef],
        signer_roles: list[SignerRoleDef],
    ) -> None:
        definitions_module.validate_definitions(info, fields, prefill_fields, signer_roles)

    # ------------------------------------------------------------------ preparation

    def prepare(self, template_pdf: bytes, prefill_fields: list[PrefillFieldDef], prefill: dict[str, str]) -> bytes:
        out = stamping.prepare(template_pdf, prefill_fields, prefill, self._settings)
        log.info("documents.prepared", size_bytes=len(out), field_count=len(prefill_fields))
        return out

    # ------------------------------------------------------------------ signing

    def sanitize_signature_png(self, data: bytes) -> bytes:
        return images.sanitize_signature_png(data, self._settings)

    def apply_signer_marks(
        self, pdf: bytes, fields: list[FieldDef], captures: list[Capture], stamp: SignerStamp
    ) -> bytes:
        out = stamping.apply_signer_marks(pdf, fields, captures, stamp, self._settings)
        log.info(
            "documents.marks_applied",
            signer_id=stamp.signer_id,
            capacity=stamp.capacity,
            field_count=len(fields),
            capture_count=len(captures),
            size_bytes=len(out),
        )
        return out

    # ------------------------------------------------------------------ completion

    def build_certificate(self, summary: CertificateSummary) -> bytes:
        out = certificate_module.build_certificate(summary, seal_profile=summary.seal_profile)
        log.info(
            "documents.certificate_built",
            envelope_id=summary.envelope_id,
            signer_count=len(summary.signers),
            event_count=summary.audit_event_count,
            size_bytes=len(out),
        )
        return out

    def build_archive_cover(self, summary: ArchiveCoverSummary) -> bytes:
        """The one page that precedes a scan inside the sealed bytes (Addendum 1 A)."""
        out = archive_cover_module.build_archive_cover(summary)
        log.info(
            "documents.archive_cover_built",
            envelope_id=summary.envelope_id,
            document_type=summary.document_type,
            page_count=summary.scan_page_count,
            size_bytes=len(out),
        )
        return out

    def page_count(self, pdf: bytes) -> int:
        """Pages in a PDF this service produced (a prepared, stamped or finalized revision)."""
        return len(open_reader(pdf).pages)

    def finalize(self, pdf: bytes, following_pdf: bytes) -> bytes:
        """Append ``following_pdf``'s pages. An archive cover goes in front of its scan this way.

        Both inputs are re-checked: a concatenation that quietly accepted a form or a script
        would put one inside the seal, where it is permanent.
        """
        writer = writer_from_bytes(pdf)
        following = writer_from_bytes(following_pdf)
        for page in following.pages:
            writer.add_page(page)
        out = sanitized_bytes(writer)
        log.info(
            "documents.finalized",
            page_count=len(writer.pages),
            size_bytes=len(out),
        )
        return out

    def embed_certificate(self, pdf: bytes, certificate_pdf: bytes) -> bytes:
        """Attach the certificate and return the exact bytes to be sealed.

        Sanitizing deletes ``/Names``, which is where a file attachment lives, so the attachment
        is added after that and the result is not sanitized again. The certificate's own pages
        are sanitized before they are attached. The document's page count does not change.
        """
        body = _sanitized_writer(writer_from_bytes(pdf))
        certificate = to_bytes(_sanitized_writer(writer_from_bytes(certificate_pdf)))
        body.add_attachment(CERTIFICATE_OF_COMPLETION_FILENAME, certificate)
        out = to_bytes(body)
        log.info(
            "documents.finalized",
            page_count=len(body.pages),
            size_bytes=len(out),
        )
        return out
