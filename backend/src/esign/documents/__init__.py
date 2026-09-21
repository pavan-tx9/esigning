"""PDF preparation, stamping and the certificate of completion. See docs/SPEC.md section 6.

The module owns everything that turns bytes into a page and back:

``inspection``   what a host is allowed to upload as a template
``codec``        the strict JSON decoder for the ``template_versions`` jsonb columns
``definitions``  whether a template version's fields, prefill and roles make sense
``geometry``     displayed-page coordinates, and the matrices that get back to user space
``pdfutil``      reading, overlaying, flattening and stripping, deterministically
``images``       the one piece of untrusted binary the browser sends
``stamping``     prefill values, signer marks, and the caption that makes a mark evidence
``certificate``  the certificate of completion
``fonts``        the vendored OFL faces, embedded in everything this module writes

Nothing in here reads a clock, a database or the network. Same input, same bytes, same hash.
"""

from __future__ import annotations

from esign.config import Settings
from esign.contracts import Clock, DocumentService
from esign.documents.codec import (
    definitions_from_json,
    definitions_to_json,
    fields_from_json,
    prefill_fields_from_json,
    signer_roles_from_json,
)
from esign.documents.service import PdfDocumentService

__all__ = [
    "PdfDocumentService",
    "build_document_service",
    "definitions_from_json",
    "definitions_to_json",
    "fields_from_json",
    "prefill_fields_from_json",
    "signer_roles_from_json",
]


def build_document_service(settings: Settings, clock: Clock | None = None) -> DocumentService:
    """The module's one factory (SPEC section 2).

    ``clock`` is accepted so every module factory has the same shape, and is deliberately unused:
    the times that appear in a document arrive in a ``SignerStamp`` or ``CertificateSummary`` that
    the envelope service already took from ``Clock``.
    """
    return PdfDocumentService(settings, clock)
