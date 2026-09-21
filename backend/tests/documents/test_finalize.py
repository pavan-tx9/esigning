"""``finalize``: the exact bytes that go under the seal.

Nothing after this point can be corrected -- appending to a sealed PDF invalidates the seal -- so
this is the last place anything can be caught.
"""

from __future__ import annotations

import io

import pytest
from pypdf import PdfReader

from esign.contracts import Capture, DocumentService, FieldDef, Rect, SignerStamp, ValidationFailed
from tests.documents.conftest import certificate_summary
from tests.documents.helpers import make_pdf, pdf_with_javascript, pdf_with_widget_annotation


def signed_revision(documents: DocumentService, stamp: SignerStamp, pages: int = 2) -> bytes:
    field = FieldDef(
        id="patient_signature",
        type="signature",
        page=1,
        rect=Rect(x=100, y=400, w=220, h=48),
        signer_role="patient",
    )
    capture = Capture(field_id="patient_signature", kind="typed", typed_text="Ada Lovelace")
    return documents.apply_signer_marks(make_pdf(pages=pages), [field], [capture], stamp)


def test_the_certificate_pages_are_appended_after_the_document(documents: DocumentService, stamp: SignerStamp) -> None:
    body = signed_revision(documents, stamp, pages=3)
    certificate = documents.build_certificate(certificate_summary())
    final = documents.finalize(body, certificate)

    reader = PdfReader(io.BytesIO(final))
    body_pages = len(PdfReader(io.BytesIO(body)).pages)
    cert_pages = len(PdfReader(io.BytesIO(certificate)).pages)
    assert len(reader.pages) == body_pages + cert_pages
    assert "Ada Lovelace" in reader.pages[0].extract_text()
    assert "Certificate of completion" in reader.pages[body_pages].extract_text()


def test_the_signed_content_survives_finalisation(documents: DocumentService, stamp: SignerStamp) -> None:
    body = signed_revision(documents, stamp)
    final = documents.finalize(body, documents.build_certificate(certificate_summary()))
    text = PdfReader(io.BytesIO(final)).pages[0].extract_text()
    assert "Ada Lovelace (self)" in text
    assert str(stamp.signer_id) in text


def test_finalisation_strips_anything_interactive_that_slipped_through(documents: DocumentService) -> None:
    """Both inputs are our own output, but a form inside a seal is permanent, so it is re-checked."""
    final = documents.finalize(pdf_with_widget_annotation(), documents.build_certificate(certificate_summary()))
    reader = PdfReader(io.BytesIO(final))
    assert "/AcroForm" not in reader.root_object
    for page in reader.pages:
        assert "/Annots" not in page


def test_a_document_carrying_javascript_is_stripped_before_sealing(documents: DocumentService) -> None:
    final = documents.finalize(pdf_with_javascript(), documents.build_certificate(certificate_summary()))
    root = PdfReader(io.BytesIO(final)).root_object
    assert "/Names" not in root
    assert "/OpenAction" not in root


def test_finalisation_is_deterministic(documents: DocumentService, stamp: SignerStamp) -> None:
    body = signed_revision(documents, stamp)
    certificate = documents.build_certificate(certificate_summary())
    assert documents.finalize(body, certificate) == documents.finalize(body, certificate)


@pytest.mark.parametrize("bad", [b"", b"not a pdf"])
def test_unreadable_input_is_refused(documents: DocumentService, stamp: SignerStamp, bad: bytes) -> None:
    certificate = documents.build_certificate(certificate_summary())
    with pytest.raises(ValidationFailed):
        documents.finalize(bad, certificate)
    with pytest.raises(ValidationFailed):
        documents.finalize(signed_revision(documents, stamp), bad)


def test_no_stale_metadata_reaches_the_sealed_bytes(documents: DocumentService, stamp: SignerStamp) -> None:
    """The template's own /Info and XMP are the host's, not ours, and could be stale or wrong."""
    final = documents.finalize(signed_revision(documents, stamp), documents.build_certificate(certificate_summary()))
    reader = PdfReader(io.BytesIO(final))
    assert "/Metadata" not in reader.root_object
    info = reader.metadata
    assert info is not None
    assert set(info) <= {"/Producer"}
