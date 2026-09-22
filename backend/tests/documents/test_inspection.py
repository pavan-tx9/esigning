"""Template intake. Every forbidden feature gets its own fixture, built in code.

The point of each test is not "pypdf can find this key" but "a host cannot get this past us", so
several of the fixtures put the payload somewhere other than the obvious place.
"""

from __future__ import annotations

import hashlib

import pytest

from esign.config import Settings
from esign.contracts import DocumentService, ValidationFailed
from tests.documents.helpers import (
    make_pdf,
    pdf_with_applied_signature,
    pdf_with_embedded_file,
    pdf_with_javascript,
    pdf_with_launch_action,
    pdf_with_page_additional_actions,
    pdf_with_signature_field,
    pdf_with_widget_annotation,
    pdf_with_xfa,
)


def test_a_plain_template_is_accepted(documents: DocumentService) -> None:
    pdf = make_pdf(pages=3)
    info = documents.inspect_template_pdf(pdf)
    assert info.page_count == 3
    assert info.page_sizes == ((612.0, 792.0),) * 3
    assert info.sha256 == hashlib.sha256(pdf).digest()


def test_page_sizes_are_reported_as_displayed(documents: DocumentService) -> None:
    info = documents.inspect_template_pdf(make_pdf(rotate=90))
    assert info.page_sizes == ((792.0, 612.0),)


def test_page_sizes_follow_the_cropbox(documents: DocumentService) -> None:
    info = documents.inspect_template_pdf(make_pdf(origin=(20.0, 30.0), crop_inset=15.0))
    assert info.page_sizes == ((582.0, 762.0),)


@pytest.mark.parametrize(
    ("builder", "code"),
    [
        (pdf_with_javascript, "template_javascript"),
        (pdf_with_page_additional_actions, "template_javascript"),
        (pdf_with_xfa, "template_xfa"),
        (pdf_with_embedded_file, "template_embedded_file"),
        (pdf_with_launch_action, "template_forbidden_action"),
        (pdf_with_signature_field, "template_signature_field"),
        (pdf_with_applied_signature, "template_already_signed"),
    ],
)
def test_forbidden_features_are_refused(documents: DocumentService, builder: object, code: str) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.inspect_template_pdf(builder())  # type: ignore[operator]
    assert excinfo.value.code == code


def test_a_plain_form_field_is_allowed_through_intake(documents: DocumentService) -> None:
    """Form fields are not a security problem -- ``prepare`` flattens them. Scripts are."""
    info = documents.inspect_template_pdf(pdf_with_widget_annotation())
    assert info.page_count == 1


def test_a_too_large_template_is_refused(settings_no_db: Settings) -> None:
    from esign.documents import build_document_service

    tight = settings_no_db.model_copy(update={"max_template_bytes": 500})
    with pytest.raises(ValidationFailed) as excinfo:
        build_document_service(tight).inspect_template_pdf(make_pdf())
    assert excinfo.value.code == "template_too_large"


def test_a_template_with_too_many_pages_is_refused(settings_no_db: Settings) -> None:
    from esign.documents import build_document_service

    tight = settings_no_db.model_copy(update={"max_template_pages": 2})
    with pytest.raises(ValidationFailed) as excinfo:
        build_document_service(tight).inspect_template_pdf(make_pdf(pages=3))
    assert excinfo.value.code == "template_too_many_pages"


@pytest.mark.parametrize("payload", [b"", b"not a pdf at all", b"%PDF-1.7\nbroken"])
def test_unparseable_input_is_a_validation_failure(documents: DocumentService, payload: bytes) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.inspect_template_pdf(payload)
    assert excinfo.value.code in {"pdf_unreadable", "pdf_no_pages"}


def test_an_encrypted_template_is_refused(documents: DocumentService) -> None:
    import io

    from pypdf import PdfReader, PdfWriter

    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(make_pdf())).pages:
        writer.add_page(page)
    writer.encrypt("correct horse battery staple")
    out = io.BytesIO()
    writer.write(out)

    with pytest.raises(ValidationFailed) as excinfo:
        documents.inspect_template_pdf(out.getvalue())
    assert excinfo.value.code == "pdf_encrypted"


def test_the_error_message_never_echoes_the_input(documents: DocumentService) -> None:
    """A rejection message goes back to the host; it must not carry the payload with it."""
    with pytest.raises(ValidationFailed) as excinfo:
        documents.inspect_template_pdf(pdf_with_javascript())
    message = str(excinfo.value)
    assert "app.alert" not in message
    assert "hello" not in message


def test_inspection_hashes_the_exact_bytes_supplied(documents: DocumentService) -> None:
    """The template hash is evidence; it must be of what arrived, not of a normalised rewrite."""
    pdf = make_pdf(pages=2)
    padded = pdf + b"\n% trailing comment\n"
    assert documents.inspect_template_pdf(padded).sha256 == hashlib.sha256(padded).digest()
