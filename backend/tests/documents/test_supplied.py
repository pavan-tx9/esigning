"""Host-supplied documents (Addendum 2): reading a report's fields, and flattening it.

Every fixture is built in code, so a reviewer can see what is being tested rather than trust a
committed binary. The geometry tests are written the hard way on purpose: the expected rectangle is
worked out from the page's own box and ``/Rotate`` and written down, instead of being computed with
the same helper the code under test uses -- a test that restates the implementation proves nothing.
"""

from __future__ import annotations

import io
import time

import pytest
from pypdf import PdfReader, PdfWriter

from esign.config import Settings
from esign.contracts import (
    DocumentService,
    FieldDef,
    Rect,
    SignerRoleDef,
    TemplatePdfInfo,
    ValidationFailed,
    resolve_page,
)
from esign.documents import build_document_service, pdfutil
from tests.documents.helpers import (
    NamedWidget,
    generated_report,
    make_pdf,
    pdf_with_acroform_javascript,
    pdf_with_embedded_file,
    pdf_with_javascript,
    pdf_with_launch_action,
    pdf_with_named_widgets,
    pdf_with_page_additional_actions,
    pdf_with_signature_field,
    pdf_with_widget_annotation,
    pdf_with_xfa,
    widget_names,
)

CLINICIAN = SignerRoleDef(
    key="clinician",
    label="Attending clinician",
    allowed_capacities=("clinician",),
    requires_reauth=True,
    order_index=0,
)
COSIGNER = SignerRoleDef(
    key="cosigner",
    label="Co-signing physician",
    allowed_capacities=("clinician",),
    requires_reauth=True,
    order_index=1,
)

#: A signature block wide and tall enough that ``validate_definitions`` accepts it, so the
#: resolution tests and the validation tests can use the same fixtures.
SIGNATURE_RECT = (72.0, 96.0, 292.0, 146.0)


def _by_id(fields: list[FieldDef]) -> dict[str, FieldDef]:
    return {field.id: field for field in fields}


# --------------------------------------------------------------------------- naming rules


def test_the_short_names_map_to_the_role_and_the_type(documents: DocumentService) -> None:
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT),
            NamedWidget(name="clinician_initials", rect=(320.0, 96.0, 460.0, 146.0)),
            NamedWidget(name="clinician_date", rect=(480.0, 96.0, 560.0, 116.0)),
        ]
    )
    fields = _by_id(documents.resolve_named_fields(pdf, [CLINICIAN]))

    assert set(fields) == {"clinician_signature", "clinician_initials", "clinician_date"}
    assert fields["clinician_signature"].type == "signature"
    assert fields["clinician_initials"].type == "initials"
    assert fields["clinician_date"].type == "date_signed"
    assert all(field.signer_role == "clinician" for field in fields.values())
    assert all(field.page == 1 for field in fields.values())


@pytest.mark.parametrize(
    ("name", "ft", "expected"),
    [
        ("clinician__attestation_signature", "/Tx", "signature"),
        ("clinician__second_initials", "/Tx", "initials"),
        ("clinician__countersigned_date", "/Tx", "date_signed"),
        ("clinician__reviewed_date_signed", "/Tx", "date_signed"),
        ("clinician__comments_text", "/Tx", "text"),
        ("clinician__agreed_checkbox", "/Btn", "checkbox"),
        ("clinician__signature", "/Tx", "signature"),
        # No suffix at all: the widget's own /FT decides, and a field that declares nothing is
        # text -- the one type that cannot silently become somebody's mark.
        ("clinician__free_note", "/Tx", "text"),
        ("clinician__acknowledged", "/Btn", "checkbox"),
    ],
)
def test_the_double_underscore_form_takes_an_optional_type_suffix(
    documents: DocumentService, name: str, ft: str, expected: str
) -> None:
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT),
            NamedWidget(name=name, rect=(72.0, 200.0, 292.0, 250.0), ft=ft),
        ]
    )
    fields = _by_id(documents.resolve_named_fields(pdf, [CLINICIAN]))
    assert fields[name].type == expected


def test_a_hierarchical_field_name_resolves_through_its_parent(documents: DocumentService) -> None:
    """A generator that writes a parent field with one kid means the same thing as a flat name."""
    pdf = pdf_with_named_widgets([NamedWidget(name="clinician.signature", rect=SIGNATURE_RECT)])
    fields = documents.resolve_named_fields(pdf, [CLINICIAN])
    assert [(field.id, field.type) for field in fields] == [("clinician_signature", "signature")]


def test_two_roles_each_get_their_own_block(documents: DocumentService) -> None:
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=2),
            NamedWidget(name="clinician_date", rect=(320.0, 96.0, 440.0, 116.0), page=2),
            NamedWidget(name="cosigner_signature", rect=(72.0, 200.0, 292.0, 250.0), page=2),
            NamedWidget(name="cosigner_date", rect=(320.0, 200.0, 440.0, 220.0), page=2),
        ],
        pages=2,
    )
    fields = _by_id(documents.resolve_named_fields(pdf, [CLINICIAN, COSIGNER]))
    assert {field.signer_role for field in fields.values()} == {"clinician", "cosigner"}
    assert fields["cosigner_signature"].type == "signature"
    assert fields["cosigner_signature"].page == 2


def test_the_longest_role_key_wins(documents: DocumentService) -> None:
    """``clinician`` is a prefix of ``clinician_2``; the widget belongs to the role that spelled it."""
    second = SignerRoleDef(
        key="clinician_2",
        label="Second clinician",
        allowed_capacities=("clinician",),
        requires_reauth=True,
        order_index=1,
    )
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT),
            NamedWidget(name="clinician_2_signature", rect=(72.0, 200.0, 292.0, 250.0)),
        ]
    )
    fields = _by_id(documents.resolve_named_fields(pdf, [CLINICIAN, second]))
    assert fields["clinician_signature"].signer_role == "clinician"
    assert fields["clinician_2_signature"].signer_role == "clinician_2"


def test_repeated_widget_names_become_distinct_field_ids(documents: DocumentService) -> None:
    """Two widgets are two places to sign, even when the generator named them the same."""
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=1),
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=2),
        ],
        pages=2,
    )
    fields = documents.resolve_named_fields(pdf, [CLINICIAN])
    assert [(field.id, field.page) for field in fields] == [
        ("clinician_signature", 1),
        ("clinician_signature_2", 2),
    ]


def test_unmatched_widgets_are_dropped(documents: DocumentService) -> None:
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT),
            NamedWidget(name="patient_address", rect=(72.0, 300.0, 292.0, 320.0)),
            NamedWidget(name="mrn", rect=(72.0, 340.0, 292.0, 360.0)),
            NamedWidget(name="clinician_notes", rect=(72.0, 380.0, 292.0, 400.0)),
        ]
    )
    fields = documents.resolve_named_fields(pdf, [CLINICIAN])
    assert [field.id for field in fields] == ["clinician_signature"]


def test_a_role_with_no_signature_field_is_refused(documents: DocumentService) -> None:
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT),
            NamedWidget(name="cosigner_date", rect=(320.0, 96.0, 440.0, 116.0)),
        ]
    )
    with pytest.raises(ValidationFailed) as excinfo:
        documents.resolve_named_fields(pdf, [CLINICIAN, COSIGNER])
    assert excinfo.value.code == "fields_unresolved"
    assert "cosigner" in str(excinfo.value)
    assert "clinician" not in str(excinfo.value)


def test_a_document_with_no_form_at_all_is_refused(documents: DocumentService) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.resolve_named_fields(make_pdf(pages=3), [CLINICIAN])
    assert excinfo.value.code == "fields_unresolved"


def test_the_refusal_never_echoes_a_widget_name(documents: DocumentService) -> None:
    """Widget names in a per-patient report are host-generated text of unknown provenance; the
    message goes into logs and back over the wire, so it names roles and nothing else."""
    pdf = pdf_with_named_widgets(
        [NamedWidget(name="sig_for_chart_00441_hodgkins", rect=SIGNATURE_RECT)],
    )
    with pytest.raises(ValidationFailed) as excinfo:
        documents.resolve_named_fields(pdf, [CLINICIAN])
    assert "00441" not in str(excinfo.value)
    assert "hodgkins" not in str(excinfo.value)


def test_an_initials_only_role_resolves(documents: DocumentService) -> None:
    """``validate_definitions`` accepts a role whose only mark is initials, so resolution does too:
    a stricter reader here would refuse documents the validator would have passed."""
    pdf = pdf_with_named_widgets([NamedWidget(name="clinician_initials", rect=SIGNATURE_RECT)])
    fields = documents.resolve_named_fields(pdf, [CLINICIAN])
    assert [field.type for field in fields] == ["initials"]


def test_required_follows_the_field_flag_for_value_fields(documents: DocumentService) -> None:
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT),
            NamedWidget(name="clinician__note_text", rect=(72.0, 200.0, 292.0, 250.0), flags=2),
            NamedWidget(name="clinician__aside_text", rect=(72.0, 300.0, 292.0, 350.0)),
        ]
    )
    fields = _by_id(documents.resolve_named_fields(pdf, [CLINICIAN]))
    assert fields["clinician_signature"].required is True
    assert fields["clinician__note_text"].required is True
    assert fields["clinician__aside_text"].required is False


def test_labels_are_built_from_the_declared_role(documents: DocumentService) -> None:
    """The label is shown in the signing UI. It comes from the role label the host sent in the
    request body, never from a string inside the generated file."""
    pdf = pdf_with_named_widgets([NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT)])
    (field,) = documents.resolve_named_fields(pdf, [CLINICIAN])
    assert field.label == "Attending clinician signature"


# --------------------------------------------------------------------------- geometry


def test_a_widget_rect_becomes_displayed_coordinates(documents: DocumentService) -> None:
    """Unrotated page whose box starts at (0, 0): displayed coordinates are user coordinates."""
    pdf = pdf_with_named_widgets([NamedWidget(name="clinician_signature", rect=(72.0, 96.0, 292.0, 146.0))])
    (field,) = documents.resolve_named_fields(pdf, [CLINICIAN])
    assert field.rect == Rect(x=72.0, y=96.0, w=220.0, h=50.0)


def test_an_offset_box_origin_is_subtracted(documents: DocumentService) -> None:
    """MediaBox [20 30 632 822]: a widget at user (120, 180) is 100pt from the left of what the
    reader shows and 150pt up from its bottom."""
    pdf = pdf_with_named_widgets(
        [NamedWidget(name="clinician_signature", rect=(120.0, 180.0, 340.0, 230.0))],
        origin=(20.0, 30.0),
    )
    (field,) = documents.resolve_named_fields(pdf, [CLINICIAN])
    assert field.rect == Rect(x=100.0, y=150.0, w=220.0, h=50.0)


def test_a_rotated_page_maps_the_rect_to_what_the_reader_sees(documents: DocumentService) -> None:
    """``/Rotate 90`` on a 612x792 page: the reader shows 792x612.

    The page turns clockwise, so user-space *y* runs along the displayed *x* axis and user-space
    *x* runs backwards down the displayed *y* axis: displayed ``(dx, dy) = (y, 612 - x)``. A widget
    at user ``(100, 150) .. (150, 370)`` is therefore a 220x50 box at displayed ``(150, 462)``.
    """
    pdf = pdf_with_named_widgets(
        [NamedWidget(name="clinician_signature", rect=(100.0, 150.0, 150.0, 370.0), page=3)],
        pages=3,
        rotate=90,
    )
    (field,) = documents.resolve_named_fields(pdf, [CLINICIAN])
    assert field.page == 3
    assert field.rect == Rect(x=150.0, y=462.0, w=220.0, h=50.0)


def test_a_rotated_last_page_block_survives_validation(documents: DocumentService) -> None:
    """The rotated block is not just placed, it is placed somewhere a signer can sign: the same
    check the envelope service runs next has to accept it."""
    pdf = pdf_with_named_widgets(
        [NamedWidget(name="clinician_signature", rect=(100.0, 150.0, 150.0, 370.0), page=3)],
        pages=3,
        rotate=90,
    )
    info = documents.inspect_supplied_pdf(pdf)
    assert info.page_sizes == ((792.0, 612.0),) * 3
    documents.validate_definitions(info, documents.resolve_named_fields(pdf, [CLINICIAN]), [], [CLINICIAN])


def test_a_widget_hanging_off_the_page_is_refused_by_validation(documents: DocumentService) -> None:
    """Resolution reports where the widget is; validation decides whether that is a usable place.
    Keeping the two apart is what makes the error say which field is wrong."""
    pdf = pdf_with_named_widgets([NamedWidget(name="clinician_signature", rect=(500.0, 96.0, 720.0, 146.0))])
    fields = documents.resolve_named_fields(pdf, [CLINICIAN])
    with pytest.raises(ValidationFailed) as excinfo:
        documents.validate_definitions(documents.inspect_supplied_pdf(pdf), fields, [], [CLINICIAN])
    assert excinfo.value.code == "template_definitions_invalid"
    assert "clinician_signature" in str(excinfo.value)


def test_the_resolved_page_is_the_page_the_widget_is_on(documents: DocumentService) -> None:
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=4),
            NamedWidget(name="cosigner_signature", rect=(72.0, 200.0, 292.0, 250.0), page=2),
        ],
        pages=4,
    )
    fields = _by_id(documents.resolve_named_fields(pdf, [CLINICIAN, COSIGNER]))
    assert fields["clinician_signature"].page == 4
    assert fields["cosigner_signature"].page == 2
    assert documents.page_count(pdf) == 4


# --------------------------------------------------------------------------- explicit rects


@pytest.mark.parametrize(("page", "count", "expected"), [(-1, 30, 30), (-2, 30, 29), (-30, 30, 1), (7, 30, 7)])
def test_a_negative_page_counts_from_the_end(page: int, count: int, expected: int) -> None:
    assert resolve_page(page, count) == expected


@pytest.mark.parametrize(("page", "count"), [(0, 30), (-31, 30), (31, 30), (1, 0)])
def test_a_page_outside_the_document_is_refused(page: int, count: int) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        resolve_page(page, count)
    assert excinfo.value.code == "field_page_out_of_range"


def test_explicit_rects_are_validated_against_the_real_page_sizes(documents: DocumentService) -> None:
    """A host that sends ``page: -1`` for a 30-page report gets page 30, and the rect it sent is
    then checked against page 30's actual size like any other."""
    report = generated_report(pages=30)
    info = documents.inspect_supplied_pdf(report)
    last = resolve_page(-1, info.page_count)
    good = FieldDef(
        id="clinician_signature",
        type="signature",
        page=last,
        rect=Rect(x=72.0, y=96.0, w=220.0, h=50.0),
        signer_role="clinician",
        label="Attending clinician signature",
    )
    documents.validate_definitions(info, [good], [], [CLINICIAN])

    off_page = FieldDef(
        id="clinician_signature",
        type="signature",
        page=last,
        rect=Rect(x=500.0, y=96.0, w=220.0, h=50.0),
        signer_role="clinician",
        label="Attending clinician signature",
    )
    with pytest.raises(ValidationFailed) as excinfo:
        documents.validate_definitions(info, [off_page], [], [CLINICIAN])
    assert excinfo.value.code == "template_definitions_invalid"


# --------------------------------------------------------------------------- hygiene


@pytest.mark.parametrize(
    ("builder", "code"),
    [
        (pdf_with_javascript, "supplied_javascript"),
        (pdf_with_page_additional_actions, "supplied_javascript"),
        (pdf_with_acroform_javascript, "supplied_javascript"),
        (pdf_with_xfa, "supplied_xfa"),
        (pdf_with_embedded_file, "supplied_embedded_file"),
        (pdf_with_launch_action, "supplied_forbidden_action"),
        (pdf_with_signature_field, "supplied_already_signed"),
    ],
)
def test_forbidden_features_are_refused_on_a_supplied_document(
    documents: DocumentService, builder: object, code: str
) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.inspect_supplied_pdf(builder())  # type: ignore[operator]
    assert excinfo.value.code == code


def test_a_supplied_documents_widgets_are_allowed_through_intake(documents: DocumentService) -> None:
    """Widgets are the point: they are how the signature block is found. Only what they *do* is
    forbidden, which is why the JavaScript fixture above is refused and this one is not."""
    info = documents.inspect_supplied_pdf(pdf_with_named_widgets([NamedWidget("clinician_signature", SIGNATURE_RECT)]))
    assert info.page_count == 1


def test_an_encrypted_supplied_document_is_refused(documents: DocumentService) -> None:
    from pypdf import PdfWriter

    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(make_pdf())).pages:
        writer.add_page(page)
    writer.encrypt("correct horse battery staple")
    out = io.BytesIO()
    writer.write(out)

    with pytest.raises(ValidationFailed) as excinfo:
        documents.inspect_supplied_pdf(out.getvalue())
    assert excinfo.value.code == "supplied_encrypted"


def test_the_supplied_bounds_are_the_ones_that_apply(settings_no_db: Settings) -> None:
    """Reading the *template* bounds here would refuse exactly the documents this addendum exists
    for, so the two are pinned apart: a document over the template limit and under the supplied one
    is accepted as a supplied document and refused as a template."""
    service = build_document_service(settings_no_db.model_copy(update={"max_template_pages": 3}))
    report = generated_report(pages=8)
    assert service.inspect_supplied_pdf(report).page_count == 8
    with pytest.raises(ValidationFailed) as excinfo:
        service.inspect_template_pdf(report)
    assert excinfo.value.code == "template_too_many_pages"


def test_the_default_limits_admit_a_thirty_page_report(settings_no_db: Settings) -> None:
    assert settings_no_db.max_supplied_document_pages >= 30
    assert build_document_service(settings_no_db).inspect_supplied_pdf(generated_report(pages=30)).page_count == 30


def test_a_supplied_document_over_the_page_limit_is_refused(settings_no_db: Settings) -> None:
    tight = settings_no_db.model_copy(update={"max_supplied_document_pages": 2})
    with pytest.raises(ValidationFailed) as excinfo:
        build_document_service(tight).inspect_supplied_pdf(make_pdf(pages=3))
    assert excinfo.value.code == "supplied_too_many_pages"


def test_a_supplied_document_over_the_size_limit_is_refused(settings_no_db: Settings) -> None:
    tight = settings_no_db.model_copy(update={"max_supplied_document_bytes": 500})
    with pytest.raises(ValidationFailed) as excinfo:
        build_document_service(tight).inspect_supplied_pdf(make_pdf())
    assert excinfo.value.code == "supplied_too_large"


def test_the_supplied_hash_is_of_the_exact_bytes(documents: DocumentService) -> None:
    import hashlib

    report = generated_report(pages=3)
    assert documents.inspect_supplied_pdf(report).sha256 == hashlib.sha256(report).digest()


# --------------------------------------------------------------------------- flattening


def _text_of(pdf: bytes) -> list[str]:
    return [page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages]


def test_flattening_removes_the_widgets_and_the_form(documents: DocumentService) -> None:
    pdf = pdf_with_named_widgets(
        [
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=2),
            NamedWidget(name="clinician_date", rect=(320.0, 96.0, 440.0, 116.0), page=2),
        ],
        pages=2,
    )
    assert widget_names(pdf)

    out = documents.flatten_supplied(pdf)
    assert widget_names(out) == []
    reader = PdfReader(io.BytesIO(out))
    assert "/AcroForm" not in reader.root_object
    for page in reader.pages:
        assert "/Annots" not in page


def test_flattening_keeps_the_page_content(documents: DocumentService) -> None:
    pdf = generated_report(pages=4, widgets=[NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=4)])
    out = documents.flatten_supplied(pdf)
    assert documents.page_count(out) == 4
    before, after = _text_of(pdf), _text_of(out)
    assert len(after) == len(before)
    for index, (was, now) in enumerate(zip(before, after, strict=True)):
        assert f"page {index + 1} of 4" in now
        assert now.split() == was.split()


def test_flattening_draws_nothing_that_was_not_already_there(documents: DocumentService) -> None:
    """A widget's appearance stream is *removed*, not burned into the page.

    ``prepare`` flattens a template's annotations into its content because a template author who
    drew something meant it to show. A host document is different: the signature widget is an empty
    box waiting for a signature, and painting it into the bytes would put ink in the document that
    the host never generated -- in the exact bytes that are then hashed as what the signer saw.
    """
    pdf = pdf_with_widget_annotation()
    assert widget_names(pdf) == ["host_field"]

    # The template path burns the appearance in: a template author who drew it meant it.
    assert "widget value" in _text_of(documents.prepare(pdf, [], {}))[0]

    out = documents.flatten_supplied(pdf)
    assert widget_names(out) == []
    assert "widget value" not in _text_of(out)[0]
    assert "template page 1" in _text_of(out)[0]


def test_flattening_is_deterministic(documents: DocumentService) -> None:
    """Revision 1's hash is evidence, so it has to be a property of the input bytes alone."""
    pdf = generated_report(pages=3, widgets=[NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=3)])
    assert documents.flatten_supplied(pdf) == documents.flatten_supplied(pdf)


def test_a_flattening_that_changed_the_page_count_is_refused(
    documents: DocumentService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard is on the produced bytes, not on the intention, so it is provoked by making the
    step that produces them lose a page."""

    def losing_a_page(writer: PdfWriter, **kwargs: object) -> None:
        pdfutil.sanitize_document(writer, **kwargs)  # type: ignore[arg-type]
        writer.remove_page(len(writer.pages) - 1)

    monkeypatch.setattr("esign.documents.supplied.sanitize_document", losing_a_page)
    with pytest.raises(ValidationFailed) as excinfo:
        documents.flatten_supplied(make_pdf(pages=3))
    assert excinfo.value.code == "supplied_flatten_changed_pages"


@pytest.mark.parametrize("payload", [b"", b"not a pdf at all", b"%PDF-1.7\nbroken"])
def test_flattening_unparseable_input_is_a_validation_failure(documents: DocumentService, payload: bytes) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.flatten_supplied(payload)
    assert excinfo.value.code in {"pdf_unreadable", "pdf_no_pages"}


# --------------------------------------------------------------------------- performance


def test_a_thirty_page_report_prepares_well_under_two_seconds(documents: DocumentService) -> None:
    """The whole documents-module share of creating a host-document envelope, on a report of the
    size the addendum describes: inspect, resolve, flatten, count. Two seconds is the budget in the
    addendum; the assertion is at half of it, so a change that doubles the cost still fails here.
    """
    report = generated_report(
        pages=30,
        widgets=[
            NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=30),
            NamedWidget(name="clinician_date", rect=(320.0, 96.0, 440.0, 116.0), page=30),
        ],
    )

    started = time.perf_counter()
    info: TemplatePdfInfo = documents.inspect_supplied_pdf(report)
    fields = documents.resolve_named_fields(report, [CLINICIAN])
    documents.validate_definitions(info, fields, [], [CLINICIAN])
    presented = documents.flatten_supplied(report)
    pages = documents.page_count(presented)
    elapsed = time.perf_counter() - started

    assert info.page_count == 30
    assert pages == 30
    assert [field.page for field in fields] == [30, 30]
    assert elapsed < 1.0, f"preparing a 30-page report took {elapsed:.3f}s"


def test_the_page_count_is_read_once_rather_than_reparsed(documents: DocumentService) -> None:
    """Addendum 0's concern: the page count of a 30-page report is a number to persist, not a parse
    to repeat. ``inspect_supplied_pdf`` already returns it, and it matches what the presented bytes
    hold, so nothing downstream has any reason to open the PDF again to ask."""
    report = generated_report(pages=30, widgets=[NamedWidget(name="clinician_signature", rect=SIGNATURE_RECT, page=30)])
    info = documents.inspect_supplied_pdf(report)
    assert info.page_count == documents.page_count(documents.flatten_supplied(report)) == 30
