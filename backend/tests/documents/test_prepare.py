"""``prepare``: merge chart data into the template, flatten, and leave nothing interactive."""

from __future__ import annotations

import hashlib
import io

import pytest
from pypdf import PdfReader

from esign.contracts import DocumentService, PrefillFieldDef, Rect, ValidationFailed
from esign.documents.fonts import PLAIN_FONT
from tests.documents.helpers import (
    NamedWidget,
    inflated_streams,
    make_pdf,
    page_content,
    pdf_with_named_widgets,
    pdf_with_widget_annotation,
    placed_text,
)


def prefill_at(
    key: str, rect: Rect, *, page: int = 1, multiline: bool = False, required: bool = True
) -> PrefillFieldDef:
    return PrefillFieldDef(key=key, page=page, rect=rect, font_size=10.0, multiline=multiline, required=required)


def test_prefill_lands_inside_its_rect(documents: DocumentService) -> None:
    rect = Rect(x=100, y=600, w=240, h=14)
    out = documents.prepare(make_pdf(), [prefill_at("patient_name", rect)], {"patient_name": "Ada Lovelace"})
    runs = [run for run in placed_text(out) if run.text == "Ada Lovelace"]
    assert runs, "the prefill value was not drawn"
    assert runs[0].box(PLAIN_FONT).inside(rect)


@pytest.mark.parametrize("rotate", [0, 90, 180, 270])
@pytest.mark.parametrize("origin", [(0.0, 0.0), (24.0, 36.0)])
def test_prefill_lands_inside_its_rect_on_every_page_shape(
    documents: DocumentService, rotate: int, origin: tuple[float, float]
) -> None:
    rect = Rect(x=60, y=120, w=200, h=16)
    pdf = make_pdf(rotate=rotate, origin=origin)
    out = documents.prepare(pdf, [prefill_at("patient_name", rect)], {"patient_name": "Ada Lovelace"})
    runs = [run for run in placed_text(out) if run.text == "Ada Lovelace"]
    assert runs
    assert runs[0].box(PLAIN_FONT).inside(rect)


def test_a_long_value_is_shrunk_rather_than_allowed_to_overflow(documents: DocumentService) -> None:
    rect = Rect(x=100, y=600, w=120, h=14)
    value = "Wolfeschlegelsteinhausenbergerdorff-Featherstonehaugh"
    out = documents.prepare(make_pdf(), [prefill_at("patient_name", rect)], {"patient_name": value})
    runs = [run for run in placed_text(out) if value[:12] in run.text]
    assert runs
    assert runs[0].box(PLAIN_FONT).inside(rect)


def test_multiline_values_wrap_inside_the_rect(documents: DocumentService) -> None:
    rect = Rect(x=100, y=400, w=200, h=80)
    value = "Left total knee replacement with cemented components, under general anaesthesia."
    out = documents.prepare(make_pdf(), [prefill_at("summary", rect, multiline=True)], {"summary": value})
    runs = [run for run in placed_text(out) if run.text]
    drawn = [run for run in runs if run.text in value or any(word in run.text for word in value.split())]
    assert len(drawn) > 1, "a long multiline value should wrap onto several lines"
    for run in drawn:
        assert run.box(PLAIN_FONT).inside(rect), run.text


def test_output_has_no_form_no_annotations_and_no_scripts(documents: DocumentService) -> None:
    out = documents.prepare(pdf_with_widget_annotation(), [], {})
    reader = PdfReader(io.BytesIO(out))
    assert "/AcroForm" not in reader.root_object
    assert "/Names" not in reader.root_object
    assert "/OpenAction" not in reader.root_object
    for page in reader.pages:
        assert "/Annots" not in page
        assert "/AA" not in page


def test_the_prepared_revision_keeps_no_widget_object_anywhere_in_its_bytes(documents: DocumentService) -> None:
    """The same rule ``flatten_supplied`` follows, for the template path.

    Burning the appearance in and deleting ``/Annots`` and ``/AcroForm`` *unlinks* the widget; it
    does not remove it. A template that carries a tooltip, or a value a reader never sees, would
    otherwise leave that text physically inside every prepared revision -- and inside the seal,
    where there is no correcting it. One definition of "produce the bytes of a sanitised document"
    (``pdfutil.sanitized_bytes``) is what makes this true on both paths at once.
    """
    pdf = pdf_with_named_widgets(
        [NamedWidget(name="host_field", rect=(72.0, 600.0, 292.0, 640.0), value="SHOWNVALUE", tooltip="TOOLTIPSECRET")]
    )
    assert b"TOOLTIPSECRET" in inflated_streams(pdf)

    out = documents.prepare(pdf, [], {})
    # The appearance is drawn into the page -- that part of the widget is ink the signer sees ...
    assert b"(SHOWNVALUE) Tj" in page_content(out)
    # ... and the object that carried it is gone from the file, tooltip and all.
    assert b"/Widget" not in out
    assert b"TOOLTIPSECRET" not in inflated_streams(out)


def test_a_widget_appearance_is_flattened_into_the_page(documents: DocumentService) -> None:
    """Dropping the annotation without burning in its appearance would silently lose content."""
    before = PdfReader(io.BytesIO(pdf_with_widget_annotation())).pages[0].extract_text()
    assert "widget value" not in before

    out = documents.prepare(pdf_with_widget_annotation(), [], {})
    assert "widget value" in PdfReader(io.BytesIO(out)).pages[0].extract_text()


def test_a_flattened_widget_lands_on_its_rectangle(documents: DocumentService) -> None:
    rect = (72.0, 600.0, 272.0, 640.0)
    out = documents.prepare(pdf_with_widget_annotation(rect=rect), [], {})
    runs = [run for run in placed_text(out) if "widget value" in run.text]
    assert runs
    x, y = runs[0].origin
    assert rect[0] - 1 <= x <= rect[2]
    assert rect[1] - 1 <= y <= rect[3]


def test_a_missing_required_prefill_key_is_refused(documents: DocumentService) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.prepare(make_pdf(), [prefill_at("patient_name", Rect(x=100, y=600, w=200, h=14))], {})
    assert excinfo.value.code == "prefill_invalid"
    assert "patient_name" in str(excinfo.value)


def test_an_optional_prefill_key_may_be_absent(documents: DocumentService) -> None:
    field = prefill_at("middle_name", Rect(x=100, y=600, w=200, h=14), required=False)
    documents.prepare(make_pdf(), [field], {})


def test_an_undeclared_prefill_key_is_refused_without_echoing_it(documents: DocumentService) -> None:
    """The key itself could identify someone, so only the count comes back."""
    with pytest.raises(ValidationFailed) as excinfo:
        documents.prepare(make_pdf(), [], {"mrn_12345_jane_roe": "x"})
    message = str(excinfo.value)
    assert excinfo.value.code == "prefill_invalid"
    assert "mrn_12345_jane_roe" not in message
    assert "1 key(s)" in message


def test_prefill_values_never_appear_in_the_error_message(documents: DocumentService) -> None:
    field = prefill_at("patient_name", Rect(x=100, y=600, w=200, h=14))
    with pytest.raises(ValidationFailed) as excinfo:
        documents.prepare(make_pdf(), [field], {"patient_name": "  ", "extra": "Jane Roe, DOB 1970-01-01"})
    assert "Jane Roe" not in str(excinfo.value)


def test_an_over_long_prefill_value_is_refused(documents: DocumentService) -> None:
    field = prefill_at("notes", Rect(x=100, y=300, w=300, h=200), multiline=True)
    with pytest.raises(ValidationFailed) as excinfo:
        documents.prepare(make_pdf(), [field], {"notes": "x" * 5000})
    assert excinfo.value.code == "prefill_invalid"


def test_preparation_is_deterministic(documents: DocumentService) -> None:
    """Same template, same chart data, same bytes -- so a revision hash means something."""
    pdf = make_pdf(pages=2)
    fields = [prefill_at("patient_name", Rect(x=100, y=600, w=240, h=14))]
    first = documents.prepare(pdf, fields, {"patient_name": "Ada Lovelace"})
    second = documents.prepare(pdf, fields, {"patient_name": "Ada Lovelace"})
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()


def test_different_chart_data_produces_different_bytes(documents: DocumentService) -> None:
    pdf = make_pdf()
    fields = [prefill_at("patient_name", Rect(x=100, y=600, w=240, h=14))]
    first = documents.prepare(pdf, fields, {"patient_name": "Ada Lovelace"})
    second = documents.prepare(pdf, fields, {"patient_name": "Grace Hopper"})
    assert first != second


def test_page_count_is_preserved(documents: DocumentService) -> None:
    out = documents.prepare(make_pdf(pages=4), [], {})
    assert len(PdfReader(io.BytesIO(out)).pages) == 4


def test_a_prefill_field_on_a_missing_page_is_refused(documents: DocumentService) -> None:
    field = prefill_at("patient_name", Rect(x=100, y=600, w=200, h=14), page=9)
    with pytest.raises(ValidationFailed) as excinfo:
        documents.prepare(make_pdf(), [field], {"patient_name": "Ada Lovelace"})
    assert excinfo.value.code == "prefill_invalid"


def test_an_unreadable_template_is_a_validation_failure(documents: DocumentService) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.prepare(b"not a pdf", [], {})
    assert excinfo.value.code == "pdf_unreadable"


def test_an_annotation_that_cannot_be_flattened_is_refused(documents: DocumentService) -> None:
    """Fail closed: losing ink the signer saw would make the stored document say less."""
    import io as _io

    from pypdf import PdfReader as _PdfReader
    from pypdf import PdfWriter as _PdfWriter
    from pypdf.generic import ArrayObject, DictionaryObject, FloatObject, NameObject

    writer = _PdfWriter()
    for page in _PdfReader(_io.BytesIO(make_pdf())).pages:
        writer.add_page(page)
    annot = DictionaryObject()
    annot[NameObject("/Type")] = NameObject("/Annot")
    annot[NameObject("/Subtype")] = NameObject("/Square")
    annot[NameObject("/Rect")] = ArrayObject([FloatObject(v) for v in (72, 600, 272, 640)])
    writer.pages[0][NameObject("/Annots")] = ArrayObject([annot])  # no /AP: nothing to flatten
    out = _io.BytesIO()
    writer.write(out)

    with pytest.raises(ValidationFailed) as excinfo:
        documents.prepare(out.getvalue(), [], {})
    assert excinfo.value.code == "annotation_not_flattenable"


def test_a_link_annotation_is_dropped_rather_than_refused(documents: DocumentService) -> None:
    """A /Link has no ink of its own, so removing it changes nothing a reader sees."""
    import io as _io

    from pypdf import PdfReader as _PdfReader
    from pypdf import PdfWriter as _PdfWriter
    from pypdf.generic import ArrayObject, DictionaryObject, FloatObject, NameObject

    writer = _PdfWriter()
    for page in _PdfReader(_io.BytesIO(make_pdf())).pages:
        writer.add_page(page)
    annot = DictionaryObject()
    annot[NameObject("/Type")] = NameObject("/Annot")
    annot[NameObject("/Subtype")] = NameObject("/Link")
    annot[NameObject("/Rect")] = ArrayObject([FloatObject(v) for v in (72, 600, 272, 640)])
    writer.pages[0][NameObject("/Annots")] = ArrayObject([annot])
    out = _io.BytesIO()
    writer.write(out)

    prepared = documents.prepare(out.getvalue(), [], {})
    assert "/Annots" not in PdfReader(io.BytesIO(prepared)).pages[0]


def test_outlines_do_not_survive_preparation(documents: DocumentService) -> None:
    """An outline item can carry an action, so the whole tree goes."""
    import io as _io

    from pypdf import PdfReader as _PdfReader
    from pypdf import PdfWriter as _PdfWriter

    writer = _PdfWriter()
    for page in _PdfReader(_io.BytesIO(make_pdf(pages=2))).pages:
        writer.add_page(page)
    writer.add_outline_item("Section one", 0)
    out = _io.BytesIO()
    writer.write(out)

    prepared = documents.prepare(out.getvalue(), [], {})
    assert "/Outlines" not in PdfReader(io.BytesIO(prepared)).root_object
