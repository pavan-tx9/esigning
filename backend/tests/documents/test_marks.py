"""``apply_signer_marks``: what the signer's act looks like on the page, and what is refused.

The refusals matter as much as the drawing. A capture that reaches a field belonging to someone
else, a second capture for a field already signed, or a client-supplied signing date would each
produce a document that says something nobody agreed to.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from uuid import UUID

import pytest
from PIL import Image
from pypdf import PdfReader

from esign.contracts import Capture, DocumentService, FieldDef, Rect, SignerStamp, ValidationFailed
from esign.documents.fonts import PLAIN_FONT, SCRIPT_FONT
from tests.documents.helpers import handwriting_png, make_pdf, placed_images, placed_text

SIG_RECT = Rect(x=100, y=400, w=220, h=48)


def sig_field(field_id: str = "patient_signature", page: int = 1, rect: Rect = SIG_RECT) -> FieldDef:
    return FieldDef(id=field_id, type="signature", page=page, rect=rect, signer_role="patient", label="Signature")


def typed(field_id: str = "patient_signature", text: str = "Ada Lovelace") -> Capture:
    return Capture(field_id=field_id, kind="typed", typed_text=text)


# --------------------------------------------------------------------------- geometry


@pytest.mark.parametrize("rotate", [0, 90, 180, 270])
@pytest.mark.parametrize("origin", [(0.0, 0.0), (24.0, 36.0)])
def test_a_typed_signature_lands_inside_its_rect(
    documents: DocumentService, stamp: SignerStamp, rotate: int, origin: tuple[float, float]
) -> None:
    out = documents.apply_signer_marks(make_pdf(rotate=rotate, origin=origin), [sig_field()], [typed()], stamp)
    runs = [run for run in placed_text(out) if run.text == "Ada Lovelace"]
    assert runs, "the typed signature was not drawn"
    assert runs[0].box(SCRIPT_FONT).inside(SIG_RECT)


@pytest.mark.parametrize("rotate", [0, 90, 180, 270])
@pytest.mark.parametrize("origin", [(0.0, 0.0), (24.0, 36.0)])
def test_a_drawn_signature_lands_inside_its_rect(
    documents: DocumentService, stamp: SignerStamp, rotate: int, origin: tuple[float, float]
) -> None:
    png = documents.sanitize_signature_png(handwriting_png())
    capture = Capture(field_id="patient_signature", kind="drawn", image_png=png)
    out = documents.apply_signer_marks(make_pdf(rotate=rotate, origin=origin), [sig_field()], [capture], stamp)
    images = placed_images(out)
    assert len(images) == 1
    assert images[0].box.inside(SIG_RECT)


def test_a_drawn_signature_keeps_its_aspect_ratio(documents: DocumentService, stamp: SignerStamp) -> None:
    """Sanitisation trims to the ink, so the ratio to preserve is the sanitized image's own."""
    png = documents.sanitize_signature_png(handwriting_png(width=600, height=200))
    source_w, source_h = Image.open(io.BytesIO(png)).size
    capture = Capture(field_id="patient_signature", kind="drawn", image_png=png)
    out = documents.apply_signer_marks(make_pdf(), [sig_field()], [capture], stamp)
    box = placed_images(out)[0].box
    drawn_ratio = (box.x1 - box.x0) / (box.y1 - box.y0)
    assert drawn_ratio == pytest.approx(source_w / source_h, rel=0.02)


def test_the_caption_is_below_the_rect_when_there_is_room(documents: DocumentService, stamp: SignerStamp) -> None:
    out = documents.apply_signer_marks(make_pdf(), [sig_field()], [typed()], stamp)
    captions = [run for run in placed_text(out) if run.text.startswith("Signed 2026-03-17")]
    assert captions
    box = captions[0].box(PLAIN_FONT)
    assert box.y1 <= SIG_RECT.y
    assert box.y0 >= 0


def test_a_field_at_the_very_bottom_still_gets_its_caption_on_the_page(
    documents: DocumentService, stamp: SignerStamp
) -> None:
    rect = Rect(x=100, y=2, w=220, h=60)
    out = documents.apply_signer_marks(make_pdf(), [sig_field(rect=rect)], [typed()], stamp)
    captions = [run for run in placed_text(out) if run.text.startswith("Signed 2026-03-17")]
    assert captions
    box = captions[0].box(PLAIN_FONT)
    assert box.y0 >= 0
    assert box.inside(rect)


def test_the_caption_says_who_in_what_capacity_when_and_which_signer(
    documents: DocumentService, stamp: SignerStamp
) -> None:
    out = documents.apply_signer_marks(make_pdf(), [sig_field()], [typed()], stamp)
    text = PdfReader(io.BytesIO(out)).pages[0].extract_text()
    assert "Ada Lovelace (self)" in text
    assert "Signed 2026-03-17 14:30:00 UTC" in text
    assert str(stamp.signer_id) in text


def test_on_behalf_of_appears_in_the_caption(documents: DocumentService) -> None:
    guardian = SignerStamp(
        signer_id=UUID(int=9),
        display_name="Grace Hopper",
        capacity="guardian",
        on_behalf_of_label="patient-ref-7",
        signed_at=datetime(2026, 3, 17, 14, 30, tzinfo=UTC),
    )
    out = documents.apply_signer_marks(make_pdf(), [sig_field()], [typed()], guardian)
    assert "on behalf of patient-ref-7" in PdfReader(io.BytesIO(out)).pages[0].extract_text()


def test_click_to_sign_renders_the_signers_name_in_the_plain_face(
    documents: DocumentService, stamp: SignerStamp
) -> None:
    capture = Capture(field_id="patient_signature", kind="click")
    out = documents.apply_signer_marks(make_pdf(), [sig_field()], [capture], stamp)
    runs = [run for run in placed_text(out) if run.text == "Ada Lovelace"]
    assert runs
    assert runs[0].box(PLAIN_FONT).inside(SIG_RECT)


def test_click_to_sign_on_an_initials_field_renders_initials(documents: DocumentService, stamp: SignerStamp) -> None:
    field = FieldDef(
        id="patient_initials",
        type="initials",
        page=1,
        rect=Rect(x=100, y=400, w=96, h=40),
        signer_role="patient",
    )
    out = documents.apply_signer_marks(make_pdf(), [field], [Capture(field_id="patient_initials", kind="click")], stamp)
    assert "AL" in PdfReader(io.BytesIO(out)).pages[0].extract_text()


def test_a_long_typed_signature_is_shrunk_to_fit(documents: DocumentService, stamp: SignerStamp) -> None:
    name = "Maximiliaan Vandenbergh-Oosterhuis"
    out = documents.apply_signer_marks(make_pdf(), [sig_field()], [typed(text=name)], stamp)
    runs = [run for run in placed_text(out) if run.text == name]
    assert runs
    assert runs[0].box(SCRIPT_FONT).inside(SIG_RECT)


# --------------------------------------------------------------------------- date_signed


def test_date_signed_comes_from_the_stamp(documents: DocumentService, stamp: SignerStamp) -> None:
    date_field = FieldDef(
        id="patient_date",
        type="date_signed",
        page=1,
        rect=Rect(x=360, y=400, w=150, h=18),
        signer_role="patient",
    )
    out = documents.apply_signer_marks(make_pdf(), [sig_field(), date_field], [typed()], stamp)
    runs = [run for run in placed_text(out) if run.text == "2026-03-17 14:30 UTC"]
    assert runs
    assert runs[0].box(PLAIN_FONT).inside(date_field.rect)


def test_a_client_supplied_date_signed_is_refused(documents: DocumentService, stamp: SignerStamp) -> None:
    """The client never supplies a timestamp. Accepting one here would backdate a signature."""
    date_field = FieldDef(
        id="patient_date",
        type="date_signed",
        page=1,
        rect=Rect(x=360, y=400, w=150, h=18),
        signer_role="patient",
    )
    forged = Capture(field_id="patient_date", kind="typed", typed_text="1999-01-01")
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field(), date_field], [typed(), forged], stamp)
    assert excinfo.value.code == "captures_invalid"
    assert "filled by the server" in str(excinfo.value)


def test_a_naive_stamp_time_is_refused(documents: DocumentService) -> None:
    naive = SignerStamp(
        signer_id=UUID(int=3),
        display_name="Ada Lovelace",
        capacity="self",
        on_behalf_of_label=None,
        signed_at=datetime(2026, 3, 17, 14, 30),
    )
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field()], [typed()], naive)
    assert excinfo.value.code == "stamp_time_naive"


# --------------------------------------------------------------------------- capture rules


def test_a_capture_for_someone_elses_field_is_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    other = Capture(field_id="witness_signature", kind="typed", typed_text="Someone Else")
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field()], [typed(), other], stamp)
    assert excinfo.value.code == "captures_invalid"
    assert "not this signer's" in str(excinfo.value)


def test_the_rejection_does_not_reveal_the_other_signers_field(documents: DocumentService, stamp: SignerStamp) -> None:
    other = Capture(field_id="witness_signature", kind="typed", typed_text="Someone Else")
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field()], [typed(), other], stamp)
    assert "witness_signature" not in str(excinfo.value)
    assert "Someone Else" not in str(excinfo.value)


def test_a_missing_required_capture_is_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field()], [], stamp)
    assert "required capture is missing" in str(excinfo.value)


def test_an_optional_field_may_be_left_unsigned(documents: DocumentService, stamp: SignerStamp) -> None:
    optional = FieldDef(
        id="optional_initials",
        type="initials",
        page=1,
        rect=Rect(x=380, y=200, w=96, h=40),
        signer_role="patient",
        required=False,
    )
    documents.apply_signer_marks(make_pdf(), [sig_field(), optional], [typed()], stamp)


def test_two_captures_for_one_field_are_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field()], [typed(), typed(text="Someone Else")], stamp)
    assert "more than one capture" in str(excinfo.value)


def test_a_drawn_capture_without_an_image_is_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(
            make_pdf(), [sig_field()], [Capture(field_id="patient_signature", kind="drawn")], stamp
        )
    assert "needs a sanitized PNG" in str(excinfo.value)


def test_an_empty_typed_capture_is_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field()], [typed(text="   ")], stamp)
    assert "needs text" in str(excinfo.value)


def test_an_over_long_typed_capture_is_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field()], [typed(text="x" * 200)], stamp)
    assert "longer than" in str(excinfo.value)


def test_an_unknown_capture_kind_is_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    """The type annotation says this cannot happen; the value still arrives from a client."""
    rogue = Capture(field_id="patient_signature", kind="stamped")  # type: ignore[arg-type]
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), [sig_field()], [rogue], stamp)
    assert "unknown capture kind" in str(excinfo.value)


def test_all_capture_problems_are_reported_together(documents: DocumentService, stamp: SignerStamp) -> None:
    fields = [sig_field(), sig_field("second_signature", rect=Rect(x=100, y=200, w=220, h=48))]
    captures = [
        Capture(field_id="ghost_field", kind="click"),
        Capture(field_id="patient_signature", kind="drawn"),
    ]
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(), fields, captures, stamp)
    message = str(excinfo.value)
    assert "not this signer's" in message
    assert "needs a sanitized PNG" in message
    assert "second_signature" in message


def test_nothing_is_drawn_when_any_capture_is_invalid(documents: DocumentService, stamp: SignerStamp) -> None:
    """Validation happens before the first pixel, so a refusal leaves no half-signed revision."""
    pdf = make_pdf()
    bad = Capture(field_id="ghost_field", kind="click")
    with pytest.raises(ValidationFailed):
        documents.apply_signer_marks(pdf, [sig_field()], [typed(), bad], stamp)


# --------------------------------------------------------------------------- other field types


def test_a_checkbox_is_ticked_inside_its_rect(documents: DocumentService, stamp: SignerStamp) -> None:
    box = FieldDef(id="agrees", type="checkbox", page=1, rect=Rect(x=100, y=300, w=14, h=14), signer_role="patient")
    out = documents.apply_signer_marks(
        make_pdf(),
        [sig_field(), box],
        [typed(), Capture(field_id="agrees", checked=True, kind="click")],
        stamp,
    )
    assert out != documents.apply_signer_marks(
        make_pdf(),
        [sig_field(), box],
        [typed(), Capture(field_id="agrees", checked=False, kind="click")],
        stamp,
    )


def test_a_checkbox_without_a_value_is_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    box = FieldDef(id="agrees", type="checkbox", page=1, rect=Rect(x=100, y=300, w=14, h=14), signer_role="patient")
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(
            make_pdf(), [sig_field(), box], [typed(), Capture(field_id="agrees", kind="click")], stamp
        )
    assert "needs `checked`" in str(excinfo.value)


def test_a_text_field_is_drawn_inside_its_rect(documents: DocumentService, stamp: SignerStamp) -> None:
    text_field = FieldDef(
        id="relationship", type="text", page=1, rect=Rect(x=100, y=300, w=200, h=16), signer_role="patient"
    )
    capture = Capture(field_id="relationship", kind="typed", text_value="Parent")
    out = documents.apply_signer_marks(make_pdf(), [sig_field(), text_field], [typed(), capture], stamp)
    runs = [run for run in placed_text(out) if run.text == "Parent"]
    assert runs
    assert runs[0].box(PLAIN_FONT).inside(text_field.rect)


def test_an_over_long_text_value_is_rejected(documents: DocumentService, stamp: SignerStamp) -> None:
    text_field = FieldDef(
        id="relationship", type="text", page=1, rect=Rect(x=100, y=300, w=200, h=16), signer_role="patient"
    )
    capture = Capture(field_id="relationship", kind="typed", text_value="x" * 900)
    with pytest.raises(ValidationFailed):
        documents.apply_signer_marks(make_pdf(), [sig_field(), text_field], [typed(), capture], stamp)


# --------------------------------------------------------------------------- document hygiene


def test_the_signed_revision_has_nothing_interactive(documents: DocumentService, stamp: SignerStamp) -> None:
    out = documents.apply_signer_marks(make_pdf(), [sig_field()], [typed()], stamp)
    reader = PdfReader(io.BytesIO(out))
    assert "/AcroForm" not in reader.root_object
    for page in reader.pages:
        assert "/Annots" not in page


def test_marks_are_deterministic(documents: DocumentService, stamp: SignerStamp) -> None:
    pdf = make_pdf()
    assert documents.apply_signer_marks(pdf, [sig_field()], [typed()], stamp) == documents.apply_signer_marks(
        pdf, [sig_field()], [typed()], stamp
    )


def test_marks_are_applied_to_the_right_page(documents: DocumentService, stamp: SignerStamp) -> None:
    out = documents.apply_signer_marks(make_pdf(pages=3), [sig_field(page=3)], [typed()], stamp)
    reader = PdfReader(io.BytesIO(out))
    assert "Ada Lovelace" not in reader.pages[0].extract_text()
    assert "Ada Lovelace" in reader.pages[2].extract_text()


def test_a_field_on_a_page_that_does_not_exist_is_refused(documents: DocumentService, stamp: SignerStamp) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.apply_signer_marks(make_pdf(pages=1), [sig_field(page=4)], [typed()], stamp)
    assert excinfo.value.code == "field_page_missing"


def test_a_second_signer_adds_to_the_first_signers_revision(documents: DocumentService, stamp: SignerStamp) -> None:
    """Each signer stamps the current revision, so both marks survive into the final document."""
    first = documents.apply_signer_marks(make_pdf(), [sig_field()], [typed()], stamp)
    witness_field = sig_field("witness_signature", rect=Rect(x=100, y=250, w=220, h=48))
    witness = SignerStamp(
        signer_id=UUID(int=22),
        display_name="Grace Hopper",
        capacity="witness",
        on_behalf_of_label=None,
        signed_at=datetime(2026, 3, 17, 15, 0, tzinfo=UTC),
    )
    second = documents.apply_signer_marks(first, [witness_field], [typed("witness_signature", "Grace Hopper")], witness)
    text = PdfReader(io.BytesIO(second)).pages[0].extract_text()
    assert "Ada Lovelace" in text
    assert "Grace Hopper" in text


def test_a_rect_too_small_for_both_bands_keeps_everything_inside_it(
    documents: DocumentService, stamp: SignerStamp
) -> None:
    """``validate_definitions`` keeps new templates comfortable; an older one might not be.

    Whatever the rect, the mark and the caption both stay inside it rather than bleeding over the
    sentence next to it.
    """
    rect = Rect(x=100, y=4, w=220, h=20)
    out = documents.apply_signer_marks(make_pdf(), [sig_field(rect=rect)], [typed()], stamp)
    for run in placed_text(out):
        if run.text in {"Ada Lovelace", "Ada Lovelace (self)"} or run.text.startswith(("Signed 2026", "Signer ")):
            font = SCRIPT_FONT if run.text == "Ada Lovelace" else PLAIN_FONT
            assert run.box(font).inside(rect, tolerance=1.5), run.text


def test_the_caption_never_abbreviates_the_signer_id(documents: DocumentService, stamp: SignerStamp) -> None:
    """The id is the link between this mark and the audit trail; the name is what gets shortened."""
    from esign.documents.definitions import MIN_MARK_RECT_WIDTH

    rect = Rect(x=100, y=400, w=MIN_MARK_RECT_WIDTH, h=48)
    field = sig_field(rect=rect)
    long_name = SignerStamp(
        signer_id=stamp.signer_id,
        display_name="Bartholomew Fitzwilliam-Harrington the Third",
        capacity="guardian",
        on_behalf_of_label="patient-ref-0000001",
        signed_at=stamp.signed_at,
    )
    out = documents.apply_signer_marks(make_pdf(), [field], [typed()], long_name)
    text = PdfReader(io.BytesIO(out)).pages[0].extract_text()
    assert str(stamp.signer_id) in text
    assert "Signed 2026-03-17 14:30:00 UTC" in text
