"""Per-patient clinical reports, rendered here and signed as *host documents* (Addendum 2).

A template cannot express a report: it is twenty to thirty pages of this patient's own record,
different every time, with a signature block at the end for the clinician who is responsible for
it. So the EHR renders the PDF itself and hands it to the signing service over its API key, and
the service treats those bytes as revision 1.

Two things here are the interesting half of the integration, and both are deliberate:

* **The signature block is named, not measured.** The last page carries ordinary AcroForm text
  widgets called ``clinician_signature`` and ``clinician_date`` (and, on a co-signed report,
  ``cosigner_signature`` and ``cosigner_date``). The service reads those names, works out the
  fields from the widgets' own pages and rectangles, and flattens every widget away before
  anybody sees the document. A report generator already knows where it put the signature block,
  so it names it; it never has to send coordinates, and a report that runs to 31 pages instead of
  30 needs no arithmetic anywhere.
* **The bytes are reproducible.** ``invariant=1`` pins reportlab's document id and creation date,
  and every word of the body is chosen from the report's own reference rather than from a random
  number generator, so rendering the same report twice gives the same bytes. That is what makes
  ``Idempotency-Key`` mean anything on a route whose request hash covers the document.

Everything written on these pages is invented. The wording is a plausible shape for a clinical
record, not clinical text, and no deployment should keep a line of it.
"""

from __future__ import annotations

import hashlib
import io
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Final

from reportlab.lib.pagesizes import LETTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen.canvas import Canvas

__all__ = ["Report", "SignatureBlock", "render"]

PAGE_W, PAGE_H = LETTER
MARGIN: Final[float] = 64.0
CONTENT_W: Final[float] = PAGE_W - 2 * MARGIN
BODY_FONT: Final[str] = "Helvetica"
BOLD_FONT: Final[str] = "Helvetica-Bold"
BODY_SIZE: Final[float] = 9.5
LEADING: Final[float] = BODY_SIZE * 1.5
INK: Final[tuple[float, float, float]] = (0.08, 0.10, 0.16)
MUTED: Final[tuple[float, float, float]] = (0.38, 0.41, 0.48)
RULE: Final[tuple[float, float, float]] = (0.78, 0.80, 0.85)

#: How tall one signature block is, including its caption and printed name.
BLOCK_H: Final[float] = 92.0
#: The signature widget itself. Room for a drawn signature at the size the UI stamps one.
SIGNATURE_W: Final[float] = 230.0
SIGNATURE_H: Final[float] = 40.0
DATE_W: Final[float] = 130.0
DATE_H: Final[float] = 22.0


@dataclass(frozen=True)
class SignatureBlock:
    """One signing slot at the end of the report.

    ``role_key`` is the whole contract with the signing service: the widgets are named
    ``<role_key>_signature`` and ``<role_key>_date``, and the envelope declares a signer role with
    the same key. Nothing else has to line up.
    """

    role_key: str
    caption: str
    #: Printed under the rule, so the paper copy says who was asked. Not evidence of anything:
    #: who actually signed is the signing service's business, and its certificate says so.
    expected_name: str


@dataclass(frozen=True)
class Report:
    """A report this EHR is about to render, in full. Rendering it is a pure function of this."""

    title: str
    #: The EHR's own reference for the report. Opaque, and the seed for every generated word.
    reference: str
    #: Exactly how many pages the rendered PDF will have. The generator fills to it.
    pages: int
    patient_name: str
    patient_dob: str
    patient_ref: str
    prepared_on: str  # ISO date
    prepared_by: str
    blocks: tuple[SignatureBlock, ...]


# --------------------------------------------------------------------------- generated wording

_OPENINGS: Final[tuple[str, ...]] = (
    "The patient was reviewed in the outpatient clinic and reports that the symptoms have",
    "This entry records a telephone review during which the patient described symptoms that have",
    "Seen in the day unit for a scheduled review. The presenting complaint was unchanged and has",
    "Reviewed on the ward round with the nursing team present. The picture over the week has",
    "A joint review with the physiotherapy team. Since the previous entry the symptoms have",
    "Attended for a planned follow-up appointment. Compared with the last entry the symptoms have",
    "Reviewed at home by the community team, who report that over the past fortnight things have",
    "Seen in the assessment area after a self-referral. The account given was that matters have",
)
_COURSES: Final[tuple[str, ...]] = (
    "settled steadily, with pain now reported only after prolonged activity.",
    "been variable, better on most days and worse after long periods of standing.",
    "improved slowly but not completely, with stiffness first thing in the morning.",
    "remained stable, neither worse nor appreciably better than at the last review.",
    "eased enough for ordinary activity to be resumed at a reduced level.",
    "fluctuated with the weather and with the amount of walking done each day.",
    "improved markedly since the change of analgesia recorded in the entry above.",
    "persisted at a level the patient describes as tolerable but intrusive at night.",
)
_EXAMINATION: Final[tuple[str, ...]] = (
    "On examination the joint was cool with no effusion. Range of movement was close to full and"
    " the surrounding musculature was symmetrical.",
    "Examination showed mild tenderness over the medial line without instability on stressing."
    " Gait was unaided and the pattern was even.",
    "There was no swelling, no erythema and no local warmth. Power was preserved throughout and"
    " sensation was intact in all distributions tested.",
    "The wound had healed with no discharge and the scar was flat and mobile. There was no"
    " tenderness along its length.",
    "Observations were within the expected range throughout the review. Cardiorespiratory"
    " examination was unremarkable.",
    "Movement was limited at the extremes by discomfort rather than by a mechanical block, and"
    " returned to full range with encouragement.",
    "Palpation reproduced the reported discomfort at one point only. The remainder of the examination was normal.",
    "Balance and proprioception were tested and were adequate for the activities discussed.",
)
_DISCUSSION: Final[tuple[str, ...]] = (
    "The findings were explained in plain language and the patient had the opportunity to ask"
    " questions. Written information was offered and accepted.",
    "The options were set out with their likely benefits and the things that can go wrong, and"
    " the patient was given time to consider them before deciding.",
    "The plan agreed at the previous review was revisited. The patient wished to continue with it"
    " and understood what would prompt an earlier appointment.",
    "The expected course over the next few weeks was described, including what would count as a"
    " reason to make contact sooner.",
    "The patient's own priorities were recorded and shaped the plan below rather than following"
    " it: returning to work and to regular exercise were the two that mattered most.",
    "An interpreter was not required. The discussion was summarised back by the patient in their"
    " own words, which matched the plan recorded here.",
    "The risks of doing nothing were covered alongside the risks of the proposed course, so that"
    " the comparison was a fair one.",
    "A family member was present at the patient's request and contributed to the discussion.",
)
_PLANS: Final[tuple[str, ...]] = (
    "Continue the current programme twice weekly and review in six weeks.",
    "Repeat the blood tests before the next appointment and bring the results to it.",
    "Step the analgesia down as tolerated, with a review if pain interferes with sleep.",
    "Refer to the specialist physiotherapy service for a graded loading programme.",
    "No change to the current plan. Review at the routine interval.",
    "Arrange imaging before the next review and discuss the report at that appointment.",
    "Discharge to the care of the general practice with open access back for six months.",
    "Bring the next review forward to four weeks given the change described above.",
)
_INVESTIGATIONS: Final[tuple[str, ...]] = (
    "Full blood count within the expected range; no action required.",
    "Inflammatory markers slightly above the reference range and falling since the last sample.",
    "Plain films reviewed with the reporting radiologist; appearances are as expected for the stage of recovery.",
    "Renal function stable and consistent with the previous three samples.",
    "Clotting screen normal. Group and save valid until the date recorded in the plan.",
    "No new investigations were requested at this review.",
    "Ultrasound reported as showing no collection and no evidence of infection.",
    "Weight and observations recorded in the nursing notes; both are stable.",
)
_MEDICATION: Final[tuple[str, ...]] = (
    "The current list was reconciled against the practice record and one duplicate was removed.",
    "No changes were made. The patient was reminded to take the anti-inflammatory with food.",
    "The dose was reduced in line with the plan agreed at the last review.",
    "An allergy recorded in error was corrected on the record with the patient's agreement.",
    "A short course was prescribed and the expected duration was written on the patient's copy.",
    "The list was reviewed with the pharmacist, who added a note about the interaction discussed.",
)

_SECTION_CYCLE: Final[tuple[str, ...]] = (
    "progress",
    "progress",
    "examination",
    "progress",
    "investigations",
    "progress",
    "discussion",
    "progress",
    "medication",
    "progress",
    "plan",
)


def _pick(options: Sequence[str], seed: str, index: int) -> str:
    """Choose deterministically from ``options``. No random number generator: the same report
    reference must render the same bytes, today and on a replay of the same request."""
    digest = hashlib.sha256(f"{seed}/{index}".encode()).digest()
    return options[int.from_bytes(digest[:4], "big") % len(options)]


def _step(seed: str, index: int) -> int:
    """How many days one progress note is after the one before it: three to eleven."""
    digest = hashlib.sha256(f"{seed}/gap/{index}".encode()).digest()
    return 3 + digest[0] % 9


def _entries(report: Report) -> Iterator[tuple[str | None, list[str]]]:
    """An endless stream of ``(heading, paragraphs)`` for this report's body.

    Endless because the page count is the thing being aimed at: the drawing loop keeps taking
    entries until it is on the last page, and a report that needs thirty pages of record gets
    thirty pages of record.
    """
    seed = report.reference
    when = date.fromisoformat(report.prepared_on) - timedelta(days=14 * report.pages)
    index = 0
    while True:
        kind = _SECTION_CYCLE[index % len(_SECTION_CYCLE)]
        when = when + timedelta(days=_step(seed, index))
        stamp = when.isoformat()
        if kind == "progress":
            yield (
                f"Progress note — {stamp}",
                [
                    f"{_pick(_OPENINGS, seed, index)} {_pick(_COURSES, seed, index * 3 + 1)}",
                    _pick(_EXAMINATION, seed, index * 3 + 2),
                ],
            )
        elif kind == "examination":
            yield (
                f"Examination — {stamp}",
                [_pick(_EXAMINATION, seed, index * 5), _pick(_DISCUSSION, seed, index * 5 + 1)],
            )
        elif kind == "investigations":
            yield (
                f"Investigations — {stamp}",
                [
                    _pick(_INVESTIGATIONS, seed, index * 7),
                    _pick(_INVESTIGATIONS, seed, index * 7 + 1),
                    _pick(_DISCUSSION, seed, index * 7 + 2),
                ],
            )
        elif kind == "discussion":
            yield (
                f"Discussion with the patient — {stamp}",
                [_pick(_DISCUSSION, seed, index * 11), _pick(_COURSES, seed, index * 11 + 1).capitalize()],
            )
        elif kind == "medication":
            yield (f"Medication review — {stamp}", [_pick(_MEDICATION, seed, index * 13)])
        else:
            yield (
                f"Plan — {stamp}",
                [_pick(_PLANS, seed, index * 17), _pick(_DISCUSSION, seed, index * 17 + 1)],
            )
        index += 1


# --------------------------------------------------------------------------- drawing


def _wrap(text: str, font: str, size: float, width: float) -> list[str]:
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}".strip()
        if current and pdfmetrics.stringWidth(candidate, font, size) > width:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _chrome(canvas: Canvas, report: Report, page_no: int) -> float:
    """The running head and foot. Returns the y the body starts at."""
    canvas.setFont(BOLD_FONT, 13)
    canvas.setFillColorRGB(*INK)
    canvas.drawString(MARGIN, PAGE_H - MARGIN, report.title)
    canvas.setFont(BODY_FONT, 8.5)
    canvas.setFillColorRGB(*MUTED)
    canvas.drawString(
        MARGIN, PAGE_H - MARGIN - 14, f"{report.patient_name} · born {report.patient_dob} · record {report.patient_ref}"
    )
    canvas.drawRightString(
        PAGE_W - MARGIN, PAGE_H - MARGIN - 14, f"{report.reference} · page {page_no} of {report.pages}"
    )
    canvas.setStrokeColorRGB(*RULE)
    canvas.setLineWidth(0.8)
    canvas.line(MARGIN, PAGE_H - MARGIN - 23, PAGE_W - MARGIN, PAGE_H - MARGIN - 23)
    canvas.setFont(BODY_FONT, 7)
    canvas.setFillColorRGB(*MUTED)
    canvas.drawString(
        MARGIN,
        MARGIN - 24,
        "Generated by the demo records system. The patient, the clinic and every word of this record are invented.",
    )
    return PAGE_H - MARGIN - 44


def _heading(canvas: Canvas, y: float, text: str) -> float:
    canvas.setFont(BOLD_FONT, 10)
    canvas.setFillColorRGB(*INK)
    canvas.drawString(MARGIN, y, text)
    return y - LEADING * 1.2


def _paragraph(canvas: Canvas, y: float, text: str) -> float:
    canvas.setFont(BODY_FONT, BODY_SIZE)
    canvas.setFillColorRGB(*INK)
    for line in _wrap(text, BODY_FONT, BODY_SIZE, CONTENT_W):
        canvas.drawString(MARGIN, y, line)
        y -= LEADING
    return y - LEADING * 0.5


def _entry_height(heading: str | None, paragraphs: list[str]) -> float:
    height = LEADING * 1.2 if heading is not None else 0.0
    for paragraph in paragraphs:
        height += LEADING * len(_wrap(paragraph, BODY_FONT, BODY_SIZE, CONTENT_W)) + LEADING * 0.5
    return height


def _cover(canvas: Canvas, report: Report, y: float) -> float:
    """What the first page says before the record starts."""
    canvas.setFont(BODY_FONT, BODY_SIZE)
    canvas.setFillColorRGB(*INK)
    for label, value in (
        ("Patient", f"{report.patient_name} (born {report.patient_dob}, record {report.patient_ref})"),
        ("Prepared by", report.prepared_by),
        ("Prepared on", report.prepared_on),
        ("Reference", report.reference),
        ("Signature required from", ", ".join(block.caption.lower() for block in report.blocks)),
    ):
        canvas.setFont(BOLD_FONT, BODY_SIZE)
        canvas.drawString(MARGIN, y, f"{label}:")
        canvas.setFont(BODY_FONT, BODY_SIZE)
        canvas.drawString(MARGIN + 110, y, value)
        y -= LEADING
    y -= LEADING * 0.5
    return _paragraph(
        canvas,
        y,
        "This report was assembled from the record for the episode of care below. It is signed"
        " electronically by the clinician responsible for it; the signature block is on the last"
        " page. Nothing in this document may be altered once it has been signed and sealed.",
    )


def _widget(canvas: Canvas, name: str, tooltip: str, x: float, y: float, width: float, height: float) -> None:
    """One named AcroForm text widget: the whole of what the host tells the service about a field.

    Not a signature field (``/FT /Sig``): a supplied document with one of those in it is refused
    with ``supplied_signature_field``, and rightly -- the seal is the service's to apply. This is
    an ordinary text widget whose *name* says which role and which kind of field, and which is
    flattened away before anybody sees the document. The name is read once, to decide the role and
    the type, and never becomes the field's id: ids come back as ``clinician_signature`` and
    ``clinician_date_signed`` whatever this generator called the widget, because an id reaches the
    append-only audit trail and a generated report's widget names are ours, not the service's.

    ``round``: reportlab takes either, its type stubs say ``int``, and every rectangle here lands
    on a whole point anyway.
    """
    canvas.acroForm.textfield(
        name=name,
        tooltip=tooltip,
        x=round(x),
        y=round(y),
        width=round(width),
        height=round(height),
        borderWidth=0,
        forceBorder=False,
        relative=False,
        fontName=BODY_FONT,
        fontSize=10,
        maxlen=120,
    )


def _signature_blocks(canvas: Canvas, report: Report, top: float) -> None:
    """The last page's signing slots, and the AcroForm widgets that name them.

    A widget per slot, named after the signer role. The service reads the name and the rectangle,
    and removes the widget itself before the document is shown to anybody -- so what is left in
    the sealed copy is the ruled line drawn here with a signature stamped onto it.
    """
    y = top
    for block in report.blocks:
        canvas.setFont(BOLD_FONT, 9.5)
        canvas.setFillColorRGB(*INK)
        canvas.drawString(MARGIN, y, block.caption)
        slot_y = y - SIGNATURE_H - 8
        _widget(
            canvas,
            f"{block.role_key}_signature",
            f"{block.caption}: signature",
            MARGIN,
            slot_y,
            SIGNATURE_W,
            SIGNATURE_H,
        )
        _widget(
            canvas,
            f"{block.role_key}_date",
            f"{block.caption}: date signed",
            MARGIN + SIGNATURE_W + 40,
            slot_y,
            DATE_W,
            DATE_H,
        )
        canvas.setStrokeColorRGB(*RULE)
        canvas.setLineWidth(0.8)
        canvas.line(MARGIN, slot_y - 3, MARGIN + SIGNATURE_W, slot_y - 3)
        canvas.line(MARGIN + SIGNATURE_W + 40, slot_y - 3, MARGIN + SIGNATURE_W + 40 + DATE_W, slot_y - 3)
        canvas.setFont(BODY_FONT, 7.5)
        canvas.setFillColorRGB(*MUTED)
        canvas.drawString(MARGIN, slot_y - 15, f"Signature — {block.expected_name}")
        canvas.drawString(MARGIN + SIGNATURE_W + 40, slot_y - 15, "Date signed")
        y -= BLOCK_H


def render(report: Report) -> bytes:
    """Render ``report`` to exactly ``report.pages`` pages. Same report in, same bytes out."""
    if report.pages < 2:
        raise ValueError("a report needs a body page and a signature page")
    if not report.blocks:
        raise ValueError("a report with nobody to sign it is not a report")

    buffer = io.BytesIO()
    # invariant=1 pins reportlab's document id and creation date. Without it two renderings of the
    # same report differ, and an idempotent replay of the upload would look like a different
    # document to the signing service.
    canvas = Canvas(buffer, pagesize=(PAGE_W, PAGE_H), invariant=1)
    canvas.setTitle(report.title)
    canvas.setSubject(report.reference)

    entries = _entries(report)
    page = 1
    y = _cover(canvas, report, _chrome(canvas, report, page))
    while page < report.pages:
        heading, paragraphs = next(entries)
        if y - _entry_height(heading, paragraphs) < MARGIN:
            canvas.showPage()
            page += 1
            if page == report.pages:
                break
            y = _chrome(canvas, report, page)
        if heading is not None:
            y = _heading(canvas, y, heading)
        for paragraph in paragraphs:
            y = _paragraph(canvas, y, paragraph)

    # The last page: the declaration, then the signature blocks, anchored above the footer.
    y = _chrome(canvas, report, page)
    y = _heading(canvas, y, "Declaration")
    _paragraph(
        canvas,
        y,
        "I have reviewed this report in full and confirm that it is an accurate record of the care"
        " described. Signing it electronically has the same effect as signing it in ink.",
    )
    _signature_blocks(canvas, report, MARGIN + BLOCK_H * len(report.blocks))
    canvas.showPage()
    canvas.save()
    return buffer.getvalue()
