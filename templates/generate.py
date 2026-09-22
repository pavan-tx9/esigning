#!/usr/bin/env python
"""Generate the four sample templates and their definitions, reproducibly.

Run from the repository root::

    uv --directory backend run python ../templates/generate.py

Byte-for-byte reproducible: the canvas is created through
``esign.documents.pdfutil.new_canvas``, which pins reportlab's document id and creation date, and
the JSON is written sorted with a trailing newline. ``tests/documents/test_sample_templates.py``
regenerates everything into a temporary directory and fails if a single byte differs, so a
template can never drift from the script that claims to produce it.

The first three templates are the ones SPEC section 6 requires; the fourth is Addendum 1's:

``patient_consent``         one signer, who may sign for themselves or as a guardian
``hipaa_acknowledgement``   one signer, one page
``procedure_consent``       patient, witness and clinician, in that order, over three pages
``clinical_order``          one signer, a clinician, one page: what a signing queue is made of

The bodies are plain-language placeholders, not legal advice. A deployment replaces them with text
its counsel has approved; the geometry and the role structure are the part worth copying.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

_HERE = Path(__file__).resolve().parent
_BACKEND_SRC = _HERE.parent / "backend" / "src"
if str(_BACKEND_SRC) not in sys.path:  # allow `python templates/generate.py` without an install
    sys.path.insert(0, str(_BACKEND_SRC))

from reportlab.lib.pagesizes import LETTER  # noqa: E402
from reportlab.pdfgen.canvas import Canvas  # noqa: E402

from esign.contracts import FieldDef, PrefillFieldDef, Rect, SignerRoleDef  # noqa: E402
from esign.documents.codec import definitions_to_json  # noqa: E402
from esign.documents.fonts import (  # noqa: E402
    PLAIN_BOLD_FONT,
    PLAIN_FONT,
    ensure_fonts_registered,
    wrap_text,
)
from esign.documents.pdfutil import new_canvas  # noqa: E402

PAGE_W, PAGE_H = LETTER
MARGIN: Final[float] = 72.0
CONTENT_W: Final[float] = PAGE_W - 2 * MARGIN
INK = (0.08, 0.10, 0.16)
MUTED = (0.38, 0.41, 0.48)
RULE = (0.78, 0.80, 0.85)


@dataclass(frozen=True)
class Sample:
    key: str
    name: str
    document_type: str
    signer_roles: list[SignerRoleDef]
    fields: list[FieldDef]
    prefill_fields: list[PrefillFieldDef]
    pages: list[tuple[str, list[str]]]  # (heading, paragraphs)


# --------------------------------------------------------------------------- drawing


def _paragraphs(canvas: Canvas, y: float, paragraphs: list[str], size: float = 10.0) -> float:
    canvas.setFillColorRGB(*INK)
    for paragraph in paragraphs:
        for line in wrap_text(paragraph, PLAIN_FONT, size, CONTENT_W):
            canvas.setFont(PLAIN_FONT, size)
            canvas.drawString(MARGIN, y, line)
            y -= size * 1.45
        y -= size * 0.7
    return y


def _slot(canvas: Canvas, label: str, rect: Rect, *, caption_room: float = 18.0) -> None:
    """A ruled signing slot. The rule sits on the rect's baseline; the caption lands below it."""
    canvas.setStrokeColorRGB(*RULE)
    canvas.setLineWidth(0.8)
    canvas.line(rect.x, rect.y - 2, rect.x + rect.w, rect.y - 2)
    canvas.setFont(PLAIN_FONT, 7.5)
    canvas.setFillColorRGB(*MUTED)
    canvas.drawString(rect.x, rect.y - caption_room, label)


def _page_chrome(canvas: Canvas, sample: Sample, heading: str, page_no: int, page_count: int) -> float:
    canvas.setFont(PLAIN_BOLD_FONT, 15)
    canvas.setFillColorRGB(*INK)
    canvas.drawString(MARGIN, PAGE_H - MARGIN, sample.name)
    canvas.setFont(PLAIN_FONT, 9)
    canvas.setFillColorRGB(*MUTED)
    canvas.drawString(MARGIN, PAGE_H - MARGIN - 15, heading)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - MARGIN - 15, f"Page {page_no} of {page_count}")
    canvas.setStrokeColorRGB(*RULE)
    canvas.setLineWidth(0.8)
    canvas.line(MARGIN, PAGE_H - MARGIN - 24, PAGE_W - MARGIN, PAGE_H - MARGIN - 24)
    canvas.setFont(PLAIN_FONT, 7.5)
    canvas.setFillColorRGB(*MUTED)
    canvas.drawString(MARGIN, MARGIN - 22, "Sample template. Replace this text with wording your counsel has approved.")
    return PAGE_H - MARGIN - 48


def render(sample: Sample) -> bytes:
    ensure_fonts_registered()
    buffer = io.BytesIO()
    canvas = new_canvas(buffer, PAGE_W, PAGE_H)
    page_count = len(sample.pages)

    slots: dict[int, list[tuple[str, Rect]]] = {}
    for field in sample.fields:
        if field.type in ("signature", "initials", "date_signed"):
            slots.setdefault(field.page, []).append((field.label or field.id, field.rect))
    for prefill in sample.prefill_fields:
        slots.setdefault(prefill.page, []).append((prefill.key.replace("_", " ").capitalize(), prefill.rect))

    for index, (heading, paragraphs) in enumerate(sample.pages, start=1):
        y = _page_chrome(canvas, sample, heading, index, page_count)
        _paragraphs(canvas, y, paragraphs)
        for label, rect in slots.get(index, []):
            _slot(canvas, label, rect)
        canvas.showPage()

    canvas.save()
    return buffer.getvalue()


# --------------------------------------------------------------------------- the four samples


def _patient_consent() -> Sample:
    roles = [
        SignerRoleDef(
            key="patient",
            label="Patient or guardian",
            allowed_capacities=("self", "guardian"),
            requires_reauth=False,
            order_index=0,
        )
    ]
    fields = [
        FieldDef(
            id="patient_signature",
            type="signature",
            page=1,
            rect=Rect(x=72, y=210, w=240, h=46),
            signer_role="patient",
            label="Signature",
        ),
        FieldDef(
            id="patient_date",
            type="date_signed",
            page=1,
            rect=Rect(x=352, y=210, w=170, h=18),
            signer_role="patient",
            label="Date signed",
        ),
        FieldDef(
            id="patient_agrees",
            type="checkbox",
            page=1,
            rect=Rect(x=72, y=300, w=14, h=14),
            signer_role="patient",
            label="I have read and understood this consent",
        ),
    ]
    prefill = [
        PrefillFieldDef(key="patient_name", page=1, rect=Rect(x=72, y=560, w=240, h=14), font_size=10),
        PrefillFieldDef(key="date_of_birth", page=1, rect=Rect(x=352, y=560, w=170, h=14), font_size=10),
        PrefillFieldDef(
            key="treatment_summary", page=1, rect=Rect(x=72, y=430, w=450, h=90), font_size=10, multiline=True
        ),
    ]
    body = [
        "This form records your consent to the treatment described below. Read it in full before "
        "you sign. If anything is unclear, ask the person treating you to explain it before you "
        "continue.",
        "You can decline, and you can ask for a paper copy instead. Declining here does not change "
        "the care you are offered.",
    ]
    return Sample(
        key="patient_consent",
        name="Consent to treatment",
        document_type="patient_consent",
        signer_roles=roles,
        fields=fields,
        prefill_fields=prefill,
        pages=[("Consent to treatment", body)],
    )


def _hipaa_acknowledgement() -> Sample:
    roles = [
        SignerRoleDef(
            key="patient",
            label="Patient",
            allowed_capacities=("self", "guardian", "proxy"),
            requires_reauth=False,
            order_index=0,
        )
    ]
    fields = [
        FieldDef(
            id="patient_signature",
            type="signature",
            page=1,
            rect=Rect(x=72, y=200, w=240, h=46),
            signer_role="patient",
            label="Signature",
        ),
        FieldDef(
            id="patient_date",
            type="date_signed",
            page=1,
            rect=Rect(x=352, y=200, w=170, h=18),
            signer_role="patient",
            label="Date signed",
        ),
    ]
    prefill = [
        PrefillFieldDef(key="patient_name", page=1, rect=Rect(x=72, y=560, w=240, h=14), font_size=10),
        PrefillFieldDef(key="notice_version", page=1, rect=Rect(x=352, y=560, w=170, h=14), font_size=10),
    ]
    body = [
        "This acknowledges that you were given the Notice of Privacy Practices, which explains how "
        "your health information may be used and shared, and the rights you have over it.",
        "Signing this form acknowledges that you received the notice. It is not consent to any "
        "particular treatment, and it does not give up any right described in the notice.",
    ]
    return Sample(
        key="hipaa_acknowledgement",
        name="Acknowledgement of privacy practices",
        document_type="hipaa_acknowledgement",
        signer_roles=roles,
        fields=fields,
        prefill_fields=prefill,
        pages=[("Notice of Privacy Practices", body)],
    )


def _procedure_consent() -> Sample:
    roles = [
        SignerRoleDef(
            key="patient",
            label="Patient",
            allowed_capacities=("self", "guardian"),
            requires_reauth=False,
            order_index=0,
        ),
        SignerRoleDef(
            key="witness",
            label="Witness",
            allowed_capacities=("witness",),
            requires_reauth=False,
            order_index=1,
        ),
        SignerRoleDef(
            key="clinician",
            label="Clinician",
            allowed_capacities=("clinician",),
            requires_reauth=True,
            order_index=2,
        ),
    ]
    fields = [
        FieldDef(
            id="patient_initials_risks",
            type="initials",
            page=2,
            rect=Rect(x=432, y=250, w=108, h=40),
            signer_role="patient",
            label="Initials",
        ),
        FieldDef(
            id="patient_signature",
            type="signature",
            page=3,
            rect=Rect(x=72, y=520, w=240, h=46),
            signer_role="patient",
            label="Patient signature",
        ),
        FieldDef(
            id="patient_date",
            type="date_signed",
            page=3,
            rect=Rect(x=352, y=520, w=170, h=18),
            signer_role="patient",
            label="Date signed",
        ),
        FieldDef(
            id="witness_signature",
            type="signature",
            page=3,
            rect=Rect(x=72, y=380, w=240, h=46),
            signer_role="witness",
            label="Witness signature",
        ),
        FieldDef(
            id="witness_date",
            type="date_signed",
            page=3,
            rect=Rect(x=352, y=380, w=170, h=18),
            signer_role="witness",
            label="Date signed",
        ),
        FieldDef(
            id="clinician_signature",
            type="signature",
            page=3,
            rect=Rect(x=72, y=240, w=240, h=46),
            signer_role="clinician",
            label="Clinician signature",
        ),
        FieldDef(
            id="clinician_date",
            type="date_signed",
            page=3,
            rect=Rect(x=352, y=240, w=170, h=18),
            signer_role="clinician",
            label="Date signed",
        ),
    ]
    prefill = [
        PrefillFieldDef(key="patient_name", page=1, rect=Rect(x=72, y=560, w=240, h=14), font_size=10),
        PrefillFieldDef(key="date_of_birth", page=1, rect=Rect(x=352, y=560, w=170, h=14), font_size=10),
        PrefillFieldDef(key="procedure_name", page=1, rect=Rect(x=72, y=520, w=450, h=14), font_size=10),
        PrefillFieldDef(
            key="procedure_description",
            page=1,
            rect=Rect(x=72, y=380, w=450, h=110),
            font_size=10,
            multiline=True,
        ),
        PrefillFieldDef(key="known_risks", page=2, rect=Rect(x=72, y=330, w=360, h=180), font_size=10, multiline=True),
    ]
    return Sample(
        key="procedure_consent",
        name="Consent to a procedure",
        document_type="procedure_consent",
        signer_roles=roles,
        fields=fields,
        prefill_fields=prefill,
        pages=[
            (
                "What is being proposed",
                [
                    "This form records your consent to the procedure named below. The description "
                    "was written for you by the team proposing it.",
                    "Take as long as you need. You can decline, ask questions, ask for a paper "
                    "copy, or change your mind before the procedure begins.",
                ],
            ),
            (
                "Risks and alternatives",
                [
                    "Every procedure carries risk. The risks below are the ones the team considers "
                    "material for you. Initial this page to confirm they were explained to you and "
                    "that you had the chance to ask about them.",
                    "Alternatives, including doing nothing, were discussed with you. Ask for them "
                    "to be explained again if you are unsure.",
                ],
            ),
            (
                "Signatures",
                [
                    "The patient signs first, then the witness confirms that the patient signed "
                    "willingly, then the clinician attests that the procedure and its risks were "
                    "explained.",
                ],
            ),
        ],
    )


def _clinical_order() -> Sample:
    """A clinician's sign-off on an order for a patient: one signer, one page, re-authentication
    required. The document a clinician signs many of in a row, which is what Addendum 1 C's
    signing queue exists for -- and the one that shows a saved signature (Addendum 1 B) earning
    its keep."""
    roles = [
        SignerRoleDef(
            key="clinician",
            label="Clinician",
            allowed_capacities=("clinician",),
            requires_reauth=True,
            order_index=0,
        )
    ]
    fields = [
        FieldDef(
            id="clinician_signature",
            type="signature",
            page=1,
            rect=Rect(x=72, y=200, w=240, h=46),
            signer_role="clinician",
            label="Clinician signature",
        ),
        FieldDef(
            id="clinician_date",
            type="date_signed",
            page=1,
            rect=Rect(x=352, y=200, w=170, h=18),
            signer_role="clinician",
            label="Date signed",
        ),
    ]
    prefill = [
        PrefillFieldDef(key="patient_name", page=1, rect=Rect(x=72, y=560, w=240, h=14), font_size=10),
        PrefillFieldDef(key="order_reference", page=1, rect=Rect(x=352, y=560, w=170, h=14), font_size=10),
        PrefillFieldDef(
            key="order_summary", page=1, rect=Rect(x=72, y=380, w=468, h=150), font_size=10, multiline=True
        ),
    ]
    body = [
        "This confirms the order described below for the patient named above. By signing, the "
        "clinician states that they gave or reviewed the order, that it is complete and accurate "
        "as written, and that it may be acted on.",
        "A signature here is a clinical act. The records system asks the clinician to confirm their "
        "identity again immediately before it is taken, and records how and when that was done.",
    ]
    return Sample(
        key="clinical_order",
        name="Clinical order sign-off",
        document_type="clinical_order",
        signer_roles=roles,
        fields=fields,
        prefill_fields=prefill,
        pages=[("Order confirmation", body)],
    )


SAMPLES: Final[tuple[Sample, ...]] = (
    _patient_consent(),
    _hipaa_acknowledgement(),
    _procedure_consent(),
    _clinical_order(),
)


# --------------------------------------------------------------------------- writing


def definition_document(sample: Sample) -> dict[str, object]:
    return {
        "key": sample.key,
        "name": sample.name,
        "document_type": sample.document_type,
        **definitions_to_json(sample.fields, sample.prefill_fields, sample.signer_roles),
    }


def write(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for sample in SAMPLES:
        pdf_path = out_dir / f"{sample.key}.pdf"
        json_path = out_dir / f"{sample.key}.json"
        pdf_path.write_bytes(render(sample))
        json_path.write_text(json.dumps(definition_document(sample), indent=2, sort_keys=True) + "\n")
        written.extend((pdf_path, json_path))
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=_HERE, help="directory to write into")
    args = parser.parse_args()
    for path in write(args.out):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
