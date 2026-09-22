"""The cover page of a paper archive (Addendum 1 A).

One page, placed *before* the scan and inside the same sealed bytes, so anyone who opens the
sealed PDF reads it first. It answers, without any access to this system: what this document is,
which paper it is a copy of, who says so, when they said it, what happened to the original, and --
in plain words, not in a footnote -- what the seal on these bytes does and does not prove.

That last part is the point of the page. A seal over a scan proves the scan has not changed since
it was filed. It says nothing about whether the ink on the paper is genuine: that rests on the
paper original and on the staff member who attested to the copy, and a reader who is not told so
could reasonably assume otherwise.

Like everything else this module writes: embedded fonts, no form fields, no scripts, and the same
bytes for the same input.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from typing import Final

from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen.canvas import Canvas

from esign.contracts import ArchiveCoverSummary
from esign.documents.fonts import (
    PLAIN_BOLD_FONT,
    PLAIN_FONT,
    ensure_fonts_registered,
    truncate_to_width,
    wrap_text,
)
from esign.documents.pdfutil import new_canvas

__all__ = ["build_archive_cover"]

_PAGE_W, _PAGE_H = LETTER
_MARGIN: Final[float] = 54.0
_CONTENT_W: Final[float] = _PAGE_W - 2 * _MARGIN
_LABEL_W: Final[float] = 150.0
_VALUE_W: Final[float] = _CONTENT_W - _LABEL_W
_BODY: Final[float] = 9.5
_LEADING: Final[float] = 13.0
_INK = (0.08, 0.10, 0.16)
_MUTED = (0.38, 0.41, 0.48)
_RULE = (0.80, 0.82, 0.86)

TITLE: Final[str] = "Scanned copy of a document signed on paper"

#: The sentence the addendum requires, on the page and (in the same words) on the certificate.
WHAT_THE_SEAL_PROVES: Final[str] = (
    "The seal on this document proves that this scan has not changed since it was filed, and who "
    "filed and attested to it. It does not prove that the signature on the paper is genuine: that "
    "rests on the paper original and on the person who attested to this copy."
)

_DISPOSITION_LABELS: Final[dict[str, str]] = {
    "retained": "kept by the practice",
    "returned_to_signer": "returned to the person who signed it",
    "destroyed_per_policy": "destroyed under the practice's retention policy",
}

_STATEMENT_LABELS: Final[dict[str, str]] = {
    "true_copy": "This scan is a complete and accurate copy of the paper document.",
}


def _when(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _split_hex(value: str) -> list[str]:
    """A digest wraps by character: there are no spaces to break on."""
    per_line = 56
    return [value[index : index + per_line] for index in range(0, len(value), per_line)] or [""]


class _Cursor:
    """A one-column layout. The page is fixed: the content is bounded, so it always fits."""

    def __init__(self, canvas: Canvas, y: float) -> None:
        self.canvas = canvas
        self.y = y

    def space(self, amount: float) -> None:
        self.y -= amount


def _heading(cursor: _Cursor, text: str) -> None:
    canvas = cursor.canvas
    cursor.space(18)
    canvas.setFont(PLAIN_BOLD_FONT, 10.5)
    canvas.setFillColorRGB(*_INK)
    canvas.drawString(_MARGIN, cursor.y, text)
    cursor.space(6)
    canvas.setStrokeColorRGB(*_RULE)
    canvas.setLineWidth(0.6)
    canvas.line(_MARGIN, cursor.y, _PAGE_W - _MARGIN, cursor.y)
    cursor.space(13)


def _row(cursor: _Cursor, label: str, value: str, *, mono_wrap: bool = False) -> None:
    lines = _split_hex(value) if mono_wrap else wrap_text(value or "—", PLAIN_FONT, _BODY, _VALUE_W)
    canvas = cursor.canvas
    canvas.setFont(PLAIN_FONT, _BODY)
    canvas.setFillColorRGB(*_MUTED)
    canvas.drawString(_MARGIN, cursor.y, truncate_to_width(label, PLAIN_FONT, _BODY, _LABEL_W - 8))
    canvas.setFillColorRGB(*_INK)
    for index, line in enumerate(lines):
        canvas.drawString(_MARGIN + _LABEL_W, cursor.y - index * _LEADING, line)
    cursor.space(len(lines) * _LEADING)


def _paragraph(cursor: _Cursor, text: str, *, size: float = 9.0, colour: tuple[float, float, float] = _MUTED) -> None:
    canvas = cursor.canvas
    canvas.setFont(PLAIN_FONT, size)
    canvas.setFillColorRGB(*colour)
    for line in wrap_text(text, PLAIN_FONT, size, _CONTENT_W):
        canvas.drawString(_MARGIN, cursor.y, line)
        cursor.space(size + 3.5)


def build_archive_cover(summary: ArchiveCoverSummary) -> bytes:
    """Implements ``DocumentService.build_archive_cover``: exactly one page, before the scan."""
    ensure_fonts_registered()
    buffer = io.BytesIO()
    canvas = new_canvas(buffer, _PAGE_W, _PAGE_H)

    canvas.setFont(PLAIN_BOLD_FONT, 16)
    canvas.setFillColorRGB(*_INK)
    canvas.drawString(_MARGIN, _PAGE_H - _MARGIN - 12, TITLE)
    canvas.setFont(PLAIN_FONT, 8.5)
    canvas.setFillColorRGB(*_MUTED)
    canvas.drawString(
        _MARGIN,
        _PAGE_H - _MARGIN - 26,
        "The pages that follow are a scan of a document that was signed in ink.",
    )

    cursor = _Cursor(canvas, _PAGE_H - _MARGIN - 44)

    attestation = summary.attestation
    _heading(cursor, "The document")
    _row(cursor, "Document type", summary.document_type)
    _row(cursor, "Signed on paper", summary.paper_signed_on.isoformat())
    _row(cursor, "Pages scanned", str(summary.scan_page_count))
    _row(cursor, "Envelope id", str(summary.envelope_id))

    _heading(cursor, "Signed on paper by")
    for signer in attestation.paper_signers:
        _row(cursor, signer.capacity, signer.display_name)

    _heading(cursor, "Attested by")
    _row(cursor, "Staff member", attestation.staff_display_name)
    _row(cursor, "Staff id", attestation.staff_user_id)
    _row(cursor, "Filed at", _when(summary.attested_at))
    _row(cursor, "Statement", _STATEMENT_LABELS.get(attestation.statement, attestation.statement))
    _row(
        cursor,
        "The original was",
        _DISPOSITION_LABELS.get(attestation.original_disposition, attestation.original_disposition),
    )

    _heading(cursor, "The scan (SHA-256)")
    _row(cursor, "Scanned pages", summary.scan_sha256.hex(), mono_wrap=True)

    _heading(cursor, "What the seal on this document proves")
    _paragraph(cursor, WHAT_THE_SEAL_PROVES, colour=_INK)

    canvas.setFont(PLAIN_FONT, 7.5)
    canvas.setFillColorRGB(*_MUTED)
    canvas.drawString(_MARGIN, _MARGIN - 18, TITLE)
    canvas.drawRightString(_PAGE_W - _MARGIN, _MARGIN - 18, "Page 1")

    canvas.showPage()
    canvas.save()
    return buffer.getvalue()
