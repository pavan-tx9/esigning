"""Drawing: prefill values, signer marks and the caption that makes a mark evidence.

Everything here draws in *displayed* page coordinates and is merged through
:func:`esign.documents.pdfutil.draw_overlay`, so rotation and a non-zero box origin are handled in
one place rather than at every call site.

Two rules that are load-bearing rather than cosmetic:

* **Nothing overflows its rectangle.** Text is shrunk, then wrapped, then clipped. A field that
  spills over the sentence next to it changes what the document appears to say.
* **The caption is not optional.** Every signature and set of initials carries who signed, in what
  capacity and on whose behalf, when (UTC), and the signer id. The time comes from the
  ``SignerStamp`` the envelope service built from ``Clock``; a ``date_signed`` field is filled from
  the same value. Neither is ever taken from a capture, so a client cannot backdate a signature.
"""

from __future__ import annotations

import io
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC
from typing import Final

from pypdf import PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen.canvas import Canvas

from esign.config import Settings
from esign.contracts import (
    Capture,
    FieldDef,
    PrefillFieldDef,
    Rect,
    SignerStamp,
    ValidationFailed,
)
from esign.documents.fonts import (
    PLAIN_FONT,
    SCRIPT_FONT,
    baseline_for_centre,
    ensure_fonts_registered,
    fit_font_size,
    line_height,
    shrink_to_width,
    truncate_to_width,
)
from esign.documents.geometry import PageGeometry
from esign.documents.pdfutil import draw_overlay, geometries, sanitize_document, to_bytes, writer_from_bytes

__all__ = ["MAX_TEXT_VALUE_CHARS", "MAX_TYPED_SIGNATURE_CHARS", "apply_signer_marks", "prepare"]

MAX_TYPED_SIGNATURE_CHARS: Final[int] = 80
MAX_TEXT_VALUE_CHARS: Final[int] = 500
MAX_PREFILL_CHARS: Final[int] = 2000

_CAPTION_SIZE: Final[float] = 6.0
_CAPTION_LEADING: Final[float] = 1.12
_CAPTION_GAP: Final[float] = 1.5
_CAPTION_LINES: Final[int] = 3
#: The caption may shrink this far to keep the signer id whole. Narrower rects than
#: ``MIN_MARK_RECT_WIDTH`` are refused at template-validation time so it never has to go lower.
_CAPTION_MIN_SIZE: Final[float] = 3.5
#: The mark itself never gets less than this, however cramped the rect.
_MIN_MARK_HEIGHT: Final[float] = 5.0

_INK = (0.06, 0.09, 0.16)
_CAPTION_INK = (0.35, 0.38, 0.45)

#: Field types that are a person's mark and therefore get a caption.
_MARK_TYPES: Final[frozenset[str]] = frozenset({"signature", "initials"})


@dataclass(frozen=True)
class _Band:
    """Where the mark goes and where its caption goes, both guaranteed on-page."""

    mark: Rect
    caption: Rect


def _caption_height(size: float = _CAPTION_SIZE) -> float:
    """Ink height of the caption block at ``size``, measured from the face rather than guessed."""
    ink = line_height(PLAIN_FONT, size)
    return ink + (_CAPTION_LINES - 1) * ink * _CAPTION_LEADING


def _caption_size_for(height: float) -> float:
    """The largest caption size whose three lines fit in ``height``, floored at the minimum."""
    full = _caption_height()
    if height >= full:
        return _CAPTION_SIZE
    ratio = height / full if full > 0 else 1.0
    return max(_CAPTION_MIN_SIZE, _CAPTION_SIZE * ratio)


def _split(rect: Rect) -> _Band:
    """Put the caption under the rect when there is room, otherwise inside its bottom.

    Either way both bands stay on the page and never overlap, so a field near the bottom edge
    still gets its caption instead of quietly losing it.
    """
    caption_h = _caption_height()
    band = caption_h + _CAPTION_GAP
    if rect.y >= band:
        return _Band(
            mark=rect,
            caption=Rect(x=rect.x, y=rect.y - band, w=rect.w, h=caption_h),
        )

    # No room below: both bands go inside the rect, and neither may leave it.
    # ``validate_definitions`` keeps signature fields tall enough for this to be comfortable, but an
    # older template version could be smaller, so the split is clamped here rather than assumed
    # upstream. The caption shrinks before the mark does: an illegible signature is still a
    # signature, a missing caption is missing evidence.
    if rect.h - band >= _MIN_MARK_HEIGHT:
        return _Band(
            mark=Rect(x=rect.x, y=rect.y + band, w=rect.w, h=rect.h - band),
            caption=Rect(x=rect.x, y=rect.y, w=rect.w, h=caption_h),
        )
    tight = _caption_height(_CAPTION_MIN_SIZE) + _CAPTION_GAP
    caption_band = min(tight, max(1.0, rect.h - _MIN_MARK_HEIGHT))
    return _Band(
        mark=Rect(x=rect.x, y=rect.y + caption_band, w=rect.w, h=max(1.0, rect.h - caption_band)),
        caption=Rect(x=rect.x, y=rect.y, w=rect.w, h=max(1.0, caption_band - _CAPTION_GAP)),
    )


def _clip(canvas: Canvas, rect: Rect) -> None:
    path = canvas.beginPath()
    path.rect(rect.x, rect.y, rect.w, rect.h)
    canvas.clipPath(path, stroke=0, fill=0)


def _draw_text_block(
    canvas: Canvas,
    rect: Rect,
    text: str,
    *,
    font: str,
    size: float,
    multiline: bool,
    colour: tuple[float, float, float] = _INK,
    leading_ratio: float = 1.12,
) -> None:
    """Draw ``text`` so that it cannot leave ``rect``: shrink, wrap, then clip.

    Placement is by ink, not by point size: the baseline is derived from the face's ascent and
    descent, so a script face with a deep descender still sits inside the rectangle.
    """
    ensure_fonts_registered()
    if not text:
        return
    fitted, lines = fit_font_size(text, font, size, rect.w, rect.h, multiline=multiline, leading_ratio=leading_ratio)
    ink = line_height(font, fitted)
    leading = ink * leading_ratio
    canvas.saveState()
    _clip(canvas, rect)
    canvas.setFillColorRGB(*colour)
    canvas.setFont(font, fitted)
    if len(lines) == 1:
        canvas.drawString(rect.x, baseline_for_centre(font, fitted, rect.y, rect.h), lines[0])
    else:
        block = ink + (len(lines) - 1) * leading
        first = baseline_for_centre(font, fitted, rect.y + rect.h - block, ink)
        for index, line in enumerate(lines):
            canvas.drawString(rect.x, first - index * leading, line)
    canvas.restoreState()


def _caption_lines(stamp: SignerStamp) -> tuple[str, str, str]:
    """Who, when, and which signer -- on three lines so none of them has to be abbreviated.

    The signer id in particular is the link between this mark and the audit trail, so it gets a
    line of its own: in a narrow field the name is what gets shortened, never the evidence.
    """
    if stamp.signed_at.tzinfo is None:
        raise ValidationFailed("signature time is not timezone-aware", code="stamp_time_naive")
    when = stamp.signed_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    who = f"{stamp.display_name} ({stamp.capacity})"
    if stamp.on_behalf_of_label:
        who = f"{who} on behalf of {stamp.on_behalf_of_label}"
    return who, f"Signed {when}", f"Signer {stamp.signer_id}"


def _draw_caption(canvas: Canvas, rect: Rect, stamp: SignerStamp) -> None:
    ensure_fonts_registered()
    lines = _caption_lines(stamp)
    canvas.saveState()
    _clip(canvas, rect)
    canvas.setFillColorRGB(*_CAPTION_INK)
    size = _caption_size_for(rect.h)
    ink = line_height(PLAIN_FONT, size)
    leading = ink * _CAPTION_LEADING
    top = rect.y + rect.h - ink
    for index, line in enumerate(lines):
        line_size = shrink_to_width(line, PLAIN_FONT, size, rect.w, min_size=_CAPTION_MIN_SIZE)
        # Only the name line may be abbreviated. The time and the signer id are the evidence.
        text = truncate_to_width(line, PLAIN_FONT, line_size, rect.w) if index == 0 else line
        canvas.setFont(PLAIN_FONT, line_size)
        canvas.drawString(rect.x, baseline_for_centre(PLAIN_FONT, line_size, top - index * leading, ink), text)
    canvas.restoreState()


def _draw_image(canvas: Canvas, rect: Rect, png: bytes) -> None:
    """Scale to fit, preserving aspect ratio, centred in the rect."""
    reader = ImageReader(io.BytesIO(png))
    source_w, source_h = reader.getSize()
    if source_w <= 0 or source_h <= 0:  # pragma: no cover - sanitisation rejects these first
        raise ValidationFailed("signature image has no extent", code="signature_image_undecodable")
    scale = min(rect.w / source_w, rect.h / source_h)
    width, height = source_w * scale, source_h * scale
    x = rect.x + (rect.w - width) / 2
    y = rect.y + (rect.h - height) / 2
    canvas.saveState()
    _clip(canvas, rect)
    canvas.drawImage(reader, x, y, width=width, height=height, mask="auto", preserveAspectRatio=True, anchor="c")
    canvas.restoreState()


def _draw_checkbox(canvas: Canvas, rect: Rect) -> None:
    """A tick drawn as strokes, so it needs no glyph and renders identically everywhere."""
    side = min(rect.w, rect.h)
    x = rect.x + (rect.w - side) / 2
    y = rect.y + (rect.h - side) / 2
    canvas.saveState()
    _clip(canvas, rect)
    canvas.setStrokeColorRGB(*_INK)
    canvas.setLineWidth(max(0.7, side * 0.12))
    canvas.setLineCap(1)
    canvas.lines(
        [
            (x + side * 0.18, y + side * 0.52, x + side * 0.42, y + side * 0.24),
            (x + side * 0.42, y + side * 0.24, x + side * 0.84, y + side * 0.78),
        ]
    )
    canvas.restoreState()


def _initials(name: str) -> str:
    parts = [part for part in name.replace("-", " ").split() if part]
    return "".join(part[0].upper() for part in parts[:4]) or name[:2].upper()


# --------------------------------------------------------------------------- prepare


def prepare(
    template_pdf: bytes,
    prefill_fields: list[PrefillFieldDef],
    prefill: dict[str, str],
    settings: Settings,
) -> bytes:
    """Implements ``DocumentService.prepare``.

    ``prefill`` is chart data. It is drawn into the PDF and then dropped: nothing here stores it,
    logs it, or puts it in an error message. Unknown keys are refused by count alone for exactly
    that reason -- a key a host invented could itself be identifying.
    """
    if len(template_pdf) > settings.max_template_bytes:
        raise ValidationFailed("template exceeds the maximum size", code="template_too_large")

    writer = writer_from_bytes(template_pdf)
    pages = geometries(writer.pages)

    declared = {definition.key for definition in prefill_fields}
    unknown = [key for key in prefill if key not in declared]
    missing = sorted(
        definition.key
        for definition in prefill_fields
        if definition.required and not str(prefill.get(definition.key, "")).strip()
    )
    problems: list[str] = []
    if unknown:
        problems.append(f"prefill contains {len(unknown)} key(s) the template does not declare")
    if missing:
        problems.append(f"prefill is missing required key(s): {', '.join(missing)}")
    oversized = sorted(
        definition.key for definition in prefill_fields if len(str(prefill.get(definition.key, ""))) > MAX_PREFILL_CHARS
    )
    if oversized:
        problems.append(f"prefill value(s) too long: {', '.join(oversized)}")
    if problems:
        raise ValidationFailed("; ".join(problems), code="prefill_invalid")

    by_page: dict[int, list[PrefillFieldDef]] = defaultdict(list)
    for definition in prefill_fields:
        if definition.page < 1 or definition.page > len(pages):
            raise ValidationFailed("prefill field references a page that does not exist", code="prefill_invalid")
        value = str(prefill.get(definition.key, ""))
        if value.strip():
            by_page[definition.page - 1].append(definition)

    for page_index, definitions in sorted(by_page.items()):
        geometry = pages[page_index]
        _draw_prefill_page(writer, geometry, definitions, prefill)

    sanitize_document(writer)
    return to_bytes(writer)


def _draw_prefill_page(
    writer: PdfWriter,
    geometry: PageGeometry,
    definitions: list[PrefillFieldDef],
    prefill: dict[str, str],
) -> None:
    def draw(canvas: Canvas) -> None:
        for definition in definitions:
            _draw_text_block(
                canvas,
                definition.rect,
                str(prefill[definition.key]).strip(),
                font=PLAIN_FONT,
                size=definition.font_size,
                multiline=definition.multiline,
            )

    draw_overlay(writer, geometry, draw)


# --------------------------------------------------------------------------- signer marks


def _validate_captures(fields: list[FieldDef], captures: list[Capture]) -> dict[str, Capture]:
    """Match captures to this signer's fields. Anything unexpected is a refusal, not a warning."""
    by_id = {field.id: field for field in fields}
    if len(by_id) != len(fields):
        raise ValidationFailed("duplicate field ids in this signer's field set", code="field_set_invalid")

    problems: list[str] = []
    matched: dict[str, Capture] = {}
    for capture in captures:
        field = by_id.get(capture.field_id)
        if field is None:
            # The field belongs to another signer, another template, or nothing at all. Do not say
            # which: the caller already knows its own field set.
            problems.append("a capture targets a field that is not this signer's")
            continue
        if capture.field_id in matched:
            problems.append(f"field {capture.field_id!r}: more than one capture")
            continue
        if field.type == "date_signed":
            problems.append(f"field {capture.field_id!r}: date_signed is filled by the server, not by a capture")
            continue
        matched[capture.field_id] = capture

    for field in fields:
        if field.type == "date_signed":
            continue
        supplied = matched.get(field.id)
        if supplied is None:
            if field.required:
                problems.append(f"field {field.id!r}: required capture is missing")
            continue
        problems.extend(_capture_problems(field, supplied))

    if problems:
        raise ValidationFailed("; ".join(sorted(set(problems))), code="captures_invalid")
    return matched


def _capture_problems(field: FieldDef, capture: Capture) -> list[str]:
    what = f"field {field.id!r}"
    # Read through ``str`` on purpose: the annotation says this is one of three literals, but the
    # value arrives from a client and an unexpected one must be refused, not fall through a branch.
    kind = str(capture.kind)
    if field.type in _MARK_TYPES:
        if kind == "drawn":
            if not capture.image_png:
                return [f"{what}: a drawn capture needs a sanitized PNG"]
        elif kind == "typed":
            text = (capture.typed_text or "").strip()
            if not text:
                return [f"{what}: a typed capture needs text"]
            if len(text) > MAX_TYPED_SIGNATURE_CHARS:
                return [f"{what}: typed signature is longer than {MAX_TYPED_SIGNATURE_CHARS} characters"]
        elif kind == "click":
            if capture.image_png or capture.typed_text:
                return [f"{what}: a click capture carries no image or text"]
        else:
            return [f"{what}: unknown capture kind"]
        return []

    if field.type == "checkbox":
        if capture.checked is None:
            return [f"{what}: a checkbox capture needs `checked`"]
        return []

    if field.type == "text":
        value = capture.text_value
        if value is None:
            return [f"{what}: a text capture needs `text_value`"]
        if len(value) > MAX_TEXT_VALUE_CHARS:
            return [f"{what}: text is longer than {MAX_TEXT_VALUE_CHARS} characters"]
        if field.required and not value.strip():
            return [f"{what}: required text is empty"]
        return []

    return [f"{what}: unsupported field type"]


def apply_signer_marks(
    pdf: bytes,
    fields: list[FieldDef],
    captures: list[Capture],
    stamp: SignerStamp,
) -> bytes:
    """Implements ``DocumentService.apply_signer_marks``."""
    ensure_fonts_registered()
    matched = _validate_captures(fields, captures)
    _caption_lines(stamp)  # fail before touching the document if the stamp time is unusable

    writer = writer_from_bytes(pdf)
    pages = geometries(writer.pages)

    by_page: dict[int, list[FieldDef]] = defaultdict(list)
    for field in fields:
        if field.page < 1 or field.page > len(pages):
            raise ValidationFailed(
                f"field {field.id!r}: page {field.page} does not exist in this revision", code="field_page_missing"
            )
        if field.type != "date_signed" and field.id not in matched:
            continue  # optional field with no capture
        by_page[field.page - 1].append(field)

    for page_index, page_fields in sorted(by_page.items()):
        _draw_marks_page(writer, pages[page_index], page_fields, matched, stamp)

    sanitize_document(writer)
    return to_bytes(writer)


def _draw_marks_page(
    writer: PdfWriter,
    geometry: PageGeometry,
    fields: list[FieldDef],
    matched: dict[str, Capture],
    stamp: SignerStamp,
) -> None:
    def draw(canvas: Canvas) -> None:
        for field in fields:
            _draw_field(canvas, field, matched.get(field.id), stamp)

    draw_overlay(writer, geometry, draw)


def _draw_field(canvas: Canvas, field: FieldDef, capture: Capture | None, stamp: SignerStamp) -> None:
    if field.type == "date_signed":
        when = stamp.signed_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        _draw_text_block(canvas, field.rect, when, font=PLAIN_FONT, size=min(11.0, field.rect.h * 0.7), multiline=False)
        return

    if capture is None:
        return

    if field.type == "checkbox":
        if capture.checked:
            _draw_checkbox(canvas, field.rect)
        return

    if field.type == "text":
        _draw_text_block(
            canvas,
            field.rect,
            (capture.text_value or "").strip(),
            font=PLAIN_FONT,
            size=min(11.0, field.rect.h * 0.7),
            multiline=field.rect.h > 24,
        )
        return

    band = _split(field.rect)
    if capture.kind == "drawn" and capture.image_png:
        _draw_image(canvas, band.mark, capture.image_png)
    elif capture.kind == "typed":
        text = (capture.typed_text or "").strip()
        _draw_text_block(canvas, band.mark, text, font=SCRIPT_FONT, size=band.mark.h * 0.8, multiline=False)
    else:  # click-to-sign: the signer's name in the plain face, never the script one
        text = _initials(stamp.display_name) if field.type == "initials" else stamp.display_name
        _draw_text_block(canvas, band.mark, text, font=PLAIN_FONT, size=band.mark.h * 0.55, multiline=False)
    _draw_caption(canvas, band.caption, stamp)
