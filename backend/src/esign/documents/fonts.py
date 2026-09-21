"""Fonts for stamping and the certificate of completion.

Three faces, all vendored under ``fonts/`` with their licences, all embedded (subset) into every
PDF this module writes:

``ESignSans`` / ``ESignSans-Bold``  PT Sans -- captions, prefill, click-to-sign, the certificate
``ESignScript``                    Great Vibes -- typed signatures

Both families are SIL Open Font License 1.1. Nothing here falls back to a base-14 font: a
non-embedded font renders differently on every machine, and a signature page that renders
differently is worse evidence. If a face will not load, registration raises at import time rather
than silently producing a document whose appearance depends on the reader.

Registration is process-wide (reportlab keeps a global font registry) and done once, lazily, under
a lock, because several threads may build documents at the same time.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Final

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

__all__ = [
    "FONT_DIR",
    "PLAIN_BOLD_FONT",
    "PLAIN_FONT",
    "SCRIPT_FONT",
    "baseline_for_centre",
    "ensure_fonts_registered",
    "face_extents",
    "fit_font_size",
    "line_height",
    "shrink_to_width",
    "text_width",
    "truncate_to_width",
    "wrap_text",
]

FONT_DIR: Final[Path] = Path(__file__).resolve().parent / "fonts"

PLAIN_FONT: Final[str] = "ESignSans"
PLAIN_BOLD_FONT: Final[str] = "ESignSans-Bold"
SCRIPT_FONT: Final[str] = "ESignScript"

#: face name -> file under :data:`FONT_DIR`.
_FACES: Final[dict[str, str]] = {
    PLAIN_FONT: "PTSans-Regular.ttf",
    PLAIN_BOLD_FONT: "PTSans-Bold.ttf",
    SCRIPT_FONT: "GreatVibes-Regular.ttf",
}

#: Licence files that must ship next to the faces. Checked so a repackaging that drops them fails
#: here rather than in a licence audit.
_LICENCES: Final[tuple[str, ...]] = ("PTSans-OFL.txt", "GreatVibes-OFL.txt")

_lock = threading.Lock()
#: A dict rather than a bare bool so the fast path and the locked re-check stay independent.
_state: dict[str, bool] = {"registered": False}


def ensure_fonts_registered() -> None:
    """Register the vendored faces with reportlab. Idempotent and thread-safe.

    One uncontended lock acquisition per call rather than a double-checked fast path: it costs
    nanoseconds and leaves no window in which a second thread sees a half-built registry.
    """
    with _lock:
        if _state["registered"]:
            return
        for licence in _LICENCES:
            if not (FONT_DIR / licence).is_file():
                raise RuntimeError(f"vendored font licence missing: {licence}")
        for name, filename in _FACES.items():
            path = FONT_DIR / filename
            if not path.is_file():
                raise RuntimeError(f"vendored font missing: {filename}")
            # Re-registering the same name is harmless, but skip the file read when possible.
            try:
                pdfmetrics.getFont(name)
            except KeyError:
                pdfmetrics.registerFont(TTFont(name, str(path)))
        pdfmetrics.registerFontFamily(PLAIN_FONT, normal=PLAIN_FONT, bold=PLAIN_BOLD_FONT)
        _state["registered"] = True


# --------------------------------------------------------------------------- measurement helpers


def text_width(text: str, font: str, size: float) -> float:
    ensure_fonts_registered()
    return float(pdfmetrics.stringWidth(text, font, size))


def face_extents(font: str) -> tuple[float, float]:
    """``(ascent, descent)`` as fractions of an em; descent is negative.

    A script face is far taller than its point size -- Great Vibes runs well past one em from
    descender to ascender -- so "does this text fit in the box" cannot be answered by comparing the
    point size to the box height. Everything that fits text uses these numbers instead.
    """
    ensure_fonts_registered()
    ascent, descent = pdfmetrics.getAscentDescent(font, 1000.0)
    return ascent / 1000.0, descent / 1000.0


def line_height(font: str, size: float) -> float:
    """Ink height of one line: the full ascender-to-descender extent at ``size``."""
    ascent, descent = face_extents(font)
    return (ascent - descent) * size


def baseline_for_centre(font: str, size: float, bottom: float, height: float) -> float:
    """The baseline that centres one line's ink inside ``(bottom, bottom + height)``.

    Guarantees both edges: the descender lands no lower than ``bottom`` and the ascender no higher
    than ``bottom + height``, provided :func:`line_height` fits.
    """
    _ascent, descent = face_extents(font)
    return bottom + (height - line_height(font, size)) / 2 - descent * size


def shrink_to_width(text: str, font: str, size: float, max_width: float, *, min_size: float = 4.0) -> float:
    """The largest size <= ``size`` at which ``text`` fits in ``max_width``, floored at ``min_size``."""
    if not text or max_width <= 0:
        return size
    width = text_width(text, font, size)
    if width <= max_width:
        return size
    scaled = size * max_width / width
    return max(min_size, scaled)


def truncate_to_width(text: str, font: str, size: float, max_width: float) -> str:
    """Cut ``text`` (with an ellipsis) so it fits. Last resort after shrinking hits ``min_size``."""
    if text_width(text, font, size) <= max_width:
        return text
    ellipsis = "…"
    if text_width(ellipsis, font, size) > max_width:
        return ""
    low, high = 0, len(text)
    while low < high:
        mid = (low + high + 1) // 2
        if text_width(text[:mid] + ellipsis, font, size) <= max_width:
            low = mid
        else:
            high = mid - 1
    return text[:low] + ellipsis


def wrap_text(text: str, font: str, size: float, max_width: float) -> list[str]:
    """Greedy word wrap. Words longer than the line are split rather than allowed to overflow."""
    lines: list[str] = []
    for paragraph in text.split("\n"):
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current = ""
        for word in words:
            candidate = f"{current} {word}" if current else word
            if text_width(candidate, font, size) <= max_width:
                current = candidate
                continue
            if current:
                lines.append(current)
            # A single word wider than the line: hard-split it.
            while text_width(word, font, size) > max_width and len(word) > 1:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], font, size) > max_width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines


def fit_font_size(
    text: str,
    font: str,
    size: float,
    max_width: float,
    max_height: float,
    *,
    multiline: bool,
    leading_ratio: float = 1.12,
    min_size: float = 4.0,
) -> tuple[float, list[str]]:
    """Largest size <= ``size`` whose wrapped lines fit inside ``max_width`` x ``max_height``.

    "Fit" is measured in ink: the width of the actual glyphs and the face's ascender-to-descender
    extent, not the point size. Returns the size and the wrapped lines, and never returns lines
    that overflow -- when even ``min_size`` does not fit, surplus lines are dropped and the last is
    ellipsised, which is the "clipped, never overflowing" behaviour the brief asks for.
    """
    current = size
    while current >= min_size:
        lines = wrap_text(text, font, current, max_width) if multiline else [text]
        if _fits(lines, font, current, max_width, max_height, leading_ratio):
            return current, lines
        current -= 0.25

    # Nothing fits at the floor: clip.
    lines = wrap_text(text, font, min_size, max_width) if multiline else [text]
    max_lines = _max_lines(font, min_size, max_height, leading_ratio)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
    lines = [truncate_to_width(line, font, min_size, max_width) for line in lines]
    return min_size, lines


def _fits(lines: list[str], font: str, size: float, max_width: float, max_height: float, leading_ratio: float) -> bool:
    if any(text_width(line, font, size) > max_width for line in lines):
        return False
    return _block_height(font, size, len(lines), leading_ratio) <= max_height


def _block_height(font: str, size: float, count: int, leading_ratio: float) -> float:
    ink = line_height(font, size)
    return ink + max(0, count - 1) * ink * leading_ratio


def _max_lines(font: str, size: float, max_height: float, leading_ratio: float) -> int:
    ink = line_height(font, size)
    if ink <= 0 or max_height < ink:
        return 1
    return max(1, 1 + int((max_height - ink) // (ink * leading_ratio)))
