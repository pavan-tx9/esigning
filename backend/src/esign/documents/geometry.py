"""Page geometry: turning "displayed page coordinates" into PDF user space.

``Rect`` in ``contracts.py`` is defined in *displayed* coordinates: origin at the bottom-left of
the page as a reader shows it, after ``/Rotate`` has been applied, with the visible box (``/CropBox``
falling back to ``/MediaBox``) starting at (0, 0). That is the only coordinate system a template
author can reason about, and it is almost never the page's own user space.

This module owns the conversion. Everything drawn by this package is drawn on an overlay page whose
size is the *displayed* size, and merged onto the real page with :meth:`PageGeometry.ctm`, so no
drawing code anywhere else has to think about rotation or a box whose origin is not (0, 0).

Derivation of the matrices, so the next person can check them rather than trust them. Write the
visible box as ``(x0, y0, x1, y1)``, ``bw = x1 - x0``, ``bh = y1 - y0``, and a point in user space
as ``(x0 + u, y0 + v)``. ``/Rotate`` turns the page clockwise for display:

===========  ==========================  ========================================
``/Rotate``  displayed point ``(dx,dy)``  user-space point
===========  ==========================  ========================================
0            ``(u, v)``                  ``(x0 + dx, y0 + dy)``
90           ``(v, bw - u)``             ``(x1 - dy, y0 + dx)``
180          ``(bw - u, bh - v)``        ``(x1 - dx, y1 - dy)``
270          ``(bh - v, u)``             ``(x0 + dy, y1 - dx)``
===========  ==========================  ========================================

Read the right-hand column as ``[a b c d e f]`` with ``x = a*dx + c*dy + e`` and
``y = b*dx + d*dy + f`` and you have :meth:`PageGeometry.ctm`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pypdf.generic import ArrayObject, DictionaryObject, NumberObject

from esign.contracts import Rect

__all__ = ["Matrix", "PageGeometry", "page_geometry", "rect_fits"]

Matrix = tuple[float, float, float, float, float, float]

#: Nothing narrower or shorter than this is a usable field.
MIN_RECT_SIDE = 4.0


@dataclass(frozen=True)
class PageGeometry:
    """The visible box and rotation of one page, plus the displayed-space conversion."""

    index: int  # 0-based
    rotate: int  # normalised to 0, 90, 180, 270
    x0: float
    y0: float
    x1: float
    y1: float

    @property
    def box_width(self) -> float:
        return self.x1 - self.x0

    @property
    def box_height(self) -> float:
        return self.y1 - self.y0

    @property
    def displayed_width(self) -> float:
        return self.box_height if self.rotate in (90, 270) else self.box_width

    @property
    def displayed_height(self) -> float:
        return self.box_width if self.rotate in (90, 270) else self.box_height

    @property
    def displayed_size(self) -> tuple[float, float]:
        return self.displayed_width, self.displayed_height

    def ctm(self) -> Matrix:
        """Matrix mapping displayed coordinates onto this page's user space."""
        if self.rotate == 90:
            return (0.0, 1.0, -1.0, 0.0, self.x1, self.y0)
        if self.rotate == 180:
            return (-1.0, 0.0, 0.0, -1.0, self.x1, self.y1)
        if self.rotate == 270:
            return (0.0, -1.0, 1.0, 0.0, self.x0, self.y1)
        return (1.0, 0.0, 0.0, 1.0, self.x0, self.y0)

    def to_user(self, dx: float, dy: float) -> tuple[float, float]:
        a, b, c, d, e, f = self.ctm()
        return (a * dx + c * dy + e, b * dx + d * dy + f)

    def to_displayed(self, x: float, y: float) -> tuple[float, float]:
        """Inverse of :meth:`to_user`. The matrices are rigid, so the inverse is exact."""
        a, b, c, d, e, f = self.ctm()
        det = a * d - b * c
        if det == 0:  # pragma: no cover - the four matrices above all have |det| == 1
            raise ValueError("degenerate page matrix")
        px, py = x - e, y - f
        return ((d * px - c * py) / det, (-b * px + a * py) / det)

    def contains(self, rect: Rect) -> bool:
        """Is ``rect`` wholly inside the displayed page, with usable sides?"""
        if rect.w < MIN_RECT_SIDE or rect.h < MIN_RECT_SIDE:
            return False
        # A hair of tolerance: template authors write round numbers and page boxes are rarely round.
        tol = 1e-6
        return (
            rect.x >= -tol
            and rect.y >= -tol
            and rect.x + rect.w <= self.displayed_width + tol
            and rect.y + rect.h <= self.displayed_height + tol
        )


def rect_fits(geometry: PageGeometry, rect: Rect) -> bool:
    return geometry.contains(rect)


# --------------------------------------------------------------------------- reading a page


def _number(value: Any) -> float:
    resolved = value.get_object() if hasattr(value, "get_object") else value
    if isinstance(resolved, NumberObject | int | float):
        return float(resolved)
    raise ValueError("page box entry is not a number")


def _box(page: DictionaryObject, key: str) -> tuple[float, float, float, float] | None:
    raw = page.get_inherited(key) if hasattr(page, "get_inherited") else page.get(key)
    if raw is None:
        return None
    resolved = raw.get_object() if hasattr(raw, "get_object") else raw
    if not isinstance(resolved, ArrayObject | list) or len(resolved) != 4:
        raise ValueError(f"malformed {key}")
    values = [_number(item) for item in resolved]
    x0, x1 = sorted((values[0], values[2]))
    y0, y1 = sorted((values[1], values[3]))
    return (x0, y0, x1, y1)


def _intersect(
    a: tuple[float, float, float, float], b: tuple[float, float, float, float]
) -> tuple[float, float, float, float]:
    return (max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3]))


def page_geometry(page: Any, index: int) -> PageGeometry:
    """Read one page's visible box and rotation.

    ``/MediaBox`` and ``/Rotate`` are inheritable attributes, so they are looked up through the page
    tree rather than on the page dictionary alone -- a detail that is easy to miss and produces
    marks in the wrong place on exactly the documents a generator did not produce.
    """
    media = _box(page, "/MediaBox")
    if media is None:
        raise ValueError("page has no /MediaBox")
    crop = _box(page, "/CropBox")
    box = _intersect(media, crop) if crop is not None else media
    if box[2] - box[0] <= 0 or box[3] - box[1] <= 0:
        # A CropBox that does not overlap the MediaBox is malformed; fall back to what is visible.
        box = media
    if box[2] - box[0] <= 0 or box[3] - box[1] <= 0:
        raise ValueError("page has an empty visible box")

    raw_rotate = page.get_inherited("/Rotate") if hasattr(page, "get_inherited") else page.get("/Rotate")
    resolved = raw_rotate.get_object() if hasattr(raw_rotate, "get_object") else raw_rotate
    rotate = int(resolved) if isinstance(resolved, NumberObject | int | float) else 0
    if rotate % 90 != 0:
        raise ValueError("/Rotate is not a multiple of 90")
    rotate %= 360

    return PageGeometry(index=index, rotate=rotate, x0=box[0], y0=box[1], x1=box[2], y1=box[3])
