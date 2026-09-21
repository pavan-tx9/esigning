"""pypdf plumbing shared by preparation, stamping and finalisation.

Three jobs:

* read untrusted PDF bytes without letting a parse error escape as something other than
  :class:`~esign.contracts.ValidationFailed`;
* draw on a page in *displayed* coordinates (see :mod:`esign.documents.geometry`) by building a
  reportlab overlay the size of the displayed page and merging it with the page's matrix;
* strip everything interactive -- appearance-flattened widgets, then no ``/AcroForm``, no
  ``/Annots``, no JavaScript, no additional actions, no stale metadata -- so what is stored, hashed
  and eventually sealed is exactly what a reader draws, with nothing left that could redraw itself.

The output is deterministic: the same input bytes and the same drawing produce the same output
bytes, so a revision hash is a property of the evidence rather than of the moment it was built.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Iterable
from typing import Any, Final

from pypdf import PdfReader, PdfWriter
from pypdf.errors import PdfReadError, PyPdfError
from pypdf.generic import (
    ArrayObject,
    ContentStream,
    DictionaryObject,
    FloatObject,
    IndirectObject,
    NameObject,
    NumberObject,
    StreamObject,
    TextStringObject,
)
from reportlab.pdfgen.canvas import Canvas

from esign.contracts import ValidationFailed
from esign.documents.geometry import Matrix, PageGeometry, page_geometry

__all__ = [
    "PRODUCER",
    "Matrix",
    "compose",
    "draw_overlay",
    "geometries",
    "new_canvas",
    "open_reader",
    "sanitize_document",
    "to_bytes",
    "writer_from_bytes",
]

PRODUCER: Final[str] = "esign"

#: Annotation flag bits (PDF 12.5.3). Hidden and NoView annotations are not drawn, so flattening
#: them would *add* ink a reader never showed.
_ANNOT_HIDDEN = 1 << 1
_ANNOT_NOVIEW = 1 << 5

#: Catalog and page keys that can make a document do something when opened.
_ACTIVE_CATALOG_KEYS: Final[tuple[str, ...]] = (
    "/AcroForm",
    "/OpenAction",
    "/AA",
    "/Names",
    "/JavaScript",
    "/Metadata",
    "/Perms",
    "/Requirements",
    "/Collection",
    "/DSS",
    "/Outlines",  # outline items carry /A actions
    "/Threads",
    "/AF",  # associated files
)
_ACTIVE_PAGE_KEYS: Final[tuple[str, ...]] = ("/AA", "/Annots", "/PieceInfo", "/AF")


# --------------------------------------------------------------------------- reading


def open_reader(data: bytes) -> PdfReader:
    """Parse ``data``. Any failure is a client-visible validation failure, never a 500."""
    if not data:
        raise ValidationFailed("empty pdf", code="pdf_unreadable")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
    except (PdfReadError, PyPdfError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise ValidationFailed("pdf could not be parsed", code="pdf_unreadable") from exc
    # Encryption is checked before the page tree is touched: reading pages out of an encrypted
    # document raises, and "encrypted" is a far more useful answer for the host than "unreadable".
    if reader.is_encrypted:
        raise ValidationFailed("pdf is encrypted", code="pdf_encrypted")
    try:
        # Touch the page tree: pypdf is lazy, and a broken tree should surface here.
        _ = len(reader.pages)
    except (PdfReadError, PyPdfError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise ValidationFailed("pdf could not be parsed", code="pdf_unreadable") from exc
    return reader


def writer_from_bytes(data: bytes) -> PdfWriter:
    """A writer holding a clone of every page in ``data``.

    ``open_reader`` has already refused anything encrypted or unparseable, so what fails here is a
    page tree that parses but cannot be copied.
    """
    reader = open_reader(data)
    writer = PdfWriter()
    try:
        for page in reader.pages:
            writer.add_page(page)
    except (PdfReadError, PyPdfError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise ValidationFailed("pdf could not be copied", code="pdf_unreadable") from exc
    if not writer.pages:
        raise ValidationFailed("pdf has no pages", code="pdf_no_pages")
    return writer


def geometries(pages: Iterable[Any]) -> list[PageGeometry]:
    result: list[PageGeometry] = []
    for index, page in enumerate(pages):
        try:
            result.append(page_geometry(page, index))
        except ValueError as exc:
            raise ValidationFailed(f"page {index + 1} has unusable geometry", code="pdf_bad_geometry") from exc
    return result


# --------------------------------------------------------------------------- matrices


def compose(first: Matrix, second: Matrix) -> Matrix:
    """``first`` then ``second``, in PDF's row-vector convention."""
    a1, b1, c1, d1, e1, f1 = first
    a2, b2, c2, d2, e2, f2 = second
    return (
        a1 * a2 + b1 * c2,
        a1 * b2 + b1 * d2,
        c1 * a2 + d1 * c2,
        c1 * b2 + d1 * d2,
        e1 * a2 + f1 * c2 + e2,
        e1 * b2 + f1 * d2 + f2,
    )


# --------------------------------------------------------------------------- drawing


def new_canvas(buffer: io.BytesIO, width: float, height: float) -> Canvas:
    """A reportlab canvas that writes byte-identical output for identical drawing.

    ``invariant=1`` pins the document id and the creation date, which is what makes a prepared
    revision's hash reproducible.
    """
    canvas = Canvas(buffer, pagesize=(width, height), invariant=1, pageCompression=1)
    canvas.setCreator(PRODUCER)
    canvas.setProducer(PRODUCER)
    canvas.setTitle("")
    canvas.setAuthor("")
    canvas.setSubject("")
    return canvas


def draw_overlay(writer: PdfWriter, geometry: PageGeometry, draw: Callable[[Canvas], None]) -> None:
    """Draw on one page in displayed coordinates.

    The overlay page is the displayed size with its origin at (0, 0), so ``draw`` works in exactly
    the coordinate system ``Rect`` is written in. The merge matrix puts it back where the reader
    sees it, whatever ``/Rotate`` and ``/CropBox`` say.
    """
    width, height = geometry.displayed_size
    buffer = io.BytesIO()
    canvas = new_canvas(buffer, width, height)
    draw(canvas)
    canvas.showPage()
    canvas.save()

    overlay = PdfReader(io.BytesIO(buffer.getvalue())).pages[0]
    writer.pages[geometry.index].merge_transformed_page(overlay, geometry.ctm())


# --------------------------------------------------------------------------- flatten and strip


def _as_float(value: Any) -> float | None:
    resolved = value.get_object() if isinstance(value, IndirectObject) else value
    if isinstance(resolved, NumberObject | int | float):
        return float(resolved)
    return None


def _as_floats(raw: Any, count: int) -> list[float] | None:
    resolved = raw.get_object() if isinstance(raw, IndirectObject) else raw
    if not isinstance(resolved, ArrayObject | list) or len(resolved) != count:
        return None
    values = [_as_float(item) for item in resolved]
    if any(value is None for value in values):
        return None
    return [value for value in values if value is not None]


def _appearance_stream(annot: DictionaryObject) -> StreamObject | None:
    appearance = annot.get("/AP")
    appearance = appearance.get_object() if isinstance(appearance, IndirectObject) else appearance
    if not isinstance(appearance, DictionaryObject):
        return None
    normal = appearance.get("/N")
    normal = normal.get_object() if isinstance(normal, IndirectObject) else normal
    if isinstance(normal, StreamObject):
        return normal
    if isinstance(normal, DictionaryObject):
        state = annot.get("/AS")
        state = state.get_object() if isinstance(state, IndirectObject) else state
        chosen = normal.get(str(state)) if state is not None else None
        if chosen is None and len(normal) == 1:
            chosen = next(iter(normal.values()))
        chosen = chosen.get_object() if isinstance(chosen, IndirectObject) else chosen
        if isinstance(chosen, StreamObject):
            return chosen
    return None


def _rect_of(annot: DictionaryObject) -> tuple[float, float, float, float] | None:
    values = _as_floats(annot.get("/Rect"), 4)
    if values is None:
        return None
    x0, x1 = sorted((values[0], values[2]))
    y0, y1 = sorted((values[1], values[3]))
    return (x0, y0, x1, y1)


def _form_matrix(stream: StreamObject) -> Matrix:
    values = _as_floats(stream.get("/Matrix"), 6)
    if values is None:
        return (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
    a, b, c, d, e, f = values
    return (a, b, c, d, e, f)


def _placement(
    stream: StreamObject, rect: tuple[float, float, float, float]
) -> tuple[Matrix, tuple[float, ...]] | None:
    """The matrix that maps a form XObject onto an annotation rectangle (PDF 12.5.5)."""
    if rect[2] - rect[0] <= 0 or rect[3] - rect[1] <= 0:
        return None
    bbox = _as_floats(stream.get("/BBox"), 4)
    if bbox is None:
        return None

    matrix = _form_matrix(stream)
    a, b, c, d, e, f = matrix
    corners = [(bbox[0], bbox[1]), (bbox[2], bbox[1]), (bbox[2], bbox[3]), (bbox[0], bbox[3])]
    mapped = [(a * x + c * y + e, b * x + d * y + f) for x, y in corners]
    tx0 = min(p[0] for p in mapped)
    tx1 = max(p[0] for p in mapped)
    ty0 = min(p[1] for p in mapped)
    ty1 = max(p[1] for p in mapped)
    if tx1 - tx0 <= 0 or ty1 - ty0 <= 0:
        return None

    sx = (rect[2] - rect[0]) / (tx1 - tx0)
    sy = (rect[3] - rect[1]) / (ty1 - ty0)
    fit: Matrix = (sx, 0.0, 0.0, sy, rect[0] - tx0 * sx, rect[1] - ty0 * sy)
    return compose(matrix, fit), (bbox[0], bbox[1], bbox[2] - bbox[0], bbox[3] - bbox[1])


def _clipped_form_page(stream: StreamObject, clip: tuple[float, ...]) -> Any:
    """Wrap an appearance stream as a merge-able page, clipped to its own ``/BBox``."""
    # pypdf exposes PageObject only from a private module; imported here rather than at module
    # scope so the dependency on it is visible at the one place that needs it.
    from pypdf._page import PageObject

    content = ContentStream(stream, None)
    content.operations.insert(
        0,
        (
            [FloatObject(clip[0]), FloatObject(clip[1]), FloatObject(clip[2]), FloatObject(clip[3])],
            b"re",
        ),
    )
    content.operations.insert(1, ([], b"W"))
    content.operations.insert(2, ([], b"n"))

    page = PageObject.create_blank_page(width=1, height=1)
    page[NameObject("/Contents")] = content
    resources = stream.get("/Resources")
    resources = resources.get_object() if isinstance(resources, IndirectObject) else resources
    page[NameObject("/Resources")] = resources if isinstance(resources, DictionaryObject) else DictionaryObject()
    return page


def _flatten_page_annotations(page: Any) -> None:
    """Burn every visible annotation appearance into the page content, then drop the annotations.

    Fails closed. The annotations are removed either way, so an appearance this code cannot render
    would be ink the signer saw and the stored document does not have -- a document that says less
    than the one that was presented. Rather than lose it quietly, the whole operation is refused
    and the host is told to supply a template without it.

    ``/Link`` and ``/Popup`` are the exception: they carry no ink of their own, so dropping them
    changes nothing a reader sees. Annotations flagged Hidden or NoView are likewise not drawn by
    any reader, so flattening them would *add* ink that was never displayed.
    """
    annots = page.get("/Annots")
    annots = annots.get_object() if isinstance(annots, IndirectObject) else annots
    if not isinstance(annots, ArrayObject | list):
        return
    for ref in list(annots):
        annot = ref.get_object() if isinstance(ref, IndirectObject) else ref
        if not isinstance(annot, DictionaryObject):
            continue
        flags = annot.get("/F")
        flags = flags.get_object() if isinstance(flags, IndirectObject) else flags
        flag_value = int(flags) if isinstance(flags, NumberObject | int) else 0
        if flag_value & (_ANNOT_HIDDEN | _ANNOT_NOVIEW):
            continue
        if str(annot.get("/Subtype")) in ("/Link", "/Popup"):
            continue
        stream = _appearance_stream(annot)
        rect = _rect_of(annot)
        placed = _placement(stream, rect) if stream is not None and rect is not None else None
        if stream is None or rect is None or placed is None:
            raise ValidationFailed(
                "document contains an annotation whose appearance cannot be flattened",
                code="annotation_not_flattenable",
            )
        ctm, clip = placed
        try:
            page.merge_transformed_page(_clipped_form_page(stream, clip), ctm)
        except (PdfReadError, PyPdfError, ValueError, KeyError, TypeError) as exc:
            raise ValidationFailed(
                "document contains an annotation whose appearance cannot be flattened",
                code="annotation_not_flattenable",
            ) from exc


def sanitize_document(writer: PdfWriter, *, flatten_annotations: bool = True) -> None:
    """Flatten, then remove everything interactive or stale from ``writer``.

    After this the document has no form, no annotations, no scripts, no launch or open actions and
    no inherited metadata. It draws the same thing in every reader and does nothing when opened.
    """
    for page in writer.pages:
        if flatten_annotations:
            _flatten_page_annotations(page)
        for key in _ACTIVE_PAGE_KEYS:
            if key in page:
                del page[NameObject(key)]

    root = writer.root_object
    for key in _ACTIVE_CATALOG_KEYS:
        if key in root:
            del root[NameObject(key)]

    target = writer._info
    if target is not None:
        for key in list(target.keys()):
            del target[NameObject(key)]
        target[NameObject("/Producer")] = TextStringObject(PRODUCER)


def to_bytes(writer: PdfWriter) -> bytes:
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()
