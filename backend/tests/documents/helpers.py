"""Fixtures built in code, and tools for looking at where ink actually landed.

Two halves:

* **builders** -- PDFs with exactly one thing wrong with them (JavaScript, XFA, an embedded file, a
  launch action, a signature field, a widget annotation, a rotated page, an offset box origin), and
  PNGs that are blank, enormous, a decompression bomb, or not a PNG at all. Everything is built
  here rather than committed as a binary so a reviewer can see what is being tested.
* **inspectors** -- :func:`placed_text` and :func:`placed_images` read the *output* content stream,
  track the graphics state, and report where each piece of ink ended up in displayed page
  coordinates. That is how the geometry tests prove a mark is inside its rect rather than merely
  believing the drawing code.
"""

from __future__ import annotations

import io
import zlib
from dataclasses import dataclass
from typing import Any

from PIL import Image
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    ContentStream,
    DecodedStreamObject,
    DictionaryObject,
    FloatObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen.canvas import Canvas

from esign.contracts import Rect
from esign.documents.geometry import PageGeometry, page_geometry
from esign.documents.pdfutil import Matrix, compose

__all__ = [
    "Box",
    "PlacedImage",
    "PlacedText",
    "blank_png",
    "bomb_png",
    "geometry_of",
    "handwriting_png",
    "make_pdf",
    "not_a_png",
    "pdf_with_embedded_file",
    "pdf_with_javascript",
    "pdf_with_launch_action",
    "pdf_with_page_additional_actions",
    "pdf_with_signature_field",
    "pdf_with_widget_annotation",
    "pdf_with_xfa",
    "placed_images",
    "placed_text",
]


# --------------------------------------------------------------------------- PDF builders


def make_pdf(
    *,
    pages: int = 1,
    size: tuple[float, float] = (612.0, 792.0),
    rotate: int = 0,
    origin: tuple[float, float] = (0.0, 0.0),
    crop_inset: float = 0.0,
) -> bytes:
    """A plain, valid PDF with ``pages`` pages, optionally rotated and/or with an offset box."""
    buffer = io.BytesIO()
    canvas = Canvas(buffer, pagesize=size, invariant=1)
    for index in range(pages):
        canvas.setFont("Helvetica", 11)
        canvas.drawString(40, size[1] - 40, f"template page {index + 1}")
        canvas.showPage()
    canvas.save()
    data = buffer.getvalue()

    if rotate == 0 and origin == (0.0, 0.0) and crop_inset == 0.0:
        return data

    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(data)).pages:
        writer.add_page(page)
    ox, oy = origin
    for page in writer.pages:
        if rotate:
            page[NameObject("/Rotate")] = NumberObject(rotate)
        media = [ox, oy, ox + size[0], oy + size[1]]
        page[NameObject("/MediaBox")] = ArrayObject([FloatObject(value) for value in media])
        if crop_inset:
            crop = [
                media[0] + crop_inset,
                media[1] + crop_inset,
                media[2] - crop_inset,
                media[3] - crop_inset,
            ]
            page[NameObject("/CropBox")] = ArrayObject([FloatObject(value) for value in crop])
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _rewrite(data: bytes, mutate: Any) -> bytes:
    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(data)).pages:
        writer.add_page(page)
    mutate(writer)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def pdf_with_javascript() -> bytes:
    """A document-level JavaScript name tree -- the classic auto-run payload."""

    def mutate(writer: PdfWriter) -> None:
        action = DictionaryObject()
        action[NameObject("/Type")] = NameObject("/Action")
        action[NameObject("/S")] = NameObject("/JavaScript")
        action[NameObject("/JS")] = TextStringObject("app.alert('hello');")
        names = DictionaryObject()
        tree = DictionaryObject()
        tree[NameObject("/Names")] = ArrayObject([TextStringObject("boot"), action])
        names[NameObject("/JavaScript")] = tree
        writer.root_object[NameObject("/Names")] = names

    return _rewrite(make_pdf(), mutate)


def pdf_with_page_additional_actions() -> bytes:
    """JavaScript hidden on a page's ``/AA``, not in the place anyone looks first."""

    def mutate(writer: PdfWriter) -> None:
        action = DictionaryObject()
        action[NameObject("/S")] = NameObject("/JavaScript")
        action[NameObject("/JS")] = TextStringObject("app.alert('open');")
        additional = DictionaryObject()
        additional[NameObject("/O")] = action
        writer.pages[0][NameObject("/AA")] = additional

    return _rewrite(make_pdf(), mutate)


def pdf_with_xfa() -> bytes:
    def mutate(writer: PdfWriter) -> None:
        form = DictionaryObject()
        form[NameObject("/Fields")] = ArrayObject([])
        form[NameObject("/XFA")] = ArrayObject([TextStringObject("<xdp:xdp/>")])
        writer.root_object[NameObject("/AcroForm")] = form

    return _rewrite(make_pdf(), mutate)


def pdf_with_embedded_file() -> bytes:
    def mutate(writer: PdfWriter) -> None:
        stream = DecodedStreamObject()
        stream.set_data(b"secret payload")
        stream[NameObject("/Type")] = NameObject("/EmbeddedFile")
        spec = DictionaryObject()
        spec[NameObject("/Type")] = NameObject("/Filespec")
        spec[NameObject("/F")] = TextStringObject("payload.bin")
        embedded = DictionaryObject()
        embedded[NameObject("/F")] = stream
        spec[NameObject("/EF")] = embedded
        names = DictionaryObject()
        tree = DictionaryObject()
        tree[NameObject("/Names")] = ArrayObject([TextStringObject("payload.bin"), spec])
        names[NameObject("/EmbeddedFiles")] = tree
        writer.root_object[NameObject("/Names")] = names

    return _rewrite(make_pdf(), mutate)


def pdf_with_launch_action() -> bytes:
    def mutate(writer: PdfWriter) -> None:
        action = DictionaryObject()
        action[NameObject("/Type")] = NameObject("/Action")
        action[NameObject("/S")] = NameObject("/Launch")
        action[NameObject("/F")] = TextStringObject("calc.exe")
        writer.root_object[NameObject("/OpenAction")] = action

    return _rewrite(make_pdf(), mutate)


def pdf_with_signature_field() -> bytes:
    def mutate(writer: PdfWriter) -> None:
        field = DictionaryObject()
        field[NameObject("/Type")] = NameObject("/Annot")
        field[NameObject("/Subtype")] = NameObject("/Widget")
        field[NameObject("/FT")] = NameObject("/Sig")
        field[NameObject("/T")] = TextStringObject("existing_signature")
        field[NameObject("/Rect")] = ArrayObject([FloatObject(v) for v in (72, 72, 272, 122)])
        form = DictionaryObject()
        form[NameObject("/Fields")] = ArrayObject([field])
        form[NameObject("/SigFlags")] = NumberObject(3)
        writer.root_object[NameObject("/AcroForm")] = form
        writer.pages[0][NameObject("/Annots")] = ArrayObject([field])

    return _rewrite(make_pdf(), mutate)


def pdf_with_widget_annotation(*, rect: tuple[float, float, float, float] = (72, 600, 272, 640)) -> bytes:
    """A text form field with a real appearance stream, for the flattening tests.

    No JavaScript, no signature flags: this is the shape ``inspect_template_pdf`` allows through
    and ``prepare`` has to flatten rather than carry.
    """

    def mutate(writer: PdfWriter) -> None:
        appearance = DecodedStreamObject()
        width = rect[2] - rect[0]
        height = rect[3] - rect[1]
        appearance.set_data(b"BT /Helv 10 Tf 2 12 Td (widget value) Tj ET")
        appearance[NameObject("/Type")] = NameObject("/XObject")
        appearance[NameObject("/Subtype")] = NameObject("/Form")
        appearance[NameObject("/BBox")] = ArrayObject([FloatObject(v) for v in (0, 0, width, height)])
        font = DictionaryObject()
        font[NameObject("/Type")] = NameObject("/Font")
        font[NameObject("/Subtype")] = NameObject("/Type1")
        font[NameObject("/BaseFont")] = NameObject("/Helvetica")
        fonts = DictionaryObject()
        fonts[NameObject("/Helv")] = font
        resources = DictionaryObject()
        resources[NameObject("/Font")] = fonts
        appearance[NameObject("/Resources")] = resources

        annot = DictionaryObject()
        annot[NameObject("/Type")] = NameObject("/Annot")
        annot[NameObject("/Subtype")] = NameObject("/Widget")
        annot[NameObject("/FT")] = NameObject("/Tx")
        annot[NameObject("/T")] = TextStringObject("host_field")
        annot[NameObject("/V")] = TextStringObject("widget value")
        annot[NameObject("/Rect")] = ArrayObject([FloatObject(v) for v in rect])
        appearances = DictionaryObject()
        appearances[NameObject("/N")] = appearance
        annot[NameObject("/AP")] = appearances

        form = DictionaryObject()
        form[NameObject("/Fields")] = ArrayObject([annot])
        writer.root_object[NameObject("/AcroForm")] = form
        writer.pages[0][NameObject("/Annots")] = ArrayObject([annot])

    return _rewrite(make_pdf(), mutate)


# --------------------------------------------------------------------------- PNG builders


def handwriting_png(width: int = 600, height: int = 200, *, opaque: bool = False) -> bytes:
    """Something that looks like a stroke: a dark diagonal band with enough ink to pass."""
    background = (255, 255, 255, 255) if opaque else (0, 0, 0, 0)
    image = Image.new("RGBA", (width, height), background)
    pixels = image.load()
    assert pixels is not None
    for x in range(width):
        centre = int(height / 2 + (height / 3) * ((x / width) * 2 - 1))
        for dy in range(-4, 5):
            y = centre + dy
            if 0 <= y < height:
                pixels[x, y] = (10, 12, 30, 255)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def blank_png(width: int = 400, height: int = 150, *, opaque: bool = False) -> bytes:
    colour = (255, 255, 255, 255) if opaque else (0, 0, 0, 0)
    image = Image.new("RGBA", (width, height), colour)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def bomb_png(width: int = 30_000, height: int = 30_000) -> bytes:
    """A few kilobytes on disk, 900 million pixels if you decode it.

    Hand-assembled rather than produced by Pillow, because Pillow will not write one this big --
    which is exactly the asymmetry the check has to survive.
    """

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return len(payload).to_bytes(4, "big") + kind + payload + zlib.crc32(kind + payload).to_bytes(4, "big")

    header = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes([8, 0, 0, 0, 0])
    scanline = b"\x00" + b"\x00" * width
    data = zlib.compress(scanline * 64, 9)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", data) + chunk(b"IEND", b"")


def not_a_png() -> bytes:
    image = Image.new("RGB", (200, 80), (255, 255, 255))
    out = io.BytesIO()
    image.save(out, format="JPEG")
    return out.getvalue()


# --------------------------------------------------------------------------- output inspectors


@dataclass(frozen=True)
class Box:
    """An axis-aligned box in displayed page coordinates."""

    x0: float
    y0: float
    x1: float
    y1: float

    def inside(self, rect: Rect, *, tolerance: float = 0.75) -> bool:
        return (
            self.x0 >= rect.x - tolerance
            and self.y0 >= rect.y - tolerance
            and self.x1 <= rect.x + rect.w + tolerance
            and self.y1 <= rect.y + rect.h + tolerance
        )

    def overlaps(self, rect: Rect) -> bool:
        return not (self.x1 <= rect.x or self.x0 >= rect.x + rect.w or self.y1 <= rect.y or self.y0 >= rect.y + rect.h)


@dataclass(frozen=True)
class PlacedText:
    """One run of text, positioned but not yet measured.

    Measuring needs to know which face drew it, and the face name inside the PDF is a subset alias.
    So the test says which of this module's fonts it expects, and :meth:`box` measures the run with
    that face's real metrics -- read from the same TTF reportlab embedded, not from the drawing
    code's own idea of how wide it was.
    """

    text: str
    size: float
    geometry: PageGeometry
    matrix: Matrix

    @property
    def origin(self) -> tuple[float, float]:
        x, y = _transform(self.matrix, 0.0, 0.0)
        return self.geometry.to_displayed(x, y)

    def box(self, font: str) -> Box:
        ascent, descent = pdfmetrics.getAscentDescent(font, self.size)
        width = float(pdfmetrics.stringWidth(self.text, font, self.size))
        corners = [
            _transform(self.matrix, 0.0, descent),
            _transform(self.matrix, width, descent),
            _transform(self.matrix, width, ascent),
            _transform(self.matrix, 0.0, ascent),
        ]
        return _box_from_corners(self.geometry, corners)


@dataclass(frozen=True)
class PlacedImage:
    name: str
    box: Box


def geometry_of(pdf: bytes, page_index: int = 0) -> PageGeometry:
    return page_geometry(PdfReader(io.BytesIO(pdf)).pages[page_index], page_index)


def _transform(matrix: Matrix, x: float, y: float) -> tuple[float, float]:
    a, b, c, d, e, f = matrix
    return (a * x + c * y + e, b * x + d * y + f)


def _box_from_corners(geometry: PageGeometry, corners: list[tuple[float, float]]) -> Box:
    displayed = [geometry.to_displayed(x, y) for x, y in corners]
    return Box(
        x0=min(p[0] for p in displayed),
        y0=min(p[1] for p in displayed),
        x1=max(p[0] for p in displayed),
        y1=max(p[1] for p in displayed),
    )


def placed_text(pdf: bytes, page_index: int = 0) -> list[PlacedText]:
    """Every run of text on the page, positioned in displayed coordinates.

    pypdf hands the visitor the current transformation and text matrices; composing them gives the
    run's baseline in page user space, which :meth:`PlacedText.box` turns into a measured box.
    """
    reader = PdfReader(io.BytesIO(pdf))
    page = reader.pages[page_index]
    geometry = page_geometry(page, page_index)
    found: list[PlacedText] = []

    def visitor(text: str, cm: list[float], tm: list[float], _font: Any, font_size: float) -> None:
        stripped = text.strip()
        if not stripped:
            return
        combined = compose(
            (tm[0], tm[1], tm[2], tm[3], tm[4], tm[5]),
            (cm[0], cm[1], cm[2], cm[3], cm[4], cm[5]),
        )
        found.append(PlacedText(text=stripped, size=float(font_size), geometry=geometry, matrix=combined))

    page.extract_text(visitor_text=visitor)
    return found


def _xobjects(resources: Any) -> dict[str, Any]:
    resources = resources.get_object() if isinstance(resources, IndirectObject) else resources
    if not isinstance(resources, DictionaryObject):
        return {}
    xobjects = resources.get("/XObject")
    xobjects = xobjects.get_object() if isinstance(xobjects, IndirectObject) else xobjects
    if not isinstance(xobjects, DictionaryObject):
        return {}
    return {
        str(key): value.get_object() if isinstance(value, IndirectObject) else value for key, value in xobjects.items()
    }


def placed_images(pdf: bytes, page_index: int = 0) -> list[PlacedImage]:
    """Every image drawn on the page, with its box in displayed coordinates.

    Walks the content stream tracking ``q``/``Q``/``cm``. A PDF image occupies the unit square in
    its own space, so the transformation in force at the ``Do`` *is* the placement.
    """
    reader = PdfReader(io.BytesIO(pdf))
    page = reader.pages[page_index]
    geometry = page_geometry(page, page_index)
    found: list[PlacedImage] = []

    def walk(stream_owner: Any, resources: Any, base: Matrix, depth: int) -> None:
        if depth > 4:
            return
        contents = stream_owner.get_object()
        content = ContentStream(contents, reader)
        xobjects = _xobjects(resources)
        state: list[Matrix] = []
        ctm: Matrix = base
        for operands, operator in content.operations:
            if operator == b"q":
                state.append(ctm)
            elif operator == b"Q":
                ctm = state.pop() if state else base
            elif operator == b"cm":
                values = [float(value) for value in operands]
                ctm = compose((values[0], values[1], values[2], values[3], values[4], values[5]), ctm)
            elif operator == b"Do":
                name = str(operands[0])
                target = xobjects.get(name)
                if target is None:
                    continue
                subtype = str(target.get("/Subtype", ""))
                if subtype == "/Image":
                    corners = [
                        _transform(ctm, 0.0, 0.0),
                        _transform(ctm, 1.0, 0.0),
                        _transform(ctm, 1.0, 1.0),
                        _transform(ctm, 0.0, 1.0),
                    ]
                    found.append(PlacedImage(name=name, box=_box_from_corners(geometry, corners)))
                elif subtype == "/Form":
                    walk(target, target.get("/Resources"), ctm, depth + 1)

    identity: Matrix = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
    walk(page.get_contents(), page.get("/Resources"), identity, 0)
    return found
