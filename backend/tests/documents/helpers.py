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
from collections.abc import Sequence
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
    "NamedWidget",
    "PlacedImage",
    "PlacedText",
    "blank_png",
    "bomb_png",
    "generated_report",
    "geometry_of",
    "handwriting_png",
    "make_pdf",
    "not_a_png",
    "pdf_with_acroform_javascript",
    "pdf_with_embedded_file",
    "pdf_with_javascript",
    "pdf_with_launch_action",
    "pdf_with_named_widgets",
    "pdf_with_page_additional_actions",
    "pdf_with_signature_field",
    "pdf_with_widget_annotation",
    "pdf_with_xfa",
    "placed_images",
    "placed_text",
    "widget_names",
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


# ------------------------------------------------------- host-supplied documents (Addendum 2)


@dataclass(frozen=True)
class NamedWidget:
    """One AcroForm widget to plant in a fixture.

    ``rect`` is in the page's own *user space*, deliberately: that is what a real generator writes,
    and the point of the geometry tests is that the conversion to displayed coordinates happens in
    the code under test rather than in the fixture. A ``name`` containing a ``.`` is built as a
    parent field with a kid, which is the other shape generators produce.
    """

    name: str
    rect: tuple[float, float, float, float]
    page: int = 1  # 1-based
    ft: str = "/Tx"
    flags: int = 0  # /Ff
    javascript: bool = False  # an /AA keystroke action, which intake must refuse


def _widget_dict(writer: PdfWriter, widget: NamedWidget) -> tuple[Any, Any]:
    """``(field_to_register, annotation_on_the_page)`` for one widget.

    They are the same object unless the name is hierarchical, in which case the page gets the kid
    and the AcroForm gets the parent -- the widget then carries no ``/T`` of its own, so resolving
    its name means walking ``/Parent``. That pair references itself both ways, as a real form does,
    so both halves are registered as indirect objects: a direct cycle is not writable.
    """
    annot = DictionaryObject()
    annot[NameObject("/Type")] = NameObject("/Annot")
    annot[NameObject("/Subtype")] = NameObject("/Widget")
    annot[NameObject("/Rect")] = ArrayObject([FloatObject(value) for value in widget.rect])
    annot[NameObject("/F")] = NumberObject(4)  # Print

    if widget.javascript:
        action = DictionaryObject()
        action[NameObject("/S")] = NameObject("/JavaScript")
        action[NameObject("/JS")] = TextStringObject("this.getField('x').value = 'tampered';")
        additional = DictionaryObject()
        additional[NameObject("/K")] = action
        annot[NameObject("/AA")] = additional

    head, _, tail = widget.name.partition(".")
    if not tail:
        annot[NameObject("/T")] = TextStringObject(widget.name)
        annot[NameObject("/FT")] = NameObject(widget.ft)
        if widget.flags:
            annot[NameObject("/Ff")] = NumberObject(widget.flags)
        return annot, annot

    parent = DictionaryObject()
    parent[NameObject("/T")] = TextStringObject(head)
    parent[NameObject("/FT")] = NameObject(widget.ft)
    if widget.flags:
        parent[NameObject("/Ff")] = NumberObject(widget.flags)
    annot[NameObject("/T")] = TextStringObject(tail)
    parent_ref = writer._add_object(parent)
    annot[NameObject("/Parent")] = parent_ref
    parent[NameObject("/Kids")] = ArrayObject([writer._add_object(annot)])
    return parent_ref, annot


def _attach_widgets(data: bytes, widgets: Sequence[NamedWidget]) -> bytes:
    def mutate(writer: PdfWriter) -> None:
        fields = ArrayObject()
        by_page: dict[int, ArrayObject] = {}
        for widget in widgets:
            field, annot = _widget_dict(writer, widget)
            fields.append(field)
            by_page.setdefault(widget.page, ArrayObject()).append(annot)
        form = DictionaryObject()
        form[NameObject("/Fields")] = fields
        writer.root_object[NameObject("/AcroForm")] = form
        for page_number, annots in by_page.items():
            writer.pages[page_number - 1][NameObject("/Annots")] = annots

    return _rewrite(data, mutate)


def pdf_with_named_widgets(
    widgets: Sequence[NamedWidget],
    *,
    pages: int = 1,
    size: tuple[float, float] = (612.0, 792.0),
    rotate: int = 0,
    origin: tuple[float, float] = (0.0, 0.0),
) -> bytes:
    """A plain document carrying exactly ``widgets``, on pages that may be rotated or offset."""
    return _attach_widgets(make_pdf(pages=pages, size=size, rotate=rotate, origin=origin), widgets)


def pdf_with_acroform_javascript() -> bytes:
    """A form field whose keystroke action runs JavaScript.

    The hygiene rules allow widgets through on a supplied document -- they are how the signature
    block is found -- so this is the fixture that proves "widgets allowed" did not quietly become
    "anything in the AcroForm allowed".
    """
    return pdf_with_named_widgets([NamedWidget(name="clinician_signature", rect=(72, 96, 292, 146), javascript=True)])


def _report_line(page_index: int, line_index: int) -> str:
    """One line of plausible, entirely synthetic report prose. No names, no dates, no numbers
    that could be mistaken for a record identifier."""
    phrases = (
        "Findings within expected range for the region examined.",
        "No acute abnormality identified on the current study.",
        "Comparison made with the prior study of record.",
        "Measurements are stable relative to the previous examination.",
        "Recommend routine follow-up per the standing care pathway.",
        "Technique: standard protocol, no contrast administered.",
        "Correlation with the clinical picture is advised.",
    )
    return f"{phrases[(page_index * 7 + line_index) % len(phrases)]} (section {line_index + 1})"


def generated_report(
    *,
    pages: int = 25,
    widgets: Sequence[NamedWidget] = (),
    size: tuple[float, float] = (612.0, 792.0),
) -> bytes:
    """A stand-in for the EHR's per-patient report: pages of generated text, a signature block last.

    Built with reportlab rather than committed, so the timing test measures work on a document of
    the shape and weight the addendum describes instead of on a one-page stub.
    """
    buffer = io.BytesIO()
    canvas = Canvas(buffer, pagesize=size, invariant=1, pageCompression=1)
    width, height = size
    for index in range(pages):
        canvas.setFont("Helvetica-Bold", 13)
        canvas.drawString(54, height - 60, f"Clinical summary - page {index + 1} of {pages}")
        canvas.setFont("Helvetica", 9.5)
        y = height - 88
        while y > 120:
            canvas.drawString(54, y, _report_line(index, int((height - 88 - y) // 14)))
            y -= 14
        canvas.setFont("Helvetica", 8)
        canvas.drawString(width - 120, 48, f"page {index + 1}")
        canvas.showPage()
    canvas.save()
    data = buffer.getvalue()
    return _attach_widgets(data, widgets) if widgets else data


def widget_names(pdf: bytes) -> list[str]:
    """Every widget annotation name still reachable from the page tree, for the flattening tests."""
    reader = PdfReader(io.BytesIO(pdf))
    found: list[str] = []
    for page in reader.pages:
        annots = page.get("/Annots")
        annots = annots.get_object() if isinstance(annots, IndirectObject) else annots
        if not isinstance(annots, ArrayObject | list):
            continue
        for ref in annots:
            annot = ref.get_object() if isinstance(ref, IndirectObject) else ref
            if isinstance(annot, DictionaryObject):
                found.append(str(annot.get("/T", "")))
    return found


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
