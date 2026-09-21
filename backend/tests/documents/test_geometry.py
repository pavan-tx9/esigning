"""Displayed-page coordinates: the conversion everything else depends on.

If these matrices are wrong, every signature in the system lands in the wrong place on exactly the
documents nobody tested by eye. So they are checked three ways: against the corners a reader sees,
by round-tripping, and by the property that the transformation is rigid.
"""

from __future__ import annotations

import math

import pytest

from esign.contracts import Rect, ValidationFailed
from esign.documents.geometry import PageGeometry, page_geometry
from esign.documents.pdfutil import geometries, open_reader
from tests.documents.helpers import make_pdf


def geom(rotate: int, origin: tuple[float, float] = (0.0, 0.0)) -> PageGeometry:
    ox, oy = origin
    return PageGeometry(index=0, rotate=rotate, x0=ox, y0=oy, x1=ox + 400.0, y1=oy + 600.0)


@pytest.mark.parametrize(
    ("rotate", "expected"),
    [(0, (400.0, 600.0)), (90, (600.0, 400.0)), (180, (400.0, 600.0)), (270, (600.0, 400.0))],
)
def test_displayed_size_swaps_on_quarter_turns(rotate: int, expected: tuple[float, float]) -> None:
    assert geom(rotate).displayed_size == expected


@pytest.mark.parametrize("rotate", [0, 90, 180, 270])
@pytest.mark.parametrize("origin", [(0.0, 0.0), (36.0, 18.0), (-12.0, -8.0)])
def test_displayed_origin_is_the_bottom_left_a_reader_sees(rotate: int, origin: tuple[float, float]) -> None:
    """The four displayed corners must map onto the four box corners, in reading order."""
    geometry = geom(rotate, origin)
    width, height = geometry.displayed_size
    corners = {
        geometry.to_user(0.0, 0.0),
        geometry.to_user(width, 0.0),
        geometry.to_user(width, height),
        geometry.to_user(0.0, height),
    }
    expected = {
        (geometry.x0, geometry.y0),
        (geometry.x1, geometry.y0),
        (geometry.x1, geometry.y1),
        (geometry.x0, geometry.y1),
    }
    assert corners == expected


@pytest.mark.parametrize("rotate", [0, 90, 180, 270])
def test_to_displayed_inverts_to_user(rotate: int) -> None:
    geometry = geom(rotate, (25.0, 40.0))
    for dx, dy in ((0.0, 0.0), (10.5, 3.25), (399.0, 599.0), (120.0, 120.0)):
        x, y = geometry.to_user(dx, dy)
        back = geometry.to_displayed(x, y)
        assert math.isclose(back[0], dx, abs_tol=1e-9)
        assert math.isclose(back[1], dy, abs_tol=1e-9)


@pytest.mark.parametrize("rotate", [0, 90, 180, 270])
def test_transform_preserves_distance(rotate: int) -> None:
    """Rotation and translation only: no scale, no shear, so lengths survive."""
    geometry = geom(rotate, (7.0, -3.0))
    a = geometry.to_user(10.0, 20.0)
    b = geometry.to_user(40.0, 60.0)
    assert math.isclose(math.dist(a, b), math.dist((10.0, 20.0), (40.0, 60.0)), abs_tol=1e-9)


def test_rotation_is_normalised() -> None:
    pdf = make_pdf(rotate=450)
    geometry = geometries(open_reader(pdf).pages)[0]
    assert geometry.rotate == 90


def test_negative_rotation_is_normalised() -> None:
    pdf = make_pdf(rotate=-90)
    geometry = geometries(open_reader(pdf).pages)[0]
    assert geometry.rotate == 270


def test_cropbox_is_the_visible_box() -> None:
    pdf = make_pdf(origin=(20.0, 30.0), crop_inset=15.0)
    geometry = geometries(open_reader(pdf).pages)[0]
    assert geometry.displayed_size == (612.0 - 30.0, 792.0 - 30.0)
    assert geometry.to_user(0.0, 0.0) == (35.0, 45.0)


def test_rotate_is_inherited_from_the_page_tree() -> None:
    """``/Rotate`` may live on /Pages, not the page. Missing that puts every mark sideways."""
    import io
    from typing import cast

    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, NumberObject

    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(make_pdf(pages=2))).pages:
        writer.add_page(page)
    for page in writer.pages:
        if "/Rotate" in page:
            del page[NameObject("/Rotate")]
    root_pages = cast("DictionaryObject", writer.root_object["/Pages"].get_object())
    root_pages[NameObject("/Rotate")] = NumberObject(90)
    out = io.BytesIO()
    writer.write(out)

    for geometry in geometries(open_reader(out.getvalue()).pages):
        assert geometry.rotate == 90
        assert geometry.displayed_size == (792.0, 612.0)


def test_contains_rejects_a_rect_that_hangs_off_the_page() -> None:
    geometry = geom(0)
    assert geometry.contains(Rect(x=0, y=0, w=400, h=600))
    assert not geometry.contains(Rect(x=1, y=0, w=400, h=600))
    assert not geometry.contains(Rect(x=-1, y=0, w=10, h=10))


def test_contains_rejects_a_hairline_rect() -> None:
    assert not geom(0).contains(Rect(x=10, y=10, w=1, h=40))


def test_contains_uses_displayed_not_box_dimensions() -> None:
    """On a quarter-turned page a landscape rect fits and a portrait one does not."""
    geometry = geom(90)  # displayed 600 x 400
    assert geometry.contains(Rect(x=0, y=0, w=590, h=390))
    assert not geometry.contains(Rect(x=0, y=0, w=390, h=590))


def test_unusable_geometry_is_a_validation_failure_not_a_crash() -> None:
    import io

    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import ArrayObject, FloatObject, NameObject

    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(make_pdf())).pages:
        writer.add_page(page)
    writer.pages[0][NameObject("/MediaBox")] = ArrayObject(
        [FloatObject(0), FloatObject(0), FloatObject(0), FloatObject(0)]
    )
    out = io.BytesIO()
    writer.write(out)

    with pytest.raises(ValidationFailed) as excinfo:
        geometries(open_reader(out.getvalue()).pages)
    assert excinfo.value.code == "pdf_bad_geometry"


def test_page_geometry_requires_a_mediabox() -> None:
    class Bare(dict[str, object]):
        pass

    with pytest.raises(ValueError, match="MediaBox"):
        page_geometry(Bare(), 0)
