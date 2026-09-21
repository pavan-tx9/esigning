"""Signature image intake: the only raw binary the browser sends."""

from __future__ import annotations

import io
import zlib

import pytest
from PIL import Image

from esign.config import Settings
from esign.contracts import DocumentService, ValidationFailed
from esign.documents import build_document_service
from esign.documents.images import MAX_SIGNATURE_PNG_DIMENSION
from tests.documents.helpers import blank_png, bomb_png, handwriting_png, not_a_png


def test_a_plausible_signature_is_accepted(documents: DocumentService) -> None:
    out = documents.sanitize_signature_png(handwriting_png())
    assert out.startswith(b"\x89PNG\r\n\x1a\n")
    Image.open(io.BytesIO(out)).load()


def test_output_is_trimmed_to_the_ink(documents: DocumentService) -> None:
    """A stroke in the corner of a big canvas should fill its field, not float in whitespace."""
    canvas = Image.new("RGBA", (800, 400), (0, 0, 0, 0))
    pixels = canvas.load()
    assert pixels is not None
    for x in range(60, 260):
        for y in range(40, 50):
            pixels[x, y] = (0, 0, 0, 255)
    buffer = io.BytesIO()
    canvas.save(buffer, format="PNG")

    out = documents.sanitize_signature_png(buffer.getvalue())
    assert Image.open(io.BytesIO(out)).size == (200, 10)


@pytest.mark.parametrize("opaque", [True, False])
def test_a_blank_canvas_is_refused(documents: DocumentService, opaque: bool) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.sanitize_signature_png(blank_png(opaque=opaque))
    assert excinfo.value.code == "signature_image_blank"


def test_a_near_blank_canvas_is_refused(documents: DocumentService) -> None:
    """One stray pixel is a mis-tap, not a signature."""
    canvas = Image.new("RGBA", (400, 150), (0, 0, 0, 0))
    pixels = canvas.load()
    assert pixels is not None
    pixels[10, 10] = (0, 0, 0, 255)
    buffer = io.BytesIO()
    canvas.save(buffer, format="PNG")

    with pytest.raises(ValidationFailed) as excinfo:
        documents.sanitize_signature_png(buffer.getvalue())
    assert excinfo.value.code == "signature_image_blank"


def test_a_decompression_bomb_is_refused_without_decoding_it(documents: DocumentService) -> None:
    payload = bomb_png()
    assert len(payload) < 100_000  # tiny on the wire, 900 megapixels if decoded
    with pytest.raises(ValidationFailed) as excinfo:
        documents.sanitize_signature_png(payload)
    assert excinfo.value.code == "signature_image_too_large"


def test_dimensions_are_bounded_even_when_the_pixel_count_is_not(documents: DocumentService) -> None:
    payload = bomb_png(width=MAX_SIGNATURE_PNG_DIMENSION + 1, height=16)
    with pytest.raises(ValidationFailed) as excinfo:
        documents.sanitize_signature_png(payload)
    assert excinfo.value.code == "signature_image_too_large"


def test_a_jpeg_is_refused(documents: DocumentService) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.sanitize_signature_png(not_a_png())
    assert excinfo.value.code == "signature_image_not_png"


def test_empty_input_is_refused(documents: DocumentService) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.sanitize_signature_png(b"")
    assert excinfo.value.code == "signature_image_empty"


def test_a_truncated_png_is_refused(documents: DocumentService) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        documents.sanitize_signature_png(handwriting_png()[:120])
    assert excinfo.value.code in {"signature_image_undecodable", "signature_image_too_small"}


def test_oversize_input_is_refused_by_byte_count(settings_no_db: Settings) -> None:
    tight = settings_no_db.model_copy(update={"max_signature_png_bytes": 500})
    with pytest.raises(ValidationFailed) as excinfo:
        build_document_service(tight).sanitize_signature_png(handwriting_png())
    assert excinfo.value.code == "signature_image_too_large"


def test_metadata_and_trailing_bytes_do_not_survive(documents: DocumentService) -> None:
    """Text chunks, EXIF and anything appended after IEND are stripped by re-encoding."""
    image = Image.open(io.BytesIO(handwriting_png()))
    info = __import__("PIL.PngImagePlugin", fromlist=["PngInfo"]).PngInfo()
    info.add_text("Comment", "MRN 123456 Jane Roe")
    info.add_text("Author", "Jane Roe")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", pnginfo=info)
    payload = buffer.getvalue() + b"trailing garbage with MRN 123456"

    out = documents.sanitize_signature_png(payload)
    assert b"MRN 123456" not in out
    assert b"Jane Roe" not in out
    assert Image.open(io.BytesIO(out)).info.get("Comment") is None


def test_a_png_lying_about_its_dimensions_is_refused(documents: DocumentService) -> None:
    """The header claims a modest size; the data does not match. Decoding must fail closed."""

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return len(payload).to_bytes(4, "big") + kind + payload + zlib.crc32(kind + payload).to_bytes(4, "big")

    header = (200).to_bytes(4, "big") + (200).to_bytes(4, "big") + bytes([8, 0, 0, 0, 0])
    payload = (
        b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(b"\x00" * 8)) + chunk(b"IEND", b"")
    )

    with pytest.raises(ValidationFailed) as excinfo:
        documents.sanitize_signature_png(payload)
    assert excinfo.value.code in {"signature_image_undecodable", "signature_image_blank"}


def test_an_opaque_white_background_still_finds_the_ink(documents: DocumentService) -> None:
    out = documents.sanitize_signature_png(handwriting_png(opaque=True))
    assert Image.open(io.BytesIO(out)).size[0] > 0


def test_sanitizing_is_idempotent(documents: DocumentService) -> None:
    once = documents.sanitize_signature_png(handwriting_png())
    twice = documents.sanitize_signature_png(once)
    assert once == twice
