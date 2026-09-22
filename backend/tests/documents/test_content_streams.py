"""A template whose page content cannot be decoded is refused at upload, not at signing time.

``inspect_template_pdf`` walks the object graph but never used to *decode* a content stream, so a
page whose FlateDecode content inflates past pypdf's output cap passed inspection and published
happily. The first thing that decodes it is stamping, at ``POST /v1/envelopes`` -- where
``draw_overlay`` had no ``except`` of its own and the host got ``500 internal_error`` for a file it
had uploaded days earlier.
"""

from __future__ import annotations

import zlib

import pytest

from esign.contracts import Capture, DocumentService, FieldDef, Rect, SignerStamp, ValidationFailed

#: Comfortably past ``pypdf.Configuration.zlib_maximum_output_length`` (75 MB), and about 80 KB on
#: the wire: the point of the cap is that the ratio makes this cheap to send and expensive to read.
_INFLATED_BYTES = 80_000_000


def over_cap_pdf() -> bytes:
    """A one-page PDF whose content stream decompresses past pypdf's limit.

    Written by hand rather than through a library, because no library will produce one: the whole
    point is a file that is structurally valid and still cannot be drawn.
    """
    content = zlib.compress(b" " * _INFLATED_BYTES, 9)
    objects = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<<>>>>",
        b"<</Length " + str(len(content)).encode() + b"/Filter/FlateDecode>>stream\n" + content + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.7\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj".encode() + body + b"endobj\n"
    start = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += b"trailer<</Size " + str(len(objects) + 1).encode() + b"/Root 1 0 R>>\n"
    out += b"startxref\n" + str(start).encode() + b"\n%%EOF\n"
    return bytes(out)


def test_inspection_refuses_a_page_whose_content_cannot_be_decoded(documents: DocumentService) -> None:
    with pytest.raises(ValidationFailed) as caught:
        documents.inspect_template_pdf(over_cap_pdf())
    assert caught.value.code == "template_content_unreadable"


def test_stamping_such_a_page_is_a_validation_failure_not_a_crash(
    documents: DocumentService, stamp: SignerStamp
) -> None:
    """Belt and braces: an older template version could already be published."""
    field = FieldDef(
        id="patient_signature",
        type="signature",
        page=1,
        rect=Rect(x=100, y=400, w=220, h=48),
        signer_role="patient",
    )
    capture = Capture(field_id="patient_signature", kind="typed", typed_text="Ada Lovelace")
    with pytest.raises(ValidationFailed) as caught:
        documents.apply_signer_marks(over_cap_pdf(), [field], [capture], stamp)
    assert caught.value.code == "pdf_unreadable"
