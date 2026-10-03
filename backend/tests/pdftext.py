"""Text from a sealed PDF: its pages, and the embedded certificate of completion."""

from __future__ import annotations

import io

from pypdf import PdfReader

from esign.contracts import CERTIFICATE_OF_COMPLETION_FILENAME


def certificate_bytes(pdf: bytes) -> bytes:
    """The one certificate of completion attached to ``pdf``."""
    found = list(PdfReader(io.BytesIO(pdf)).attachments.get(CERTIFICATE_OF_COMPLETION_FILENAME) or [])
    if len(found) != 1:
        raise AssertionError(f"expected one embedded certificate, found {len(found)}")
    return found[0]


def certificate_text(pdf: bytes) -> str:
    """The text of the embedded certificate, pages joined by newlines."""
    reader = PdfReader(io.BytesIO(certificate_bytes(pdf)))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def pages_text(pdf: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def document_text(pdf: bytes) -> str:
    """Page text plus the embedded certificate, for a check that used to read one continuous file."""
    return pages_text(pdf) + "\n" + certificate_text(pdf)
