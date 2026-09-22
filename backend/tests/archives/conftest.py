"""Fixtures for paper archives (Addendum 1 A).

The stack is the real one: ``tests/e2e/conftest.py``'s ``world`` is ``create_app`` over
``build_runtime``, with Postgres as the restricted ``esign_app`` role, the fs blob store, the
local key backend and the in-process timestamp authority. Filing a scan is a host-side action, so
every test here drives the Host API over HTTP exactly as an EHR backend would.

The scans are built in code rather than committed as binaries, so a reader can see what each test
is filing: a plain PDF for the happy path, an image-only one for the "rasterised pages are
expected" case, and the documents module's hostile builders for the hygiene refusals.
"""

from __future__ import annotations

import io
import json
from typing import Any

import httpx
import pytest
from PIL import Image
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen.canvas import Canvas

from tests.e2e.conftest import Ehr, World
from tests.e2e.conftest import e2e_pki as e2e_pki
from tests.e2e.conftest import e2e_settings as e2e_settings
from tests.e2e.conftest import ehr as ehr
from tests.e2e.conftest import world as world

#: Names that must never leave the database and the sealed PDF: not a log line, not audit data,
#: not a webhook payload. Deliberately unmistakable if one ever shows up in a grep.
STAFF_NAME = "Bernadette Quillfeather-Ngata"
PAPER_SIGNER_NAME = "Aurelio Vandenbrouck-Mbeki"
SECOND_PAPER_SIGNER_NAME = "Perpetua Thistlewood"

#: Opaque host identifiers, as SPEC section 4 requires of anything that reaches the trail.
STAFF_USER_ID = "staff-4417"
PATIENT_REF = "chart-88213"

#: The clock is frozen at 2026-03-17 (``tests.conftest.FROZEN_NOW``), so this is last week.
PAPER_SIGNED_ON = "2026-03-10"


@pytest.fixture
def host(world: World) -> Ehr:
    """A registered EHR with a webhook and no templates: an archive needs none."""
    return world.host(webhook=True)


def scan_pdf(*, pages: int = 2, text: str = "Consent to treatment") -> bytes:
    """A plain, valid PDF standing in for a scan of a signed page."""
    buffer = io.BytesIO()
    canvas = Canvas(buffer, pagesize=(612.0, 792.0), invariant=1)
    for index in range(pages):
        canvas.setFont("Helvetica", 12)
        canvas.drawString(72, 700, f"{text} -- page {index + 1}")
        canvas.drawString(72, 120, "Signed: ______________________")
        canvas.showPage()
    canvas.save()
    return buffer.getvalue()


def image_only_scan_pdf(*, pages: int = 1) -> bytes:
    """What a scanner actually produces: a page that is one image and no text at all.

    The addendum says rasterised, image-only pages are expected and fine, so the hygiene check has
    to accept a document with nothing but a picture on it.
    """
    image = Image.new("RGB", (850, 1100), "white")
    for y in range(540, 560):
        for x in range(120, 700):
            image.putpixel((x, y), (20, 20, 40))
    buffer = io.BytesIO()
    canvas = Canvas(buffer, pagesize=(612.0, 792.0), invariant=1)
    for _ in range(pages):
        canvas.drawImage(ImageReader(image), 0, 0, width=612, height=792)
        canvas.showPage()
    canvas.save()
    return buffer.getvalue()


def attestation(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "staff_user_id": STAFF_USER_ID,
        "staff_display_name": STAFF_NAME,
        "statement": "true_copy",
        "original_disposition": "retained",
        "paper_signers": [{"display_name": PAPER_SIGNER_NAME, "capacity": "self"}],
    }
    body.update(overrides)
    return body


def archive_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "patient_ref": PATIENT_REF,
        "document_type": "patient_consent",
        "host_document_ref": "chart-note-9901",
        "paper_signed_on": PAPER_SIGNED_ON,
        "attestation": attestation(),
    }
    body.update(overrides)
    return body


def file_archive(
    host: Ehr,
    scan: bytes | None = None,
    *,
    key: str | None = None,
    filename: str = "scan.pdf",
    body: dict[str, Any] | None = None,
    **overrides: Any,
) -> httpx.Response:
    """``POST /v1/archives`` as an EHR backend makes it: multipart, ``scan`` plus ``body``."""
    headers = dict(host.headers)
    if key is not None:
        headers["Idempotency-Key"] = key
    payload = body if body is not None else archive_body(**overrides)
    response: httpx.Response = host.client.post(
        "/v1/archives",
        headers=headers,
        files={"scan": (filename, io.BytesIO(scan if scan is not None else scan_pdf()), "application/pdf")},
        data={"body": json.dumps(payload)},
    )
    return response


def filed(host: Ehr, scan: bytes | None = None, **kwargs: Any) -> dict[str, Any]:
    """File a scan and return the ``EnvelopeView``, asserting it was accepted."""
    response = file_archive(host, scan, **kwargs)
    assert response.status_code == 201, response.text
    view: dict[str, Any] = response.json()
    return view


def error_code(response: httpx.Response) -> str:
    body: dict[str, Any] = response.json()
    return str(body["error"]["code"])
