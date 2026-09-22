"""The cover page on its own, without a database anywhere near it.

``build_archive_cover`` is a pure function of its summary, like everything else the documents
module writes: same input, same bytes. It is also a page this service will seal, so it has to pass
the same hygiene check a host's upload does -- no form fields, no scripts, nothing active -- and
it has to say, in words a reader will actually read, what the seal does and does not prove.
"""

from __future__ import annotations

import io
from dataclasses import replace
from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID

import pytest
from pypdf import PdfReader

from esign.config import Settings
from esign.contracts import ArchiveCoverSummary, Attestation, DocumentService, PaperSigner, ValidationFailed
from esign.documents import build_document_service
from tests.archives.conftest import scan_pdf
from tests.documents.helpers import placed_text

ENVELOPE_ID = UUID("6f1c7bd6-1f5a-4a6c-9f4f-9f0d9f7b1a55")
ATTESTED_AT = datetime(2026, 3, 17, 14, 30, tzinfo=UTC)

ATTESTATION = Attestation(
    staff_user_id="staff-4417",
    staff_display_name="Bernadette Quillfeather-Ngata",
    statement="true_copy",
    original_disposition="returned_to_signer",
    paper_signers=(
        PaperSigner(display_name="Aurelio Vandenbrouck-Mbeki", capacity="self"),
        PaperSigner(display_name="Perpetua Thistlewood", capacity="witness"),
    ),
)

COVER = ArchiveCoverSummary(
    envelope_id=ENVELOPE_ID,
    document_type="patient_consent",
    paper_signed_on=date(2026, 3, 10),
    attestation=ATTESTATION,
    attested_at=ATTESTED_AT,
    scan_sha256=bytes(range(32)),
    scan_page_count=4,
)


def summary(**overrides: Any) -> ArchiveCoverSummary:
    return replace(COVER, **overrides)


@pytest.fixture
def documents(settings_no_db: Settings) -> DocumentService:
    return build_document_service(settings_no_db)


def _text(pdf: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf))
    return " ".join(" ".join((page.extract_text() or "").split()) for page in reader.pages)


def test_the_cover_is_exactly_one_page(documents: DocumentService) -> None:
    assert len(PdfReader(io.BytesIO(documents.build_archive_cover(COVER))).pages) == 1


def test_it_says_everything_the_addendum_asks_for(documents: DocumentService) -> None:
    printed = _text(documents.build_archive_cover(COVER))
    assert "Scanned copy of a document signed on paper" in printed
    assert "patient_consent" in printed
    assert "2026-03-10" in printed  # the date on the paper
    assert "2026-03-17 14:30:00 UTC" in printed  # when it was filed, and by whom
    assert "Bernadette Quillfeather-Ngata" in printed
    assert "staff-4417" in printed
    assert "returned to the person who signed it" in printed
    assert "Aurelio Vandenbrouck-Mbeki" in printed and "Perpetua Thistlewood" in printed
    assert str(ENVELOPE_ID) in printed
    assert bytes(range(32)).hex() in printed.replace(" ", "")
    assert "has not changed since it was filed" in printed
    assert "does not prove that the signature on the paper is genuine" in printed


def test_the_same_summary_gives_the_same_bytes(documents: DocumentService) -> None:
    """A revision's hash only means something if the page it describes is reproducible."""
    assert documents.build_archive_cover(COVER) == documents.build_archive_cover(COVER)
    assert documents.build_archive_cover(COVER) != documents.build_archive_cover(summary(scan_page_count=5))


def test_the_cover_passes_the_hygiene_check_it_will_be_sealed_under(documents: DocumentService) -> None:
    """Whatever we put inside a seal has to survive the rules we hold a host's upload to."""
    pdf = documents.build_archive_cover(COVER)
    info = documents.inspect_template_pdf(pdf)
    assert info.page_count == 1
    root = str(PdfReader(io.BytesIO(pdf)).trailer["/Root"].get_object())
    assert "/AcroForm" not in root
    assert "/JavaScript" not in root


def test_a_long_name_does_not_break_the_page(documents: DocumentService) -> None:
    long_name = "Wilhelmina " + "Featherstonehaugh-" * 12 + "Ngata"
    pdf = documents.build_archive_cover(
        summary(
            attestation=replace(
                ATTESTATION,
                staff_display_name=long_name,
                original_disposition="destroyed_per_policy",
                paper_signers=tuple(
                    PaperSigner(display_name=f"{long_name} {index}", capacity="self") for index in range(6)
                ),
            )
        )
    )
    assert len(PdfReader(io.BytesIO(pdf)).pages) == 1
    assert "destroyed under the practice's retention policy" in _text(pdf)


#: What ``archives.service`` lets through: twenty paper signers, each named up to 200 characters.
#: The cover has to survive the worst filing the API will accept, not the typical one.
MAX_PAPER_SIGNERS = 20
MAX_NAME_CHARS = 200

#: Where the footer sits. Anything drawn below it is outside the page a reader ever sees.
PAGE_FLOOR = 54.0 - 18.0


def crowded_name(seed: str) -> str:
    return (f"{seed} " + "Featherstonehaugh-Ngata " * 20)[:MAX_NAME_CHARS].strip()


def crowded_cover() -> ArchiveCoverSummary:
    return summary(
        attestation=replace(
            ATTESTATION,
            staff_display_name=crowded_name("Bernadette"),
            original_disposition="destroyed_per_policy",
            paper_signers=tuple(
                PaperSigner(display_name=crowded_name(f"Signatory {index}"), capacity="witness")
                for index in range(MAX_PAPER_SIGNERS)
            ),
        )
    )


def test_the_most_crowded_cover_the_api_accepts_still_fits_on_the_page(documents: DocumentService) -> None:
    """Nothing is drawn off the bottom of the cover, whatever was filed.

    The page is fixed at one page, so a signer list long enough to run past the bottom margin used
    to push the attestation, the scan's hash and the "what the seal proves" sentence to a negative
    y -- outside the MediaBox, inside the sealed bytes, and silently: the seal succeeded and the
    document was stored. The sentence is the reason the page exists, so it is the one thing that
    may never be crowded out.
    """
    pdf = documents.build_archive_cover(crowded_cover())

    assert len(PdfReader(io.BytesIO(pdf)).pages) == 1
    lowest = min(run.origin[1] for run in placed_text(pdf))
    assert lowest >= PAGE_FLOOR, f"a line was drawn at y={lowest}, below the page's footer"

    printed = _text(pdf)
    assert "does not prove that the signature on the paper is genuine" in printed
    assert bytes(range(32)).hex() in printed.replace(" ", "")  # the scan's digest
    assert "2026-03-17 14:30:00 UTC" in printed  # who attested, and when


def test_the_signers_it_cannot_fit_are_counted_and_pointed_at_the_certificate(documents: DocumentService) -> None:
    """A truncated list says it is truncated, and says where the rest is.

    The certificate of completion paginates and lists every paper signer, so the information is
    not lost from the sealed bytes -- but a reader of the cover has to be told that.
    """
    printed = _text(documents.build_archive_cover(crowded_cover()))

    shown = printed.count("Signatory ")
    assert 0 < shown < MAX_PAPER_SIGNERS
    assert f"and {MAX_PAPER_SIGNERS - shown} more, listed on the certificate of completion" in printed


def test_a_short_list_is_printed_whole_with_no_notice(documents: DocumentService) -> None:
    printed = _text(documents.build_archive_cover(COVER))
    assert "Aurelio Vandenbrouck-Mbeki" in printed and "Perpetua Thistlewood" in printed
    assert "listed on the certificate of completion" not in printed


def test_inspect_scan_pdf_applies_the_scan_bounds_and_scan_codes(settings_no_db: Settings) -> None:
    """A 100-page scan passes the check a 50-page template would fail, and the refusal codes say
    ``scan`` so a host knows which file they are about."""
    documents = build_document_service(settings_no_db.model_copy(update={"max_scan_pages": 3, "max_template_pages": 1}))
    two_pages = scan_pdf(pages=2)
    assert documents.inspect_scan_pdf(two_pages).page_count == 2
    with pytest.raises(ValidationFailed) as as_template:
        documents.inspect_template_pdf(two_pages)
    assert as_template.value.code == "template_too_many_pages"
    with pytest.raises(ValidationFailed) as too_many:
        documents.inspect_scan_pdf(scan_pdf(pages=4))
    assert too_many.value.code == "scan_too_many_pages"


def test_something_that_is_not_a_pdf_is_refused_before_it_is_ever_filed(documents: DocumentService) -> None:
    with pytest.raises(ValidationFailed) as refused:
        documents.inspect_template_pdf(b"%PDF-1.7\nnot really")
    assert refused.value.code.startswith(("pdf_", "template_"))
