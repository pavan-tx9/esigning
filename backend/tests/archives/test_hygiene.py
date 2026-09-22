"""What a scan has to be before it is filed.

A scan is the one whole PDF a host hands us outside of a template upload, so it goes through
exactly the template hygiene rules -- nothing encrypted, scripted, XFA-bearing, attachment-bearing
or already signed -- under the scan bounds rather than the template ones. Everything here is a
refusal with a stable code and no input echoed back, checked before anything is stored: a refused
request leaves no blob, no envelope and no audit event.
"""

from __future__ import annotations

from sqlalchemy import text

from tests.archives.conftest import archive_body, attestation, error_code, file_archive, scan_pdf
from tests.documents.helpers import (
    pdf_with_embedded_file,
    pdf_with_javascript,
    pdf_with_launch_action,
    pdf_with_signature_field,
    pdf_with_xfa,
)
from tests.e2e.conftest import Ehr, World


def test_an_active_or_signed_scan_is_refused(host: Ehr) -> None:
    for scan, code in (
        (pdf_with_javascript(), "scan_javascript"),
        (pdf_with_xfa(), "scan_xfa"),
        (pdf_with_embedded_file(), "scan_embedded_file"),
        (pdf_with_launch_action(), "scan_forbidden_action"),
        (pdf_with_signature_field(), "scan_already_signed"),
    ):
        response = file_archive(host, scan)
        assert response.status_code == 422, response.text
        assert error_code(response) == code


def test_something_that_is_not_a_pdf_is_refused(host: Ehr) -> None:
    response = file_archive(host, b"%PNG\r\n\x1a\n not a pdf at all", filename="scan.pdf")
    assert response.status_code == 422
    assert error_code(response).startswith("scan_")


def test_a_scan_with_too_many_pages_is_refused_at_the_scan_limit(host: Ehr, world: World) -> None:
    """The scan bound, not the template one: 100 pages are allowed where 50 would be for a
    template, because a rasterised consent packet is long."""
    assert world.settings.max_scan_pages > world.settings.max_template_pages
    ok = file_archive(host, scan_pdf(pages=world.settings.max_template_pages + 5))
    assert ok.status_code == 201, ok.text

    too_many = file_archive(host, scan_pdf(pages=world.settings.max_scan_pages + 1))
    assert too_many.status_code == 422
    assert error_code(too_many) == "scan_too_many_pages"


def test_a_scan_over_the_byte_limit_is_refused(host: Ehr, world: World) -> None:
    """The route refuses the part itself, so the code is about the scan and not about the
    request around it."""
    oversized = b"%PDF-1.7\n" + b"0" * (world.settings.max_scan_bytes + 1)
    response = file_archive(host, oversized)
    assert response.status_code in (413, 422)
    if response.status_code == 422:
        assert error_code(response) == "scan_too_large"


def test_an_unapproved_document_type_is_refused(host: Ehr) -> None:
    response = file_archive(host, document_type="controlled_substance_script")
    assert response.status_code == 422
    assert error_code(response) == "document_type_not_approved"


def test_a_date_on_the_paper_in_the_future_is_refused(host: Ehr) -> None:
    response = file_archive(host, paper_signed_on="2026-03-18")
    assert response.status_code == 422
    assert error_code(response) == "paper_signed_on_in_future"


def test_identifiers_that_are_facts_about_a_person_are_refused(host: Ehr) -> None:
    """``patient_ref`` and the attesting ``staff_user_id`` reach the audit trail, so neither may
    be a name or a date (SPEC section 4)."""
    named = file_archive(host, attestation=attestation(staff_user_id="Bernadette Quillfeather"))
    assert named.status_code == 422
    assert error_code(named) == "host_user_id_invalid"

    dated = file_archive(host, patient_ref="1971-04-02")
    assert dated.status_code == 422
    assert error_code(dated) == "host_user_id_invalid"


def test_an_attestation_without_a_paper_signer_is_refused(host: Ehr) -> None:
    response = file_archive(host, attestation=attestation(paper_signers=[]))
    assert response.status_code == 422
    assert error_code(response) == "validation_failed"


def test_an_unknown_statement_or_disposition_is_refused(host: Ehr) -> None:
    for overrides in (
        {"statement": "close_enough"},
        {"original_disposition": "shredded_probably"},
    ):
        response = file_archive(host, attestation=attestation(**overrides))
        assert response.status_code == 422
        assert error_code(response) == "validation_failed"


def test_a_body_that_looks_like_an_electronic_envelope_is_refused(host: Ehr) -> None:
    """Unknown keys are refused rather than dropped: an archive has no template and no signers,
    and a host that thinks otherwise has a bug worth hearing about."""
    body = archive_body()
    body["signers"] = [{"role_key": "patient"}]
    response = file_archive(host, body=body)
    assert response.status_code == 422
    assert error_code(response) == "validation_failed"


def test_a_refused_scan_leaves_nothing_behind(host: Ehr, world: World) -> None:
    assert file_archive(host, pdf_with_javascript()).status_code == 422
    with world.sessions() as db:
        assert db.execute(text("SELECT count(*) FROM envelopes")).scalar_one() == 0
        assert db.execute(text("SELECT count(*) FROM blobs")).scalar_one() == 0
        assert db.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 0


def test_an_unauthenticated_request_files_nothing(host: Ehr, world: World) -> None:
    import io
    import json

    response = host.client.post(
        "/v1/archives",
        files={"scan": ("scan.pdf", io.BytesIO(scan_pdf()), "application/pdf")},
        data={"body": json.dumps(archive_body())},
    )
    assert response.status_code == 401
    with world.sessions() as db:
        assert db.execute(text("SELECT count(*) FROM envelopes")).scalar_one() == 0
