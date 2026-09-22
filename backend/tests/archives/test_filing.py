"""Filing a scan, end to end: sealed, verified, and the record it leaves behind.

The addendum's promise is that a paper-signed document filed here enjoys "the same write-once
storage, seal, timestamp, audit trail and verification as an electronic signature". These tests
are that sentence, checked one clause at a time.
"""

from __future__ import annotations

import io
import json
import re
from typing import Any

from pypdf import PdfReader
from sqlalchemy import text

from esign.audit.canonical import archive_attested_detail_digest
from esign.worker import run_once
from tests.archives.conftest import (
    PAPER_SIGNED_ON,
    PAPER_SIGNER_NAME,
    STAFF_NAME,
    STAFF_USER_ID,
    error_code,
    file_archive,
    filed,
    image_only_scan_pdf,
    scan_pdf,
)
from tests.e2e.conftest import Ehr, World


def _sealed_text(host: Ehr, envelope_id: str) -> str:
    response = host.get(f"/envelopes/{envelope_id}/document")
    assert response.status_code == 200, response.text
    reader = PdfReader(io.BytesIO(response.content))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_a_filed_scan_is_sealed_and_verifies(host: Ehr) -> None:
    """The happy path: file, seal, fetch, verify. Everything the base spec promises an envelope."""
    scan = scan_pdf(pages=3)
    view = filed(host, scan)
    assert view["kind"] == "paper_archive"
    # No template, no signing order, no signers: there is nobody in this system who signed.
    assert (view["template_key"], view["template_version"], view["signing_order"]) == (None, None, None)
    assert view["signers"] == []
    assert view["paper_signed_on"] == PAPER_SIGNED_ON
    assert view["attested_at"] is not None
    # The scan is revision 1 and the last revision: nothing is ever applied to it.
    assert view["presented_sha256"] == view["current_revision_sha256"]

    after = host.envelope(view["id"])
    assert after["status"] == "sealed", after
    assert after["sealed_sha256"] is not None
    assert after["kind"] == "paper_archive"

    report = host.verification(view["id"])
    assert report["ok"] is True, report["problems"]
    assert report["complete"] is True, report["problems"]


def test_the_trail_is_the_one_the_addendum_describes(host: Ehr) -> None:
    view = filed(host)
    assert host.audit_types(view["id"])[:5] == [
        "archive.created",
        "archive.attested",
        "document.finalized",
        "document.sealed",
        "document.stored",
    ]
    events = {e["event_type"]: e for e in host.audit(view["id"])}
    created = events["archive.created"]
    assert created["actor"]["role"] == "host"
    assert created["document_sha256"] == view["presented_sha256"]
    assert created["data"]["document_type"] == "patient_consent"
    assert created["data"]["page_count"] == 2
    assert created["data"]["scan_sha256"] == view["presented_sha256"]

    attested = events["archive.attested"]
    # The staff member is the actor, by opaque id. The signature on the paper is not theirs and
    # the trail never says it is: what they attest to is the copy.
    assert attested["actor"] == {
        "user_id": STAFF_USER_ID,
        "role": "staff",
        "capacity": None,
        "on_behalf_of": None,
    }
    # Names by digest, never as text: one joint SHA-256 over the attesting staff member's display
    # name, the ordered paper signers and the paper signing date. That is what lets verification
    # and the seal contradict a rewritten ``attestation`` column, which for an archive carries the
    # entire attribution -- there is no signer row, no session and no stamped revision behind it.
    assert attested["data"] == {
        "staff_user_id": STAFF_USER_ID,
        "statement": "true_copy",
        "original_disposition": "retained",
        "paper_signer_count": 1,
        "attested_detail_sha256": archive_attested_detail_digest(
            staff_display_name=STAFF_NAME,
            paper_signers=[(PAPER_SIGNER_NAME, "self")],
            paper_signed_on=PAPER_SIGNED_ON,
        ).hex(),
    }
    # And the digest is the only place any of them appears.
    assert STAFF_NAME not in json.dumps(attested)
    assert PAPER_SIGNER_NAME not in json.dumps(attested)
    assert PAPER_SIGNED_ON not in json.dumps(attested)


def test_the_scan_is_stored_write_once_as_revision_one(host: Ehr, world: World) -> None:
    scan = scan_pdf(pages=2)
    view = filed(host, scan)
    with world.sessions() as db:
        revisions = db.execute(
            text(
                "SELECT revision_no, kind, sha256 FROM document_revisions WHERE envelope_id = :id ORDER BY revision_no"
            ),
            {"id": view["id"]},
        ).all()
        blob_kind = db.execute(
            text("SELECT kind FROM blobs WHERE sha256 = :sha"),
            {"sha": bytes.fromhex(view["presented_sha256"])},
        ).scalar_one()
    assert [(r.revision_no, r.kind) for r in revisions] == [
        (1, "scan"),
        (2, "final_unsealed"),
        (3, "sealed"),
    ]
    assert bytes(revisions[0].sha256).hex() == view["presented_sha256"]
    assert blob_kind == "scan_pdf"


def test_the_sealed_document_is_cover_then_scan_then_certificate(host: Ehr) -> None:
    """The cover goes *before* the scan, inside the same sealed bytes (addendum, Documents)."""
    scan = scan_pdf(pages=3, text="Procedure consent")
    view = filed(host, scan)
    response = host.get(f"/envelopes/{view['id']}/document")
    assert response.status_code == 200, response.text
    reader = PdfReader(io.BytesIO(response.content))
    pages = [page.extract_text() or "" for page in reader.pages]

    assert "Scanned copy of a document signed on paper" in pages[0]
    assert "Procedure consent -- page 1" in pages[1]
    assert "Procedure consent -- page 3" in pages[3]
    assert "Certificate of completion" in pages[4]
    assert len(pages) >= 5  # cover, three scanned pages, and the certificate


def test_the_cover_says_what_the_seal_does_and_does_not_prove(host: Ehr) -> None:
    view = filed(host)
    printed = re.sub(r"\s+", " ", _sealed_text(host, view["id"]))

    assert "Scanned copy of a document signed on paper" in printed
    assert "has not changed since it was filed" in printed
    assert "does not prove that the signature on the paper is genuine" in printed
    # The facts a reader of the paper needs: what, when, who, and what became of the original.
    assert "patient_consent" in printed
    assert PAPER_SIGNED_ON in printed
    assert STAFF_NAME in printed
    assert STAFF_USER_ID in printed
    assert PAPER_SIGNER_NAME in printed
    assert "kept by the practice" in printed
    assert view["id"] in printed
    assert view["presented_sha256"] in printed.replace(" ", "")


def test_the_certificate_prints_the_attestation_instead_of_a_signer_table(host: Ehr) -> None:
    view = filed(host)
    printed = re.sub(r"\s+", " ", _sealed_text(host, view["id"]))
    assert "Certificate of completion" in printed
    assert "Attestation" in printed
    assert "This scan is a complete and accurate copy of the paper document." in printed
    # No signer table: nobody authenticated, consented or clicked anything in this system.
    assert "Authentication" not in printed
    assert "Consent version" not in printed


def test_an_image_only_scan_is_accepted(host: Ehr) -> None:
    """A page that is one picture and no text is what a scanner produces, and is fine."""
    view = filed(host, image_only_scan_pdf(pages=2))
    assert host.envelope(view["id"])["status"] == "sealed"
    assert host.verification(view["id"])["ok"] is True


def test_the_webhook_fires_for_the_seal_and_carries_ids_only(host: Ehr, world: World) -> None:
    view = filed(host)
    run_once(world.rt, send=host.receive)
    payloads = [_json(body) for _url, body, _headers in host.deliveries]
    sealed = [p for p in payloads if p["event"] == "envelope.sealed"]
    assert len(sealed) == 1, payloads
    assert sealed[0]["envelope_id"] == view["id"]
    assert sealed[0]["kind"] == "paper_archive"
    assert sealed[0]["template_key"] is None and sealed[0]["template_version"] is None
    assert sealed[0]["signers"] == []
    # A paper archive fires envelope.sealed and envelope.voided only (SPEC section 9).
    assert [p["event"] for p in payloads] == ["envelope.sealed"]


def test_a_retry_with_the_same_key_files_one_archive(host: Ehr, world: World) -> None:
    scan = scan_pdf()
    first = file_archive(host, scan, key="archive-1")
    second = file_archive(host, scan, key="archive-1")
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    with world.sessions() as db:
        assert db.execute(text("SELECT count(*) FROM envelopes")).scalar_one() == 1
        assert db.execute(text("SELECT count(*) FROM document_revisions WHERE kind = 'scan'")).scalar_one() == 1


def test_the_same_key_with_a_different_scan_is_a_conflict(host: Ehr) -> None:
    """The digest covers the scan: a second document under one key is a different request."""
    assert file_archive(host, scan_pdf(pages=1), key="archive-2").status_code == 201
    clash = file_archive(host, scan_pdf(pages=2), key="archive-2")
    assert clash.status_code == 409
    assert error_code(clash) == "idempotency_key_reused"


def test_another_hosts_archive_is_not_found(host: Ehr, world: World) -> None:
    view = filed(host)
    stranger = world.host("Other EHR")
    assert stranger.get(f"/envelopes/{view['id']}").status_code == 404
    assert stranger.get(f"/envelopes/{view['id']}/document").status_code == 404
    assert stranger.get(f"/envelopes/{view['id']}/audit").status_code == 404


def _json(body: bytes) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(body)
    return payload
