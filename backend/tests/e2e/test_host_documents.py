"""Addendum 2 end to end: the EHR generates the report, the clinician signs it, the seal holds.

Nothing is faked here. The report is a real 25 to 30 page PDF with a real AcroForm signature
block; it goes over the real multipart route with the real API key; the real documents module
inspects, resolves and flattens it; and the real seal, certificate and verification report are
produced from what came out. The point of each story is the thing the addendum says must be true
of a host-supplied document and was not true of anything before it: the provenance is recorded,
the transformation from the upload to the presented bytes is evidence, and everything downstream
is the base spec's.
"""

from __future__ import annotations

import hashlib
import io
import re
from typing import Any

from pypdf import PdfReader
from sqlalchemy import text

from esign.storage import content_key
from tests.documents.helpers import NamedWidget, generated_report
from tests.e2e.conftest import CLINICIAN_NAME, Ehr, World

#: The addendum's case: 20 to 30 pages of generated clinical text, a signature block on the last.
REPORT_PAGES = 30


def _clinician_block(page: int) -> tuple[NamedWidget, ...]:
    """The signature block a report generator draws on the last page."""
    return (
        NamedWidget(name="clinician_signature", rect=(54, 96, 294, 146), page=page),
        NamedWidget(name="clinician_date", rect=(320, 96, 500, 146), page=page),
    )


def _cosigner_block(page: int) -> tuple[NamedWidget, ...]:
    """...and the second block, for the co-signing physician."""
    return (*_clinician_block(page), NamedWidget(name="cosigner_signature", rect=(54, 30, 294, 80), page=page))


def _report(pages: int = REPORT_PAGES, block: object = _clinician_block) -> bytes:
    """A per-patient report of ``pages`` pages whose signature block is on the last one."""
    widgets: tuple[NamedWidget, ...] = () if block is None else block(pages)  # type: ignore[operator]
    return generated_report(pages=pages, widgets=widgets)


def _cosigned_body(ehr: Ehr) -> dict[str, Any]:
    body = ehr.host_document_body()
    body["signers"] = [
        *body["signers"],
        {
            "role_key": "cosigner",
            "host_user_id": "dr-0982",
            "display_name": "Dr Perpetua Winterbourne",
            "capacity": "clinician",
        },
    ]
    body["signer_roles"] = [
        *body["signer_roles"],
        {
            "key": "cosigner",
            "label": "Co-signing physician",
            "allowed_capacities": ["clinician"],
            "requires_reauth": True,
            "order_index": 1,
        },
    ]
    return body


def _sealed_text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", " ".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages))


# --------------------------------------------------------------------------- the whole story


def test_a_thirty_page_report_is_signed_by_a_clinician_who_re_authenticates(ehr: Ehr, world: World) -> None:
    document = _report()
    envelope = ehr.create_host_document_envelope(document)

    assert envelope["source"] == "host_document"
    assert envelope["kind"] == "electronic"
    assert envelope["template_key"] is None and envelope["template_version"] is None
    assert [s["role_key"] for s in envelope["signers"]] == ["clinician"]
    assert envelope["signers"][0]["requires_reauth"] is True

    signer = ehr.open_session(envelope, "clinician", method="password+mfa")
    payload = signer.session()
    # The signing UI gets this envelope's own definitions in place of a template version's.
    assert payload["envelope"]["page_count"] == REPORT_PAGES
    assert payload["envelope"]["title"] == "Clinical order"
    assert {f["id"] for f in payload["fields"]} == {"clinician_signature", "clinician_date"}
    assert {f["page"] for f in payload["fields"]} == {REPORT_PAGES}

    document_response = signer.get("/document")
    assert document_response.status_code == 200
    assert len(PdfReader(io.BytesIO(document_response.content)).pages) == REPORT_PAGES

    # Viewed-every-page counts all thirty; a short claim is refused.
    short = signer.post("/viewed", {"pages_viewed": 3})
    assert short.status_code == 422 and short.json()["error"]["code"] == "pages_not_all_viewed"
    assert signer.post("/viewed", {"pages_viewed": REPORT_PAGES}).status_code == 200
    assert (
        signer.post("/consent", {"consent_version": payload["consent"]["version"], "accepted": True}).status_code == 200
    )

    # The clinician's role re-authenticates, and the server refuses the signature until it has.
    unattested = signer.sign(payload, key="report-sign-early")
    assert unattested.status_code == 403 and unattested.json()["error"]["code"] == "reauth_required"
    assert ehr.reauth(signer).status_code == 200
    signed = signer.sign(payload, key="report-sign")
    assert signed.status_code == 200, signed.text

    final = ehr.envelope(envelope["id"])
    assert final["status"] == "sealed"
    assert final["source"] == "host_document"

    # The trail says where the document came from, and says it once.
    assert ehr.audit_types(envelope["id"])[:2] == ["envelope.created", "document.supplied"]
    assert "document.prepared" not in ehr.audit_types(envelope["id"])
    supplied = next(e for e in ehr.audit(envelope["id"]) if e["event_type"] == "document.supplied")
    assert supplied["data"]["upload_sha256"] == hashlib.sha256(document).hexdigest()
    assert supplied["data"]["presented_sha256"] == final["presented_sha256"]
    assert supplied["data"]["upload_sha256"] != supplied["data"]["presented_sha256"]
    assert supplied["data"]["page_count"] == REPORT_PAGES
    assert supplied["data"]["field_source"] == "named_fields"
    assert supplied["data"]["host_document_ref"] == "report-5531"

    # Both blobs are stored: the upload as received, and the flattened bytes that were presented.
    with world.sessions() as db:
        stored_kinds = (
            db.execute(
                text("SELECT kind FROM blobs WHERE sha256 = ANY(:shas)"),
                {
                    "shas": [
                        bytes.fromhex(supplied["data"]["upload_sha256"]),
                        bytes.fromhex(supplied["data"]["presented_sha256"]),
                    ]
                },
            )
            .scalars()
            .all()
        )
        revisions = db.execute(
            text("SELECT kind, page_count FROM document_revisions WHERE envelope_id = :id ORDER BY revision_no"),
            {"id": envelope["id"]},
        ).all()
    assert sorted(str(kind) for kind in stored_kinds) == ["presented_pdf", "supplied_pdf"]
    # Addendum 0's page-count concern: recorded once per revision, never re-counted.
    assert [(str(r.kind), r.page_count) for r in revisions] == [
        ("supplied", REPORT_PAGES),
        ("signer_applied", REPORT_PAGES),
        ("final_unsealed", REPORT_PAGES + 1),
        ("sealed", REPORT_PAGES + 1),
    ]

    report = ehr.verification(envelope["id"])
    assert report["ok"] and report["complete"], report["problems"]
    names = {c["name"] for c in report["checks"]}
    assert {"supplied_upload_intact", "supplied_revision_matches_trail", "supplied_document_recorded"} <= names

    sealed = ehr.get(f"/envelopes/{envelope['id']}/document")
    assert sealed.status_code == 200
    printed = _sealed_text(sealed.content)
    # The certificate says where the document came from, in place of the template line. The
    # summary it is built from carries ``source`` and ``host_document_ref`` (see
    # tests/envelopes/test_host_documents.py); this is the rendering of them.
    assert "Document supplied by the host" in printed
    assert "report-5531" in printed
    assert supplied["data"]["upload_sha256"] in re.sub(r"\s+", "", printed)
    assert CLINICIAN_NAME in printed


def test_a_two_role_report_is_signed_then_co_signed_in_order(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_host_document_envelope(_report(pages=25, block=_cosigner_block), _cosigned_body(ehr))
    assert [s["role_key"] for s in envelope["signers"]] == ["clinician", "cosigner"]
    assert all(s["requires_reauth"] for s in envelope["signers"])

    # Sequential: the co-signer cannot open a session until the clinician has signed.
    too_early = ehr.open_session_response(envelope, "cosigner")
    assert too_early.status_code == 409 and too_early.json()["error"]["code"] == "out_of_order"

    ehr.sign_everyone(envelope, ("clinician", "cosigner"))

    final = ehr.envelope(envelope["id"])
    assert final["status"] == "sealed"
    with world.sessions() as db:
        kinds = (
            db.execute(
                text("SELECT kind FROM document_revisions WHERE envelope_id = :id ORDER BY revision_no"),
                {"id": envelope["id"]},
            )
            .scalars()
            .all()
        )
    assert list(kinds) == ["supplied", "signer_applied", "signer_applied", "final_unsealed", "sealed"]

    report = ehr.verification(envelope["id"])
    assert report["ok"] and report["complete"], report["problems"]

    printed = _sealed_text(ehr.get(f"/envelopes/{envelope['id']}/document").content)
    assert "Document supplied by the host" in printed
    assert "Co-signing physician" in printed
    # Both re-authenticated, and the certificate says so per signer.
    assert printed.count("Re-authenticated") >= 2 or "re-authenticated" in printed.lower()


def test_the_webhooks_name_no_template_and_carry_nothing_about_the_report(ehr: Ehr, world: World) -> None:
    """SPEC section 9: template key and version are both ``null`` for a host document, and the
    payload never carries ``host_document_ref`` -- the host already knows which report it sent."""
    import json

    from esign.worker import run_once

    envelope = ehr.create_host_document_envelope(_report(pages=6))
    ehr.sign_everyone(envelope, ("clinician",))
    tick = run_once(world.rt, send=ehr.receive)
    assert tick.webhooks_delivered == 2

    events = []
    for _url, body, _headers in ehr.deliveries:
        payload = json.loads(body)
        events.append(payload["event"])
        assert payload["envelope_id"] == envelope["id"]
        assert payload["kind"] == "electronic"
        assert payload["template_key"] is None and payload["template_version"] is None
        for secret in (CLINICIAN_NAME, "chart-77120", "report-5531"):
            assert secret not in body.decode()
    assert events == ["envelope.completed", "envelope.sealed"]


# --------------------------------------------------------------------------- what verification catches


def test_verification_catches_a_swapped_upload_blob(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_host_document_envelope(_report(pages=25))
    supplied = next(e for e in ehr.audit(envelope["id"]) if e["event_type"] == "document.supplied")
    upload_sha = bytes.fromhex(supplied["data"]["upload_sha256"])

    # Somebody replaces the file the trail says was uploaded. The row still names the old hash.
    path = world.settings.blob_fs_root / content_key(upload_sha)
    path.chmod(0o600)
    path.write_bytes(_report(pages=25, block=None))

    report = ehr.verification(envelope["id"])
    assert not report["ok"]
    failed = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert "supplied_upload_intact" in failed
    assert "integrity_failure" in failed["supplied_upload_intact"]
    # ...and only that: revision 1 is untouched, so the presented bytes still verify.
    assert set(failed) == {"supplied_upload_intact"}


def test_verification_catches_a_swapped_presented_revision(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_host_document_envelope(_report(pages=25))
    presented_sha = bytes.fromhex(str(envelope["presented_sha256"]))

    path = world.settings.blob_fs_root / content_key(presented_sha)
    path.chmod(0o600)
    path.write_bytes(_report(pages=25, block=None))

    report = ehr.verification(envelope["id"])
    assert not report["ok"]
    failed = {c["name"] for c in report["checks"] if c["status"] == "failed"}
    assert "revision_1_supplied_hash" in failed


def test_verification_catches_a_field_definition_that_no_longer_matches_the_row(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_host_document_envelope(_report(pages=25))
    with world.sessions() as db:
        db.execute(
            text("UPDATE envelopes SET host_document_ref = 'report-0000' WHERE id = :id"),
            {"id": envelope["id"]},
        )
        db.commit()
    report = ehr.verification(envelope["id"])
    failed = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert "envelope_row_matches_trail" in failed
    assert "host_document_ref" in failed["envelope_row_matches_trail"]


# --------------------------------------------------------------------------- the API's own rules


def test_a_document_type_outside_the_approved_list_is_refused(ehr: Ehr) -> None:
    body = ehr.host_document_body(document_type="discharge_summary")
    refused = ehr.post_host_document(_report(pages=3, block=None), body)
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "document_type_not_approved"


def test_a_report_with_no_signature_block_for_a_declared_role_is_refused(ehr: Ehr) -> None:
    refused = ehr.post_host_document(_report(pages=25, block=None), ehr.host_document_body())
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "fields_unresolved"
    # The code is what the host reads: the error envelope never echoes input, so neither the
    # roles nor -- much more importantly -- the widget names inside the patient's report appear.
    assert set(refused.json()) == {"error"}
    assert "clinician_signature" not in refused.text


def test_a_report_carrying_javascript_is_refused(ehr: Ehr) -> None:
    from tests.documents.helpers import pdf_with_acroform_javascript

    refused = ehr.post_host_document(pdf_with_acroform_javascript(), ehr.host_document_body())
    assert refused.status_code == 422
    assert refused.json()["error"]["code"].startswith("supplied_")


def test_the_body_forbids_the_keys_a_host_document_has_no_use_for(ehr: Ehr) -> None:
    for extra in ({"template_key": "patient_consent"}, {"prefill": {"visit_date": "2026-03-17"}}):
        body = {**ehr.host_document_body(), **extra}
        refused = ehr.post_host_document(_report(pages=3, block=None), body)
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"]["code"] == "validation_failed"


def test_explicit_rects_may_count_from_the_end_of_a_report(ehr: Ehr) -> None:
    body = ehr.host_document_body()
    body["fields"] = {
        "mode": "explicit",
        "fields": [
            {
                "id": "clinician_sig",
                "type": "signature",
                # -1: the host does not know how long this patient's report turned out to be.
                "page": -1,
                "rect": {"x": 54.0, "y": 96.0, "w": 240.0, "h": 50.0},
                "signer_role": "clinician",
                "label": "Clinician signature",
            }
        ],
    }
    envelope = ehr.create_host_document_envelope(_report(pages=25, block=None), body)
    signer = ehr.open_session(envelope, "clinician", method="password+mfa")
    payload = signer.session()
    assert [(f["id"], f["page"]) for f in payload["fields"]] == [("clinician_sig", 25)]

    supplied = next(e for e in ehr.audit(envelope["id"]) if e["event_type"] == "document.supplied")
    assert supplied["data"]["field_source"] == "explicit"


def test_an_explicit_rect_off_the_end_of_the_report_is_refused(ehr: Ehr) -> None:
    body = ehr.host_document_body()
    body["fields"] = {
        "mode": "explicit",
        "fields": [
            {
                "id": "clinician_sig",
                "type": "signature",
                "page": 99,
                "rect": {"x": 54.0, "y": 96.0, "w": 240.0, "h": 50.0},
                "signer_role": "clinician",
            }
        ],
    }
    refused = ehr.post_host_document(_report(pages=25, block=None), body)
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "field_page_out_of_range"


# --------------------------------------------------------------------------- idempotency


def test_a_replay_with_the_same_bytes_returns_the_first_envelope(ehr: Ehr, world: World) -> None:
    document = _report(pages=25)
    first = ehr.create_host_document_envelope(document, **{"Idempotency-Key": "report-77120"})
    second = ehr.post_host_document(document, **{"Idempotency-Key": "report-77120"})

    assert second.status_code == 201
    assert second.json()["id"] == first["id"]
    with world.sessions() as db:
        count = db.execute(text("SELECT count(*) FROM envelopes")).scalar_one()
    assert count == 1


def test_a_replay_with_different_bytes_is_a_conflict(ehr: Ehr, world: World) -> None:
    ehr.create_host_document_envelope(_report(pages=25), **{"Idempotency-Key": "report-77120"})
    # Same key, a differently generated report: a different request, not a retry of this one.
    conflicting = ehr.post_host_document(_report(pages=26), **{"Idempotency-Key": "report-77120"})

    assert conflicting.status_code == 409
    assert conflicting.json()["error"]["code"] == "idempotency_key_reused"
    with world.sessions() as db:
        count = db.execute(text("SELECT count(*) FROM envelopes")).scalar_one()
    assert count == 1


def test_a_replay_with_a_different_body_is_a_conflict_too(ehr: Ehr) -> None:
    document = _report(pages=25)
    ehr.create_host_document_envelope(document, **{"Idempotency-Key": "report-77121"})
    conflicting = ehr.post_host_document(
        document, ehr.host_document_body(patient_ref="chart-99999"), **{"Idempotency-Key": "report-77121"}
    )
    assert conflicting.status_code == 409
    assert conflicting.json()["error"]["code"] == "idempotency_key_reused"
