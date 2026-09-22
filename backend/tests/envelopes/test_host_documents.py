"""Addendum 2: envelopes whose document the host's backend supplied.

What is new is how revision 1 is arrived at, so that is what these test: the hygiene check, the
two ways fields are decided, what gets stored, and what the trail says about the step from the
upload to the bytes the signer sees. Everything downstream is the base spec's, and the last few
tests are here to show that it really is -- the signing flow reads its fields and roles from the
envelope instead of a template version and is otherwise untouched.
"""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import (
    Capture,
    Conflict,
    ExplicitFields,
    FieldDef,
    Forbidden,
    Host,
    NewSigner,
    Rect,
    SignerRoleDef,
    ValidationFailed,
)
from tests.envelopes.conftest import CLINICIAN_ROLES, COSIGNED_ROLES, CTX, Bench, signers_for
from tests.envelopes.fakes import supplied_pdf

REPORT_PAGES = 25


@pytest.fixture
def host(bench: Bench, db: Session) -> Host:
    host = bench.host(db)
    bench.consent(db)
    return host


def _explicit(page: int = -1, *, role: str = "clinician") -> ExplicitFields:
    return ExplicitFields(
        fields=(
            FieldDef(
                id=f"{role}_sig",
                type="signature",
                page=page,
                rect=Rect(x=72.0, y=120.0, w=220.0, h=48.0),
                signer_role=role,
                label="Clinician signature",
            ),
        )
    )


# --------------------------------------------------------------------------- creation


def test_a_supplied_report_becomes_an_ordinary_electronic_envelope(bench: Bench, db: Session, host: Host) -> None:
    document = supplied_pdf(pages=REPORT_PAGES)
    view = bench.create_from_document(db, host, document=document)

    assert view.source == "host_document"
    assert view.kind == "electronic"
    # No template version to name, and everything else exactly as for a template envelope.
    assert view.template_key is None and view.template_version is None
    assert view.status == "created"
    assert view.signing_order == "sequential"
    assert [s.role_key for s in view.signers] == ["clinician"]
    assert view.presented_sha256 == view.current_revision_sha256
    assert bench.revisions(db, view.id) == [(1, "supplied")]

    # The upload is kept as received, beside the flattened revision it became.
    assert tuple(kind for kind, _ in bench.blobs.puts[-2:]) == ("supplied_pdf", "presented_pdf")
    upload_sha = hashlib.sha256(document).digest()
    assert bench.blobs.exists(db, upload_sha)
    assert bench.blobs.get(db, upload_sha) == document
    presented = view.presented_sha256
    assert presented is not None and bench.blobs.get(db, presented) != document  # flattened


def test_document_supplied_records_both_hashes_the_page_count_and_the_reference(
    bench: Bench, db: Session, host: Host
) -> None:
    document = supplied_pdf(pages=REPORT_PAGES)
    view = bench.create_from_document(db, host, document=document)

    assert bench.event_types(db, view.id) == ["envelope.created", "document.supplied"]
    created = bench.event_data(db, view.id, "envelope.created")
    # There is no published version to name, and the event says so rather than inventing one.
    assert created["template_key"] is None and created["template_version_id"] is None
    assert created["document_type"] == "clinical_order"

    supplied = bench.event_data(db, view.id, "document.supplied")
    assert supplied["upload_sha256"] == hashlib.sha256(document).hexdigest()
    assert view.presented_sha256 is not None
    assert supplied["presented_sha256"] == view.presented_sha256.hex()
    assert supplied["upload_sha256"] != supplied["presented_sha256"]
    assert supplied["page_count"] == REPORT_PAGES
    assert supplied["field_source"] == "named_fields"
    assert supplied["host_document_ref"] == "report-88120"


def test_the_envelope_carries_its_own_fields_and_roles(bench: Bench, db: Session, host: Host) -> None:
    view = bench.create_from_document(db, host, roles=COSIGNED_ROLES, document=_cosigned_report())

    stored = bench.field_definitions(db, view.id)
    assert set(stored) == {"fields", "signer_roles"}
    assert [r["key"] for r in stored["signer_roles"]] == ["clinician", "cosigner"]
    assert [f["id"] for f in stored["fields"]] == [
        "clinician_signature",
        "clinician_date",
        "cosigner_signature",
    ]
    # Pages are stored positive, on the document's real last page.
    assert {f["page"] for f in stored["fields"]} == {REPORT_PAGES}

    template_version_id = db.execute(
        text("SELECT template_version_id FROM envelopes WHERE id = :id"), {"id": view.id}
    ).scalar_one()
    assert template_version_id is None


def test_the_page_count_is_persisted_on_revision_one(bench: Bench, db: Session, host: Host) -> None:
    view = bench.create_from_document(db, host, document=supplied_pdf(pages=REPORT_PAGES))
    assert bench.revision_pages(db, view.id) == [(1, "supplied", REPORT_PAGES)]


def test_a_template_envelope_persists_its_page_count_too(bench: Bench, db: Session, host: Host) -> None:
    from tests.envelopes.conftest import PAGES, PATIENT_CONSENT

    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    assert bench.revision_pages(db, view.id) == [(1, "presented", PAGES)]


# --------------------------------------------------------------------------- hygiene and refusals


def test_hygiene_runs_before_anything_is_stored(bench: Bench, db: Session, host: Host) -> None:
    document = supplied_pdf(pages=REPORT_PAGES, problems=("javascript",))
    before = len(bench.blobs.puts)
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(db, host, document=document)
    assert refused.value.code == "supplied_javascript"
    assert len(bench.blobs.puts) == before
    assert db.execute(text("SELECT count(*) FROM envelopes")).scalar_one() == 0


def test_a_document_over_the_page_limit_is_refused(bench: Bench, db: Session, host: Host) -> None:
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(
            db, host, document=supplied_pdf(pages=bench.settings.max_supplied_document_pages + 1)
        )
    assert refused.value.code == "supplied_too_many_pages"


def test_a_document_type_outside_the_approved_list_is_refused(bench: Bench, db: Session, host: Host) -> None:
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(db, host, document_type="discharge_summary")
    assert refused.value.code == "document_type_not_approved"
    # Refused before the PDF is even looked at: compliance decides, whoever rendered it.
    assert bench.documents.flattened == 0


def test_a_host_document_ref_that_is_a_fact_about_a_person_is_refused(bench: Bench, db: Session, host: Host) -> None:
    # On this path the reference reaches the audit trail, so it is held to is_opaque_id.
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(db, host, host_document_ref="Marguerite Okonkwo 1971-04-02")
    assert refused.value.code == "host_document_ref_invalid"

    with pytest.raises(ValidationFailed) as also_refused:
        bench.create_from_document(db, host, patient_ref="1971-04-02")
    assert also_refused.value.code == "patient_ref_invalid"


def test_a_reference_may_be_omitted(bench: Bench, db: Session, host: Host) -> None:
    view = bench.create_from_document(db, host, host_document_ref=None)
    # The allowlist writes every declared field, so it is present and null rather than missing.
    assert bench.event_data(db, view.id, "document.supplied")["host_document_ref"] is None
    assert (
        db.execute(text("SELECT host_document_ref FROM envelopes WHERE id = :id"), {"id": view.id}).scalar_one() is None
    )


def test_a_role_with_no_signature_widget_is_refused_by_name(bench: Bench, db: Session, host: Host) -> None:
    # The report only carries the clinician's block; the co-signer's is missing.
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(db, host, roles=COSIGNED_ROLES, document=supplied_pdf(pages=REPORT_PAGES))
    assert refused.value.code == "fields_unresolved"
    assert "cosigner" in str(refused.value)


def test_widgets_no_role_claims_are_dropped(bench: Bench, db: Session, host: Host) -> None:
    document = supplied_pdf(
        pages=REPORT_PAGES,
        widgets=("clinician_signature", "clinician_date", "billing_code", "reviewer_signature"),
    )
    view = bench.create_from_document(db, host, document=document)
    stored = bench.field_definitions(db, view.id)
    assert [f["id"] for f in stored["fields"]] == ["clinician_signature", "clinician_date"]


def test_the_general_double_underscore_spelling_resolves_too(bench: Bench, db: Session, host: Host) -> None:
    document = supplied_pdf(pages=REPORT_PAGES, widgets=("clinician__attending_signature",))
    view = bench.create_from_document(db, host, document=document)
    stored = bench.field_definitions(db, view.id)
    assert [(f["id"], f["type"]) for f in stored["fields"]] == [("clinician__attending_signature", "signature")]


def test_a_flattening_that_changed_the_page_count_is_refused(bench: Bench, db: Session, host: Host) -> None:
    bench.documents.flatten_drops_a_page = True
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(db, host, document=supplied_pdf(pages=REPORT_PAGES))
    assert refused.value.code == "supplied_flatten_changed_pages"


def test_signer_roles_are_required_and_unique(bench: Bench, db: Session, host: Host) -> None:
    with pytest.raises(ValidationFailed) as empty:
        bench.create_from_document(db, host, roles=(), signers=())
    assert empty.value.code == "signer_roles_required"

    twice = (CLINICIAN_ROLES[0], CLINICIAN_ROLES[0])
    with pytest.raises(ValidationFailed) as duplicated:
        bench.create_from_document(db, host, roles=twice, signers=signers_for(CLINICIAN_ROLES, "patient-ref-001"))
    assert duplicated.value.code == "duplicate_role"


def test_the_people_rules_are_the_ones_create_applies(bench: Bench, db: Session, host: Host) -> None:
    wrong_capacity = (
        NewSigner(
            role_key="clinician",
            host_user_id="dr-0311",
            display_name="Dr Quincy Ravensworth",
            capacity="witness",
        ),
    )
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(db, host, signers=wrong_capacity)
    assert refused.value.code == "capacity_not_allowed"

    not_opaque = (
        NewSigner(
            role_key="clinician",
            host_user_id="Dr Quincy Ravensworth",
            display_name="Dr Quincy Ravensworth",
            capacity="clinician",
        ),
    )
    with pytest.raises(ValidationFailed) as also_refused:
        bench.create_from_document(db, host, signers=not_opaque)
    assert also_refused.value.code == "host_user_id_invalid"


def test_a_clinician_re_authenticates_whatever_the_request_declared(bench: Bench, db: Session, host: Host) -> None:
    # The roles arrive with the request here, so the standing rule matters more than it does for
    # a published template: a clinician signature needs an attestation whatever the host says.
    lax = (
        SignerRoleDef(
            key="clinician",
            label="Clinician",
            allowed_capacities=("clinician", "witness"),
            requires_reauth=False,
            order_index=0,
        ),
    )
    view = bench.create_from_document(db, host, roles=lax, signers=signers_for(lax, "patient-ref-001"))
    assert [s.requires_reauth for s in view.signers] == [True]
    stored = db.execute(
        text("SELECT requires_reauth FROM signers WHERE envelope_id = :id"), {"id": view.id}
    ).scalar_one()
    assert stored is True


# --------------------------------------------------------------------------- explicit rects


def test_explicit_rects_resolve_a_negative_page_to_the_real_last_page(bench: Bench, db: Session, host: Host) -> None:
    view = bench.create_from_document(
        db, host, document=supplied_pdf(pages=REPORT_PAGES, widgets=()), fields=_explicit(page=-1)
    )
    stored = bench.field_definitions(db, view.id)
    assert [f["page"] for f in stored["fields"]] == [REPORT_PAGES]
    assert bench.event_data(db, view.id, "document.supplied")["field_source"] == "explicit"


def test_explicit_rects_accept_a_positive_page_unchanged(bench: Bench, db: Session, host: Host) -> None:
    view = bench.create_from_document(
        db, host, document=supplied_pdf(pages=REPORT_PAGES, widgets=()), fields=_explicit(page=3)
    )
    assert [f["page"] for f in bench.field_definitions(db, view.id)["fields"]] == [3]


@pytest.mark.parametrize("page", [0, REPORT_PAGES + 1, -(REPORT_PAGES + 1)])
def test_a_page_outside_the_document_is_refused(bench: Bench, db: Session, host: Host, page: int) -> None:
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(
            db, host, document=supplied_pdf(pages=REPORT_PAGES, widgets=()), fields=_explicit(page=page)
        )
    assert refused.value.code == "field_page_out_of_range"


def test_a_rect_off_the_page_is_refused(bench: Bench, db: Session, host: Host) -> None:
    off_the_page = ExplicitFields(
        fields=(
            FieldDef(
                id="clinician_sig",
                type="signature",
                page=-1,
                rect=Rect(x=500.0, y=770.0, w=220.0, h=48.0),
                signer_role="clinician",
            ),
        )
    )
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(db, host, document=supplied_pdf(pages=REPORT_PAGES, widgets=()), fields=off_the_page)
    assert refused.value.code == "template_definitions_invalid"
    assert db.execute(text("SELECT count(*) FROM envelopes")).scalar_one() == 0


def test_an_explicit_field_naming_an_undeclared_role_is_refused(bench: Bench, db: Session, host: Host) -> None:
    with pytest.raises(ValidationFailed) as refused:
        bench.create_from_document(
            db,
            host,
            document=supplied_pdf(pages=REPORT_PAGES, widgets=()),
            fields=_explicit(role="pharmacist"),
        )
    assert refused.value.code == "template_definitions_invalid"


# --------------------------------------------------------------------------- downstream is unchanged


def test_the_signing_view_is_served_the_envelopes_own_fields(bench: Bench, db: Session, host: Host) -> None:
    view = bench.create_from_document(db, host, document=supplied_pdf(pages=REPORT_PAGES))
    session = bench.session(db, bench.signer_id(view, "clinician"))
    signing = bench.service.signing_view(db, session)

    assert signing.page_count == REPORT_PAGES
    assert [f.id for f in signing.fields] == ["clinician_signature", "clinician_date"]
    assert signing.signer.role_label == "Clinician"
    assert signing.signer.requires_reauth is True
    # No template name to show: the document type, which carries nothing about anybody.
    assert signing.title == "Clinical order"


def test_a_thirty_page_report_is_signed_by_a_clinician_who_re_authenticates(
    bench: Bench, db: Session, host: Host
) -> None:
    view = bench.create_from_document(db, host, document=supplied_pdf(pages=30))
    signer_id = bench.signer_id(view, "clinician")
    session = bench.session(db, signer_id, method="password+mfa")

    bench.service.present(db, session, CTX)
    # The viewed-every-page gate counts the real pages of the real document.
    with pytest.raises(ValidationFailed) as short:
        bench.service.record_viewed(db, session, 3, CTX)
    assert short.value.code == "pages_not_all_viewed"
    bench.service.record_viewed(db, session, 30, CTX)
    bench.service.accept_consent(db, session, "2026-09", CTX)

    with pytest.raises(Forbidden) as unattested:
        bench.service.sign(db, session, [_signature("clinician_signature")], CTX)
    assert unattested.value.code == "reauth_required"

    bench.reauth(db, session)
    signed = bench.service.sign(db, session, [_signature("clinician_signature")], CTX)
    assert signed.status == "completed_pending_seal"
    assert bench.revisions(db, view.id) == [(1, "supplied"), (2, "signer_applied")]
    assert bench.revision_pages(db, view.id) == [(1, "supplied", 30), (2, "signer_applied", 30)]

    event = bench.event_data(db, view.id, "signer.signed")
    assert event["reauth_used"] is True and event["reauth_scope"] == "session"


def test_a_two_role_report_signs_in_order_and_seals(bench: Bench, db: Session, host: Host) -> None:
    view = bench.create_from_document(db, host, roles=COSIGNED_ROLES, document=_cosigned_report())
    clinician = bench.signer_id(view, "clinician")
    cosigner = bench.signer_id(view, "cosigner")

    # Sequential: the co-signer cannot start until the clinician has signed.
    with pytest.raises(Conflict) as too_early:
        bench.service.assert_signer_may_start(db, host, view.id, cosigner)
    assert too_early.value.code == "out_of_order"

    for signer_id, field_id in ((clinician, "clinician_signature"), (cosigner, "cosigner_signature")):
        session = bench.session(db, signer_id, method="password+mfa")
        bench.ready_to_sign_pages(db, session, REPORT_PAGES)
        bench.reauth(db, session)
        final = bench.service.sign(db, session, [_signature(field_id)], CTX)

    assert final.status == "completed_pending_seal"
    assert bench.revisions(db, view.id) == [(1, "supplied"), (2, "signer_applied"), (3, "signer_applied")]

    sealed = bench.service.seal_pending(db, view.id)
    assert sealed.status == "sealed"
    summary = bench.documents.last_summary
    assert summary.source == "host_document"
    assert summary.host_document_ref == "report-88120"
    assert summary.template_key is None and summary.template_version is None
    assert [s.role_label for s in summary.signers] == ["Clinician", "Co-signing physician"]


def test_a_capture_for_another_role_is_still_refused(bench: Bench, db: Session, host: Host) -> None:
    view = bench.create_from_document(db, host, roles=COSIGNED_ROLES, document=_cosigned_report())
    session = bench.session(db, bench.signer_id(view, "clinician"), method="password+mfa")
    bench.ready_to_sign_pages(db, session, REPORT_PAGES)
    bench.reauth(db, session)
    with pytest.raises(Forbidden) as refused:
        bench.service.sign(db, session, [_signature("cosigner_signature")], CTX)
    assert refused.value.code == "foreign_field"


def test_a_host_document_may_supersede_a_sealed_envelope(bench: Bench, db: Session, host: Host) -> None:
    first = bench.create_from_document(db, host, document=supplied_pdf(pages=REPORT_PAGES))
    session = bench.session(db, bench.signer_id(first, "clinician"), method="password+mfa")
    bench.ready_to_sign_pages(db, session, REPORT_PAGES)
    bench.reauth(db, session)
    bench.service.sign(db, session, [_signature("clinician_signature")], CTX)
    bench.service.seal_pending(db, first.id)

    corrected = bench.create_from_document(db, host, document=supplied_pdf(pages=REPORT_PAGES + 1), supersedes=first.id)
    assert corrected.supersedes_envelope_id == first.id
    assert bench.service.get(db, host, first.id).superseded_by_envelope_id == corrected.id
    assert "envelope.superseded" in bench.event_types(db, first.id)


# --------------------------------------------------------------------------- helpers


def _cosigned_report() -> bytes:
    return supplied_pdf(
        pages=REPORT_PAGES,
        widgets=("clinician_signature", "clinician_date", "cosigner_signature"),
    )


def _signature(field_id: str) -> Capture:
    return Capture(field_id=field_id, kind="typed", typed_text="Q Ravensworth")
