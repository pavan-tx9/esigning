"""The read side added at integration: the signing view, the two download gates, the page-count
check on ``viewed``, optional roles, and the notifications a transition queues."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from esign.contracts import Capture, Conflict, Forbidden, NewSigner, NotFound, StorageUnavailable, ValidationFailed
from tests.envelopes.conftest import (
    CTX,
    HIPAA_PAIR,
    PAGES,
    PATIENT_CONSENT,
    PROCEDURE_CONSENT,
    Bench,
    TemplateSpec,
    field,
    role,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"scribbled signature bytes"


def sig(field_id: str) -> Capture:
    return Capture(field_id=field_id, kind="drawn", image_png=PNG)


def test_the_signing_view_shows_this_signers_fields_and_nobody_elses_name(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PROCEDURE_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))

    signing = bench.service.signing_view(db, session)

    assert signing.envelope_id == view.id
    assert signing.page_count == PAGES
    assert signing.title == "Procedure Consent"
    assert [f.id for f in signing.fields] == ["patient_sig", "patient_ack"]
    assert signing.other_signers == (("Witness", "pending"), ("Clinician", "pending"))
    assert signing.signer.role_key == "patient"
    assert signing.reauth_valid_until is None


def test_the_signing_view_says_until_when_a_reauthentication_holds(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    clinician_only = TemplateSpec(
        key="attestation",
        document_type="procedure_consent",
        roles=(role("clinician", "Clinician", ("clinician",), requires_reauth=True),),
        fields=(field("clinician_sig", "clinician"),),
    )
    bench.template(db, host, clinician_only)
    bench.consent(db)
    view = bench.create(
        db,
        host,
        clinician_only,
        signers=(NewSigner(role_key="clinician", host_user_id="dr-1", display_name="Dr A", capacity="clinician"),),
    )
    session = bench.session(db, bench.signer_id(view, "clinician"))
    assert bench.service.signing_view(db, session).reauth_valid_until is None

    bench.reauth(db, session)
    until = bench.service.signing_view(db, session).reauth_valid_until
    assert until is not None and until > bench.clock.now()


def test_viewed_must_claim_every_page_of_what_was_served(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.service.present(db, session, CTX)

    for claim in (0, PAGES - 1, PAGES + 1):
        with pytest.raises(ValidationFailed) as seen:
            bench.service.record_viewed(db, session, claim, CTX)
        assert seen.value.code == "pages_not_all_viewed"
    assert bench.signer_status(db, session.signer_id) == "pending"

    bench.service.record_viewed(db, session, PAGES, CTX)
    assert bench.signer_status(db, session.signer_id) == "viewed"


def test_an_optional_role_may_be_left_out_and_a_required_one_may_not(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    optional_witness = dict(role("witness", "Witness", ("witness",), order_index=1), required=False)
    spec = TemplateSpec(
        key="with_optional_witness",
        document_type="patient_consent",
        roles=(role("patient", "Patient", ("self",)), optional_witness),
        fields=(field("patient_sig", "patient"), field("witness_sig", "witness")),
    )
    bench.template(db, host, spec)
    bench.consent(db)
    patient = NewSigner(role_key="patient", host_user_id="u-1", display_name="A Person", capacity="self")
    witness = NewSigner(role_key="witness", host_user_id="u-2", display_name="B Person", capacity="witness")

    view = bench.create(db, host, spec, signers=(patient,))
    assert [s.role_key for s in view.signers] == ["patient"]
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    assert bench.service.sign(db, session, [sig("patient_sig")], CTX).status == "completed_pending_seal"

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, spec, signers=(witness,))
    assert seen.value.code == "missing_required_role"


def test_the_copy_is_only_ever_the_sealed_document(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR, signing_order="parallel")
    patient = bench.session(db, bench.signer_id(view, "patient"))
    witness = bench.session(db, bench.signer_id(view, "witness"))
    bench.ready_to_sign(db, patient)

    with pytest.raises(Forbidden):  # has not signed
        bench.service.signer_copy(db, patient, CTX)

    bench.service.sign(db, patient, [sig("patient_sig")], CTX)
    with pytest.raises(Conflict) as seen:  # the witness is still to sign
        bench.service.signer_copy(db, patient, CTX)
    assert seen.value.code == "envelope_not_complete"
    with pytest.raises(Conflict) as not_sealed:
        bench.service.sealed_document(db, host, view.id, CTX)
    assert not_sealed.value.code == "not_sealed"

    bench.ready_to_sign(db, witness)
    bench.service.sign(db, witness, [sig("witness_sig")], CTX)
    assert bench.service.signer_copy(db, patient, CTX) is None  # sealing: say so, hand out nothing
    assert "document.downloaded" not in bench.event_types(db, view.id)

    sealed = bench.service.seal_pending(db, view.id)
    assert sealed.sealed_sha256 is not None
    copy = bench.service.signer_copy(db, patient, CTX)
    assert copy is not None and copy == bench.service.sealed_document(db, host, view.id, CTX)

    downloads = [e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "document.downloaded"]
    assert [e.data["audience"] for e in downloads] == ["signer", "host"]
    assert all(e.document_sha256 == sealed.sealed_sha256 for e in downloads)

    with pytest.raises(NotFound):  # another host's envelope does not exist
        bench.service.sealed_document(db, bench.host(db, "Other EHR"), view.id, CTX)


def test_every_ending_is_announced_inside_the_transaction_that_caused_it(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)

    signed = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(signed, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [sig("patient_sig")], CTX)
    bench.service.seal_pending(db, signed.id)

    declined = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(declined, "patient"))
    bench.service.present(db, session, CTX)
    bench.service.decline(db, session, "prefers_paper", CTX)

    voided = bench.create(db, host, PATIENT_CONSENT)
    bench.service.void(db, host, voided.id, "entered_in_error", CTX)

    expired = bench.create(db, host, PATIENT_CONSENT)
    bench.clock.advance(60 * 60 * 24 * 30)
    assert bench.service.expire_due(db) == 1

    assert [(event, envelope.id, envelope.status) for event, envelope in bench.notified] == [
        ("envelope.completed", signed.id, "completed_pending_seal"),
        ("envelope.sealed", signed.id, "sealed"),
        ("envelope.declined", declined.id, "declined"),
        ("envelope.voided", voided.id, "voided"),
        ("envelope.expired", expired.id, "expired"),
    ]
    assert all(envelope.host_id == host.id for _event, envelope in bench.notified)


def test_storage_being_down_leaves_the_envelope_pending_like_a_kms_outage(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [sig("patient_sig")], CTX)

    real_put = bench.blobs.put

    def refusing_put(*args: object, **kwargs: object) -> object:
        raise StorageUnavailable("the blob store did not answer")

    bench.blobs.put = refusing_put  # type: ignore[method-assign, assignment]
    with pytest.raises(StorageUnavailable):
        bench.service.seal_pending(db, view.id)
    assert bench.status(db, view.id) == "completed_pending_seal"
    assert ("envelope.sealed", view.id) not in [(event, envelope.id) for event, envelope in bench.notified]

    bench.blobs.put = real_put  # type: ignore[method-assign]
    assert bench.service.seal_pending(db, view.id).status == "sealed"
