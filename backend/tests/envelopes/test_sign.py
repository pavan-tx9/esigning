"""Signing: preconditions, capture validation, re-authentication, revisions and evidence."""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import Capture, Conflict, Forbidden, IntegrityFailure, SessionInfo, ValidationFailed
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


def sig(field_id: str = "patient_sig") -> Capture:
    return Capture(field_id=field_id, kind="drawn", image_png=PNG)


def setup_single(bench: Bench, db: Session, spec: TemplateSpec = PATIENT_CONSENT) -> tuple[object, SessionInfo]:
    host = bench.host(db)
    bench.template(db, host, spec)
    bench.consent(db)
    view = bench.create(db, host, spec)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    return view, session


# --------------------------------------------------------------------------- happy path


def test_signing_creates_a_new_revision_and_completes_the_envelope(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db)

    result = bench.service.sign(db, session, [sig()], CTX)

    assert result.status == "completed_pending_seal"
    assert result.signers[0].status == "signed"
    assert bench.revisions(db, result.id) == [(1, "presented"), (2, "signer_applied")]
    assert bench.event_types(db, result.id)[-2:] == ["signer.signed", "envelope.completed"]

    row = db.execute(
        text("SELECT presented_sha256, current_revision_sha256, completed_at FROM envelopes WHERE id = :id"),
        {"id": result.id},
    ).one()
    assert bytes(row.presented_sha256) != bytes(row.current_revision_sha256)
    assert row.completed_at == bench.clock.now()


def test_signer_signed_records_both_hashes(bench: Bench, db: Session) -> None:
    """The bytes this signer was shown, and the revision the marks were applied to."""
    _view, session = setup_single(bench, db)
    presented = db.execute(
        text("SELECT presented_sha256 FROM signing_sessions WHERE id = :id"), {"id": session.id}
    ).scalar_one()

    result = bench.service.sign(db, session, [sig()], CTX)

    signed = next(e for e in bench.audit.list(db, "envelope", result.id) if str(e.event_type) == "signer.signed")
    assert signed.data["presented_sha256"] == bytes(presented).hex()
    assert signed.data["base_revision_sha256"] == bytes(presented).hex()
    assert signed.data["revision_no"] == 2
    assert signed.data["capture_count"] == 1
    new_sha = db.execute(
        text("SELECT current_revision_sha256 FROM envelopes WHERE id = :id"), {"id": result.id}
    ).scalar_one()
    assert signed.document_sha256 == bytes(new_sha)


def test_a_seal_job_is_enqueued_exactly_once(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db)
    result = bench.service.sign(db, session, [sig()], CTX)

    row = db.execute(
        text("SELECT attempts, completed_at FROM seal_jobs WHERE envelope_id = :id"), {"id": result.id}
    ).one()
    assert row.attempts == 0
    assert row.completed_at is None


def test_the_drawn_image_is_sanitised_stored_and_linked(bench: Bench, db: Session) -> None:
    view, session = setup_single(bench, db)

    bench.service.sign(db, session, [sig()], CTX)

    assert bench.documents.sanitized == 1
    signer_id = bench.signer_id(view, "patient")  # type: ignore[arg-type]
    row = db.execute(
        text("SELECT field_id, kind, image_sha256, typed_text FROM signature_captures WHERE signer_id = :id"),
        {"id": signer_id},
    ).one()
    assert (row.field_id, row.kind, row.typed_text) == ("patient_sig", "drawn", None)
    stored = bench.blobs.get(db, bytes(row.image_sha256))
    assert stored != PNG  # re-encoded, not the client's bytes
    assert stored == b"\x89PNG\r\n\x1a\n" + hashlib.sha256(PNG).digest()


def test_the_caption_carries_the_signer_and_the_server_clock(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db)
    result = bench.service.sign(db, session, [sig()], CTX)

    sha = db.execute(
        text("SELECT current_revision_sha256 FROM envelopes WHERE id = :id"), {"id": result.id}
    ).scalar_one()
    stamped = bench.blobs.get(db, bytes(sha)).decode(errors="replace")
    assert str(result.signers[0].id) in stamped
    assert bench.clock.now().isoformat() in stamped
    assert "patient_date" in stamped  # the date_signed field was filled from Clock, not a capture


@pytest.mark.parametrize(
    "capture",
    [
        pytest.param(Capture(field_id="patient_sig", kind="typed", typed_text="Alex Doe"), id="typed"),
        pytest.param(Capture(field_id="patient_sig", kind="click"), id="click"),
    ],
)
def test_typed_and_click_signatures_are_accepted(bench: Bench, db: Session, capture: Capture) -> None:
    _view, session = setup_single(bench, db)
    result = bench.service.sign(db, session, [capture], CTX)

    assert result.status == "completed_pending_seal"
    row = db.execute(
        text("SELECT kind, image_sha256, typed_text FROM signature_captures WHERE signer_id = :id"),
        {"id": result.signers[0].id},
    ).one()
    assert row.kind == capture.kind
    assert (row.image_sha256 is None) == (capture.kind != "drawn")


# --------------------------------------------------------------------------- preconditions


def test_signing_before_viewing_is_a_conflict(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.service.present(db, session, CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.sign(db, session, [sig()], CTX)
    assert seen.value.code == "not_viewed"
    assert bench.revisions(db, view.id) == [(1, "presented")]


def test_signing_before_consenting_is_a_conflict(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.service.present(db, session, CTX)
    bench.service.record_viewed(db, session, PAGES, CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.sign(db, session, [sig()], CTX)
    assert seen.value.code == "not_consented"


def test_signing_twice_is_a_conflict_and_makes_one_revision(bench: Bench, db: Session) -> None:
    """SPEC 12: a double submission must never produce two revisions.

    The API layer turns a repeated ``Idempotency-Key`` into the first response; underneath it, the
    service has to refuse outright, and refuse without leaving a second revision behind.
    """
    _view, session = setup_single(bench, db)
    result = bench.service.sign(db, session, [sig()], CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.sign(db, session, [sig()], CTX)
    # This signer completed the envelope, so the envelope's own status answers first.
    assert seen.value.code == "envelope_already_complete"
    assert bench.revisions(db, result.id) == [(1, "presented"), (2, "signer_applied")]
    assert bench.event_types(db, result.id).count("signer.signed") == 1


def test_signing_twice_while_others_remain_is_refused_as_already_signed(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)
    bench.service.sign(db, patient, [sig()], CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.sign(db, patient, [sig()], CTX)
    assert seen.value.code == "signer_already_signed"
    assert bench.revisions(db, view.id) == [(1, "presented"), (2, "signer_applied")]
    assert bench.event_types(db, view.id).count("signer.signed") == 1


def test_signing_a_voided_envelope_is_a_conflict(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.void(db, host, view.id, "entered_in_error", CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.sign(db, session, [sig()], CTX)
    assert seen.value.code == "envelope_voided"


# --------------------------------------------------------------------------- re-authentication


def sequential_procedure(bench: Bench, db: Session) -> tuple[object, object]:
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PROCEDURE_CONSENT, signing_order="sequential")
    return host, view


def advance_to_clinician(bench: Bench, db: Session, view: object) -> SessionInfo:
    patient = bench.session(db, bench.signer_id(view, "patient"))  # type: ignore[arg-type]
    bench.ready_to_sign(db, patient)
    bench.service.sign(
        db,
        patient,
        [sig(), Capture(field_id="patient_ack", checked=True)],
        CTX,
    )
    witness = bench.session(db, bench.signer_id(view, "witness"))  # type: ignore[arg-type]
    bench.ready_to_sign(db, witness)
    bench.service.sign(db, witness, [sig("witness_sig")], CTX)
    clinician = bench.session(db, bench.signer_id(view, "clinician"))  # type: ignore[arg-type]
    bench.ready_to_sign(db, clinician)
    return clinician


def test_a_clinician_without_fresh_reauth_is_forbidden(bench: Bench, db: Session) -> None:
    """SPEC 12: clinician sign without fresh re-auth -> forbidden."""
    _host, view = sequential_procedure(bench, db)
    clinician = advance_to_clinician(bench, db, view)

    with pytest.raises(Forbidden) as seen:
        bench.service.sign(db, clinician, [sig("clinician_sig")], CTX)
    assert seen.value.code == "reauth_required"
    assert seen.value.http_status == 403


def test_a_clinician_with_fresh_reauth_may_sign(bench: Bench, db: Session) -> None:
    _host, view = sequential_procedure(bench, db)
    clinician = advance_to_clinician(bench, db, view)
    bench.reauth(db, clinician)

    result = bench.service.sign(db, clinician, [sig("clinician_sig")], CTX)

    assert result.status == "completed_pending_seal"
    signed = [e for e in bench.audit.list(db, "envelope", result.id) if str(e.event_type) == "signer.signed"][-1]
    assert signed.data["reauth_method"] == "password+mfa"


def test_a_stale_reauth_does_not_count(bench: Bench, db: Session) -> None:
    _host, view = sequential_procedure(bench, db)
    clinician = advance_to_clinician(bench, db, view)
    bench.reauth(db, clinician)
    bench.clock.advance(bench.settings.reauth_max_age_seconds + 1)

    with pytest.raises(Forbidden) as seen:
        bench.service.sign(db, clinician, [sig("clinician_sig")], CTX)
    assert seen.value.code == "reauth_required"


def test_a_reauth_on_someone_elses_session_does_not_count(bench: Bench, db: Session) -> None:
    _host, view = sequential_procedure(bench, db)
    clinician = advance_to_clinician(bench, db, view)
    other = bench.session(db, bench.signer_id(view, "patient"))  # type: ignore[arg-type]
    bench.reauth(db, other)

    with pytest.raises(Forbidden):
        bench.service.sign(db, clinician, [sig("clinician_sig")], CTX)


def test_a_signer_whose_role_does_not_need_reauth_is_not_asked(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db)
    result = bench.service.sign(db, session, [sig()], CTX)

    signed = next(e for e in bench.audit.list(db, "envelope", result.id) if str(e.event_type) == "signer.signed")
    assert signed.data["reauth_used"] is False
    assert signed.data["reauth_method"] is None


# --------------------------------------------------------------------------- captures


def test_a_capture_for_someone_elses_field_is_forbidden(bench: Bench, db: Session) -> None:
    """SPEC 12: a capture for someone else's field is rejected."""
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)

    with pytest.raises(Forbidden) as seen:
        bench.service.sign(db, patient, [sig(), sig("witness_sig")], CTX)
    assert seen.value.code == "foreign_field"
    assert bench.revisions(db, view.id) == [(1, "presented")]
    assert bench.signer_status(db, bench.signer_id(view, "patient")) == "consented"


def test_the_service_refuses_the_foreign_field_itself(bench: Bench, db: Session) -> None:
    """Not delegated: with the document service turned into a no-op it still refuses."""
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)
    bench.documents.apply_signer_marks = lambda pdf, fields, captures, stamp: pdf  # type: ignore[method-assign]

    with pytest.raises(Forbidden):
        bench.service.sign(db, patient, [sig("witness_sig"), sig()], CTX)


def test_an_unknown_field_is_refused(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(db, session, [sig(), sig("no_such_field")], CTX)
    assert seen.value.code == "unknown_field"


def test_a_client_supplied_signing_date_is_refused(bench: Bench, db: Session) -> None:
    """SPEC section 6: date_signed is filled by the server from Clock, never by the client."""
    _view, session = setup_single(bench, db)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(
            db,
            session,
            [sig(), Capture(field_id="patient_date", kind="typed", typed_text="2020-01-01")],
            CTX,
        )
    assert seen.value.code == "client_supplied_date"


def test_a_missing_required_field_is_refused(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db, PROCEDURE_CONSENT_PATIENT_ONLY)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(db, session, [sig()], CTX)
    assert seen.value.code == "missing_required_field"


def test_an_optional_field_may_be_left_out(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db, OPTIONAL_EXTRA)
    result = bench.service.sign(db, session, [sig()], CTX)
    assert result.status == "completed_pending_seal"


def test_the_same_field_cannot_be_captured_twice(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(db, session, [sig(), sig()], CTX)
    assert seen.value.code == "duplicate_capture"


@pytest.mark.parametrize(
    "capture",
    [
        pytest.param(Capture(field_id="patient_sig", kind="drawn"), id="drawn without an image"),
        pytest.param(Capture(field_id="patient_sig", kind="typed", typed_text="   "), id="typed whitespace"),
        pytest.param(Capture(field_id="patient_sig", kind="typed"), id="typed without text"),
        pytest.param(Capture(field_id="patient_sig", kind="click", typed_text="x"), id="click with a payload"),
        pytest.param(Capture(field_id="patient_sig", kind="drawn", image_png=PNG, typed_text="x"), id="both payloads"),
        pytest.param(Capture(field_id="patient_sig", kind="click", checked=True), id="a checkbox value"),
        pytest.param(Capture(field_id="patient_sig", kind="click", text_value="x"), id="a text value"),
    ],
)
def test_a_malformed_signature_capture_is_refused(bench: Bench, db: Session, capture: Capture) -> None:
    _view, session = setup_single(bench, db)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(db, session, [capture], CTX)
    assert seen.value.code == "capture_shape_invalid"


def test_a_png_that_is_not_a_png_is_refused(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db)
    capture = Capture(field_id="patient_sig", kind="drawn", image_png=b"<svg onload=alert(1)>")

    with pytest.raises(ValidationFailed):
        bench.service.sign(db, session, [capture], CTX)


def test_checkbox_and_text_fields_carry_their_values(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db, WITH_VALUES)
    result = bench.service.sign(
        db,
        session,
        [
            sig(),
            Capture(field_id="patient_ack", checked=True),
            Capture(field_id="patient_note", text_value="Room 3"),
        ],
        CTX,
    )

    assert result.status == "completed_pending_seal"
    # Only signature marks get a capture row: signature_captures is shaped for them. The checkbox
    # and text values reach the PDF and are covered by the revision hash instead.
    rows = db.execute(
        text("SELECT field_id FROM signature_captures WHERE signer_id = :id ORDER BY field_id"),
        {"id": result.signers[0].id},
    ).all()
    assert [r.field_id for r in rows] == ["patient_sig"]

    sha = db.execute(
        text("SELECT current_revision_sha256 FROM envelopes WHERE id = :id"), {"id": result.id}
    ).scalar_one()
    stamped = bench.blobs.get(db, bytes(sha)).decode(errors="replace")
    # Checkbox and text captures carry no capture kind (SPEC 9's wire shapes have none).
    assert "patient_ack:None" in stamped
    assert "patient_note:None" in stamped
    signed = next(e for e in bench.audit.list(db, "envelope", result.id) if str(e.event_type) == "signer.signed")
    assert {"field_id": "patient_ack", "kind": "checkbox"} in signed.data["captures"]
    assert {"field_id": "patient_note", "kind": "text"} in signed.data["captures"]


def test_a_checkbox_without_a_value_is_refused(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db, WITH_VALUES)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(
            db,
            session,
            [
                sig(),
                Capture(field_id="patient_ack", kind="click"),
                Capture(field_id="patient_note", text_value="x"),
            ],
            CTX,
        )
    assert seen.value.code == "capture_shape_invalid"


# --------------------------------------------------------------------------- sessions after signing


def test_signing_leaves_this_session_alive_for_the_copy_only(bench: Bench, db: Session) -> None:
    _view, session = setup_single(bench, db)
    bench.service.sign(db, session, [sig()], CTX)

    row = db.execute(text("SELECT revoked_at FROM signing_sessions WHERE id = :id"), {"id": session.id}).one()
    assert row.revoked_at is None
    assert bench.service.may_download_copy(db, session) is True


def test_signing_revokes_the_signers_other_sessions(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    stale = bench.session(db, signer_id)
    db.execute(text("UPDATE signing_sessions SET revoked_at = NULL WHERE id = :id"), {"id": stale.id})
    session = bench.session(db, signer_id)
    db.execute(text("UPDATE signing_sessions SET revoked_at = NULL WHERE id = :id"), {"id": stale.id})
    bench.ready_to_sign(db, session)

    bench.service.sign(db, session, [sig()], CTX)

    revoked = db.execute(text("SELECT revoked_at FROM signing_sessions WHERE id = :id"), {"id": stale.id}).scalar_one()
    assert revoked is not None


def test_may_download_copy_says_no_before_anyone_has_signed(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)
    assert bench.service.may_download_copy(db, patient) is False

    bench.service.sign(db, patient, [sig()], CTX)
    # Signed, but the envelope is not complete: nothing to hand over yet.
    assert bench.service.may_download_copy(db, patient) is False


def test_may_download_copy_checks_the_session_against_the_rows(bench: Bench, db: Session) -> None:
    import dataclasses

    _view, session = setup_single(bench, db)
    bench.service.sign(db, session, [sig()], CTX)
    assert bench.service.may_download_copy(db, session) is True

    # A SessionInfo claiming a different envelope, or a signer that does not exist, gets nothing.
    assert bench.service.may_download_copy(db, dataclasses.replace(session, envelope_id=session.id)) is False
    assert bench.service.may_download_copy(db, dataclasses.replace(session, signer_id=session.id)) is False


def test_a_signer_cannot_download_another_signers_way_in(bench: Bench, db: Session) -> None:
    """A session belonging to a signer who has not signed never opens the copy."""
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    witness = bench.session(db, bench.signer_id(view, "witness"))
    bench.ready_to_sign(db, patient)
    bench.service.sign(db, patient, [sig()], CTX)
    bench.ready_to_sign(db, witness)
    bench.service.sign(db, witness, [sig("witness_sig")], CTX)

    assert bench.service.may_download_copy(db, patient) is True
    assert bench.service.may_download_copy(db, witness) is True


# --------------------------------------------------------------------------- integrity


def test_a_corrupted_base_revision_stops_the_signature(bench: Bench, db: Session) -> None:
    view, session = setup_single(bench, db)
    sha = db.execute(
        text("SELECT current_revision_sha256 FROM envelopes WHERE id = :id"),
        {"id": view.id},  # type: ignore[attr-defined]
    ).scalar_one()
    bench.blobs.corrupt(bytes(sha))

    with pytest.raises(IntegrityFailure):
        bench.service.sign(db, session, [sig()], CTX)


# --------------------------------------------------------------------------- template variants

PROCEDURE_CONSENT_PATIENT_ONLY = TemplateSpec(
    key="two_required_fields",
    document_type="patient_consent",
    roles=(role("patient", "Patient", ("self",)),),
    fields=(field("patient_sig", "patient"), field("patient_initials", "patient", field_type="initials")),
)

OPTIONAL_EXTRA = TemplateSpec(
    key="optional_extra",
    document_type="patient_consent",
    roles=(role("patient", "Patient", ("self",)),),
    fields=(
        field("patient_sig", "patient"),
        field("patient_initials", "patient", field_type="initials", required=False),
    ),
)

WITH_VALUES = TemplateSpec(
    key="with_values",
    document_type="patient_consent",
    roles=(role("patient", "Patient", ("self",)),),
    fields=(
        field("patient_sig", "patient"),
        field("patient_ack", "patient", field_type="checkbox"),
        field("patient_note", "patient", field_type="text"),
    ),
)
