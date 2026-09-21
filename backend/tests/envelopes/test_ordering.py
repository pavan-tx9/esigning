"""Sequential and parallel signing order (SPEC section 3 and SPEC 12)."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import Capture, Conflict
from tests.envelopes.conftest import CTX, HIPAA_PAIR, PROCEDURE_CONSENT, Bench

PNG = b"\x89PNG\r\n\x1a\n" + b"scribbled signature bytes"


def sig(field_id: str) -> Capture:
    return Capture(field_id=field_id, kind="drawn", image_png=PNG)


def test_sequential_order_gates_session_creation(bench: Bench, db: Session) -> None:
    """SPEC section 3: sequential order gates session creation on all earlier signers signing."""
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PROCEDURE_CONSENT, signing_order="sequential")
    patient, witness, clinician = (bench.signer_id(view, key) for key in ("patient", "witness", "clinician"))

    bench.service.assert_signer_may_start(db, host, view.id, patient)
    for later in (witness, clinician):
        with pytest.raises(Conflict) as seen:
            bench.service.assert_signer_may_start(db, host, view.id, later)
        assert seen.value.code == "out_of_order"


def test_each_signer_opens_as_the_one_before_finishes(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PROCEDURE_CONSENT, signing_order="sequential")
    patient, witness, clinician = (bench.signer_id(view, key) for key in ("patient", "witness", "clinician"))

    patient_session = bench.session(db, patient)
    bench.ready_to_sign(db, patient_session)
    bench.service.sign(db, patient_session, [sig("patient_sig"), Capture("patient_ack", "click", checked=True)], CTX)

    bench.service.assert_signer_may_start(db, host, view.id, witness)
    with pytest.raises(Conflict):
        bench.service.assert_signer_may_start(db, host, view.id, clinician)

    witness_session = bench.session(db, witness)
    bench.ready_to_sign(db, witness_session)
    bench.service.sign(db, witness_session, [sig("witness_sig")], CTX)

    bench.service.assert_signer_may_start(db, host, view.id, clinician)


def test_a_later_signer_with_a_session_still_cannot_present_or_sign(bench: Bench, db: Session) -> None:
    """Defence in depth: the order rule is checked on every command, not only when a session opens."""
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PROCEDURE_CONSENT, signing_order="sequential")
    witness_session = bench.session(db, bench.signer_id(view, "witness"))

    with pytest.raises(Conflict) as seen:
        bench.service.present(db, witness_session, CTX)
    assert seen.value.code == "out_of_order"


def test_a_sequential_envelope_seals_only_after_the_last_signer(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PROCEDURE_CONSENT, signing_order="sequential")

    for role_key, captures in (
        ("patient", [sig("patient_sig"), Capture("patient_ack", "click", checked=True)]),
        ("witness", [sig("witness_sig")]),
    ):
        session = bench.session(db, bench.signer_id(view, role_key))
        bench.ready_to_sign(db, session)
        bench.service.sign(db, session, captures, CTX)
        assert bench.status(db, view.id) == "in_progress"

    clinician = bench.session(db, bench.signer_id(view, "clinician"))
    bench.ready_to_sign(db, clinician)
    bench.reauth(db, clinician)
    result = bench.service.sign(db, clinician, [sig("clinician_sig")], CTX)

    assert result.status == "completed_pending_seal"
    assert bench.revisions(db, view.id) == [
        (1, "presented"),
        (2, "signer_applied"),
        (3, "signer_applied"),
        (4, "signer_applied"),
    ]


def test_each_signer_signs_on_top_of_the_previous_revision(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)

    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)
    bench.service.sign(db, patient, [sig("patient_sig")], CTX)
    after_first = db.execute(
        text("SELECT current_revision_sha256 FROM envelopes WHERE id = :id"), {"id": view.id}
    ).scalar_one()

    witness = bench.session(db, bench.signer_id(view, "witness"))
    bench.ready_to_sign(db, witness)
    bench.service.sign(db, witness, [sig("witness_sig")], CTX)

    events = [e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "signer.signed"]
    assert events[1].data["base_revision_sha256"] == bytes(after_first).hex()
    assert events[1].data["presented_sha256"] == bytes(after_first).hex()


def test_parallel_signers_may_go_in_any_order(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR, signing_order="parallel")

    witness = bench.session(db, bench.signer_id(view, "witness"))
    bench.ready_to_sign(db, witness)
    bench.service.sign(db, witness, [sig("witness_sig")], CTX)
    assert bench.status(db, view.id) == "in_progress"

    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)
    result = bench.service.sign(db, patient, [sig("patient_sig")], CTX)
    assert result.status == "completed_pending_seal"


def test_a_parallel_signer_sees_a_document_that_moved_under_them(bench: Bench, db: Session) -> None:
    """The presented hash and the base revision hash diverge, and both are in the trail."""
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)

    patient = bench.session(db, bench.signer_id(view, "patient"))
    witness = bench.session(db, bench.signer_id(view, "witness"))
    bench.ready_to_sign(db, patient)
    bench.ready_to_sign(db, witness)  # both were shown revision 1

    bench.service.sign(db, witness, [sig("witness_sig")], CTX)
    bench.service.sign(db, patient, [sig("patient_sig")], CTX)

    signed = [e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "signer.signed"]
    last = signed[-1]
    assert last.data["presented_sha256"] == view.presented_sha256.hex()  # type: ignore[union-attr]
    assert last.data["base_revision_sha256"] != last.data["presented_sha256"]
