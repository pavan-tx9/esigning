"""Guards a sceptical reviewer asks about: the places where the module could quietly certify,
stamp or record something the record does not actually support.

Each test here pins a rule that is easy to lose in a refactor and expensive to lose in court:
the trail's description of a capture comes from the template rather than the browser, a signature
has to leave a mark, a certificate never quotes a chain it has not verified or a completion time
it has not been given, and the strings that reach the sealed bytes are bounded.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import (
    Capture,
    Conflict,
    EnvelopeView,
    IntegrityFailure,
    NewSigner,
    SessionInfo,
    ValidationFailed,
)
from esign.ids import new_id
from tests.envelopes.conftest import (
    CTX,
    HIPAA_PAIR,
    PAGES,
    PATIENT_CONSENT,
    Bench,
    TemplateSpec,
    field,
    role,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"scribbled signature bytes"


def sig(field_id: str = "patient_sig") -> Capture:
    return Capture(field_id=field_id, kind="drawn", image_png=PNG)


#: A patient with a signature, a checkbox and a free-text field: one of each capture shape.
WITH_VALUES = TemplateSpec(
    key="with_values_guard",
    document_type="patient_consent",
    roles=(role("patient", "Patient", ("self",)),),
    fields=(
        field("patient_sig", "patient"),
        field("patient_ack", "patient", field_type="checkbox"),
        field("patient_note", "patient", field_type="text", required=False),
    ),
)

#: Every field this signer has is optional, so they can offer no captures at all.
ALL_OPTIONAL = TemplateSpec(
    key="all_optional_guard",
    document_type="patient_consent",
    roles=(role("patient", "Patient", ("self",)),),
    fields=(field("patient_sig", "patient", required=False),),
)


SessionFactory = Callable[[], AbstractContextManager[Session]]


def ready(bench: Bench, db: Session, spec: TemplateSpec = PATIENT_CONSENT) -> tuple[EnvelopeView, SessionInfo]:
    """A host, a published template, an envelope and a session presented, viewed and consented."""
    host = bench.host(db)
    bench.template(db, host, spec)
    bench.consent(db)
    view = bench.create(db, host, spec)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    return view, session


def signed_and_pending(bench: Bench, db: Session) -> EnvelopeView:
    """An envelope with every signature in, waiting for its seal."""
    view, session = ready(bench, db)
    bench.service.sign(db, session, [sig()], CTX)
    return view


# ------------------------------------------------- the trail describes the template, not the client


def test_the_trail_takes_a_capture_kind_from_the_template_not_the_client(bench: Bench, db: Session) -> None:
    """``Capture.kind`` is for signature fields only, and ``signer.signed`` records
    ``kind or <field type>``. If a client-supplied ``kind`` were accepted on a checkbox, the
    browser would be choosing how the audit trail says that checkbox was filled."""
    view, session = ready(bench, db, WITH_VALUES)

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

    signed = next(e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "signer.signed")
    assert {c["field_id"]: c["kind"] for c in signed.data["captures"]} == {
        "patient_sig": "drawn",
        "patient_ack": "checkbox",
        "patient_note": "text",
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"kind": "click", "checked": True}, id="checkbox claiming click"),
        pytest.param({"kind": "drawn", "checked": True}, id="checkbox claiming drawn"),
        pytest.param({"kind": "typed", "text_value": "x"}, id="text claiming typed"),
        pytest.param({"checked": True, "image_png": PNG}, id="checkbox with an image payload"),
        pytest.param({"text_value": "x", "typed_text": "y"}, id="text with a typed payload"),
        # The two non-signature shapes must not accept each other's value either: a value the
        # service silently dropped would be a value the signer believes they supplied.
        pytest.param({"checked": True, "text_value": "x"}, id="checkbox with a text value"),
        pytest.param({"image_png": PNG}, id="an image without a kind"),
        pytest.param({"typed_text": "x"}, id="typed text without a kind"),
    ],
)
def test_a_capture_cannot_mix_a_signature_shape_with_a_value(kwargs: dict[str, object]) -> None:
    """``Capture.kind`` decides what the trail says a field was filled with, so a value capture
    carrying a signature shape (or the reverse) is not representable at all: the constructor
    refuses it, the API body refuses the same shape on the wire, and the service's own check is
    the last line."""
    with pytest.raises(ValueError):
        Capture(field_id="patient_ack", **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "capture",
    [
        pytest.param(Capture(field_id="patient_ack", kind="click"), id="click at a checkbox"),
        pytest.param(Capture(field_id="patient_note", kind="typed", typed_text="x"), id="typed at a text field"),
        pytest.param(Capture(field_id="patient_note", kind="drawn", image_png=PNG), id="drawn at a text field"),
    ],
)
def test_a_checkbox_or_text_field_refuses_a_signature_capture(bench: Bench, db: Session, capture: Capture) -> None:
    """The shape that *is* representable -- a well-formed signature capture aimed at a value
    field -- is refused by the service against the template."""
    _view, session = ready(bench, db, WITH_VALUES)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(db, session, [sig(), capture], CTX)
    assert seen.value.code == "capture_shape_invalid"


# ------------------------------------------------------------------- a signature has to leave a mark


def test_a_signature_with_no_marks_at_all_is_refused(bench: Bench, db: Session) -> None:
    """Every field optional, no captures offered: the stamped bytes would equal the base bytes,
    so ``signer.signed`` would attest to a signature the document does not carry."""
    view, session = ready(bench, db, ALL_OPTIONAL)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(db, session, [], CTX)
    assert seen.value.code == "no_captures"

    assert bench.status(db, view.id) == "in_progress"
    assert bench.signer_status(db, session.signer_id) == "consented"
    assert "signer.signed" not in bench.event_types(db, view.id)
    assert bench.revisions(db, view.id) == [(1, "presented")]


def test_an_optional_field_left_out_is_still_fine_when_something_was_signed(bench: Bench, db: Session) -> None:
    """The guard above must not turn a legitimately skipped optional field into a refusal."""
    _view, session = ready(bench, db, WITH_VALUES)

    result = bench.service.sign(
        db,
        session,
        [sig(), Capture(field_id="patient_ack", checked=True)],
        CTX,
    )
    assert result.status == "completed_pending_seal"


# --------------------------------------------------------------------- bounds on stamped strings


@pytest.mark.parametrize(
    ("capture", "field_id"),
    [
        pytest.param(Capture(field_id="patient_sig", kind="typed", typed_text="A" * 201), "patient_sig", id="typed"),
        pytest.param(Capture(field_id="patient_note", text_value="A" * 2001), "patient_note", id="text"),
    ],
)
def test_an_oversized_stamped_string_is_refused(bench: Bench, db: Session, capture: Capture, field_id: str) -> None:
    """These strings are stamped into bytes that are kept for a decade. The API bounds the body;
    the service bounds it again, because the service is what stores it."""
    _view, session = ready(bench, db, WITH_VALUES)
    captures = [capture] if field_id == "patient_sig" else [sig(), capture]

    with pytest.raises(ValidationFailed) as seen:
        bench.service.sign(db, session, captures, CTX)
    assert seen.value.code == "capture_shape_invalid"


def test_a_string_at_the_limit_is_accepted(bench: Bench, db: Session) -> None:
    _view, session = ready(bench, db, WITH_VALUES)

    result = bench.service.sign(
        db,
        session,
        [
            Capture(field_id="patient_sig", kind="typed", typed_text="A" * 200),
            Capture(field_id="patient_ack", checked=True),
            Capture(field_id="patient_note", text_value="B" * 2000),
        ],
        CTX,
    )
    assert result.status == "completed_pending_seal"


# ------------------------------------------------------------- the certificate quotes only what holds


def test_the_certificate_quotes_the_chain_it_verified(bench: Bench, db: Session) -> None:
    view = signed_and_pending(bench, db)

    bench.service.seal_pending(db, view.id)

    summary = bench.documents.last_summary
    report = bench.audit.verify(db, "envelope", view.id)
    events = bench.audit.list(db, "envelope", view.id)
    assert report.ok
    # The certificate was built before document.finalized/sealed/stored were appended, so it
    # quotes the chain as it stood at that moment -- three events short of the head now.
    assert summary.audit_event_count == len(events) - 3
    assert summary.audit_head_hash == events[summary.audit_event_count - 1].event_hash
    assert summary.completed_at is not None


def test_a_broken_audit_chain_refuses_to_seal(bench: Bench, db: Session) -> None:
    """An inserted event with a bogus predecessor breaks the chain. The app role can INSERT into
    ``audit_events`` (it cannot UPDATE or DELETE), which is exactly how a tamperer with app
    credentials would have to work -- and it must not be possible to seal a certificate around it.
    """
    view = signed_and_pending(bench, db)
    head = db.execute(
        text("SELECT max(sequence) AS s FROM audit_events WHERE stream_type = 'envelope' AND stream_id = :i"),
        {"i": view.id},
    ).scalar_one()

    db.execute(
        text(
            "INSERT INTO audit_events (id, stream_type, stream_id, sequence, event_type, data, "
            "  occurred_at, prev_event_hash, event_hash) "
            "VALUES (:id, 'envelope', :sid, :seq, 'envelope.expired', '{}', :at, :prev, :hash)"
        ),
        {
            "id": new_id(),
            "sid": view.id,
            "seq": int(head) + 2,  # a gap, and a predecessor that is not the head
            "at": bench.clock.now(),
            "prev": bytes(32),
            "hash": bytes(range(32)),
        },
    )
    assert not bench.audit.verify(db, "envelope", view.id).ok

    # ``seal_pending`` rolls its own transaction back before recording the failure, so the
    # setup this assertion reads has to be committed first.
    db.commit()

    with pytest.raises(IntegrityFailure) as seen:
        bench.service.seal_pending(db, view.id)
    assert seen.value.code == "audit_chain_broken"

    # Pending, not sealed, and nothing was handed out as complete.
    assert bench.status(db, view.id) == "completed_pending_seal"
    assert db.execute(text("SELECT sealed_sha256 FROM envelopes WHERE id = :i"), {"i": view.id}).scalar_one() is None
    assert "document.sealed" not in bench.event_types(db, view.id)
    assert ("envelope.sealed", view.id) not in [(e, v.id) for e, v in bench.notified]


def test_a_broken_chain_records_the_failure_and_backs_the_job_off(
    committing_bench: Bench,
    db_factory: SessionFactory,
) -> None:
    """The non-retryable failures get the same treatment as a KMS outage: pending, recorded, loud."""
    bench = committing_bench
    factory = db_factory

    with factory() as setup:
        view = signed_and_pending(bench, setup)
        head = setup.execute(
            text("SELECT max(sequence) AS s FROM audit_events WHERE stream_type = 'envelope' AND stream_id = :i"),
            {"i": view.id},
        ).scalar_one()
        setup.execute(
            text(
                "INSERT INTO audit_events (id, stream_type, stream_id, sequence, event_type, data, "
                "  occurred_at, prev_event_hash, event_hash) "
                "VALUES (:id, 'envelope', :sid, :seq, 'envelope.expired', '{}', :at, :prev, :hash)"
            ),
            {
                "id": new_id(),
                "sid": view.id,
                "seq": int(head) + 2,
                "at": bench.clock.now(),
                "prev": bytes(32),
                "hash": bytes(range(32)),
            },
        )
        setup.commit()

    with factory() as attempt, pytest.raises(IntegrityFailure):
        bench.service.seal_pending(attempt, view.id)

    with factory() as check:
        job = check.execute(
            text("SELECT attempts, last_error_code, completed_at FROM seal_jobs WHERE envelope_id = :i"),
            {"i": view.id},
        ).one()
        assert job.attempts == 1
        assert job.last_error_code == "audit_chain_broken"
        assert job.completed_at is None
        failed = [e for e in bench.audit.list(check, "envelope", view.id) if str(e.event_type) == "seal.failed"]
        assert len(failed) == 1
        assert failed[0].data["error_code"] == "audit_chain_broken"


def test_a_certificate_never_invents_a_completion_time(bench: Bench, db: Session) -> None:
    """``completed_at`` is written in the same transaction as the move to
    ``completed_pending_seal``. If it is ever missing, the certificate must refuse rather than put
    the current time on the page as though it were the moment the last signer finished."""
    view = signed_and_pending(bench, db)
    db.execute(text("UPDATE envelopes SET completed_at = NULL WHERE id = :i"), {"i": view.id})
    # ``seal_pending`` rolls its own transaction back before recording the failure, so the
    # setup this assertion reads has to be committed first.
    db.commit()

    with pytest.raises(IntegrityFailure) as seen:
        bench.service.seal_pending(db, view.id)
    assert seen.value.code == "missing_completed_at"
    assert bench.status(db, view.id) == "completed_pending_seal"


# ----------------------------------------------------------------------- template read defensively


def test_a_template_with_two_fields_sharing_an_id_cannot_be_signed_against(bench: Bench, db: Session) -> None:
    """A capture names a field by id. Two fields with one id makes "is this yours?" ambiguous, and
    that answer is what stops one signer stamping another's box."""
    host = bench.host(db)
    ambiguous = TemplateSpec(
        key="ambiguous_ids",
        document_type="patient_consent",
        roles=(
            role("patient", "Patient", ("self",), order_index=0),
            role("witness", "Witness", ("witness",), order_index=1),
        ),
        fields=(field("shared_sig", "patient"), field("shared_sig", "witness")),
    )
    bench.template(db, host, ambiguous)
    bench.consent(db)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(
            db,
            host,
            ambiguous,
            signers=(
                NewSigner(role_key="patient", host_user_id="u-1", display_name="A Person", capacity="self"),
                NewSigner(role_key="witness", host_user_id="u-2", display_name="B Person", capacity="witness"),
            ),
        )
    assert seen.value.code == "template_definitions_invalid"


def test_signing_requires_the_bytes_this_session_was_served_to_have_been_viewed(bench: Bench, db: Session) -> None:
    """``viewed`` is a signer-level status carried across sessions; the *bytes* are not.

    So a signer who read revision 1 in session 1 could, after the host opened session 2, fetch the
    document and sign in session 2 with no ``document.viewed`` covering the bytes that session was
    served. ``signer.signed.presented_sha256`` could then name a revision nothing says was read.
    """
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR, signing_order="parallel")
    witness_id = bench.signer_id(view, "witness")

    first = bench.session(db, witness_id)
    bench.ready_to_sign(db, first)  # present, view and consent revision 1

    # The patient signs, so the current revision moves on.
    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)
    bench.service.sign(db, patient, [Capture(field_id="patient_sig", kind="click")], CTX)

    # A new session for the witness, served the *new* revision and never told it was read.
    second = bench.session(db, witness_id)
    bench.service.present(db, second, CTX)
    with pytest.raises(Conflict) as seen:
        bench.service.sign(db, second, [Capture(field_id="witness_sig", kind="click")], CTX)
    assert seen.value.code == "not_viewed"

    # Reading it again is all that is needed, and then the signature stands.
    bench.service.record_viewed(db, second, PAGES, CTX)
    signed = bench.service.sign(db, second, [Capture(field_id="witness_sig", kind="click")], CTX)
    assert signed.status == "completed_pending_seal"
