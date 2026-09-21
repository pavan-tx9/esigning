"""The ways an envelope ends without being signed: decline, void, expiry -- and supersede."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import Capture, Conflict, NotFound, ValidationFailed
from esign.envelopes import DECLINE_REASON_CODES
from tests.envelopes.conftest import CTX, HIPAA_PAIR, PATIENT_CONSENT, Bench

PNG = b"\x89PNG\r\n\x1a\n" + b"scribbled signature bytes"


def sig(field_id: str = "patient_sig") -> Capture:
    return Capture(field_id=field_id, kind="drawn", image_png=PNG)


# --------------------------------------------------------------------------- decline


def test_declining_ends_the_envelope(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)

    result = bench.service.decline(db, patient, "prefers_paper", CTX)

    assert result.status == "declined"
    assert bench.signer_status(db, bench.signer_id(view, "patient")) == "declined"
    assert bench.signer_status(db, bench.signer_id(view, "witness")) == "pending"
    assert bench.event_types(db, view.id)[-1] == "signer.declined"

    row = db.execute(
        text("SELECT declined_at, decline_reason_code FROM signers WHERE id = :id"),
        {"id": bench.signer_id(view, "patient")},
    ).one()
    assert row.declined_at == bench.clock.now()
    assert row.decline_reason_code == "prefers_paper"


def test_the_reason_code_reaches_the_audit_trail_and_nothing_else_does(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)

    bench.service.decline(db, session, "needs_interpreter", CTX)

    declined = next(e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "signer.declined")
    assert declined.data == {"decline_reason_code": "needs_interpreter"}


def test_an_unknown_decline_reason_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.decline(db, session, "my doctor is rude", CTX)
    assert seen.value.code == "unknown_reason_code"
    assert bench.status(db, view.id) == "in_progress"


def test_prefers_paper_is_always_available(bench: Bench) -> None:
    """SPEC section 4: there is always a visible decline/paper path."""
    assert "prefers_paper" in DECLINE_REASON_CODES


def test_declining_revokes_every_session_on_the_envelope(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    witness = bench.session(db, bench.signer_id(view, "witness"))
    bench.ready_to_sign(db, patient)

    bench.service.decline(db, patient, "prefers_paper", CTX)

    live = db.execute(
        text(
            "SELECT count(*) FROM signing_sessions WHERE revoked_at IS NULL AND signer_id IN "
            "(SELECT id FROM signers WHERE envelope_id = :id)"
        ),
        {"id": view.id},
    ).scalar_one()
    assert live == 0
    assert witness.id is not None


def test_a_decline_after_another_signer_signed_still_ends_it(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)
    bench.service.sign(db, patient, [sig()], CTX)

    witness = bench.session(db, bench.signer_id(view, "witness"))
    bench.ready_to_sign(db, witness)
    result = bench.service.decline(db, witness, "disagrees_with_terms", CTX)

    assert result.status == "declined"
    assert bench.signer_status(db, bench.signer_id(view, "patient")) == "signed"


def test_declining_twice_is_a_conflict(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.decline(db, session, "prefers_paper", CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.decline(db, session, "prefers_paper", CTX)
    assert seen.value.code == "envelope_declined"


# --------------------------------------------------------------------------- void


def test_voiding_records_the_reason_and_the_time(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)

    result = bench.service.void(db, host, view.id, "entered_in_error", CTX)

    assert result.status == "voided"
    row = db.execute(text("SELECT voided_at, void_reason_code FROM envelopes WHERE id = :id"), {"id": view.id}).one()
    assert row.voided_at == bench.clock.now()
    assert row.void_reason_code == "entered_in_error"

    voided = next(e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "envelope.voided")
    assert voided.data == {"reason_code": "entered_in_error"}
    assert voided.actor.role == "host"


def test_voiding_is_host_scoped(bench: Bench, db: Session) -> None:
    owner = bench.host(db, "Owner EHR")
    stranger = bench.host(db, "Stranger EHR")
    bench.template(db, owner, PATIENT_CONSENT)
    view = bench.create(db, owner, PATIENT_CONSENT)

    with pytest.raises(NotFound) as seen:
        bench.service.void(db, stranger, view.id, "entered_in_error", CTX)
    assert seen.value.code == "not_found"
    assert bench.status(db, view.id) == "created"


def test_a_sealed_envelope_is_never_voided(bench: Bench, db: Session) -> None:
    """SPEC section 3: a correction is a new envelope, and the sealed bytes are never touched."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [sig()], CTX)
    bench.service.seal_pending(db, view.id)

    with pytest.raises(Conflict) as seen:
        bench.service.void(db, host, view.id, "entered_in_error", CTX)
    assert seen.value.code == "envelope_sealed"
    assert bench.status(db, view.id) == "sealed"


def test_a_complete_envelope_cannot_be_voided(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [sig()], CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.void(db, host, view.id, "entered_in_error", CTX)
    assert seen.value.code == "envelope_already_complete"


@pytest.mark.parametrize("reason", ["", "Entered In Error", "a reason with spaces", "x" * 80, "9lives"])
def test_a_void_reason_that_is_not_a_machine_code_is_refused(bench: Bench, db: Session, reason: str) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)

    with pytest.raises(ValidationFailed) as seen:
        bench.service.void(db, host, view.id, reason, CTX)
    assert seen.value.code == "invalid_reason_code"
    assert bench.status(db, view.id) == "created"


def test_voiding_revokes_sessions(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))

    bench.service.void(db, host, view.id, "duplicate", CTX)

    revoked = db.execute(
        text("SELECT revoked_at FROM signing_sessions WHERE id = :id"), {"id": session.id}
    ).scalar_one()
    assert revoked is not None


# --------------------------------------------------------------------------- expiry


def test_expire_due_only_catches_envelopes_past_their_date(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    soon = bench.create(db, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(hours=1))
    later = bench.create(db, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(days=30))

    assert bench.service.expire_due(db) == 0

    bench.clock.advance(timedelta(hours=2))
    assert bench.service.expire_due(db) == 1
    assert bench.status(db, soon.id) == "expired"
    assert bench.status(db, later.id) == "created"
    assert bench.event_types(db, soon.id)[-1] == "envelope.expired"


def test_expiry_is_recorded_by_the_system_actor_with_no_data(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(hours=1))
    bench.clock.advance(timedelta(hours=2))
    bench.service.expire_due(db)

    expired = next(e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "envelope.expired")
    assert expired.data == {}
    assert expired.actor.role == "system"
    assert expired.ctx.ip is None


def test_expiry_never_catches_a_completed_envelope(bench: Bench, db: Session) -> None:
    """Never fail open in the other direction either: a signed document does not expire."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(hours=1))
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [sig()], CTX)

    bench.clock.advance(timedelta(days=2))
    assert bench.service.expire_due(db) == 0
    assert bench.status(db, view.id) == "completed_pending_seal"


def test_expiry_is_idempotent(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(hours=1))
    bench.clock.advance(timedelta(hours=2))

    assert bench.service.expire_due(db) == 1
    assert bench.service.expire_due(db) == 0
    assert bench.event_types(db, view.id).count("envelope.expired") == 1


def test_an_expired_envelope_refuses_everything(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(hours=1))
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.clock.advance(timedelta(hours=2))
    bench.service.expire_due(db)

    for call in (
        lambda: bench.service.present(db, session, CTX),
        lambda: bench.service.sign(db, session, [sig()], CTX),
        lambda: bench.service.decline(db, session, "prefers_paper", CTX),
        lambda: bench.service.void(db, host, view.id, "too_late", CTX),
    ):
        with pytest.raises(Conflict) as seen:
            call()
        assert seen.value.code == "envelope_expired"


# --------------------------------------------------------------------------- supersede


def sealed_envelope(bench: Bench, db: Session, host: object) -> object:
    view = bench.create(db, host, PATIENT_CONSENT)  # type: ignore[arg-type]
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [sig()], CTX)
    return bench.service.seal_pending(db, view.id)


def test_superseding_a_sealed_envelope_links_both_ways(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    old = sealed_envelope(bench, db, host)

    new = bench.create(db, host, PATIENT_CONSENT, supersedes=old.id)  # type: ignore[attr-defined]

    assert new.supersedes_envelope_id == old.id  # type: ignore[attr-defined]
    assert bench.service.get(db, host, old.id).superseded_by_envelope_id == new.id  # type: ignore[attr-defined]
    assert bench.status(db, old.id) == "sealed"  # type: ignore[attr-defined]


def test_superseding_records_an_event_on_the_old_stream(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    old = sealed_envelope(bench, db, host)

    new = bench.create(db, host, PATIENT_CONSENT, supersedes=old.id)  # type: ignore[attr-defined]

    old_events = bench.audit.list(db, "envelope", old.id)  # type: ignore[attr-defined]
    assert str(old_events[-1].event_type) == "envelope.superseded"
    assert old_events[-1].data == {"superseded_by_envelope_id": str(new.id)}
    assert "envelope.superseded" not in bench.event_types(db, new.id)


def test_an_unsealed_envelope_cannot_be_superseded(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    live = bench.create(db, host, PATIENT_CONSENT)

    with pytest.raises(Conflict) as seen:
        bench.create(db, host, PATIENT_CONSENT, supersedes=live.id)
    assert seen.value.code == "supersedes_not_sealed"


def test_superseding_another_hosts_envelope_is_not_found(bench: Bench, db: Session) -> None:
    owner = bench.host(db, "Owner EHR")
    stranger = bench.host(db, "Stranger EHR")
    bench.template(db, owner, PATIENT_CONSENT)
    bench.template(db, stranger, PATIENT_CONSENT)
    bench.consent(db)
    old = sealed_envelope(bench, db, owner)

    with pytest.raises(NotFound) as seen:
        bench.create(db, stranger, PATIENT_CONSENT, supersedes=old.id)  # type: ignore[attr-defined]
    assert seen.value.code == "not_found"


def test_superseding_an_unknown_envelope_is_not_found(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)

    with pytest.raises(NotFound):
        bench.create(db, host, PATIENT_CONSENT, supersedes=uuid4())


def test_an_envelope_can_only_be_superseded_once(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    old = sealed_envelope(bench, db, host)
    bench.create(db, host, PATIENT_CONSENT, supersedes=old.id)  # type: ignore[attr-defined]

    with pytest.raises(Conflict) as seen:
        bench.create(db, host, PATIENT_CONSENT, supersedes=old.id)  # type: ignore[attr-defined]
    assert seen.value.code == "already_superseded"


def test_the_schema_refuses_a_second_superseding_envelope(bench: Bench, db: Session) -> None:
    """Migration 0500: the one-replacement guarantee is in the schema, not only in the service."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    old = sealed_envelope(bench, db, host)
    first = bench.create(db, host, PATIENT_CONSENT, supersedes=old.id)  # type: ignore[attr-defined]
    second = bench.create(db, host, PATIENT_CONSENT)

    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        db.execute(
            text("UPDATE envelopes SET supersedes_envelope_id = :old WHERE id = :id"),
            {"old": old.id, "id": second.id},  # type: ignore[attr-defined]
        )
        db.flush()
    db.rollback()
    assert first.supersedes_envelope_id == old.id  # type: ignore[attr-defined]
