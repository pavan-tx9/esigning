"""Present, view, consent: the preconditions signing depends on."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import Conflict, IntegrityFailure, NotFound
from tests.envelopes.conftest import CONSENT_VERSION, CTX, PAGES, PATIENT_CONSENT, Bench


def test_presenting_moves_created_to_in_progress(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))

    pdf = bench.service.present(db, session, CTX)

    assert view.presented_sha256 is not None
    assert pdf == bench.blobs.get(db, view.presented_sha256)
    assert bench.status(db, view.id) == "in_progress"
    assert bench.event_types(db, view.id)[-1] == "document.presented"


def test_presenting_records_what_this_session_was_shown(bench: Bench, db: Session) -> None:
    """SPEC section 3: the session carries the hash of the bytes it actually received."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))

    bench.service.present(db, session, CTX)

    stored = db.execute(
        text("SELECT presented_sha256 FROM signing_sessions WHERE id = :id"), {"id": session.id}
    ).scalar_one()
    assert bytes(stored) == view.presented_sha256

    events = bench.audit.list(db, "envelope", view.id)
    presented = next(e for e in events if str(e.event_type) == "document.presented")
    assert presented.document_sha256 == view.presented_sha256
    assert presented.data["revision_no"] == 1
    assert presented.data["page_count"] == PAGES
    assert presented.data["signer_id"] == str(session.signer_id)


def test_a_corrupted_revision_is_never_served(bench: Bench, db: Session) -> None:
    """Never fail open: a blob that no longer matches its hash raises, it does not get shown."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    assert view.presented_sha256 is not None
    bench.blobs.corrupt(view.presented_sha256)

    with pytest.raises(IntegrityFailure):
        bench.service.present(db, session, CTX)


def test_presenting_does_not_advance_the_signer(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    session = bench.session(db, signer_id)

    bench.service.present(db, session, CTX)
    assert bench.signer_status(db, signer_id) == "pending"


# --------------------------------------------------------------------------- viewed


def test_viewed_requires_the_document_to_have_been_served(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))

    with pytest.raises(Conflict) as seen:
        bench.service.record_viewed(db, session, PAGES, CTX)
    assert seen.value.code == "not_presented"


def test_a_second_session_cannot_claim_a_view_it_was_not_served(bench: Bench, db: Session) -> None:
    """The presented hash is per session, so a fresh session starts from nothing."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    first = bench.session(db, signer_id)
    bench.service.present(db, first, CTX)

    second = bench.session(db, signer_id)
    with pytest.raises(Conflict) as seen:
        bench.service.record_viewed(db, second, PAGES, CTX)
    assert seen.value.code == "not_presented"


def test_viewed_is_recorded_once(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    session = bench.session(db, signer_id)
    bench.service.present(db, session, CTX)

    bench.service.record_viewed(db, session, PAGES, CTX)
    first_at = db.execute(text("SELECT viewed_at FROM signers WHERE id = :id"), {"id": signer_id}).scalar_one()
    bench.clock.advance(600)
    bench.service.record_viewed(db, session, PAGES, CTX)

    again = db.execute(text("SELECT viewed_at FROM signers WHERE id = :id"), {"id": signer_id}).scalar_one()
    assert again == first_at
    assert bench.signer_status(db, signer_id) == "viewed"


def test_viewing_again_after_consent_does_not_undo_consent(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    session = bench.session(db, signer_id)
    bench.ready_to_sign(db, session)

    bench.service.record_viewed(db, session, PAGES, CTX)
    assert bench.signer_status(db, signer_id) == "consented"


# --------------------------------------------------------------------------- consent


def test_consent_requires_viewing_first(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.service.present(db, session, CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.accept_consent(db, session, CONSENT_VERSION, CTX)
    assert seen.value.code == "not_viewed"


def test_consent_to_a_stale_version_is_refused(bench: Bench, db: Session) -> None:
    """The version has to be the current one, or the record says they agreed to text they never saw."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    session = bench.session(db, signer_id)
    bench.service.present(db, session, CTX)
    bench.service.record_viewed(db, session, PAGES, CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.accept_consent(db, session, "2019-01", CTX)
    assert seen.value.code == "consent_version_stale"
    assert bench.signer_status(db, signer_id) == "viewed"
    assert "consent.accepted" not in bench.event_types(db, view.id)


def test_consent_stores_the_text_it_was_given(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    consent_version = CONSENT_VERSION
    bench.consent(db, consent_version)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    session = bench.session(db, signer_id)
    bench.ready_to_sign(db, session)

    stored = db.execute(text("SELECT consent_text_id FROM signers WHERE id = :id"), {"id": signer_id}).scalar_one()
    current = bench.identity.current_consent(db, bench.settings.default_locale)
    assert stored == current.id

    accepted = next(e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "consent.accepted")
    assert accepted.data == {
        "signer_id": str(signer_id),
        "consent_text_id": str(current.id),
        "consent_version": consent_version,
        "locale": "en-US",
        "body_sha256": current.body_sha256.hex(),
        # Addendum 3 C: this acceptance was given here, so it relies on nothing. The keys are
        # still written -- every declared field always is -- which is what lets a reader tell an
        # acceptance that stood on an earlier one from an event that predates the question.
        "relied_on_envelope_id": None,
        "relied_on_accepted_at": None,
    }


def test_consent_is_idempotent(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    session = bench.session(db, signer_id)
    bench.ready_to_sign(db, session)
    first_at = db.execute(text("SELECT consented_at FROM signers WHERE id = :id"), {"id": signer_id}).scalar_one()

    bench.clock.advance(60)
    bench.service.accept_consent(db, session, CONSENT_VERSION, CTX)

    again = db.execute(text("SELECT consented_at FROM signers WHERE id = :id"), {"id": signer_id}).scalar_one()
    assert again == first_at


# --------------------------------------------------------------------------- session binding


def test_a_session_for_another_envelopes_signer_is_not_found(bench: Bench, db: Session) -> None:
    """The service never takes SessionInfo's word for which envelope a signer belongs to."""
    import dataclasses

    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    first = bench.create(db, host, PATIENT_CONSENT)
    second = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(first, "patient"))
    forged = dataclasses.replace(session, envelope_id=second.id)

    with pytest.raises(NotFound):
        bench.service.present(db, forged, CTX)
