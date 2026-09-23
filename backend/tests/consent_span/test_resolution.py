"""Whose acceptance stands for another document, and whose never does (Addendum 3 C).

Standing consent is the one place in this service where a signer is *not* shown the disclosure
again, so the rule that decides it is tested here first, on real rows, one refusal at a time:

* with the span off nothing ever stands, which is the shipped behaviour;
* a standing acceptance is the same person on the same host, and never anybody else;
* it is the same disclosure -- the same version, in the same language -- and never a rolled-over
  one, because "you agreed at 09:12" would then be about a text nobody read;
* it runs out at the end of the span;
* a kiosk session neither offers standing consent nor leaves one behind;
* and an envelope never stands for itself.

Every refusal is checked twice: once as "the UI is not offered the shortcut" and once as "the
server refuses to record it if asked anyway", because a client is free to ask.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.audit.canonical import canonical_value
from esign.clock import FixedClock
from esign.config import CONSENT_SPAN_MAX_SECONDS, Settings
from esign.contracts import Conflict, KioskContext, StandingConsent
from tests.consent_span.conftest import (
    PATIENT,
    SITTING_SECONDS,
    SOMEBODY_ELSE,
    Document,
    Standing,
    already_agreed,
    open_document,
    practice,
)
from tests.envelopes.conftest import CONSENT_VERSION, CTX, Bench

KIOSK = KioskContext(staff_user_id="staff-2207", identity_check="photo_id")


def standing_of(bench: Bench, db: Session, document: Document) -> StandingConsent | None:
    return bench.service.signing_view(db, document.session).consent_standing


def refuses(bench: Bench, db: Session, document: Document, relies_on: UUID) -> None:
    """The server is asked to rely on that acceptance anyway, and says no.

    The version posted is whatever is current, so the refusal under test is the standing one and
    never a stale disclosure wearing its clothes.
    """
    version = bench.identity.current_consent(db, bench.settings.default_locale).version
    with pytest.raises(Conflict) as refusal:
        bench.service.accept_consent(db, document.session, version, CTX, relies_on_envelope_id=relies_on)
    assert refusal.value.code == "consent_not_standing"


def test_with_the_span_off_nothing_stands(standing: Standing, db: Session) -> None:
    """The shipped behaviour: every document collects its own consent."""
    bench = standing(0)
    host = practice(bench, db)
    bench.consent(db)
    first = already_agreed(bench, db, host)
    second = open_document(bench, db, host)

    assert standing_of(bench, db, second) is None
    refuses(bench, db, second, first.envelope.id)


def test_with_the_span_on_the_same_person_stands_on_their_own_acceptance(
    standing: Standing, db: Session, clock: FixedClock
) -> None:
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    agreed_at = clock.now()
    first = already_agreed(bench, db, host)

    clock.advance(120)
    second = open_document(bench, db, host)
    found = bench.service.signing_view(db, second.session).consent_standing
    assert found is not None
    assert found.envelope_id == first.envelope.id
    assert found.accepted_at == agreed_at

    # ...and the acceptance is still recorded here, on this envelope, at this moment.
    bench.service.accept_consent(db, second.session, CONSENT_VERSION, CTX, relies_on_envelope_id=first.envelope.id)
    row = db.execute(
        text("SELECT status, consent_text_id, consented_at FROM signers WHERE id = :id"),
        {"id": second.signer_id},
    ).one()
    assert row.status == "consented"
    assert row.consent_text_id == bench.identity.current_consent(db, bench.settings.default_locale).id
    assert row.consented_at == clock.now()


def test_the_event_names_the_acceptance_it_relied_on(standing: Standing, db: Session, clock: FixedClock) -> None:
    """The shortcut is evidence, not an absence: the trail says which acceptance and when."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    agreed_at = clock.now()
    first = already_agreed(bench, db, host)
    clock.advance(90)
    second = open_document(bench, db, host)

    bench.service.accept_consent(db, second.session, CONSENT_VERSION, CTX, relies_on_envelope_id=first.envelope.id)

    data = bench.event_data(db, second.envelope.id, "consent.accepted")
    assert data["relied_on_envelope_id"] == str(first.envelope.id)
    assert data["relied_on_accepted_at"] == canonical_value(agreed_at)
    # The first document's own acceptance relied on nothing, and says so rather than staying quiet.
    assert bench.event_data(db, first.envelope.id, "consent.accepted")["relied_on_envelope_id"] is None


def test_consent_without_the_field_behaves_exactly_as_before(standing: Standing, db: Session) -> None:
    """Backward compatibility is the whole of the API change: a client that knows nothing about
    standing consent posts what it always posted and is recorded as it always was."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    already_agreed(bench, db, host)
    second = open_document(bench, db, host)

    bench.service.accept_consent(db, second.session, CONSENT_VERSION, CTX)

    data = bench.event_data(db, second.envelope.id, "consent.accepted")
    assert data["relied_on_envelope_id"] is None
    assert data["relied_on_accepted_at"] is None
    assert bench.signer_status(db, second.signer_id) == "consented"


def test_somebody_elses_acceptance_never_stands(standing: Standing, db: Session) -> None:
    """Two patients at one practice, and consent is a thing a person gives, not a desk."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    theirs = already_agreed(bench, db, host, host_user_id=SOMEBODY_ELSE)
    mine = open_document(bench, db, host, host_user_id=PATIENT)

    assert standing_of(bench, db, mine) is None
    refuses(bench, db, mine, theirs.envelope.id)


def test_the_same_person_at_another_host_never_stands(standing: Standing, db: Session) -> None:
    """Host user ids are the host's own namespace: the same string at two practices is two people,
    and even if it were one, one practice's disclosure is not another's."""
    bench = standing(SITTING_SECONDS)
    elsewhere = practice(bench, db, "Another EHR")
    here = practice(bench, db, "Test EHR")
    bench.consent(db)
    theirs = already_agreed(bench, db, elsewhere, host_user_id=PATIENT)
    mine = open_document(bench, db, here, host_user_id=PATIENT)

    assert standing_of(bench, db, mine) is None
    refuses(bench, db, mine, theirs.envelope.id)


def test_an_acceptance_of_a_different_disclosure_never_stands(standing: Standing, db: Session) -> None:
    """The disclosure rolled over between the two documents.

    Standing consent says "you agreed to *this*, a few minutes ago". Against a version the person
    has not read, that sentence is false, and the checkbox is the only honest thing to show.
    """
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db, CONSENT_VERSION)
    first = already_agreed(bench, db, host)

    bench.consent(db, "2026-10")  # the fake serves the newest seeded text for the locale
    second = open_document(bench, db, host)

    assert standing_of(bench, db, second) is None
    refuses(bench, db, second, first.envelope.id)


def test_an_acceptance_in_another_language_never_stands(standing: Standing, db: Session) -> None:
    """Same version, different locale: a different text, with a different hash, that this signer
    did not read. ``consent_texts`` is unique on (version, locale), so matching the id is matching
    both -- there is no way to spell "the Spanish one stands for the English one"."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.identity.seed_consent(db, version=CONSENT_VERSION, locale="es-US", body="Divulgación.")
    bench.consent(db, CONSENT_VERSION)
    document = open_document(bench, db, host)
    bench.service.accept_consent(db, document.session, CONSENT_VERSION, CTX, locale="es-US")

    second = open_document(bench, db, host)
    assert bench.service.signing_view(db, second.session, locale="en-US").consent_standing is None
    assert bench.service.signing_view(db, second.session, locale="es-US").consent_standing is not None


def test_an_acceptance_stops_standing_at_the_end_of_the_span(
    standing: Standing, db: Session, clock: FixedClock
) -> None:
    """The boundary is the boundary: at the last second of the span it stands, a second later it
    does not -- and what decides is when the person agreed, not when they opened the next form."""
    span = 120
    bench = standing(span)
    host = practice(bench, db)
    bench.consent(db)
    first = already_agreed(bench, db, host)

    clock.advance(span)
    second = open_document(bench, db, host)
    assert standing_of(bench, db, second) is not None

    clock.advance(1)
    assert standing_of(bench, db, second) is None
    refuses(bench, db, second, first.envelope.id)


def test_a_kiosk_session_is_never_offered_standing_consent(standing: Standing, db: Session) -> None:
    """A shared tablet is the one place "the same person is still here" cannot be assumed."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    first = already_agreed(bench, db, host)
    on_the_tablet = open_document(bench, db, host, kiosk=KIOSK)

    assert standing_of(bench, db, on_the_tablet) is None
    refuses(bench, db, on_the_tablet, first.envelope.id)


def test_an_acceptance_given_on_a_kiosk_never_stands_for_a_later_document(standing: Standing, db: Session) -> None:
    """The other direction, for the same reason. Whoever was holding the tablet agreed on it; a
    document opened afterwards, anywhere, starts from the disclosure again."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    on_the_tablet = already_agreed(bench, db, host, kiosk=KIOSK)
    later = open_document(bench, db, host)

    assert standing_of(bench, db, later) is None
    refuses(bench, db, later, on_the_tablet.envelope.id)


def test_an_envelope_never_stands_for_itself(standing: Standing, db: Session) -> None:
    """Re-posting consent on the document you are signing is legal and changes nothing (SPEC
    section 13, fourth round). What it must not do is become its own earlier acceptance."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    document = already_agreed(bench, db, host)

    assert standing_of(bench, db, document) is None
    refuses(bench, db, document, document.envelope.id)


def test_an_envelope_that_was_never_consented_to_does_not_stand(standing: Standing, db: Session) -> None:
    """Opening a document is not agreeing to one."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    opened_only = open_document(bench, db, host)
    second = open_document(bench, db, host)

    assert standing_of(bench, db, second) is None
    refuses(bench, db, second, opened_only.envelope.id)


def test_a_stale_version_is_still_refused_as_a_stale_version(standing: Standing, db: Session) -> None:
    """Standing consent does not become a way past the version check: a client posting an old
    version number is told the disclosure changed, whether or not it named an earlier envelope."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db, CONSENT_VERSION)
    first = already_agreed(bench, db, host)
    bench.consent(db, "2026-10")
    second = open_document(bench, db, host)

    with pytest.raises(Conflict) as refusal:
        bench.service.accept_consent(db, second.session, CONSENT_VERSION, CTX, relies_on_envelope_id=first.envelope.id)
    assert refusal.value.code == "consent_version_stale"


def test_the_span_is_capped_at_an_hour_rather_than_clamped() -> None:
    """The ceiling is the number compliance is quoted, so it is a test rather than a reading of
    the code: a span past it refuses to start."""
    assert Settings(consent_span_seconds=CONSENT_SPAN_MAX_SECONDS).consent_span_seconds == CONSENT_SPAN_MAX_SECONDS
    with pytest.raises(ValueError, match="consent_span_seconds"):
        Settings(consent_span_seconds=CONSENT_SPAN_MAX_SECONDS + 1)


def test_the_default_is_off() -> None:
    """Nothing about this feature happens to a host that has not asked for it."""
    assert Settings().consent_span_seconds == 0


def test_the_most_recent_acceptance_is_the_one_that_stands(standing: Standing, db: Session, clock: FixedClock) -> None:
    """The acceptance used is the most recent one, not any one inside the span: a person who
    agreed this morning and again five minutes ago stands on the five-minute-old acceptance."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    already_agreed(bench, db, host)
    clock.advance(300)
    recent = already_agreed(bench, db, host)
    clock.advance(60)

    second = open_document(bench, db, host)
    found = bench.service.signing_view(db, second.session).consent_standing
    assert found is not None
    assert found.envelope_id == recent.envelope.id
    assert found.accepted_at == clock.now() - timedelta(seconds=60)


def test_a_chain_of_acceptances_does_not_renew_the_span_one_document_at_a_time(
    standing: Standing, db: Session, clock: FixedClock
) -> None:
    """The span bounds how long the disclosure may go undisplayed, not how far apart two documents
    may be.

    Each hop here is inside the span -- 840 seconds of a 900-second sitting -- so a rule that only
    looked at the acceptance being relied on would let the queue run for ever: document 3 stands on
    2, which stood on 1, and the notice was displayed once. What decides is the moment it *was*
    displayed, so the third document asks again.
    """
    span = 900
    hop = 840
    bench = standing(span)
    host = practice(bench, db)
    bench.consent(db)
    root = already_agreed(bench, db, host)

    clock.advance(hop)
    second = open_document(bench, db, host)
    found = standing_of(bench, db, second)
    assert found is not None, "one hop inside the span still stands"
    assert found.envelope_id == root.envelope.id
    bench.service.accept_consent(db, second.session, CONSENT_VERSION, CTX, relies_on_envelope_id=root.envelope.id)

    clock.advance(hop)
    third = open_document(bench, db, host)
    assert standing_of(bench, db, third) is None
    # ...and asking anyway is refused, whichever link of the chain is named.
    refuses(bench, db, third, second.envelope.id)
    refuses(bench, db, third, root.envelope.id)


def test_a_standing_acceptance_carries_the_time_the_disclosure_was_displayed(
    standing: Standing, db: Session, clock: FixedClock
) -> None:
    """The root travels with the chain, so it is read once and never recomputed by walking back.

    ``accepted_at`` is what the UI shows ("you agreed at 09:12"); ``root_accepted_at`` is what the
    span is measured against, and on the third document the two are different facts.
    """
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    displayed_at = clock.now()
    root = already_agreed(bench, db, host)

    clock.advance(120)
    second = open_document(bench, db, host)
    bench.service.accept_consent(db, second.session, CONSENT_VERSION, CTX, relies_on_envelope_id=root.envelope.id)
    agreed_again_at = clock.now()

    clock.advance(120)
    third = open_document(bench, db, host)
    found = standing_of(bench, db, third)
    assert found is not None
    assert found.envelope_id == second.envelope.id, "the most recent acceptance is still the one relied on"
    assert found.accepted_at == agreed_again_at
    assert found.root_accepted_at == displayed_at

    bench.service.accept_consent(db, third.session, CONSENT_VERSION, CTX, relies_on_envelope_id=second.envelope.id)
    data = bench.event_data(db, third.envelope.id, "consent.accepted")
    assert data["relied_on_envelope_id"] == str(second.envelope.id)
    assert data["relied_on_accepted_at"] == canonical_value(agreed_again_at)
    assert data["relied_on_root_accepted_at"] == canonical_value(displayed_at)
    # The document the notice was displayed on names no root at all: it is one.
    assert bench.event_data(db, root.envelope.id, "consent.accepted")["relied_on_root_accepted_at"] is None


def test_the_consent_text_the_row_keeps_is_this_envelopes_own(standing: Standing, db: Session) -> None:
    """Standing consent changes where the *agreement* came from, not what this envelope records:
    the row, the event and the certificate all still name this envelope's disclosure."""
    bench = standing(SITTING_SECONDS)
    host = practice(bench, db)
    bench.consent(db)
    first = already_agreed(bench, db, host)
    second = open_document(bench, db, host)
    bench.service.accept_consent(db, second.session, CONSENT_VERSION, CTX, relies_on_envelope_id=first.envelope.id)

    current = bench.identity.current_consent(db, bench.settings.default_locale)
    data = bench.event_data(db, second.envelope.id, "consent.accepted")
    assert data["consent_text_id"] == str(current.id)
    assert data["consent_version"] == CONSENT_VERSION
    assert data["body_sha256"] == current.body_sha256.hex()
