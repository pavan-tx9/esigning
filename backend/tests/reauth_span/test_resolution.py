"""Which attestation covers a signature, and whose it has to be (Addendum 1 C).

``fresh_reauth`` is the whole of the span: everything above it -- the signature, the certificate,
the session payload -- reports what this function decided. So the rules are tested here first, on
real rows, one refusal at a time:

* this session's own attestation always wins, and with the span off it is the only answer there is;
* a borrowed one is the same user on the same host, and never anyone else;
* a borrowed one expires at the end of the span *and* at the maximum age, whichever comes first;
* both sessions -- the one the attestation was made for and the one asking -- must still be live;
* a row written before ``0700`` has no user on it and is never borrowed.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import AuthContext
from esign.identity import SqlIdentityService
from esign.ids import new_id
from tests.reauth_span.conftest import (
    DEMO_SPAN_SECONDS,
    Spanning,
    attest,
    make_clinician,
    open_session,
)


def test_an_attestation_records_whose_it_is(db: Session, clock: FixedClock, identity: SqlIdentityService) -> None:
    """The pair comes from the signer and envelope rows, never from the request: it is what makes
    "the most recent attestation for this user on this host" answerable at all."""
    clinician = make_clinician(db, clock, host_user_id="dr-0311")
    session_id = open_session(identity, db, clinician, clock)
    attest(identity, db, clinician, session_id, clock)

    row = db.execute(
        text("SELECT host_id, host_user_id FROM reauth_attestations WHERE session_id = :id"),
        {"id": session_id},
    ).one()
    assert row.host_id == clinician.host_id
    assert row.host_user_id == "dr-0311"


def test_with_the_span_off_a_second_document_gets_nothing(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    """The shipped behaviour: one attestation, one document."""
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    attested = open_session(identity, db, first, clock)
    attest(identity, db, first, attested, clock)
    asking = open_session(identity, db, second, clock)

    assert identity.fresh_reauth(db, attested) is not None
    assert identity.fresh_reauth(db, asking) is None


def test_with_the_span_on_the_same_user_borrows_within_it(
    db: Session, clock: FixedClock, identity: SqlIdentityService, spanning: Spanning
) -> None:
    span = spanning(DEMO_SPAN_SECONDS)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    attested_at = clock.now()
    attest(span, db, first, open_session(span, db, first, clock), clock)
    asking = open_session(span, db, second, clock)

    borrowed = span.fresh_reauth(db, asking)
    assert borrowed is not None
    assert borrowed.scope == "span"
    assert borrowed.method == "password+mfa"
    assert borrowed.auth_time == attested_at

    # The same rows, read by a service whose span is off, answer nothing: it is configuration that
    # decides, not anything stored.
    assert identity.fresh_reauth(db, asking) is None


def test_this_sessions_own_attestation_is_preferred_to_a_borrowable_one(
    db: Session, clock: FixedClock, spanning: Spanning
) -> None:
    """A signature says what it rests on, so "its own" and "borrowed" must not be interchangeable
    when both are available."""
    span = spanning(DEMO_SPAN_SECONDS)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    attest(span, db, first, open_session(span, db, first, clock), clock)
    asking = open_session(span, db, second, clock)
    clock.advance(5)
    attest(span, db, second, asking, clock)

    own = span.fresh_reauth(db, asking)
    assert own is not None
    assert own.scope == "session"
    assert own.auth_time == clock.now()


def test_a_borrowed_attestation_stops_at_the_end_of_the_span(
    db: Session, clock: FixedClock, spanning: Spanning, settings: Settings
) -> None:
    """A span shorter than the maximum age is the span that decides."""
    short = 30
    assert short < settings.reauth_max_age_seconds
    span = spanning(short)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    attest(span, db, first, open_session(span, db, first, clock), clock)
    asking = open_session(span, db, second, clock)

    clock.advance(short)
    assert span.fresh_reauth(db, asking) is not None
    clock.advance(1)
    assert span.fresh_reauth(db, asking) is None


def test_a_borrowed_attestation_is_still_bounded_by_the_maximum_age(
    db: Session, clock: FixedClock, spanning: Spanning, settings: Settings
) -> None:
    """The span says which *documents* an attestation covers, never how old it may be. With a span
    longer than ``REAUTH_MAX_AGE_SECONDS`` the maximum age is what ends it."""
    span = spanning(900)
    assert settings.reauth_max_age_seconds < 900
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    attest(span, db, first, open_session(span, db, first, clock), clock)
    asking = open_session(span, db, second, clock)

    clock.advance(settings.reauth_max_age_seconds)
    assert span.fresh_reauth(db, asking) is not None
    clock.advance(1)
    assert span.fresh_reauth(db, asking) is None


def test_a_different_user_on_the_same_host_never_borrows(db: Session, clock: FixedClock, spanning: Spanning) -> None:
    span = spanning(DEMO_SPAN_SECONDS)
    mine = make_clinician(db, clock, host_user_id="dr-0311")
    someone_else = make_clinician(db, clock, host_user_id="dr-9999", host_id=mine.host_id)
    attest(span, db, mine, open_session(span, db, mine, clock), clock)

    assert span.fresh_reauth(db, open_session(span, db, someone_else, clock)) is None


def test_the_same_user_id_on_another_host_never_borrows(db: Session, clock: FixedClock, spanning: Spanning) -> None:
    """Host ids are ours, ``host_user_id`` values are each host's own: two hosts may well number
    their clinicians the same way, and one host's attestation can never cover another's signature."""
    span = spanning(DEMO_SPAN_SECONDS)
    ours = make_clinician(db, clock, host_user_id="dr-0311")
    theirs = make_clinician(db, clock, host_user_id="dr-0311")
    assert ours.host_id != theirs.host_id
    attest(span, db, ours, open_session(span, db, ours, clock), clock)

    assert span.fresh_reauth(db, open_session(span, db, theirs, clock)) is None


def test_a_revoked_asking_session_borrows_nothing(db: Session, clock: FixedClock, spanning: Spanning) -> None:
    """A span is a shortcut through the hand-off, never a way around a dead session."""
    span = spanning(DEMO_SPAN_SECONDS)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    attest(span, db, first, open_session(span, db, first, clock), clock)
    asking = open_session(span, db, second, clock)
    assert span.fresh_reauth(db, asking) is not None

    span.revoke_sessions(db, second.signer_id)
    assert span.fresh_reauth(db, asking) is None


def test_an_expired_asking_session_borrows_nothing(db: Session, clock: FixedClock, spanning: Spanning) -> None:
    """Expiring only the session asking, so this is about that session and not about the clock
    catching up with the whole queue."""
    span = spanning(DEMO_SPAN_SECONDS)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    attest(span, db, first, open_session(span, db, first, clock), clock)
    asking = open_session(span, db, second, clock)
    assert span.fresh_reauth(db, asking) is not None

    db.execute(
        text("UPDATE signing_sessions SET expires_at = :past WHERE id = :id"),
        {"past": clock.now() - timedelta(seconds=1), "id": asking},
    )
    assert span.fresh_reauth(db, asking) is None


def test_an_attestation_whose_own_session_died_is_not_borrowed(
    db: Session, clock: FixedClock, spanning: Spanning
) -> None:
    """The same rule the base spec applies to a session's own attestation: if the session it was
    made for is revoked, the attestation goes with it."""
    span = spanning(DEMO_SPAN_SECONDS)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    attest(span, db, first, open_session(span, db, first, clock), clock)
    asking = open_session(span, db, second, clock)
    assert span.fresh_reauth(db, asking) is not None

    span.revoke_sessions(db, first.signer_id)
    assert span.fresh_reauth(db, asking) is None


def test_a_row_written_before_0700_is_never_borrowed(db: Session, clock: FixedClock, spanning: Spanning) -> None:
    """``reauth_attestations`` is append-only, so the rows that predate the migration cannot be
    backfilled with whose they are. They go on serving their own session and nothing else."""
    span = spanning(DEMO_SPAN_SECONDS)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    old_session = open_session(span, db, first, clock)
    db.execute(
        text(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at) "
            "VALUES (:id, :session_id, 'password+mfa', :now, :now)"
        ),
        {"id": new_id(), "session_id": old_session, "now": clock.now()},
    )

    assert span.fresh_reauth(db, old_session) is not None  # its own session, exactly as before
    assert span.fresh_reauth(db, open_session(span, db, second, clock)) is None


def test_an_attestation_in_the_future_is_not_borrowed_either(
    db: Session, clock: FixedClock, spanning: Spanning
) -> None:
    """``attest_reauth`` refuses one at the door; a row from another path is ignored on the way out,
    in every scope."""
    span = spanning(DEMO_SPAN_SECONDS)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    session_id = open_session(span, db, first, clock)
    db.execute(
        text(
            "INSERT INTO reauth_attestations "
            "(id, session_id, method, auth_time, attested_at, host_id, host_user_id) "
            "VALUES (:id, :session_id, 'password+mfa', :auth_time, :now, :host, 'dr-0311')"
        ),
        {
            "id": new_id(),
            "session_id": session_id,
            "auth_time": clock.now() + timedelta(hours=1),
            "now": clock.now(),
            "host": first.host_id,
        },
    )

    assert span.fresh_reauth(db, open_session(span, db, second, clock)) is None


def test_the_most_recent_borrowable_attestation_wins(db: Session, clock: FixedClock, spanning: Spanning) -> None:
    span = spanning(DEMO_SPAN_SECONDS)
    first = make_clinician(db, clock, host_user_id="dr-0311")
    second = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    third = make_clinician(db, clock, host_user_id="dr-0311", host_id=first.host_id)
    older = open_session(span, db, first, clock)
    span.attest_reauth(db, host=first.host, session_id=older, auth=AuthContext("pin", clock.now()))
    clock.advance(10)
    newer = open_session(span, db, second, clock)
    span.attest_reauth(db, host=second.host, session_id=newer, auth=AuthContext("sso", clock.now()))

    borrowed = span.fresh_reauth(db, open_session(span, db, third, clock))
    assert borrowed is not None
    assert borrowed.method == "sso"
    assert borrowed.auth_time == clock.now()
