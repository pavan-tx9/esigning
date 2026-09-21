"""Signing sessions: minting, authenticating, expiry, revocation and what the host may attest.

The properties under test are the ones a dispute would turn on. A token is bound to one signer.
A stale or future ``auth_time`` is refused rather than rounded. Unknown, expired and revoked
tokens are one failure, so the API cannot be used to enumerate sessions. What is recorded about
the request comes from the server, not from the browser.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import AuthContext, Host, KioskContext, NotFound, RequestContext, Unauthorized, ValidationFailed
from esign.identity import SESSION_TOKEN_PREFIX, SqlIdentityService
from esign.identity.tokens import TOKEN_LENGTH, token_sha256
from esign.ids import new_id
from tests.identity.factories import SignerFixture, host_of, insert_host_row, live_session_count, make_signer

CTX = RequestContext(ip="203.0.113.9", user_agent="Mozilla/5.0 (iPad; CPU OS 18_0)")


def _auth(clock: FixedClock, *, method: str = "password+mfa", age_seconds: int = 30) -> AuthContext:
    return AuthContext(method=method, auth_time=clock.now() - timedelta(seconds=age_seconds))  # type: ignore[arg-type]  # deliberately outside the Literal


@pytest.fixture
def signer(db: Session, clock: FixedClock) -> SignerFixture:
    return make_signer(db, clock)


# --------------------------------------------------------------------------- minting


def test_a_session_binds_a_token_to_one_signer(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    token, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)

    assert token.startswith(SESSION_TOKEN_PREFIX)
    assert len(token) == TOKEN_LENGTH
    assert info.signer_id == signer.signer_id
    assert info.envelope_id == signer.envelope_id
    assert info.kiosk is None
    assert info.auth.method == "password+mfa"
    assert info.expires_at == clock.now() + timedelta(seconds=settings.session_ttl_seconds)


def test_the_plaintext_token_never_reaches_the_database(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    token, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    dump = db.execute(
        text("SELECT to_jsonb(ss)::text FROM signing_sessions ss WHERE id = :id"), {"id": info.id}
    ).scalar_one()

    assert token not in str(dump)
    assert token[len(SESSION_TOKEN_PREFIX) :] not in str(dump)
    stored_hash = db.execute(
        text("SELECT token_hash FROM signing_sessions WHERE id = :id"), {"id": info.id}
    ).scalar_one()
    assert bytes(stored_hash) == token_sha256(token)


def test_the_session_is_timed_by_the_clock_not_the_database(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    _, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    created_at = db.execute(
        text("SELECT created_at FROM signing_sessions WHERE id = :id"), {"id": info.id}
    ).scalar_one()
    assert created_at == clock.now()


def test_request_provenance_is_taken_from_the_server_side_context(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    _, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    row = db.execute(
        text("SELECT host(ip) AS ip, user_agent FROM signing_sessions WHERE id = :id"), {"id": info.id}
    ).one()
    assert row.ip == "203.0.113.9"
    assert row.user_agent == CTX.user_agent


@pytest.mark.parametrize("ip", [None, "", "not-an-ip", "203.0.113.9; DROP TABLE hosts", "10.0.0.1/8"])
def test_an_unusable_ip_is_recorded_as_absent_rather_than_breaking_the_session(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, ip: str | None
) -> None:
    _, info = identity.create_session(
        db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=RequestContext(ip=ip)
    )
    stored = db.execute(text("SELECT ip FROM signing_sessions WHERE id = :id"), {"id": info.id}).scalar_one()
    assert stored is None


def test_a_long_user_agent_is_truncated_rather_than_rejected(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    _, info = identity.create_session(
        db,
        signer_id=signer.signer_id,
        auth=_auth(clock),
        kiosk=None,
        ctx=RequestContext(user_agent="U" * 5000),
    )
    stored = db.execute(text("SELECT user_agent FROM signing_sessions WHERE id = :id"), {"id": info.id}).scalar_one()
    assert stored is not None
    assert len(stored) == 512


def test_an_unknown_signer_is_not_found(db: Session, clock: FixedClock, identity: SqlIdentityService) -> None:
    with pytest.raises(NotFound) as caught:
        identity.create_session(db, signer_id=new_id(), auth=_auth(clock), kiosk=None, ctx=CTX)
    assert caught.value.code == "signer_not_found"


# --------------------------------------------------------------------------- the auth_time window


def test_auth_time_in_the_future_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    auth = AuthContext(method="password", auth_time=clock.now() + timedelta(seconds=1))
    with pytest.raises(ValidationFailed) as caught:
        identity.create_session(db, signer_id=signer.signer_id, auth=auth, kiosk=None, ctx=CTX)
    assert caught.value.code == "auth_time_in_future"


def test_auth_time_older_than_the_window_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    auth = _auth(clock, age_seconds=settings.auth_max_age_seconds + 1)
    with pytest.raises(ValidationFailed) as caught:
        identity.create_session(db, signer_id=signer.signer_id, auth=auth, kiosk=None, ctx=CTX)
    assert caught.value.code == "auth_too_old"


def test_the_edges_of_the_window_are_exact(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    exactly_now = AuthContext(method="password", auth_time=clock.now())
    identity.create_session(db, signer_id=signer.signer_id, auth=exactly_now, kiosk=None, ctx=CTX)

    exactly_old = _auth(clock, age_seconds=settings.auth_max_age_seconds)
    identity.create_session(db, signer_id=signer.signer_id, auth=exactly_old, kiosk=None, ctx=CTX)


def test_a_naive_auth_time_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    naive = AuthContext(method="password", auth_time=clock.now().replace(tzinfo=None))
    with pytest.raises(ValidationFailed) as caught:
        identity.create_session(db, signer_id=signer.signer_id, auth=naive, kiosk=None, ctx=CTX)
    assert caught.value.code == "invalid_auth_time"


def test_an_auth_time_in_another_zone_is_compared_correctly(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    from datetime import timezone

    elsewhere = (clock.now() - timedelta(minutes=5)).astimezone(timezone(timedelta(hours=-7)))
    _, info = identity.create_session(
        db,
        signer_id=signer.signer_id,
        auth=AuthContext(method="sso", auth_time=elsewhere),
        kiosk=None,
        ctx=CTX,
    )
    assert info.auth.auth_time == clock.now() - timedelta(minutes=5)


@pytest.mark.parametrize("method", ["", "magic", "password ", "PASSWORD", "sso;DROP", "Mrs Wanda Testpatient"])
def test_an_authentication_method_we_do_not_recognise_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, method: str
) -> None:
    """The method reaches the certificate of completion, so it is a closed list, not free text."""
    with pytest.raises(ValidationFailed) as caught:
        identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock, method=method), kiosk=None, ctx=CTX)
    assert caught.value.code == "unsupported_auth_method"


# --------------------------------------------------------------------------- kiosk context


def test_a_kiosk_session_records_the_staff_member_and_the_check(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    kiosk = KioskContext(staff_user_id="staff-42", identity_check="photo_id")
    _, info = identity.create_session(
        db, signer_id=signer.signer_id, auth=_auth(clock, method="staff_verified"), kiosk=kiosk, ctx=CTX
    )

    assert info.kiosk == kiosk
    row = db.execute(
        text("SELECT kiosk_staff_user_id, kiosk_identity_check FROM signing_sessions WHERE id = :id"),
        {"id": info.id},
    ).one()
    assert row.kiosk_staff_user_id == "staff-42"
    assert row.kiosk_identity_check == "photo_id"
    # The session still belongs to the signer, never to the member of staff.
    assert info.signer_id == signer.signer_id


def test_a_kiosk_session_reads_back_from_its_token(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    kiosk = KioskContext(staff_user_id="staff-42", identity_check="wristband")
    token, _ = identity.create_session(
        db, signer_id=signer.signer_id, auth=_auth(clock, method="staff_verified"), kiosk=kiosk, ctx=CTX
    )
    assert identity.authenticate_session(db, token).kiosk == kiosk


@pytest.mark.parametrize(
    "kiosk",
    [
        KioskContext(staff_user_id="", identity_check="photo_id"),
        KioskContext(staff_user_id="   ", identity_check="photo_id"),
        KioskContext(staff_user_id="s" * 129, identity_check="photo_id"),
        KioskContext(staff_user_id="staff-42", identity_check="vibes"),  # type: ignore[arg-type]  # deliberately outside the Literal
        KioskContext(staff_user_id="staff-42", identity_check=""),  # type: ignore[arg-type]  # deliberately outside the Literal
    ],
)
def test_an_unusable_kiosk_context_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, kiosk: KioskContext
) -> None:
    with pytest.raises(ValidationFailed) as caught:
        identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=kiosk, ctx=CTX)
    assert caught.value.code == "invalid_kiosk_context"


def test_staff_verified_without_a_named_staff_member_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    """ "Staff said so" is only evidence if the record says which member of staff."""
    with pytest.raises(ValidationFailed) as caught:
        identity.create_session(
            db, signer_id=signer.signer_id, auth=_auth(clock, method="staff_verified"), kiosk=None, ctx=CTX
        )
    assert caught.value.code == "kiosk_context_required"


# --------------------------------------------------------------------------- authenticating


def test_a_token_authenticates_to_its_own_session(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    token, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    seen = identity.authenticate_session(db, token)
    assert seen == info


def test_a_token_authenticates_when_presented_as_a_header(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    token, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    assert identity.authenticate_session(db, f"Bearer {token}").id == info.id


def test_one_signers_token_never_resolves_to_another(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    other = make_signer(db, clock, envelope_id=signer.envelope_id, role_key="witness")
    token_a, _ = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    token_b, _ = identity.create_session(db, signer_id=other.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)

    assert identity.authenticate_session(db, token_a).signer_id == signer.signer_id
    assert identity.authenticate_session(db, token_b).signer_id == other.signer_id


@pytest.mark.parametrize("bearer", ["", "est_" + "a" * 43, "esk_" + "a" * 43, "nonsense", "Bearer est_short"])
def test_an_unknown_token_is_unauthorized(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, bearer: str
) -> None:
    identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    with pytest.raises(Unauthorized) as caught:
        identity.authenticate_session(db, bearer)
    assert str(caught.value) == "invalid credentials"


def test_expired_revoked_and_unknown_are_indistinguishable(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    expired_token, _ = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    clock.advance(settings.session_ttl_seconds)

    revoked_token, _ = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    identity.revoke_sessions(db, signer.signer_id)

    failures = []
    for bearer in (expired_token, revoked_token, "est_" + "a" * 43):
        with pytest.raises(Unauthorized) as caught:
            identity.authenticate_session(db, bearer)
        failures.append((caught.value.code, str(caught.value), caught.value.http_status))

    assert len(set(failures)) == 1


def test_a_session_is_expired_the_instant_it_expires(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    token, _ = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)

    clock.advance(settings.session_ttl_seconds - 1)
    identity.authenticate_session(db, token)

    clock.advance(1)
    with pytest.raises(Unauthorized):
        identity.authenticate_session(db, token)


# --------------------------------------------------------------------------- revocation


def test_creating_a_session_revokes_the_previous_one(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    first_token, first = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    clock.advance(5)
    second_token, _ = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)

    with pytest.raises(Unauthorized):
        identity.authenticate_session(db, first_token)
    identity.authenticate_session(db, second_token)

    assert live_session_count(db, signer.signer_id) == 1
    revoked_at = db.execute(
        text("SELECT revoked_at FROM signing_sessions WHERE id = :id"), {"id": first.id}
    ).scalar_one()
    assert revoked_at == clock.now()


def test_revoking_another_signers_sessions_leaves_this_one_alone(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    other = make_signer(db, clock, envelope_id=signer.envelope_id, role_key="witness")
    token, _ = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    identity.create_session(db, signer_id=other.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)

    identity.revoke_sessions(db, other.signer_id)

    identity.authenticate_session(db, token)
    assert live_session_count(db, other.signer_id) == 0


def test_revoking_twice_is_harmless(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    identity.revoke_sessions(db, signer.signer_id)
    identity.revoke_sessions(db, signer.signer_id)
    identity.revoke_sessions(db, new_id())
    assert live_session_count(db, signer.signer_id) == 0


def test_a_revoked_session_stays_revoked_even_within_its_ttl(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    token, _ = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    identity.revoke_sessions(db, signer.signer_id)
    clock.advance(1)
    with pytest.raises(Unauthorized):
        identity.authenticate_session(db, token)


# --------------------------------------------------------------------------- concurrency


def test_two_hosts_opening_a_session_at_once_leave_exactly_one_live(
    db_factory: Callable[[], AbstractContextManager[Session]],
    settings: Settings,
    clock: FixedClock,
) -> None:
    """The second caller must wait for the first, or both read "no live session" and both insert.

    The interleaving is forced rather than raced: the first transaction holds its per-signer lock
    open while the second calls in, so the test fails deterministically if the lock is removed.
    """
    identity = SqlIdentityService(settings, clock)
    with db_factory() as setup:
        fixture = make_signer(setup, clock)
        setup.commit()

    second_started = threading.Event()
    second_finished = threading.Event()
    errors: list[BaseException] = []

    def open_second_session() -> None:
        try:
            with db_factory() as session:
                second_started.set()
                identity.create_session(session, signer_id=fixture.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
                session.commit()
        except BaseException as exc:  # reported through the assertion below
            errors.append(exc)
        finally:
            second_finished.set()

    with db_factory() as first:
        identity.create_session(first, signer_id=fixture.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)

        thread = threading.Thread(target=open_second_session)
        thread.start()
        assert second_started.wait(timeout=10)
        assert not second_finished.wait(timeout=1.0), "the second session did not wait for the first"

        first.commit()
        thread.join(timeout=30)

    assert not errors, errors
    assert second_finished.is_set()
    with db_factory() as check:
        total = check.execute(
            text("SELECT count(*) FROM signing_sessions WHERE signer_id = :id"), {"id": fixture.signer_id}
        ).scalar_one()
        assert total == 2
        assert live_session_count(check, fixture.signer_id) == 1


# --------------------------------------------------------------------------- host scoping


def test_a_session_can_be_traced_back_to_its_host(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    _, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    assert identity.session_host_id(db, info.id) == signer.host_id

    with pytest.raises(NotFound):
        identity.session_host_id(db, new_id())


def test_another_hosts_session_does_not_exist_for_reauth(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    """SPEC section 10: one host can never refresh another host's session, and is told
    ``not_found`` rather than ``forbidden``."""
    _, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    stranger = Host(id=insert_host_row(db, clock, name="Other EHR"), name="Other EHR", allowed_origins=())

    with pytest.raises(NotFound) as caught:
        identity.attest_reauth(db, host=stranger, session_id=info.id, auth=_auth(clock, age_seconds=0))
    assert caught.value.code == "session_not_found"
    assert identity.fresh_reauth(db, info.id) is None

    returned = identity.attest_reauth(db, host=host_of(signer), session_id=info.id, auth=_auth(clock, age_seconds=0))
    assert returned.id == info.id and returned.signer_id == signer.signer_id


def test_revoking_can_spare_the_session_a_signer_signed_from(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    token, info = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    assert identity.revoke_sessions(db, signer.signer_id, except_session_id=info.id) == 0
    assert identity.authenticate_session(db, token).id == info.id
    assert identity.revoke_sessions(db, signer.signer_id) == 1
    with pytest.raises(Unauthorized):
        identity.authenticate_session(db, token)


# --------------------------------------------------------------------------- configuration and scope


def test_the_session_lifetime_comes_from_configuration(
    db: Session, clock: FixedClock, settings: Settings, signer: SignerFixture
) -> None:
    short = SqlIdentityService(settings.model_copy(update={"session_ttl_seconds": 60}), clock)
    token, info = short.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)

    assert info.expires_at == clock.now() + timedelta(seconds=60)
    clock.advance(60)
    with pytest.raises(Unauthorized):
        short.authenticate_session(db, token)


def test_the_authentication_window_comes_from_configuration(
    db: Session, clock: FixedClock, settings: Settings, signer: SignerFixture
) -> None:
    strict = SqlIdentityService(settings.model_copy(update={"auth_max_age_seconds": 60}), clock)
    strict.create_session(db, signer_id=signer.signer_id, auth=_auth(clock, age_seconds=60), kiosk=None, ctx=CTX)
    with pytest.raises(ValidationFailed) as caught:
        strict.create_session(db, signer_id=signer.signer_id, auth=_auth(clock, age_seconds=61), kiosk=None, ctx=CTX)
    assert caught.value.code == "auth_too_old"


def test_envelope_state_is_not_this_modules_question(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    """The envelopes module gates this through ``assert_signer_may_start``; identity must not
    half-answer it, or two modules would disagree about when signing may begin."""
    db.execute(
        text("UPDATE envelopes SET status = 'voided', voided_at = :now WHERE id = :id"),
        {"id": signer.envelope_id, "now": clock.now()},
    )
    token, _ = identity.create_session(db, signer_id=signer.signer_id, auth=_auth(clock), kiosk=None, ctx=CTX)
    assert identity.authenticate_session(db, token).envelope_id == signer.envelope_id
