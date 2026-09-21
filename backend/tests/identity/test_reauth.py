"""Re-authentication attestations.

A clinician signing an attestation has to have proved who they are in the last couple of minutes.
That claim comes from the host, so every way of stretching it is closed: an attestation cannot be
in the future, cannot be older than the window, and cannot predate the session it claims to
refresh. The table is append-only, so ``fresh_reauth`` re-checks all of that on the way out --
a bad row can never be corrected, only ignored.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import AuthContext, Conflict, Host, NotFound, RequestContext, ValidationFailed
from esign.identity import SqlIdentityService
from esign.ids import new_id
from tests.identity.factories import SignerFixture, host_of, make_signer

CTX = RequestContext(ip="203.0.113.9", user_agent="test-agent")


@pytest.fixture
def signer(db: Session, clock: FixedClock) -> SignerFixture:
    return make_signer(db, clock, requires_reauth=True)


def _session_id(db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture) -> UUID:
    _, info = identity.create_session(
        db,
        signer_id=signer.signer_id,
        auth=AuthContext(method="password+mfa", auth_time=clock.now()),
        kiosk=None,
        ctx=CTX,
    )
    return info.id


def test_without_an_attestation_there_is_no_fresh_reauth(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    assert identity.fresh_reauth(db, session_id) is None


def test_an_attestation_is_fresh_inside_the_window(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    identity.attest_reauth(
        db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )

    fresh = identity.fresh_reauth(db, session_id)
    assert fresh is not None
    assert fresh.method == "password+mfa"
    assert fresh.auth_time == clock.now()

    clock.advance(settings.reauth_max_age_seconds)
    assert identity.fresh_reauth(db, session_id) is not None

    clock.advance(1)
    assert identity.fresh_reauth(db, session_id) is None


def test_the_newest_usable_attestation_wins(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    identity.attest_reauth(db, host=host_of(signer), session_id=session_id, auth=AuthContext("pin", clock.now()))
    clock.advance(30)
    identity.attest_reauth(
        db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )

    fresh = identity.fresh_reauth(db, session_id)
    assert fresh is not None
    assert fresh.method == "password+mfa"


def test_an_attestation_in_the_future_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    with pytest.raises(ValidationFailed) as caught:
        identity.attest_reauth(
            db,
            host=host_of(signer),
            session_id=session_id,
            auth=AuthContext("password+mfa", clock.now() + timedelta(seconds=1)),
        )
    assert caught.value.code == "auth_time_in_future"


def test_an_attestation_older_than_the_window_is_refused_at_the_door(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    """Recording one that is already too old would only fail later, at signing, confusingly."""
    session_id = _session_id(db, clock, identity, signer)
    stale = clock.now() - timedelta(seconds=settings.reauth_max_age_seconds + 1)
    with pytest.raises(ValidationFailed) as caught:
        identity.attest_reauth(db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", stale))
    assert caught.value.code == "auth_too_old"


def test_an_attestation_that_predates_the_session_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    """Otherwise a login from before the session started would count as re-authentication."""
    clock.advance(60)
    session_id = _session_id(db, clock, identity, signer)
    earlier = clock.now() - timedelta(seconds=30)
    with pytest.raises(ValidationFailed) as caught:
        identity.attest_reauth(
            db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", earlier)
        )
    assert caught.value.code == "reauth_predates_session"


def test_a_row_that_predates_the_session_is_ignored_on_the_way_out(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    """The table is append-only: a row written by another path can only ever be ignored."""
    clock.advance(60)
    session_id = _session_id(db, clock, identity, signer)
    db.execute(
        text(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at) "
            "VALUES (:id, :session_id, 'password+mfa', :auth_time, :attested_at)"
        ),
        {
            "id": new_id(),
            "session_id": session_id,
            "auth_time": clock.now() - timedelta(seconds=30),
            "attested_at": clock.now(),
        },
    )
    assert identity.fresh_reauth(db, session_id) is None


def test_a_row_in_the_future_is_ignored_on_the_way_out(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    db.execute(
        text(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at) "
            "VALUES (:id, :session_id, 'password+mfa', :auth_time, :attested_at)"
        ),
        {
            "id": new_id(),
            "session_id": session_id,
            "auth_time": clock.now() + timedelta(hours=1),
            "attested_at": clock.now(),
        },
    )
    assert identity.fresh_reauth(db, session_id) is None


def test_a_future_row_does_not_hide_a_good_one(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    identity.attest_reauth(
        db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )
    db.execute(
        text(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at) "
            "VALUES (:id, :session_id, 'sso', :auth_time, :attested_at)"
        ),
        {
            "id": new_id(),
            "session_id": session_id,
            "auth_time": clock.now() + timedelta(hours=1),
            "attested_at": clock.now(),
        },
    )
    fresh = identity.fresh_reauth(db, session_id)
    assert fresh is not None
    assert fresh.method == "password+mfa"


def test_a_row_with_an_unrecognised_method_is_ignored(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    db.execute(
        text(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at) "
            "VALUES (:id, :session_id, 'vibes', :auth_time, :attested_at)"
        ),
        {"id": new_id(), "session_id": session_id, "auth_time": clock.now(), "attested_at": clock.now()},
    )
    assert identity.fresh_reauth(db, session_id) is None


@pytest.mark.parametrize("method", ["", "magic", "PASSWORD", "password+mfa "])
def test_an_unrecognised_method_is_refused(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, method: str
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    with pytest.raises(ValidationFailed) as caught:
        identity.attest_reauth(db, host=host_of(signer), session_id=session_id, auth=AuthContext(method, clock.now()))  # type: ignore[arg-type]  # deliberately outside the Literal
    assert caught.value.code == "unsupported_auth_method"


def test_an_unknown_session_cannot_be_attested(db: Session, clock: FixedClock, identity: SqlIdentityService) -> None:
    with pytest.raises(NotFound) as caught:
        identity.attest_reauth(
            db,
            host=Host(id=new_id(), name="x", allowed_origins=()),
            session_id=new_id(),
            auth=AuthContext("password+mfa", clock.now()),
        )
    assert caught.value.code == "session_not_found"


def test_fresh_reauth_for_an_unknown_session_is_simply_none(db: Session, identity: SqlIdentityService) -> None:
    assert identity.fresh_reauth(db, new_id()) is None


def test_a_revoked_session_cannot_be_refreshed(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    identity.revoke_sessions(db, signer.signer_id)
    with pytest.raises(Conflict) as caught:
        identity.attest_reauth(
            db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
        )
    assert caught.value.code == "session_not_live"


def test_an_expired_session_cannot_be_refreshed(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    clock.advance(settings.session_ttl_seconds)
    with pytest.raises(Conflict) as caught:
        identity.attest_reauth(
            db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
        )
    assert caught.value.code == "session_not_live"


def test_an_attestation_belongs_to_one_session_only(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    other = make_signer(db, clock, envelope_id=signer.envelope_id, role_key="clinician", requires_reauth=True)
    first = _session_id(db, clock, identity, signer)
    second = _session_id(db, clock, identity, other)

    identity.attest_reauth(db, host=host_of(signer), session_id=first, auth=AuthContext("password+mfa", clock.now()))

    assert identity.fresh_reauth(db, first) is not None
    assert identity.fresh_reauth(db, second) is None


def test_a_new_session_does_not_inherit_the_old_sessions_attestation(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    first = _session_id(db, clock, identity, signer)
    identity.attest_reauth(db, host=host_of(signer), session_id=first, auth=AuthContext("password+mfa", clock.now()))
    clock.advance(10)
    second = _session_id(db, clock, identity, signer)
    assert identity.fresh_reauth(db, second) is None


def test_the_stored_attestation_is_timed_by_the_clock(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    identity.attest_reauth(
        db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )
    attested_at = db.execute(
        text("SELECT attested_at FROM reauth_attestations WHERE session_id = :id"), {"id": session_id}
    ).scalar_one()
    assert attested_at == clock.now()


def test_the_app_role_cannot_rewrite_an_attestation(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    identity.attest_reauth(
        db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )

    for statement in (
        "UPDATE reauth_attestations SET auth_time = now() WHERE session_id = :id",
        "DELETE FROM reauth_attestations WHERE session_id = :id",
    ):
        with pytest.raises(DBAPIError) as caught, db.begin_nested():
            db.execute(text(statement), {"id": session_id})
        assert getattr(caught.value.orig, "sqlstate", None) == "42501"


def test_even_the_owner_role_hits_the_append_only_trigger(owner_db: Session, clock: FixedClock) -> None:
    """The grants stop the app role; the trigger stops everyone the grants do not."""
    fixture = make_signer(owner_db, clock, requires_reauth=True)
    session_id = new_id()
    owner_db.execute(
        text(
            "INSERT INTO signing_sessions (id, signer_id, token_hash, auth_method, auth_time, created_at, expires_at) "
            "VALUES (:id, :signer, :token, 'password+mfa', :now, :now, :expires)"
        ),
        {
            "id": session_id,
            "signer": fixture.signer_id,
            "token": b"\x01" * 32,
            "now": clock.now(),
            "expires": clock.now() + timedelta(minutes=30),
        },
    )
    attestation_id = new_id()
    owner_db.execute(
        text(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at) "
            "VALUES (:id, :session, 'password+mfa', :now, :now)"
        ),
        {"id": attestation_id, "session": session_id, "now": clock.now()},
    )

    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text("UPDATE reauth_attestations SET method = 'pin' WHERE id = :id"), {"id": attestation_id})
    assert getattr(caught.value.orig, "sqlstate", None) == "P0001"


def test_a_revoked_session_has_no_fresh_reauth(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    identity.attest_reauth(
        db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )
    assert identity.fresh_reauth(db, session_id) is not None

    identity.revoke_sessions(db, signer.signer_id)
    assert identity.fresh_reauth(db, session_id) is None


def test_an_expired_session_has_no_fresh_reauth(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture, settings: Settings
) -> None:
    """A long re-auth window must not outlive the session it belongs to."""
    long_window = SqlIdentityService(
        settings.model_copy(update={"reauth_max_age_seconds": settings.session_ttl_seconds * 10}), clock
    )
    session_id = _session_id(db, clock, long_window, signer)
    long_window.attest_reauth(
        db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )

    clock.advance(settings.session_ttl_seconds)
    assert long_window.fresh_reauth(db, session_id) is None


def test_an_unusable_row_does_not_mask_an_earlier_good_one(
    db: Session, clock: FixedClock, identity: SqlIdentityService, signer: SignerFixture
) -> None:
    session_id = _session_id(db, clock, identity, signer)
    identity.attest_reauth(
        db, host=host_of(signer), session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )
    clock.advance(10)
    db.execute(
        text(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at) "
            "VALUES (:id, :session_id, 'vibes', :auth_time, :attested_at)"
        ),
        {"id": new_id(), "session_id": session_id, "auth_time": clock.now(), "attested_at": clock.now()},
    )

    fresh = identity.fresh_reauth(db, session_id)
    assert fresh is not None
    assert fresh.method == "password+mfa"
