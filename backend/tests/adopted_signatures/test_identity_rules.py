"""The rules the identity module enforces on its own (SPEC section 8, Addendum 1 B).

The HTTP tests reach these through the sign path, which only ever calls ``adopt_signature`` after
a signature has succeeded and never from a kiosk. These call it directly, because a rule that is
only true because of the way it happens to be called is not a rule the next caller will keep.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import (
    AuthContext,
    Conflict,
    Forbidden,
    KioskContext,
    RequestContext,
    SessionInfo,
    Unauthorized,
    ValidationFailed,
)
from esign.identity import SqlIdentityService
from tests.identity.factories import SignerFixture, make_signer

SIGNATURE = b"a sanitised signature image"


@pytest.fixture
def identity(settings: Settings, clock: FixedClock) -> SqlIdentityService:
    return SqlIdentityService(settings, clock)


def _signed_session(
    db: Session,
    identity: SqlIdentityService,
    clock: FixedClock,
    *,
    kiosk: KioskContext | None = None,
    signed: bool = True,
    fixture: SignerFixture | None = None,
) -> SessionInfo:
    """A signer with a live session, having signed unless the test says otherwise."""
    fixture = fixture or make_signer(db, clock)
    auth = AuthContext(method="staff_verified" if kiosk else "password", auth_time=clock.now() - timedelta(minutes=1))
    _token, info = identity.create_session(db, signer_id=fixture.signer_id, auth=auth, kiosk=kiosk, ctx=_ctx())
    if signed:
        db.execute(
            text("UPDATE signers SET status = 'signed', signed_at = :now WHERE id = :id"),
            {"now": clock.now(), "id": fixture.signer_id},
        )
    return info


def _ctx() -> RequestContext:
    """Provenance as the API would have captured it, server-side."""
    return RequestContext(ip="198.51.100.7", user_agent="tests")


def _store_image(db: Session, clock: FixedClock, data: bytes = SIGNATURE) -> bytes:
    sha = hashlib.sha256(data).digest()
    db.execute(
        text(
            "INSERT INTO blobs (sha256, size_bytes, kind, storage_key, created_at) "
            "VALUES (:sha, :size, 'signature_image', :key, :now) ON CONFLICT DO NOTHING"
        ),
        {"sha": sha, "size": len(data), "key": sha.hex(), "now": clock.now()},
    )
    return sha


def test_only_a_signer_who_has_signed_may_save_one(
    db: Session, identity: SqlIdentityService, clock: FixedClock
) -> None:
    info = _signed_session(db, identity, clock, signed=False)

    with pytest.raises(Conflict) as refusal:
        identity.adopt_signature(db, info.id, kind="typed", typed_text="Wanda Testpatient")

    # The row is created after the signature succeeds, in the same transaction: a saved signature
    # that signed nothing is evidence of nothing.
    assert refusal.value.code == "signature_not_applied"


def test_a_kiosk_session_may_not_save_one(db: Session, identity: SqlIdentityService, clock: FixedClock) -> None:
    kiosk = KioskContext(staff_user_id="staff-3310", identity_check="photo_id")
    info = _signed_session(db, identity, clock, kiosk=kiosk)

    with pytest.raises(Forbidden) as refusal:
        identity.adopt_signature(db, info.id, kind="typed", typed_text="Wanda Testpatient")

    assert refusal.value.code == "adoption_not_allowed"


def test_a_revoked_session_may_not_save_one(db: Session, identity: SqlIdentityService, clock: FixedClock) -> None:
    info = _signed_session(db, identity, clock)
    identity.revoke_sessions(db, info.signer_id)

    with pytest.raises(Unauthorized):
        identity.adopt_signature(db, info.id, kind="typed", typed_text="Wanda Testpatient")


def test_an_expired_session_may_not_save_one(db: Session, identity: SqlIdentityService, clock: FixedClock) -> None:
    info = _signed_session(db, identity, clock)
    clock.advance(timedelta(days=1))

    with pytest.raises(Unauthorized):
        identity.adopt_signature(db, info.id, kind="typed", typed_text="Wanda Testpatient")


def test_a_drawn_signature_must_name_a_stored_signature_image(
    db: Session, identity: SqlIdentityService, clock: FixedClock
) -> None:
    info = _signed_session(db, identity, clock)

    with pytest.raises(ValidationFailed) as refusal:
        identity.adopt_signature(db, info.id, kind="drawn", image_sha256=hashlib.sha256(b"never stored").digest())

    assert refusal.value.code == "invalid_adopted_signature"


def test_a_kind_and_its_payload_must_agree(db: Session, identity: SqlIdentityService, clock: FixedClock) -> None:
    info = _signed_session(db, identity, clock)
    sha = _store_image(db, clock)

    for kind, kwargs in (
        ("drawn", {"typed_text": "Wanda Testpatient"}),
        ("typed", {"image_sha256": sha}),
        ("typed", {"typed_text": "   "}),
        ("typed", {"typed_text": "W" * 500}),
    ):
        with pytest.raises(ValidationFailed) as refusal:
            identity.adopt_signature(db, info.id, kind=kind, **kwargs)  # type: ignore[arg-type]
        assert refusal.value.code == "invalid_adopted_signature"


def test_saving_again_leaves_exactly_one_live_row(db: Session, identity: SqlIdentityService, clock: FixedClock) -> None:
    info = _signed_session(db, identity, clock)
    sha = _store_image(db, clock)

    first = identity.adopt_signature(db, info.id, kind="drawn", image_sha256=sha)
    clock.advance(5)
    second = identity.adopt_signature(db, info.id, kind="typed", typed_text="Wanda Testpatient")

    live = identity.get_adopted_signature(db, host_id=info.host_id, host_user_id=info.host_user_id)
    assert live is not None and live.id == second.id
    replaced = _row(db, first.id)
    assert replaced.revoke_reason == "replaced"
    assert replaced.revoked_at is not None


def test_a_saved_signature_belongs_to_the_session_that_saved_it(
    db: Session, identity: SqlIdentityService, clock: FixedClock
) -> None:
    info = _signed_session(db, identity, clock)

    adopted = identity.adopt_signature(db, info.id, kind="typed", typed_text="  Wanda Testpatient  ")

    # Whose it is comes from the session's rows, never from an argument.
    assert adopted.host_id == info.host_id
    assert adopted.host_user_id == info.host_user_id
    assert adopted.created_by_session_id == info.id
    assert adopted.created_in_envelope_id == info.envelope_id
    assert adopted.typed_text == "Wanda Testpatient"  # stored as it was stamped, stripped
    assert adopted.is_live


def test_revoking_needs_a_reason_a_caller_may_give(
    db: Session, identity: SqlIdentityService, clock: FixedClock
) -> None:
    info = _signed_session(db, identity, clock)
    identity.adopt_signature(db, info.id, kind="typed", typed_text="Wanda Testpatient")

    with pytest.raises(ValidationFailed) as refusal:
        # ``replaced`` is what adopt_signature writes when it supersedes a row. A caller claiming
        # it would be claiming a replacement that never happened, in a row that cannot be corrected.
        identity.revoke_adopted_signature(db, host_id=info.host_id, host_user_id=info.host_user_id, reason="replaced")

    assert refusal.value.code == "invalid_revoke_reason"


def test_revoking_is_idempotent_and_scoped_to_the_user(
    db: Session, identity: SqlIdentityService, clock: FixedClock
) -> None:
    info = _signed_session(db, identity, clock)
    identity.adopt_signature(db, info.id, kind="typed", typed_text="Wanda Testpatient")

    first = identity.revoke_adopted_signature(db, host_id=info.host_id, host_user_id=info.host_user_id, reason="user")
    second = identity.revoke_adopted_signature(db, host_id=info.host_id, host_user_id=info.host_user_id, reason="user")
    other_user = identity.revoke_adopted_signature(
        db, host_id=info.host_id, host_user_id="somebody-else", reason="host"
    )

    assert first is not None and first.revoke_reason == "user"
    assert second is None
    assert other_user is None
    assert identity.get_adopted_signature(db, host_id=info.host_id, host_user_id=info.host_user_id) is None


def _row(db: Session, adopted_signature_id: UUID) -> Any:
    return db.execute(
        text("SELECT revoked_at, revoke_reason FROM adopted_signatures WHERE id = :id"),
        {"id": adopted_signature_id},
    ).one()
