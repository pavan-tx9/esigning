"""The one UPDATE ``adopted_signatures`` allows, and everything it does not (Addendum 1 B).

Migration ``0700`` states the rule twice, as SPEC section 12 requires of every evidence table: the
grants stop the runtime role (no DELETE, no TRUNCATE), and ``adopted_signatures_guard`` stops
anyone the grants do not -- the owner role that runs migrations included. Between them they are
what "rows are never deleted, because a ``signature_captures`` row may point at one" rests on.

``tests/foundation/test_roles.py`` proves the grants and the DELETE/TRUNCATE triggers alongside
the other append-only tables. What is left, and what lives here, is the *shape* of the single
permitted UPDATE: it sets ``revoked_at`` and ``revoke_reason`` together, changes nothing else, and
happens once. Each case below is written through the app role -- the role the service actually
runs as -- against a signature saved through the real API, because that is the row an attacker
would find.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from tests.adopted_signatures.conftest import adopt, adopted_rows
from tests.e2e.conftest import Ehr, World

#: ``RAISE EXCEPTION`` from a PL/pgSQL trigger, as `tests/foundation/helpers.py` names it.
RAISE_EXCEPTION = "P0001"


def _live_row_id(ehr: Ehr, world: World) -> str:
    adopt(ehr)
    rows = adopted_rows(world)
    assert len(rows) == 1 and rows[0].revoked_at is None
    return str(rows[0].id)


def _refused(world: World, statement: str, adopted_id: str) -> str:
    with world.sessions() as db:
        with pytest.raises(DBAPIError) as caught:
            db.execute(text(statement), {"id": adopted_id})
        db.rollback()
    assert getattr(caught.value.orig, "sqlstate", None) == RAISE_EXCEPTION
    return str(caught.value.orig)


def test_revoking_without_a_reason_is_refused(ehr: Ehr, world: World) -> None:
    """Both columns or neither. A row marked revoked with no reason is a row nobody can account
    for, and the ``system`` stream's ``signature.adoption_revoked`` would have nothing to match."""
    adopted_id = _live_row_id(ehr, world)

    message = _refused(world, "UPDATE adopted_signatures SET revoked_at = now() WHERE id = :id", adopted_id)

    assert "revoked_at and revoke_reason" in message
    assert adopted_rows(world)[0].revoked_at is None


def test_a_revocation_that_also_rewrites_the_signature_is_refused(ehr: Ehr, world: World) -> None:
    """Revoking is not a licence to edit. Without this, the one permitted UPDATE would be a way to
    change the ink or the text a ``signature_captures`` row points back at."""
    adopted_id = _live_row_id(ehr, world)

    message = _refused(
        world,
        "UPDATE adopted_signatures SET revoked_at = now(), revoke_reason = 'user', typed_text = 'Someone Else' "
        "WHERE id = :id",
        adopted_id,
    )

    assert "may only be revoked" in message
    row = adopted_rows(world)[0]
    assert row.revoked_at is None and row.typed_text != "Someone Else"


def test_a_revoked_row_cannot_be_revoked_again_or_brought_back(ehr: Ehr, world: World) -> None:
    """Once, and once only. A second revocation could restate the reason -- "the user asked for
    this" over "we replaced it" -- and un-revoking would put a signature back in front of a person
    who had asked for it to be gone, both on a row the trail can never correct."""
    adopted_id = _live_row_id(ehr, world)
    with world.sessions() as db:
        db.execute(
            text("UPDATE adopted_signatures SET revoked_at = now(), revoke_reason = 'user' WHERE id = :id"),
            {"id": adopted_id},
        )
        db.commit()

    second = _refused(
        world,
        "UPDATE adopted_signatures SET revoked_at = now(), revoke_reason = 'host' WHERE id = :id",
        adopted_id,
    )
    assert "revoked and immutable" in second

    undo = _refused(
        world,
        "UPDATE adopted_signatures SET revoked_at = NULL, revoke_reason = NULL WHERE id = :id",
        adopted_id,
    )
    assert "revoked and immutable" in undo

    row = adopted_rows(world)[0]
    assert row.revoked_at is not None and row.revoke_reason == "user"


def test_the_owner_role_cannot_delete_a_saved_signature_either(ehr: Ehr, world: World, owner_engine: Engine) -> None:
    """The second line of defence, for the role the grants do not constrain. A deleted row would
    leave every ``signature_captures`` row that points at it naming nothing."""
    adopted_id = _live_row_id(ehr, world)

    with owner_engine.begin() as conn, pytest.raises(DBAPIError) as caught:
        conn.execute(text("DELETE FROM adopted_signatures WHERE id = :id"), {"id": adopted_id})

    assert getattr(caught.value.orig, "sqlstate", None) == RAISE_EXCEPTION
    assert "rows are revoked, never removed" in str(caught.value.orig)
    assert len(adopted_rows(world)) == 1
