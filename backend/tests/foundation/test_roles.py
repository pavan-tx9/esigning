"""Two lines of defence over the append-only tables.

The grants stop the runtime role outright. The triggers stop anyone the grants do not -- including
the owner role that runs migrations. SPEC section 12 requires both to be proven.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from tests.foundation.helpers import (
    APPEND_ONLY_ROW_MAKERS,
    INSUFFICIENT_PRIVILEGE,
    RAISE_EXCEPTION,
    insert_audit_event,
    sqlstate,
)

APPEND_ONLY_TABLES = ["audit_events", "blobs", "document_revisions", "consent_texts", "reauth_attestations"]


def test_app_role_may_insert_and_read_audit_events(db: Session) -> None:
    event_id = insert_audit_event(db)
    found = db.execute(text("SELECT id FROM audit_events WHERE id = :id"), {"id": event_id}).scalar_one()
    assert found == event_id


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET event_type = 'tampered'",
        "UPDATE audit_events SET data = '{\"x\": 1}'::jsonb WHERE id = :id",
        "DELETE FROM audit_events",
        "DELETE FROM audit_events WHERE id = :id",
        "TRUNCATE TABLE audit_events",
    ],
)
def test_app_role_cannot_mutate_audit_events(db: Session, statement: str) -> None:
    event_id = insert_audit_event(db)
    with pytest.raises(DBAPIError) as caught, db.begin_nested():
        db.execute(text(statement), {"id": event_id})
    assert sqlstate(caught.value) == INSUFFICIENT_PRIVILEGE


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
def test_app_role_has_no_update_delete_or_truncate_grant(db: Session, table: str) -> None:
    """Asked directly of the catalogue, so a table with no rows is covered too."""
    row = db.execute(
        text(
            "SELECT has_table_privilege('esign_app', :t, 'SELECT') AS can_select, "
            "       has_table_privilege('esign_app', :t, 'INSERT') AS can_insert, "
            "       has_table_privilege('esign_app', :t, 'UPDATE') AS can_update, "
            "       has_table_privilege('esign_app', :t, 'DELETE') AS can_delete, "
            "       has_table_privilege('esign_app', :t, 'TRUNCATE') AS can_truncate"
        ),
        {"t": table},
    ).one()
    assert row.can_select and row.can_insert
    assert not row.can_update
    assert not row.can_delete
    assert not row.can_truncate


@pytest.mark.parametrize(
    "table",
    [
        "hosts",
        "templates",
        "template_versions",
        "envelopes",
        "signers",
        "signing_sessions",
        "signature_captures",
        "idempotency_keys",
        "seal_jobs",
        "webhook_deliveries",
    ],
)
def test_app_role_has_full_dml_but_never_truncate(db: Session, table: str) -> None:
    row = db.execute(
        text(
            "SELECT has_table_privilege('esign_app', :t, 'SELECT') AS can_select, "
            "       has_table_privilege('esign_app', :t, 'INSERT') AS can_insert, "
            "       has_table_privilege('esign_app', :t, 'UPDATE') AS can_update, "
            "       has_table_privilege('esign_app', :t, 'DELETE') AS can_delete, "
            "       has_table_privilege('esign_app', :t, 'TRUNCATE') AS can_truncate"
        ),
        {"t": table},
    ).one()
    assert row.can_select and row.can_insert and row.can_update and row.can_delete
    assert not row.can_truncate


def test_app_role_cannot_create_tables(db: Session) -> None:
    with pytest.raises(DBAPIError) as caught, db.begin_nested():
        db.execute(text("CREATE TABLE app_should_not_be_able_to_do_this (id integer)"))
    assert sqlstate(caught.value) == INSUFFICIENT_PRIVILEGE


# --------------------------------------------------------------------------- the owner and the triggers


def test_owner_update_of_an_audit_event_hits_the_trigger(owner_db: Session) -> None:
    """The owner is not stopped by the grants, so the trigger has to stop it."""
    event_id = insert_audit_event(owner_db)
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text("UPDATE audit_events SET event_type = 'tampered' WHERE id = :id"), {"id": event_id})
    assert sqlstate(caught.value) == RAISE_EXCEPTION
    assert "append-only" in str(caught.value.orig)


def test_owner_delete_of_an_audit_event_hits_the_trigger(owner_db: Session) -> None:
    event_id = insert_audit_event(owner_db)
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": event_id})
    assert sqlstate(caught.value) == RAISE_EXCEPTION
    assert "append-only" in str(caught.value.orig)


def test_owner_truncate_of_audit_events_hits_the_trigger(owner_db: Session) -> None:
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text("TRUNCATE TABLE audit_events"))
    assert sqlstate(caught.value) == RAISE_EXCEPTION
    assert "append-only" in str(caught.value.orig)


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_ROW_MAKERS))
def test_owner_cannot_delete_from_the_other_append_only_tables(owner_db: Session, table: str) -> None:
    """Every append-only table carries the trigger, not just the audit trail."""
    APPEND_ONLY_ROW_MAKERS[table](owner_db)
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text(f"DELETE FROM {table}"))
    assert sqlstate(caught.value) == RAISE_EXCEPTION
    assert "append-only" in str(caught.value.orig)


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_ROW_MAKERS))
def test_both_defences_hold_against_truncating_the_other_append_only_tables(
    db: Session, owner_db: Session, table: str
) -> None:
    """SPEC section 12: the app role is denied, and the owner role hits the trigger.

    ``0001`` put a TRUNCATE trigger on ``audit_events`` only; ``0100`` (blobs) and ``0600`` (the
    rest) closed the gap, so ``TRUNCATE ... CASCADE`` as the owner no longer erases evidence.
    """
    assert not db.execute(text("SELECT has_table_privilege('esign_app', :t, 'TRUNCATE')"), {"t": table}).scalar_one()
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text(f"TRUNCATE TABLE {table} CASCADE"))
    assert sqlstate(caught.value) == RAISE_EXCEPTION
    assert "append-only" in str(caught.value.orig)


def test_app_role_is_not_a_superuser_and_cannot_bypass_rls(db: Session) -> None:
    row = db.execute(text("SELECT rolsuper, rolbypassrls, rolcreatedb FROM pg_roles WHERE rolname = 'esign_app'")).one()
    assert not row.rolsuper
    assert not row.rolbypassrls
    assert not row.rolcreatedb
