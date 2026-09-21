"""The two lines of defence over the audit trail, exercised through this module's own writes.

SPEC section 12: "app role cannot UPDATE/DELETE/TRUNCATE audit events; owner role hits the
trigger". The foundation proves it for hand-inserted rows; this proves it for the rows the audit
log actually writes, and that the log itself never needs anything more than SELECT and INSERT.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from esign.contracts import AuditLog, EventType
from tests.audit.helpers import sample_data

INSUFFICIENT_PRIVILEGE = "42501"
RAISE_EXCEPTION = "P0001"


def _sqlstate(exc: DBAPIError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)


def _one_event(db: Session, audit: AuditLog) -> tuple[object, object]:
    stream = uuid4()
    event = audit.append(
        db,
        stream_type="envelope",
        stream_id=stream,
        event_type=EventType.ENVELOPE_CREATED,
        data=sample_data(EventType.ENVELOPE_CREATED),
    )
    return stream, event.id


def test_the_app_role_can_write_and_read_the_trail(db: Session, audit: AuditLog) -> None:
    stream, event_id = _one_event(db, audit)
    events = audit.list(db, "envelope", stream)  # type: ignore[arg-type]
    assert [event.id for event in events] == [event_id]
    assert audit.verify(db, "envelope", stream).ok  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET event_type = 'envelope.voided' WHERE id = :id",
        "UPDATE audit_events SET data = '{}'::jsonb WHERE id = :id",
        "UPDATE audit_events SET event_hash = '\\x00'::bytea WHERE id = :id",
        "DELETE FROM audit_events WHERE id = :id",
        "DELETE FROM audit_events",
        "TRUNCATE TABLE audit_events",
    ],
)
def test_the_app_role_cannot_change_an_event_it_wrote(db: Session, audit: AuditLog, statement: str) -> None:
    _, event_id = _one_event(db, audit)
    with pytest.raises(DBAPIError) as caught, db.begin_nested():
        db.execute(text(statement), {"id": event_id})
    assert _sqlstate(caught.value) == INSUFFICIENT_PRIVILEGE


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET event_type = 'envelope.voided' WHERE id = :id",
        "UPDATE audit_events SET occurred_at = now() WHERE id = :id",
        "DELETE FROM audit_events WHERE id = :id",
    ],
)
def test_the_owner_role_gets_past_the_grants_and_hits_the_trigger(
    owner_db: Session, audit: AuditLog, statement: str
) -> None:
    _, event_id = _one_event(owner_db, audit)
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text(statement), {"id": event_id})
    assert _sqlstate(caught.value) == RAISE_EXCEPTION
    assert "append-only" in str(caught.value.orig)


def test_the_owner_role_cannot_truncate_the_trail_either(owner_db: Session, audit: AuditLog) -> None:
    _one_event(owner_db, audit)
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text("TRUNCATE TABLE audit_events"))
    assert _sqlstate(caught.value) == RAISE_EXCEPTION


def test_the_audit_log_needs_no_privilege_beyond_select_and_insert(db: Session) -> None:
    row = db.execute(
        text(
            "SELECT has_table_privilege('esign_app', 'audit_events', 'SELECT') AS can_select, "
            "       has_table_privilege('esign_app', 'audit_events', 'INSERT') AS can_insert, "
            "       has_table_privilege('esign_app', 'audit_events', 'UPDATE') AS can_update, "
            "       has_table_privilege('esign_app', 'audit_events', 'DELETE') AS can_delete, "
            "       has_table_privilege('esign_app', 'audit_events', 'TRUNCATE') AS can_truncate"
        )
    ).one()
    assert row.can_select and row.can_insert
    assert not (row.can_update or row.can_delete or row.can_truncate)


def test_the_audit_log_exposes_no_way_to_remove_an_event(audit: AuditLog) -> None:
    forbidden = {"delete", "remove", "purge", "update", "rewrite", "truncate", "drop"}
    names = {name for name in dir(audit) if not name.startswith("_")}
    assert not {name for name in names if any(word in name.lower() for word in forbidden)}
