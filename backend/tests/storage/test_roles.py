"""The two lines of defence over ``blobs``, exercised through rows this module actually wrote.

SPEC section 12 asks for both: the app role is denied outright by the grants, and the owner role,
which the grants do not stop, still hits the append-only trigger.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from esign.contracts import BlobService

INSUFFICIENT_PRIVILEGE = "42501"
RAISE_EXCEPTION = "P0001"

PDF = b"%PDF-1.7\nrole test\n%%EOF\n"


def _sqlstate(exc: DBAPIError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)


def test_the_app_role_can_store_and_read_a_blob(db: Session, fs_blobs: BlobService) -> None:
    ref = fs_blobs.put(db, PDF, kind="sealed_pdf")
    assert fs_blobs.get(db, ref.sha256) == PDF


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE blobs SET kind = 'template_pdf' WHERE sha256 = :sha",
        "UPDATE blobs SET storage_key = 'elsewhere' WHERE sha256 = :sha",
        "UPDATE blobs SET retain_until = now() WHERE sha256 = :sha",
        "DELETE FROM blobs WHERE sha256 = :sha",
        "DELETE FROM blobs",
        "TRUNCATE TABLE blobs",
    ],
)
def test_the_app_role_cannot_change_a_blob_row(db: Session, fs_blobs: BlobService, statement: str) -> None:
    ref = fs_blobs.put(db, PDF, kind="sealed_pdf")
    with pytest.raises(DBAPIError) as caught, db.begin_nested():
        db.execute(text(statement), {"sha": ref.sha256})
    assert _sqlstate(caught.value) == INSUFFICIENT_PRIVILEGE


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE blobs SET kind = 'template_pdf' WHERE sha256 = :sha",
        "UPDATE blobs SET retain_until = NULL WHERE sha256 = :sha",
        "DELETE FROM blobs WHERE sha256 = :sha",
        # The interesting one: CASCADE is the form that would otherwise work, because plain
        # TRUNCATE is stopped earlier by the foreign keys pointing at this table.
        "TRUNCATE TABLE blobs CASCADE",
    ],
)
def test_the_owner_role_gets_past_the_grants_and_hits_the_trigger(
    owner_db: Session, fs_blobs: BlobService, statement: str
) -> None:
    ref = fs_blobs.put(owner_db, PDF, kind="sealed_pdf")
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text(statement), {"sha": ref.sha256})
    assert _sqlstate(caught.value) == RAISE_EXCEPTION
    assert "append-only" in str(caught.value.orig)


def test_the_truncate_guard_added_by_migration_0100_is_installed(owner_db: Session) -> None:
    """`0001` gave the TRUNCATE trigger to `audit_events` only; `0100` gives it to `blobs` too."""
    installed = owner_db.execute(
        text(
            "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
            "WHERE c.relname = 'blobs' AND t.tgname = 'blobs_no_truncate' AND t.tgenabled = 'O'"
        )
    ).scalar_one()
    assert installed == 1


def test_the_blob_service_needs_no_privilege_beyond_select_and_insert(db: Session) -> None:
    row = db.execute(
        text(
            "SELECT has_table_privilege('esign_app', 'blobs', 'SELECT') AS can_select, "
            "       has_table_privilege('esign_app', 'blobs', 'INSERT') AS can_insert, "
            "       has_table_privilege('esign_app', 'blobs', 'UPDATE') AS can_update, "
            "       has_table_privilege('esign_app', 'blobs', 'DELETE') AS can_delete, "
            "       has_table_privilege('esign_app', 'blobs', 'TRUNCATE') AS can_truncate"
        )
    ).one()
    assert row.can_select and row.can_insert
    assert not (row.can_update or row.can_delete or row.can_truncate)
