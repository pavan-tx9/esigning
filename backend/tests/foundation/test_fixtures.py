"""The fixtures themselves.

Every module's tests are built on these, so their guarantees are worth asserting once here: the
``db`` session leaves nothing behind even if the code under test commits, and ``db_factory`` gives
out real connections whose commits other connections can see, cleaned up afterwards.

The pairs of tests below depend on file order, which pytest guarantees within a module.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from esign.config import Settings
from tests.foundation.helpers import insert_host

SessionMaker = Callable[[], AbstractContextManager[Session]]


def _count(db: Session, table: str) -> int:
    return int(db.execute(text(f"SELECT count(*) FROM {table}")).scalar_one())


# --------------------------------------------------------------------------- the rollback session


def test_db_session_survives_a_commit_by_the_code_under_test(db: Session) -> None:
    insert_host(db, "rolled back")
    db.commit()  # a service would; the outer transaction still owns the truth
    assert _count(db, "hosts") == 1


def test_db_session_left_nothing_behind(db: Session) -> None:
    assert _count(db, "hosts") == 0


# --------------------------------------------------------------------------- real connections


def test_db_factory_commits_are_visible_to_another_connection(db_factory: SessionMaker) -> None:
    with db_factory() as writer:
        insert_host(writer, "really committed")
        writer.commit()
    with db_factory() as reader:
        assert _count(reader, "hosts") == 1


def test_db_factory_cleaned_up_after_the_previous_test(db_factory: SessionMaker) -> None:
    with db_factory() as reader:
        assert _count(reader, "hosts") == 0


def test_db_factory_cleanup_can_empty_the_append_only_tables(db_factory: SessionMaker) -> None:
    """The harness can reset tables the application itself is forbidden to touch."""
    from tests.foundation.helpers import insert_audit_event

    with db_factory() as writer:
        insert_audit_event(writer)
        writer.commit()
    with db_factory() as reader:
        assert _count(reader, "audit_events") == 1


def test_append_only_tables_were_reset_too(db_factory: SessionMaker) -> None:
    with db_factory() as reader:
        assert _count(reader, "audit_events") == 0


# --------------------------------------------------------------------------- roles and settings


def test_the_two_engines_really_are_two_roles(app_engine: Engine, owner_engine: Engine) -> None:
    with app_engine.connect() as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "esign_app"
    with owner_engine.connect() as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "esign_owner"


def test_tests_never_touch_the_development_database(settings: Settings, env_settings: Settings) -> None:
    from sqlalchemy.engine import make_url

    test_db = make_url(settings.database_url).database
    dev_db = make_url(env_settings.database_url).database
    assert test_db is not None
    assert test_db.startswith("esign_test_")
    assert test_db != dev_db


def test_blob_dir_is_empty_and_writable(blob_dir: Path, settings: Settings) -> None:
    assert blob_dir.is_dir()
    assert list(blob_dir.iterdir()) == []
    assert settings.blob_fs_root == blob_dir
