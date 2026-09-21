"""The migration runner and the schema it produces."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from esign.config import Settings
from esign.migrate import MigrationError, applied_versions, apply_pending, discover

EXPECTED_TABLES = {
    "audit_events",
    "blobs",
    "consent_texts",
    "document_revisions",
    "envelopes",
    "hosts",
    "idempotency_keys",
    "reauth_attestations",
    "seal_jobs",
    "signature_captures",
    "signers",
    "signing_sessions",
    "template_versions",
    "templates",
    "webhook_deliveries",
}


def test_every_schema_table_exists(owner_engine: Engine) -> None:
    with owner_engine.connect() as conn:
        present = {
            str(row[0])
            for row in conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).all()
        }
    assert present >= EXPECTED_TABLES


def test_both_migrations_are_recorded(owner_engine: Engine) -> None:
    applied = applied_versions(owner_engine)
    assert "0001_schema" in applied
    assert "0002_roles" in applied


def test_reapplying_is_a_no_op(owner_engine: Engine, env_settings: Settings) -> None:
    before = applied_versions(owner_engine)
    assert apply_pending(owner_engine, env_settings.migrations_dir) == []
    assert applied_versions(owner_engine) == before


def test_migrations_are_discovered_in_filename_order(env_settings: Settings) -> None:
    versions = [m.version for m in discover(env_settings.migrations_dir)]
    assert versions == sorted(versions)
    assert versions[:2] == ["0001_schema", "0002_roles"]


@pytest.fixture
def scratch_migrations(env_settings: Settings, tmp_path: Path) -> Path:
    """A copy of the real migrations, so history checks see the versions already applied."""
    directory = tmp_path / "migrations"
    directory.mkdir()
    for source in sorted(env_settings.migrations_dir.glob("*.sql")):
        (directory / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return directory


def _drop_probe(owner_engine: Engine, table: str, version: str) -> None:
    with owner_engine.begin() as conn:
        conn.execute(text(f"DROP TABLE IF EXISTS {table}"))
        conn.execute(text("DELETE FROM schema_migrations WHERE version = :v"), {"v": version})


def test_editing_an_applied_migration_is_refused(owner_engine: Engine, scratch_migrations: Path) -> None:
    """A file whose checksum no longer matches what was applied is an error, not a silent skip.

    Migrations are how the schema is described to whoever reads this repository in five years.
    A file that no longer matches the database it produced makes that description a lie.
    """
    migration = scratch_migrations / "9001_probe.sql"
    migration.write_text("CREATE TABLE foundation_probe (id integer PRIMARY KEY);")
    try:
        assert apply_pending(owner_engine, scratch_migrations) == ["9001_probe"]

        migration.write_text("CREATE TABLE foundation_probe (id integer PRIMARY KEY, extra text);")
        with pytest.raises(MigrationError, match="edited after it was applied"):
            apply_pending(owner_engine, scratch_migrations)
    finally:
        _drop_probe(owner_engine, "foundation_probe", "9001_probe")


def test_a_missing_migration_file_is_refused(owner_engine: Engine, scratch_migrations: Path) -> None:
    migration = scratch_migrations / "9002_probe.sql"
    migration.write_text("CREATE TABLE foundation_probe2 (id integer PRIMARY KEY);")
    try:
        assert apply_pending(owner_engine, scratch_migrations) == ["9002_probe"]
        migration.unlink()

        with pytest.raises(MigrationError, match="its file is gone"):
            apply_pending(owner_engine, scratch_migrations)
    finally:
        _drop_probe(owner_engine, "foundation_probe2", "9002_probe")


def test_a_new_table_inherits_grants_from_the_default_privileges(
    owner_engine: Engine, scratch_migrations: Path, db: Session
) -> None:
    """A later module's migration should not have to remember to GRANT anything (SPEC 0002)."""
    (scratch_migrations / "9003_probe.sql").write_text("CREATE TABLE foundation_probe3 (id integer PRIMARY KEY);")
    try:
        apply_pending(owner_engine, scratch_migrations)
        row = db.execute(
            text(
                "SELECT has_table_privilege('esign_app', 'foundation_probe3', 'SELECT') AS can_select, "
                "       has_table_privilege('esign_app', 'foundation_probe3', 'INSERT') AS can_insert, "
                "       has_table_privilege('esign_app', 'foundation_probe3', 'TRUNCATE') AS can_truncate"
            )
        ).one()
        assert row.can_select and row.can_insert
        assert not row.can_truncate
    finally:
        _drop_probe(owner_engine, "foundation_probe3", "9003_probe")


def test_missing_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(MigrationError, match="migrations directory not found"):
        discover(tmp_path / "nope")
