"""Migration runner.

Plain SQL files in ``backend/migrations/``, applied in filename order as the owner role, recorded
in ``schema_migrations``. Each file runs in its own transaction together with the row that records
it, so a half-applied migration is not a state this can end in.

An applied file's checksum is stored. Editing a migration that has already run is refused rather
than silently ignored: the schema in front of you must be the schema the files describe.

    uv run python -m esign.migrate            # apply everything pending
    uv run python -m esign.migrate --status   # show what is applied and what is pending
    uv run python -m esign.migrate --dry-run  # list what would run, change nothing
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Connection, Engine, text

from esign.config import Settings
from esign.db import make_engine

__all__ = ["Migration", "applied_versions", "apply_pending", "discover", "main"]

#: Advisory lock id so two runners (CI and a developer, two agents) cannot interleave.
_MIGRATION_LOCK_KEY = 0x0E_51_9A_17

_SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version    text PRIMARY KEY,
  checksum   text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
)
"""


class MigrationError(RuntimeError):
    """A migration cannot be applied, or the recorded history disagrees with the files."""


def run_script(conn: Connection, sql: str) -> None:
    """Execute a whole SQL script on the driver cursor, parameters and all left alone.

    Migrations are literal SQL: they contain ``%`` inside ``RAISE`` and ``format()`` strings and
    ``$$`` dollar-quoted function bodies. Anything that hands the text to psycopg *with* a
    parameter sequence makes psycopg try to interpolate those, so this goes straight to the driver
    with no parameters at all. It runs inside whatever transaction the caller has open.
    """
    dbapi_connection = conn.connection.dbapi_connection
    if dbapi_connection is None:  # pragma: no cover - only if the pool handed back a dead connection
        raise MigrationError("no live DBAPI connection")
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(sql)
    finally:
        cursor.close()


@dataclass(frozen=True)
class Migration:
    version: str  # filename stem, e.g. "0002_roles"
    path: Path
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def discover(migrations_dir: Path) -> list[Migration]:
    """Every ``*.sql`` in the directory, in filename order."""
    if not migrations_dir.is_dir():
        raise MigrationError(f"migrations directory not found: {migrations_dir}")
    migrations = [
        Migration(version=path.stem, path=path, sql=path.read_text(encoding="utf-8"))
        for path in sorted(migrations_dir.glob("*.sql"))
    ]
    versions = [m.version for m in migrations]
    duplicates = {v for v in versions if versions.count(v) > 1}
    if duplicates:
        raise MigrationError(f"duplicate migration versions: {sorted(duplicates)}")
    return migrations


def applied_versions(engine: Engine) -> dict[str, str]:
    """``{version: checksum}`` for everything already applied."""
    with engine.begin() as conn:
        run_script(conn, _SCHEMA_MIGRATIONS_DDL)
        rows = conn.execute(text("SELECT version, checksum FROM schema_migrations")).all()
    return {str(row[0]): str(row[1]) for row in rows}


def _check_history(migrations: list[Migration], applied: dict[str, str]) -> None:
    by_version = {m.version: m for m in migrations}
    for version, checksum in sorted(applied.items()):
        migration = by_version.get(version)
        if migration is None:
            raise MigrationError(f"migration {version} is recorded as applied but its file is gone")
        if migration.checksum != checksum:
            raise MigrationError(
                f"migration {version} was edited after it was applied "
                f"(recorded {checksum[:12]}, file {migration.checksum[:12]}). "
                "Add a new numbered migration instead of changing an applied one."
            )


def apply_pending(engine: Engine, migrations_dir: Path, *, dry_run: bool = False) -> list[str]:
    """Apply every migration not yet recorded. Returns the versions applied (or that would be)."""
    migrations = discover(migrations_dir)
    applied = applied_versions(engine)
    _check_history(migrations, applied)

    pending = [m for m in migrations if m.version not in applied]
    if dry_run or not pending:
        return [m.version for m in pending]

    done: list[str] = []
    with engine.connect() as conn:
        # Session-scoped, so it outlives the per-migration transactions below.
        conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": _MIGRATION_LOCK_KEY})
        conn.commit()
        try:
            # Another runner may have held the lock and applied some of these already.
            already = {str(row[0]) for row in conn.execute(text("SELECT version FROM schema_migrations")).all()}
            conn.commit()
            for migration in pending:
                if migration.version in already:
                    continue
                with conn.begin():
                    run_script(conn, migration.sql)
                    conn.execute(
                        text("INSERT INTO schema_migrations (version, checksum) VALUES (:v, :c)"),
                        {"v": migration.version, "c": migration.checksum},
                    )
                done.append(migration.version)
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": _MIGRATION_LOCK_KEY})
            conn.commit()
    return done


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="esign.migrate", description=__doc__)
    parser.add_argument("--url", help="database URL to migrate (default: DATABASE_OWNER_URL)")
    parser.add_argument("--dir", type=Path, help="migrations directory (default: backend/migrations)")
    parser.add_argument("--dry-run", action="store_true", help="list pending migrations, change nothing")
    parser.add_argument("--status", action="store_true", help="show applied and pending migrations")
    args = parser.parse_args(argv)

    settings = Settings()
    url = args.url or settings.database_owner_url
    migrations_dir = args.dir or settings.migrations_dir
    engine = make_engine(url, application_name="esign-migrate", pool_size=1)

    try:
        if args.status:
            applied = applied_versions(engine)
            for migration in discover(migrations_dir):
                mark = "applied" if migration.version in applied else "pending"
                print(f"{mark:>7}  {migration.version}")
            return 0

        versions = apply_pending(engine, migrations_dir, dry_run=args.dry_run)
        if not versions:
            print("up to date")
        elif args.dry_run:
            for version in versions:
                print(f"would apply {version}")
        else:
            for version in versions:
                print(f"applied {version}")
        return 0
    except MigrationError as exc:
        print(f"migration failed: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
