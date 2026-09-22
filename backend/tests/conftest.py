"""Shared test fixtures.

Several agents run several test suites against the same Postgres at the same time, and pytest-xdist
runs several workers inside each of those. So nothing here shares a database: every pytest process
creates its own uniquely named database, migrates it, and drops it when the process ends. Two suites
running at once cannot see, lock or truncate each other's rows.

What you get:

``settings``        a ``Settings`` pointed at this process's database and a temporary blob directory
``clock``           a ``FixedClock`` you can ``advance()``; pinned to ``FROZEN_NOW``
``owner_engine``    engine for ``esign_owner`` -- migrations, and tests that need to beat the grants
``app_engine``      engine for ``esign_app`` -- the restricted runtime role
``db``              an ``esign_app`` ``Session`` inside a transaction that is rolled back afterwards
``owner_db``        the same, as ``esign_owner``
``db_factory``      real, separately-connected, really-committing sessions (concurrency tests)
``blob_dir``        an empty temporary directory for the ``fs`` blob backend

Database fixtures skip -- with a message telling you to run ``make up`` -- when Postgres is not
reachable, so the non-database tests still run in a sandbox without it.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.db import make_engine
from esign.migrate import apply_pending

#: Every clock-dependent test starts here unless it says otherwise.
FROZEN_NOW = datetime(2026, 3, 17, 14, 30, 0, tzinfo=UTC)

#: Tables the fixtures may empty between tests. ``schema_migrations`` is not one of them.
_NEVER_TRUNCATE = frozenset({"schema_migrations"})

_SKIP_MESSAGE = (
    "Postgres is not reachable on the configured DATABASE_OWNER_URL. "
    "Run `make up` from the repository root to start it (port 54329)."
)


# --------------------------------------------------------------------------- database lifecycle


def _worker_tag() -> str:
    """A short tag unique to this process, xdist worker included."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
    return f"{worker}_{os.getpid()}_{secrets.token_hex(3)}"


def _with_database(url: str | URL, database: str) -> URL:
    return make_url(url).set(database=database)


def dsn(url: URL) -> str:
    """A connectable string. ``str(URL)`` masks the password, which silently breaks auth."""
    return url.render_as_string(hide_password=False)


@pytest.fixture(scope="session")
def env_settings() -> Settings:
    """Settings as the environment has them: the URLs of the *development* database.

    Used only to find the server. No test ever touches the database these point at.
    """
    return Settings()


@pytest.fixture(scope="session")
def test_database(env_settings: Settings) -> Iterator[tuple[URL, URL]]:
    """Create, migrate and finally drop a database that belongs to this process alone.

    Yields ``(owner_url, app_url)``.
    """
    name = f"esign_test_{_worker_tag()}"
    owner_url = _with_database(env_settings.database_owner_url, name)
    app_url = _with_database(env_settings.database_url, name)

    # CREATE DATABASE cannot run inside a transaction, hence AUTOCOMMIT on a maintenance connection.
    admin = make_engine(
        dsn(_with_database(env_settings.database_owner_url, "postgres")),
        application_name="esign-tests-admin",
        pool_size=1,
    ).execution_options(isolation_level="AUTOCOMMIT")

    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{name}"'))
    except OperationalError as exc:  # server not running, wrong port, wrong credentials
        admin.dispose()
        pytest.skip(f"{_SKIP_MESSAGE}\n({exc.orig})")

    engine = make_engine(dsn(owner_url), application_name="esign-tests-migrate", pool_size=1)
    try:
        apply_pending(engine, env_settings.migrations_dir)
    finally:
        engine.dispose()

    try:
        yield owner_url, app_url
    finally:
        with admin.connect() as conn:
            # FORCE: a leaked connection must not keep a throwaway database alive.
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture(scope="session")
def owner_engine(test_database: tuple[URL, URL]) -> Iterator[Engine]:
    """``esign_owner``: owns the schema. The grants do not stop it -- the triggers do."""
    engine = make_engine(dsn(test_database[0]), application_name="esign-tests-owner", pool_size=4)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def app_engine(test_database: tuple[URL, URL]) -> Iterator[Engine]:
    """``esign_app``: what the service actually runs as. Use this unless a test needs otherwise."""
    engine = make_engine(dsn(test_database[1]), application_name="esign-tests-app", pool_size=8)
    try:
        yield engine
    finally:
        engine.dispose()


def reset_database(owner_engine: Engine) -> None:
    """Empty every table.

    The append-only tables refuse ``TRUNCATE`` and ``DELETE`` by trigger, which is the behaviour
    under test elsewhere, so this disables the user triggers for the duration and puts them back.
    It is a test-harness escape hatch and the only place in the repository that does this: no
    application code can reach it.
    """
    with owner_engine.begin() as conn:
        tables = [
            str(row[0])
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
            ).all()
            if str(row[0]) not in _NEVER_TRUNCATE
        ]
        if not tables:
            return
        quoted = ", ".join(f'"{name}"' for name in tables)
        for name in tables:
            conn.execute(text(f'ALTER TABLE "{name}" DISABLE TRIGGER USER'))
        conn.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))
        for name in tables:
            conn.execute(text(f'ALTER TABLE "{name}" ENABLE TRIGGER USER'))


# --------------------------------------------------------------------------- settings and time


@pytest.fixture
def blob_dir(tmp_path: Path) -> Path:
    """An empty directory for the ``fs`` blob backend. Files land here read-only and stay."""
    path = tmp_path / "blobstore"
    path.mkdir()
    return path


@pytest.fixture
def settings(test_database: tuple[URL, URL], tmp_path: Path, blob_dir: Path) -> Settings:
    """Settings pointed at this process's database and this test's temporary directories."""
    owner_url, app_url = test_database
    return Settings(
        app_env="test",
        database_url=dsn(app_url),
        database_owner_url=dsn(owner_url),
        blob_backend="fs",
        blob_fs_root=blob_dir,
        dev_pki_dir=tmp_path / "dev-pki",
        trust_roots_path=tmp_path / "dev-pki" / "trust-roots.pem",
        # Explicit, because B-T is never a default: the dev PKI cannot supply revocation data
        # offline, so tests ask for B-T by name (SPEC section 5).
        seal_profile="PAdES-B-T",
        tsa_url="",
        log_level="DEBUG",
    )


@pytest.fixture
def settings_no_db(tmp_path: Path) -> Settings:
    """Settings for tests that never touch the database, so they need no Postgres to run."""
    return Settings(
        app_env="test",
        blob_backend="fs",
        blob_fs_root=tmp_path / "blobstore",
        dev_pki_dir=tmp_path / "dev-pki",
        trust_roots_path=tmp_path / "dev-pki" / "trust-roots.pem",
        seal_profile="PAdES-B-T",
        tsa_url="",
    )


@pytest.fixture
def clock() -> FixedClock:
    """A stopped clock. ``clock.advance(seconds)`` or ``clock.set(when)`` to move it."""
    return FixedClock(FROZEN_NOW)


# --------------------------------------------------------------------------- sessions


@pytest.fixture
def db(app_engine: Engine) -> Iterator[Session]:
    """An ``esign_app`` session whose work is rolled back at the end of the test.

    The session runs inside an outer transaction and joins it with a savepoint, so code under test
    may call ``commit()`` normally and still leave the database as it found it.
    """
    connection = app_engine.connect()
    outer = connection.begin()
    session = Session(bind=connection, expire_on_commit=False, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        if outer.is_active:
            outer.rollback()
        connection.close()


@pytest.fixture
def owner_db(owner_engine: Engine) -> Iterator[Session]:
    """The same, as ``esign_owner``. For tests that must get past the grants to reach a trigger."""
    connection = owner_engine.connect()
    outer = connection.begin()
    session = Session(bind=connection, expire_on_commit=False, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        if outer.is_active:
            outer.rollback()
        connection.close()


@pytest.fixture
def db_factory(app_engine: Engine, owner_engine: Engine) -> Iterator[Callable[[], AbstractContextManager[Session]]]:
    """Real sessions on separate connections, whose commits really commit.

    For anything the rollback trick cannot express: two threads appending to one audit stream, row
    locks, advisory locks, `SELECT ... FOR UPDATE`. Use it as a context manager::

        with db_factory() as db:
            ...
            db.commit()

    Every table is emptied after the test, append-only ones included.
    """
    opened: list[Session] = []

    @contextmanager
    def _session() -> Iterator[Session]:
        session = Session(bind=app_engine, expire_on_commit=False)
        opened.append(session)
        try:
            yield session
        finally:
            session.close()

    try:
        yield _session
    finally:
        for session in opened:
            session.close()
        reset_database(owner_engine)
        reset_database(owner_engine)


@pytest.fixture
def owner_db_factory(owner_engine: Engine) -> Iterator[Callable[[], AbstractContextManager[Session]]]:
    """``db_factory`` as the owner role, for tests that must get past the grants with real commits."""
    opened: list[Session] = []

    @contextmanager
    def _session() -> Iterator[Session]:
        session = Session(bind=owner_engine, expire_on_commit=False)
        opened.append(session)
        try:
            yield session
        finally:
            session.close()

    try:
        yield _session
    finally:
        for session in opened:
            session.close()
        reset_database(owner_engine)
