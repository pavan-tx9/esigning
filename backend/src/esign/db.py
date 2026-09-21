"""Database engines and sessions.

Two roles, two engines. ``esign_app`` is the runtime role and can only ``SELECT``/``INSERT`` on the
append-only tables; ``esign_owner`` owns the schema and runs migrations. Nothing in the application
path should ever reach for the owner engine.

Contract functions take a ``Session`` inside a transaction the caller owns and never commit; the
helpers here are the callers that do.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from esign.config import Settings

__all__ = [
    "advisory_xact_lock",
    "app_engine",
    "make_engine",
    "owner_engine",
    "session_factory",
    "transaction",
]


def make_engine(url: str, *, echo: bool = False, pool_size: int = 5, application_name: str = "esign") -> Engine:
    """An engine for one database URL.

    ``pool_pre_ping`` because a signing session outlives a Postgres restart more often than not,
    and a stale connection must not look like a signing failure.
    """
    return create_engine(
        url,
        echo=echo,
        future=True,
        pool_pre_ping=True,
        # A driver error's text otherwise quotes the statement's parameters -- display names,
        # prefill-derived values -- and exception text has a way of reaching logs.
        hide_parameters=True,
        pool_size=pool_size,
        max_overflow=pool_size,
        connect_args={"application_name": application_name},
    )


def app_engine(settings: Settings, *, application_name: str = "esign-app") -> Engine:
    """Engine for the restricted runtime role."""
    return make_engine(
        settings.database_url,
        echo=settings.db_echo,
        pool_size=settings.db_pool_size,
        application_name=application_name,
    )


def owner_engine(settings: Settings, *, application_name: str = "esign-owner") -> Engine:
    """Engine for the migration role. Migrations and the test harness only."""
    return make_engine(
        settings.database_owner_url,
        echo=settings.db_echo,
        pool_size=2,
        application_name=application_name,
    )


def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Sessions that do not expire objects on commit, so a view built inside the transaction
    stays readable after it."""
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def transaction(factory: sessionmaker[Session]) -> Iterator[Session]:
    """One unit of work: commit on clean exit, roll back on any exception.

    The state change and its audit event share this transaction, which is the whole point --
    an envelope can never move without the event that explains why.
    """
    session = factory()
    try:
        with session.begin():
            yield session
    finally:
        session.close()


def advisory_xact_lock(db: Session, key: int) -> None:
    """Take a transaction-scoped advisory lock. Released when the transaction ends, always."""
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def ping(engine: Engine) -> bool:
    """True when the database answers. Used by fixtures and health checks."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        return False
    return True


def exec_sql(db: Session, sql: str, params: dict[str, Any] | None = None) -> Any:
    """Run one statement with bound parameters. Thin, but it keeps `text()` imports out of modules."""
    return db.execute(text(sql), params or {})
