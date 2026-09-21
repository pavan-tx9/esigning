"""The one place every module is wired together.

The API, the worker and the CLI all need the same object graph: settings, a clock, an engine for
the restricted ``esign_app`` role, and each module built through its factory with its
collaborators injected. ``build_runtime`` makes that graph once; nothing else in the codebase calls
a module factory.

Transactions belong to the caller. ``Runtime.transaction()`` is the unit of work every request and
every job step runs in: commit on clean exit, roll back on any exception. ``Runtime.new_session``
hands the envelope service a *separate* session for the one thing that must outlive a rollback --
the ``seal.failed`` record.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from esign.audit import build_audit_log
from esign.clock import SystemClock
from esign.config import Settings, get_settings
from esign.contracts import (
    AuditLog,
    BlobService,
    Clock,
    DocumentService,
    EnvelopeService,
    IdentityService,
    RateLimiter,
    Sealer,
)
from esign.db import app_engine, session_factory, transaction
from esign.documents import build_document_service
from esign.envelopes import build_envelope_service
from esign.identity import build_identity_service, build_rate_limiter
from esign.sealing import build_sealer
from esign.storage import build_blob_service
from esign.webhooks import WebhookQueue

__all__ = ["Runtime", "build_runtime"]


@dataclass(frozen=True)
class Runtime:
    settings: Settings
    clock: Clock
    engine: Engine
    sessions: sessionmaker[Session]
    audit: AuditLog
    blobs: BlobService
    documents: DocumentService
    identity: IdentityService
    limiter: RateLimiter
    sealer: Sealer
    envelopes: EnvelopeService
    webhooks: WebhookQueue

    def transaction(self) -> AbstractContextManager[Session]:
        """One unit of work: commit on clean exit, roll back on any exception."""
        return transaction(self.sessions)

    @contextmanager
    def new_session(self) -> Iterator[Session]:
        """A session on its own connection; the caller commits. Closed (and rolled back if it
        was not committed) on exit."""
        session = self.sessions()
        try:
            yield session
        finally:
            session.close()


def build_runtime(
    settings: Settings | None = None,
    *,
    clock: Clock | None = None,
    engine: Engine | None = None,
    sealer: Sealer | None = None,
    limiter: RateLimiter | None = None,
) -> Runtime:
    """Wire every module through its factory. ``engine``, ``sealer`` and ``limiter`` can be
    supplied by tests (a shared test engine, a sealer with an outage injected)."""
    settings = settings or get_settings()
    clock = clock or SystemClock()
    engine = engine or app_engine(settings)
    sessions = session_factory(engine)

    audit = build_audit_log(settings, clock)
    blobs = build_blob_service(settings, clock)
    documents = build_document_service(settings, clock)
    identity = build_identity_service(settings, clock)
    the_sealer = sealer or build_sealer(settings, clock)
    webhooks = WebhookQueue(clock)

    @contextmanager
    def fresh_session() -> Iterator[Session]:
        session = sessions()
        try:
            yield session
        finally:
            session.close()

    envelopes = build_envelope_service(
        settings,
        clock,
        audit_log=audit,
        blob_service=blobs,
        document_service=documents,
        identity_service=identity,
        sealer=the_sealer,
        new_session=fresh_session,
        notifier=webhooks,
    )
    return Runtime(
        settings=settings,
        clock=clock,
        engine=engine,
        sessions=sessions,
        audit=audit,
        blobs=blobs,
        documents=documents,
        identity=identity,
        limiter=limiter or build_rate_limiter(settings, clock),
        sealer=the_sealer,
        envelopes=envelopes,
        webhooks=webhooks,
    )
