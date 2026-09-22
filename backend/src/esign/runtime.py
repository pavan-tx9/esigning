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
from typing import Final, Protocol
from uuid import UUID

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from esign.archives import build_archive_service
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
from esign.identity import build_identity_service, build_rate_limiter, parse_trusted_proxies
from esign.sealing import build_sealer
from esign.storage import build_blob_service
from esign.webhooks import WebhookQueue

__all__ = ["ConfigurationError", "GatedEnvelopeService", "Runtime", "build_runtime", "check_production_settings"]


class ConfigurationError(RuntimeError):
    """Settings that must not be used as they stand.

    A ``RuntimeError`` so the existing contract (``create_app`` refuses to start) is unchanged, and
    a named subclass so the CLI can turn it into a non-zero exit with a readable message instead of
    a traceback.
    """


#: The passwords ``0002_roles.sql`` sets when it has to create the roles itself. A production
#: deployment creates them out of band; a DSN still carrying these is a deployment that did not.
_DEV_APP_PASSWORD: Final[str] = "esign_app_dev"  # noqa: S105 - a value to refuse, not a credential to use
_DEV_OWNER_PASSWORD: Final[str] = "esign_owner_dev"  # noqa: S105 - likewise


def check_production_settings(settings: Settings) -> None:
    """Fail at startup, not at the first signature. Production only.

    Called from :func:`build_runtime`, which is the single door every process goes through -- the
    API, ``esign worker`` (the process that actually seals), ``esign verify`` and every other
    command. Gating only the API would leave the worker sealing real documents at ``PAdES-B-T``
    with the dev key while the API container beside it refused to start.
    """
    parse_trusted_proxies(settings.trusted_proxy_cidrs)  # a typo here silently changes every recorded IP
    if settings.blob_backend == "s3" and not settings.blob_s3_bucket:
        # Not gated on the environment: the s3 backend has no usable meaning without a bucket in
        # *any* environment. Left to the backend it surfaces as a bare ValueError at the first
        # blob write -- from ``esign worker`` or ``esign verify``, which catch ConfigurationError
        # and EsignError only, so it reached the operator as a traceback instead of a refusal.
        raise ConfigurationError("refusing to start: BLOB_S3_BUCKET is required when BLOB_BACKEND is s3")
    if settings.app_env == "dev" and (settings.seal_key_backend == "aws_kms" or settings.blob_backend == "s3"):
        # A production key or a production bucket with the *default* environment is a deployment
        # that forgot ``APP_ENV``, and every production rule below -- a real TSA above all -- is
        # keyed on it. Caught here, at startup, rather than at the first seal.
        raise ConfigurationError(
            "refusing to start: APP_ENV=dev with a production key or blob backend; set APP_ENV=prod"
        )
    if settings.app_env != "prod":
        return
    problems: list[str] = []
    if settings.seal_profile == "PAdES-B-T":
        problems.append("SEAL_PROFILE must be PAdES-B-LT or PAdES-B-LTA in production")
    if settings.seal_key_backend != "aws_kms":
        problems.append("SEAL_KEY_BACKEND must be aws_kms in production (the local dev PKI is not a production key)")
    if settings.seal_key_backend == "aws_kms":
        # Otherwise these are only noticed at the first seal, by which time a document is signed
        # and waiting, and the failure looks like an outage rather than a misconfiguration.
        if not settings.seal_kms_key_id:
            problems.append("SEAL_KMS_KEY_ID is required when SEAL_KEY_BACKEND is aws_kms")
        if settings.seal_cert_path is None or not settings.seal_cert_path.is_file():
            problems.append("SEAL_CERT_PATH must point at the seal certificate when SEAL_KEY_BACKEND is aws_kms")
    if settings.blob_backend != "s3":
        problems.append("BLOB_BACKEND must be s3 in production (the fs backend cannot enforce retention)")
    if not settings.trust_roots_path.is_file():
        problems.append("TRUST_ROOTS_PATH does not exist; every verification would fail")
    if not settings.tsa_url:
        problems.append("TSA_URL is required in production")
    if _DEV_APP_PASSWORD in settings.database_url:
        problems.append("DATABASE_URL still holds the development password for esign_app")
    if _DEV_OWNER_PASSWORD in settings.database_owner_url:
        problems.append("DATABASE_OWNER_URL still holds the development password for esign_owner")
    if settings.db_echo:
        # SQLAlchemy's echo goes to the stdlib logger with bound parameters attached: display
        # names, prefill values and typed signatures, in a log line. SPEC section 10.
        problems.append("DB_ECHO must be off in production (it would log statement parameters, which carry PHI)")
    if problems:
        raise ConfigurationError("refusing to start: " + "; ".join(problems))


class GatedEnvelopeService(EnvelopeService, Protocol):
    """``EnvelopeService`` plus the one gate the API needs that the contract does not yet declare.

    ``assert_reauth_allowed`` belongs beside ``assert_signer_may_start`` in
    ``contracts.EnvelopeService``: both answer "may this host still do this to this signer?" under
    the envelope row lock. ``contracts.py`` is architecture-owned, so the extra method is declared
    here, at the wiring layer, until it can be moved. See the integration report.
    """

    def assert_reauth_allowed(self, db: Session, envelope_id: UUID, signer_id: UUID) -> None:
        """Raise ``Conflict`` unless a re-authentication attestation could still belong to this
        signer's signature: envelope live, signer not finished, role re-authenticates."""


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
    envelopes: GatedEnvelopeService
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
    supplied by tests (a shared test engine, a sealer with an outage injected).

    The production settings check runs first, before anything opens a connection, so the API, the
    worker and every CLI command are gated identically (SPEC sections 3 and 5).
    """
    settings = settings or get_settings()
    check_production_settings(settings)
    clock = clock or SystemClock()
    engine = engine or app_engine(settings)
    sessions = session_factory(engine)

    audit = build_audit_log(settings, clock)
    blobs = build_blob_service(settings, clock)
    documents = build_document_service(settings, clock)
    identity = build_identity_service(settings, clock)
    the_sealer = sealer or build_sealer(settings, clock)
    webhooks = WebhookQueue(clock)

    # Addendum 1 A. The archives module checks a scan with ``DocumentService.inspect_scan_pdf``:
    # the template hygiene rules under the scan bounds, from the same document service.
    archives = build_archive_service(settings, clock, audit_log=audit, blob_service=blobs, document_service=documents)

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
        archives=archives,
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
