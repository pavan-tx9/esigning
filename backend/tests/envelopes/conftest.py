"""Fixtures for the envelope tests.

``Bench`` is one service wired to the fakes in ``fakes.py``, plus the small amount of setup every
test needs: a host, a published template, an envelope, a signing session. It is a class rather
than a pile of fixtures so the concurrency tests can hand the *same* fakes to two threads holding
two different database sessions.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import (
    AuthContext,
    AuthMethod,
    Capacity,
    EnvelopeView,
    Host,
    KioskContext,
    NewEnvelope,
    NewSigner,
    RequestContext,
    SessionInfo,
    WebhookEvent,
)
from esign.envelopes import build_envelope_service
from esign.envelopes.service import EnvelopeServiceImpl, SessionScope
from esign.ids import new_id
from tests.envelopes.fakes import (
    FakeAuditLog,
    FakeBlobService,
    FakeDocumentService,
    FakeIdentityService,
    FakeSealer,
)

CTX = RequestContext(ip="198.51.100.7", user_agent="EsignTest/1.0", auth_method="password")
CONSENT_VERSION = "2026-09"
#: Pages in every document the fake document service produces.
PAGES = 3


# --------------------------------------------------------------------------- template definitions


def role(
    key: str,
    label: str,
    capacities: tuple[str, ...],
    *,
    requires_reauth: bool = False,
    order_index: int = 0,
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "allowed_capacities": list(capacities),
        "requires_reauth": requires_reauth,
        "order_index": order_index,
    }


def field(
    field_id: str,
    signer_role: str,
    *,
    field_type: str = "signature",
    page: int = 1,
    required: bool = True,
    label: str = "",
) -> dict[str, Any]:
    return {
        "id": field_id,
        "type": field_type,
        "page": page,
        "rect": {"x": 72.0, "y": 120.0, "w": 220.0, "h": 48.0},
        "signer_role": signer_role,
        "required": required,
        "label": label,
    }


@dataclass(frozen=True)
class TemplateSpec:
    key: str
    document_type: str
    roles: tuple[dict[str, Any], ...]
    fields: tuple[dict[str, Any], ...]
    prefill_fields: tuple[dict[str, Any], ...] = ()
    version: int = 1
    status: str = "published"


PATIENT_CONSENT = TemplateSpec(
    key="patient_consent",
    document_type="patient_consent",
    roles=(role("patient", "Patient", ("self", "guardian")),),
    fields=(
        field("patient_sig", "patient", label="Patient signature"),
        field("patient_date", "patient", field_type="date_signed"),
    ),
    prefill_fields=({"key": "visit_date", "page": 1, "rect": {"x": 72.0, "y": 700.0, "w": 200.0, "h": 14.0}},),
)

#: Two signers, either order. The parallel-signing and foreign-field tests live here.
HIPAA_PAIR = TemplateSpec(
    key="hipaa_pair",
    document_type="hipaa_acknowledgement",
    roles=(
        role("patient", "Patient", ("self", "guardian"), order_index=0),
        role("witness", "Witness", ("witness",), order_index=1),
    ),
    fields=(
        field("patient_sig", "patient"),
        field("witness_sig", "witness"),
    ),
)

#: Patient, then witness, then a clinician who must re-authenticate. SPEC section 6's third sample.
PROCEDURE_CONSENT = TemplateSpec(
    key="procedure_consent",
    document_type="procedure_consent",
    roles=(
        role("patient", "Patient", ("self", "guardian"), order_index=0),
        role("witness", "Witness", ("witness",), order_index=1),
        role("clinician", "Clinician", ("clinician",), requires_reauth=True, order_index=2),
    ),
    fields=(
        field("patient_sig", "patient"),
        field("patient_ack", "patient", field_type="checkbox"),
        field("witness_sig", "witness"),
        field("clinician_sig", "clinician"),
        field("clinician_date", "clinician", field_type="date_signed"),
    ),
    prefill_fields=({"key": "visit_date", "page": 1, "rect": {"x": 72.0, "y": 700.0, "w": 200.0, "h": 14.0}},),
)


# --------------------------------------------------------------------------- bench


class Bench:
    """One envelope service, its fakes, and the setup helpers the tests share."""

    def __init__(
        self,
        settings: Settings,
        clock: FixedClock,
        blob_dir: Path,
        *,
        new_session: SessionScope | None = None,
    ) -> None:
        self.notified: list[tuple[str, EnvelopeView]] = []
        self.settings = settings
        self.clock = clock
        self.blobs = FakeBlobService(blob_dir)
        self.audit = FakeAuditLog(clock)
        self.documents = FakeDocumentService()
        self.identity = FakeIdentityService(settings, clock)
        self.sealer = FakeSealer(clock)
        self.service: EnvelopeServiceImpl = build_envelope_service(
            settings,
            clock,
            audit_log=self.audit,
            blob_service=self.blobs,
            document_service=self.documents,
            identity_service=self.identity,
            sealer=self.sealer,
            new_session=new_session,
            notifier=self,
        )

    def envelope_event(self, db: Session, *, event: WebhookEvent, envelope: EnvelopeView) -> None:
        """``EnvelopeNotifier``: remember what the service asked to have announced."""
        _ = db
        self.notified.append((event, envelope))

    # -- setup -------------------------------------------------------------

    def host(self, db: Session, name: str = "Test EHR") -> Host:
        host_id = new_id()
        db.execute(
            text("INSERT INTO hosts (id, name, api_key_hash, allowed_origins) VALUES (:id, :name, :key, :origins)"),
            {
                "id": host_id,
                "name": name,
                "key": new_id().bytes + new_id().bytes,
                "origins": ["https://ehr.example"],
            },
        )
        return Host(id=host_id, name=name, allowed_origins=("https://ehr.example",))

    def template(self, db: Session, host: Host, spec: TemplateSpec) -> UUID:
        """Publish a template version for this host. Returns the template_version id."""
        import json

        pdf = b"%PDF-1.7\n% template " + spec.key.encode()
        blob = self.blobs.put(db, pdf, kind="template_pdf")
        template_id = db.execute(
            text("SELECT id FROM templates WHERE host_id = :h AND key = :k"),
            {"h": host.id, "k": spec.key},
        ).scalar_one_or_none()
        if template_id is None:
            template_id = new_id()
            db.execute(
                text(
                    "INSERT INTO templates (id, host_id, key, name, document_type) "
                    "VALUES (:id, :host, :key, :name, :dt)"
                ),
                {
                    "id": template_id,
                    "host": host.id,
                    "key": spec.key,
                    "name": spec.key.replace("_", " ").title(),
                    "dt": spec.document_type,
                },
            )
        version_id = new_id()
        db.execute(
            text(
                "INSERT INTO template_versions (id, template_id, version, status, pdf_sha256, fields, "
                "  prefill_fields, signer_roles, published_at) "
                "VALUES (:id, :tpl, :version, :status, :sha, CAST(:fields AS jsonb), "
                "  CAST(:prefill AS jsonb), CAST(:roles AS jsonb), :at)"
            ),
            {
                "id": version_id,
                "tpl": template_id,
                "version": spec.version,
                "status": spec.status,
                "sha": blob.sha256,
                "fields": json.dumps(list(spec.fields)),
                "prefill": json.dumps(list(spec.prefill_fields)),
                "roles": json.dumps(list(spec.roles)),
                "at": self.clock.now() if spec.status == "published" else None,
            },
        )
        return version_id

    def consent(self, db: Session, version: str = CONSENT_VERSION) -> None:
        self.identity.seed_consent(db, version=version, locale=self.settings.default_locale)

    # -- envelopes ---------------------------------------------------------

    def new_envelope(
        self,
        spec: TemplateSpec,
        *,
        signers: tuple[NewSigner, ...] | None = None,
        signing_order: str = "parallel",
        patient_ref: str = "patient-ref-001",
        prefill: dict[str, str] | None = None,
        expires_at: datetime | None = None,
        supersedes: UUID | None = None,
        template_version: int | None = None,
    ) -> NewEnvelope:
        return NewEnvelope(
            template_key=spec.key,
            template_version=template_version,
            patient_ref=patient_ref,
            host_document_ref="chart-doc-7",
            signing_order=signing_order,  # type: ignore[arg-type]
            signers=signers if signers is not None else default_signers(spec, patient_ref),
            prefill=prefill or {"visit_date": "2026-03-17"},
            expires_at=expires_at,
            supersedes_envelope_id=supersedes,
        )

    def create(self, db: Session, host: Host, spec: TemplateSpec, **kwargs: Any) -> EnvelopeView:
        return self.service.create(db, host, self.new_envelope(spec, **kwargs), CTX)

    # -- sessions ----------------------------------------------------------

    def session(
        self,
        db: Session,
        signer_id: UUID,
        *,
        method: AuthMethod = "password",
        kiosk: KioskContext | None = None,
    ) -> SessionInfo:
        auth = AuthContext(method=method, auth_time=self.clock.now() - timedelta(minutes=1))
        _token, info = self.identity.create_session(db, signer_id=signer_id, auth=auth, kiosk=kiosk, ctx=CTX)
        return info

    def reauth(self, db: Session, session: SessionInfo, method: AuthMethod = "password+mfa") -> None:
        self.identity.attest_reauth(
            db,
            host=Host(id=new_id(), name="unchecked by the fake", allowed_origins=()),
            session_id=session.id,
            auth=AuthContext(method=method, auth_time=self.clock.now()),
        )

    # -- flow shortcuts ----------------------------------------------------

    def ready_to_sign(self, db: Session, session: SessionInfo) -> None:
        """Present, view and consent, which is the precondition ``sign`` insists on."""
        self.service.present(db, session, CTX)
        self.service.record_viewed(db, session, PAGES, CTX)
        self.service.accept_consent(db, session, CONSENT_VERSION, CTX)

    def signer_id(self, view: EnvelopeView, role_key: str) -> UUID:
        return next(s.id for s in view.signers if s.role_key == role_key)

    def status(self, db: Session, envelope_id: UUID) -> str:
        return str(db.execute(text("SELECT status FROM envelopes WHERE id = :id"), {"id": envelope_id}).scalar_one())

    def signer_status(self, db: Session, signer_id: UUID) -> str:
        return str(db.execute(text("SELECT status FROM signers WHERE id = :id"), {"id": signer_id}).scalar_one())

    def event_types(self, db: Session, envelope_id: UUID) -> list[str]:
        return [str(e.event_type) for e in self.audit.list(db, "envelope", envelope_id)]

    def revisions(self, db: Session, envelope_id: UUID) -> list[tuple[int, str]]:
        rows = db.execute(
            text("SELECT revision_no, kind FROM document_revisions WHERE envelope_id = :id ORDER BY revision_no"),
            {"id": envelope_id},
        ).all()
        return [(int(r.revision_no), str(r.kind)) for r in rows]


def default_signers(spec: TemplateSpec, patient_ref: str) -> tuple[NewSigner, ...]:
    """One signer per declared role, each in the first capacity the role allows."""
    signers: list[NewSigner] = []
    for index, definition in enumerate(spec.roles):
        capacity: Capacity = definition["allowed_capacities"][0]
        signers.append(
            NewSigner(
                role_key=definition["key"],
                host_user_id=f"host-user-{index}",
                display_name=f"{definition['label']} Person",
                capacity=capacity,
                on_behalf_of=patient_ref if capacity in ("guardian", "proxy") else None,
            )
        )
    return tuple(signers)


def with_capacity(signer: NewSigner, capacity: Capacity, *, on_behalf_of: str | None = None) -> NewSigner:
    return replace(signer, capacity=capacity, on_behalf_of=on_behalf_of)


# --------------------------------------------------------------------------- fixtures


@pytest.fixture
def bench(settings: Settings, clock: FixedClock, blob_dir: Path) -> Bench:
    return Bench(settings, clock, blob_dir)


@pytest.fixture
def committing_bench(
    settings: Settings,
    clock: FixedClock,
    blob_dir: Path,
    db_factory: Callable[[], AbstractContextManager[Session]],
) -> Iterator[Bench]:
    """A bench whose ``seal_pending`` can record a failure in a separately committing session."""
    yield Bench(settings, clock, blob_dir, new_session=db_factory)
