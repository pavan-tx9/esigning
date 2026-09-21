"""Fixtures for the documents module.

Nothing here needs Postgres: ``DocumentService`` has no ``db`` parameter anywhere in its Protocol
and touches no connection, which is deliberate -- the pieces that turn bytes into a page are pure,
so their tests are fast and their outputs are reproducible.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from esign.config import Settings
from esign.contracts import (
    CertificateSigner,
    CertificateSummary,
    DocumentService,
    FieldDef,
    PrefillFieldDef,
    Rect,
    SignerRoleDef,
    SignerStamp,
)
from esign.documents import build_document_service

SIGNED_AT = datetime(2026, 3, 17, 14, 30, 0, tzinfo=UTC)


@pytest.fixture
def documents(settings_no_db: Settings) -> DocumentService:
    return build_document_service(settings_no_db)


@pytest.fixture
def stamp() -> SignerStamp:
    return SignerStamp(
        signer_id=UUID("11111111-2222-4333-8444-555555555555"),
        display_name="Ada Lovelace",
        capacity="self",
        on_behalf_of_label=None,
        signed_at=SIGNED_AT,
    )


@pytest.fixture
def patient_role() -> SignerRoleDef:
    return SignerRoleDef(
        key="patient",
        label="Patient",
        allowed_capacities=("self", "guardian"),
        requires_reauth=False,
        order_index=0,
    )


@pytest.fixture
def signature_field() -> FieldDef:
    return FieldDef(
        id="patient_signature",
        type="signature",
        page=1,
        rect=Rect(x=100, y=400, w=220, h=48),
        signer_role="patient",
        label="Patient signature",
    )


@pytest.fixture
def date_field() -> FieldDef:
    return FieldDef(
        id="patient_date",
        type="date_signed",
        page=1,
        rect=Rect(x=360, y=400, w=150, h=18),
        signer_role="patient",
        label="Date signed",
    )


@pytest.fixture
def prefill_field() -> PrefillFieldDef:
    return PrefillFieldDef(key="patient_name", page=1, rect=Rect(x=100, y=600, w=240, h=14), font_size=10.0)


def certificate_summary(*, signers: int = 2) -> CertificateSummary:
    return CertificateSummary(
        envelope_id=UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        document_type="procedure_consent",
        template_key="procedure_consent",
        template_version=3,
        seal_profile="PAdES-B-T",
        presented_sha256=bytes(range(32)),
        final_revision_sha256=bytes(range(32, 64)),
        created_at=datetime(2026, 3, 17, 9, 0, tzinfo=UTC),
        completed_at=SIGNED_AT,
        signers=tuple(
            CertificateSigner(
                signer_id=UUID(int=index + 1),
                display_name=f"Signer Number {index}",
                role_label="Patient" if index == 0 else "Witness",
                capacity="self" if index == 0 else "witness",
                auth_method="password+mfa",
                reauth_method="sso" if index else None,
                consent_version="2026-09",
                viewed_at=datetime(2026, 3, 17, 13, 0, tzinfo=UTC),
                consented_at=datetime(2026, 3, 17, 13, 5, tzinfo=UTC),
                signed_at=datetime(2026, 3, 17, 13, 10, tzinfo=UTC),
                ip="203.0.113.7",
                user_agent="Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)",
                kiosk_staff_user_id="staff-42" if index else None,
                kiosk_identity_check="photo_id" if index else None,
            )
            for index in range(signers)
        ),
        audit_event_count=37,
        audit_head_hash=bytes(range(64, 96)),
    )
