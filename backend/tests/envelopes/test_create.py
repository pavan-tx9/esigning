"""Creating an envelope: template lookup, signer validation, revision 1 and the audit trail."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import Conflict, NewSigner, NotFound, ValidationFailed
from tests.envelopes.conftest import (
    CTX,
    HIPAA_PAIR,
    PATIENT_CONSENT,
    PROCEDURE_CONSENT,
    Bench,
    TemplateSpec,
    default_signers,
    field,
    role,
)


def test_create_stores_revision_one_and_records_two_events(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)

    view = bench.create(db, host, PATIENT_CONSENT)

    assert view.status == "created"
    assert view.document_type == "patient_consent"
    assert view.template_key == "patient_consent"
    assert view.template_version == 1
    assert view.presented_sha256 is not None
    assert view.sealed_sha256 is None
    assert bench.revisions(db, view.id) == [(1, "presented")]
    assert bench.event_types(db, view.id) == ["envelope.created", "document.prepared"]

    row = db.execute(
        text("SELECT presented_sha256, current_revision_sha256, status FROM envelopes WHERE id = :id"),
        {"id": view.id},
    ).one()
    assert bytes(row.presented_sha256) == bytes(row.current_revision_sha256) == view.presented_sha256
    assert row.status == "created"


def test_the_prepared_pdf_is_stored_with_a_retention_date(bench: Bench, db: Session, settings: Settings) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    view = bench.create(db, host, PATIENT_CONSENT)

    assert view.presented_sha256 is not None
    retain_until = bench.blobs.retain_until_for(view.presented_sha256, db)
    assert retain_until is not None
    expected = settings.retain_until("patient_consent", bench.clock.now())
    assert abs((retain_until - expected).total_seconds()) < 1


def test_prefill_reaches_the_pdf_and_nothing_else(bench: Bench, db: Session) -> None:
    """SPEC section 3: prefill is used once to prepare the document and never stored."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    secret = "1999-02-03 Ward 7"

    view = bench.create(db, host, PATIENT_CONSENT, prefill={"visit_date": secret})

    assert bench.documents.prepared_with == [{"visit_date": secret}]
    assert view.presented_sha256 is not None
    assert secret.encode() in bench.blobs.get(db, view.presented_sha256)

    dumped = db.execute(
        text(
            "SELECT to_jsonb(e.*)::text AS body FROM envelopes e WHERE id = :id "
            "UNION ALL SELECT to_jsonb(a.*)::text FROM audit_events a WHERE stream_id = :id "
            "UNION ALL SELECT to_jsonb(s.*)::text FROM signers s WHERE envelope_id = :id"
        ),
        {"id": view.id},
    ).all()
    assert all(secret not in str(r.body) for r in dumped)


def test_requires_reauth_is_copied_from_the_role_not_the_request(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)

    view = bench.create(db, host, PROCEDURE_CONSENT, signing_order="sequential")

    by_role = {s.role_key: s for s in view.signers}
    assert by_role["clinician"].requires_reauth is True
    assert by_role["patient"].requires_reauth is False
    assert by_role["witness"].requires_reauth is False
    assert [s.order_index for s in sorted(view.signers, key=lambda s: s.order_index)] == [0, 1, 2]


def test_order_index_comes_from_the_template(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    reversed_signers = tuple(reversed(default_signers(PROCEDURE_CONSENT, "patient-ref-001")))

    view = bench.create(db, host, PROCEDURE_CONSENT, signers=reversed_signers, signing_order="sequential")

    assert {s.role_key: s.order_index for s in view.signers} == {"patient": 0, "witness": 1, "clinician": 2}


# --------------------------------------------------------------------------- template lookup


def test_a_draft_version_cannot_be_used(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    draft = TemplateSpec(
        key="draft_only",
        document_type="patient_consent",
        roles=PATIENT_CONSENT.roles,
        fields=PATIENT_CONSENT.fields,
        status="draft",
    )
    bench.template(db, host, draft)

    with pytest.raises(NotFound):
        bench.create(db, host, draft)
    with pytest.raises(Conflict) as seen:
        bench.create(db, host, draft, template_version=1)
    assert seen.value.code == "template_not_published"


def test_a_retired_version_cannot_be_used(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    db.execute(text("UPDATE template_versions SET status = 'retired'"))

    with pytest.raises(NotFound):
        bench.create(db, host, PATIENT_CONSENT)


def test_no_version_means_the_latest_published_one(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    second = TemplateSpec(
        key=PATIENT_CONSENT.key,
        document_type=PATIENT_CONSENT.document_type,
        roles=PATIENT_CONSENT.roles,
        fields=PATIENT_CONSENT.fields,
        version=2,
    )
    bench.template(db, host, second)

    assert bench.create(db, host, PATIENT_CONSENT).template_version == 2
    assert bench.create(db, host, PATIENT_CONSENT, template_version=1).template_version == 1


def test_another_hosts_template_is_not_found(bench: Bench, db: Session) -> None:
    """SPEC section 10: not_found, never forbidden -- existence itself is not leaked."""
    owner = bench.host(db, "Owner EHR")
    stranger = bench.host(db, "Stranger EHR")
    bench.template(db, owner, PATIENT_CONSENT)

    with pytest.raises(NotFound) as seen:
        bench.create(db, stranger, PATIENT_CONSENT)
    assert seen.value.code == "template_not_found"
    assert seen.value.http_status == 404


def test_an_unapproved_document_type_is_refused(bench: Bench, db: Session, settings: Settings) -> None:
    host = bench.host(db)
    odd = TemplateSpec(
        key="controlled_substance",
        document_type="controlled_substance_rx",
        roles=PATIENT_CONSENT.roles,
        fields=PATIENT_CONSENT.fields,
    )
    bench.template(db, host, odd)
    assert not settings.is_approved_document_type("controlled_substance_rx")

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, odd)
    assert seen.value.code == "document_type_not_approved"


# --------------------------------------------------------------------------- signer validation


def test_an_unknown_role_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    signers = (NewSigner(role_key="surgeon", host_user_id="u1", display_name="A Person", capacity="self"),)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signers=signers)
    assert seen.value.code == "unknown_role"


def test_duplicate_roles_are_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    one = NewSigner(role_key="patient", host_user_id="u1", display_name="A Person", capacity="self")
    signers = (one, NewSigner(role_key="patient", host_user_id="u2", display_name="B Person", capacity="self"))

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signers=signers)
    assert seen.value.code == "duplicate_role"


def test_a_missing_role_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    only_patient = default_signers(HIPAA_PAIR, "patient-ref-001")[:1]

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, HIPAA_PAIR, signers=only_patient)
    assert seen.value.code == "missing_required_role"


def test_a_capacity_the_role_does_not_allow_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    signers = (NewSigner(role_key="patient", host_user_id="u1", display_name="A Person", capacity="clinician"),)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signers=signers)
    assert seen.value.code == "capacity_not_allowed"


def test_a_guardian_must_say_who_they_act_for(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    signers = (NewSigner(role_key="patient", host_user_id="u1", display_name="A Parent", capacity="guardian"),)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signers=signers)
    assert seen.value.code == "on_behalf_of_required"


def test_a_guardian_acts_for_this_envelopes_patient(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    signers = (
        NewSigner(
            role_key="patient",
            host_user_id="u1",
            display_name="A Parent",
            capacity="guardian",
            on_behalf_of="somebody-else",
        ),
    )

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signers=signers, patient_ref="patient-ref-001")
    assert seen.value.code == "on_behalf_of_mismatch"


def test_a_guardian_with_the_right_patient_is_accepted(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    signers = (
        NewSigner(
            role_key="patient",
            host_user_id="u1",
            display_name="A Parent",
            capacity="guardian",
            on_behalf_of="patient-ref-001",
        ),
    )

    view = bench.create(db, host, PATIENT_CONSENT, signers=signers, patient_ref="patient-ref-001")
    assert view.signers[0].capacity == "guardian"


def test_only_a_guardian_or_proxy_acts_on_behalf_of_someone(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    signers = (
        NewSigner(
            role_key="patient",
            host_user_id="u1",
            display_name="A Person",
            capacity="self",
            on_behalf_of="patient-ref-001",
        ),
    )

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signers=signers)
    assert seen.value.code == "on_behalf_of_not_allowed"


def test_an_envelope_needs_a_signer(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signers=())
    assert seen.value.code == "signers_required"


@pytest.mark.parametrize(
    ("blank", "code"), [("display_name", "display_name_required"), ("host_user_id", "host_user_id_required")]
)
def test_a_blank_signer_field_is_refused(bench: Bench, db: Session, blank: str, code: str) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    values = {"role_key": "patient", "host_user_id": "u1", "display_name": "A Person", "capacity": "self"}
    values[blank] = "   "

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signers=(NewSigner(**values),))  # type: ignore[arg-type]
    assert seen.value.code == code


def test_a_blank_patient_ref_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, patient_ref="")
    assert seen.value.code == "patient_ref_required"


# --------------------------------------------------------------------------- expiry


def test_expiry_defaults_from_settings(bench: Bench, db: Session, settings: Settings, clock: FixedClock) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)

    view = bench.create(db, host, PATIENT_CONSENT)
    assert view.expires_at == settings.default_expiry(clock.now())


def test_an_expiry_in_the_past_is_refused(bench: Bench, db: Session, clock: FixedClock) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, expires_at=clock.now() - timedelta(seconds=1))
    assert seen.value.code == "expires_at_invalid"


def test_a_naive_expiry_is_refused(bench: Bench, db: Session, clock: FixedClock) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, expires_at=clock.now().replace(tzinfo=None) + timedelta(days=1))
    assert seen.value.code == "expires_at_invalid"


# --------------------------------------------------------------------------- broken templates


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param(({"id": "x"},), id="missing type"),
        pytest.param(
            ({"id": "x", "type": "scribble", "page": 1, "rect": {}, "signer_role": "patient"},), id="bad type"
        ),
        pytest.param(
            ({"id": "x", "type": "signature", "page": "one", "rect": {}, "signer_role": "patient"},), id="bad page"
        ),
        pytest.param("not-a-list", id="not a list"),
    ],
)
def test_a_template_with_unparsable_fields_is_refused(bench: Bench, db: Session, fields: object) -> None:
    host = bench.host(db)
    broken = TemplateSpec(
        key="broken_fields",
        document_type="patient_consent",
        roles=PATIENT_CONSENT.roles,
        fields=fields,  # type: ignore[arg-type]
    )
    bench.template(db, host, broken)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, broken)
    assert seen.value.code == "template_definitions_invalid"


def test_a_template_with_no_roles_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    broken = TemplateSpec(key="no_roles", document_type="patient_consent", roles=(), fields=())
    bench.template(db, host, broken)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, broken)
    assert seen.value.code == "template_definitions_invalid"


def test_a_template_with_two_identical_roles_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    broken = TemplateSpec(
        key="twin_roles",
        document_type="patient_consent",
        roles=(role("patient", "Patient", ("self",)), role("patient", "Patient again", ("self",))),
        fields=(field("patient_sig", "patient"),),
    )
    bench.template(db, host, broken)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, broken)
    assert seen.value.code == "template_definitions_invalid"


def test_a_template_with_an_unknown_capacity_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    odd = TemplateSpec(
        key="odd_capacity",
        document_type="patient_consent",
        roles=(role("patient", "Patient", ("notary",)),),
        fields=(field("patient_sig", "patient"),),
    )
    bench.template(db, host, odd)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, odd)
    assert seen.value.code == "template_definitions_invalid"


# --------------------------------------------------------------------------- get


def test_get_is_host_scoped(bench: Bench, db: Session) -> None:
    owner = bench.host(db, "Owner EHR")
    stranger = bench.host(db, "Stranger EHR")
    bench.template(db, owner, PATIENT_CONSENT)
    view = bench.create(db, owner, PATIENT_CONSENT)

    assert bench.service.get(db, owner, view.id).id == view.id
    with pytest.raises(NotFound) as seen:
        bench.service.get(db, stranger, view.id)
    assert seen.value.code == "not_found"


def test_get_on_an_unknown_envelope_is_not_found(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    with pytest.raises(NotFound):
        bench.service.get(db, host, uuid4())


def test_assert_signer_may_start_is_host_scoped(bench: Bench, db: Session) -> None:
    owner = bench.host(db, "Owner EHR")
    stranger = bench.host(db, "Stranger EHR")
    bench.template(db, owner, PATIENT_CONSENT)
    view = bench.create(db, owner, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")

    bench.service.assert_signer_may_start(db, owner, view.id, signer_id)
    with pytest.raises(NotFound):
        bench.service.assert_signer_may_start(db, stranger, view.id, signer_id)


def test_assert_signer_may_start_rejects_a_signer_from_another_envelope(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    first = bench.create(db, host, PATIENT_CONSENT)
    second = bench.create(db, host, PATIENT_CONSENT)

    with pytest.raises(NotFound):
        bench.service.assert_signer_may_start(db, host, first.id, bench.signer_id(second, "patient"))


def test_create_returns_the_same_view_as_get(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    created = bench.service.create(db, host, bench.new_envelope(PATIENT_CONSENT), CTX)
    assert created == bench.service.get(db, host, created.id)


def test_signer_text_is_stored_stripped(bench: Bench, db: Session) -> None:
    """A trailing space in a name ends up in the signature caption, and then in the sealed bytes."""
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    signers = (NewSigner(role_key="patient", host_user_id="  u1  ", display_name="  Alex Doe  ", capacity="self"),)

    view = bench.create(db, host, PATIENT_CONSENT, signers=signers)

    assert view.signers[0].display_name == "Alex Doe"
    row = db.execute(
        text("SELECT display_name, host_user_id FROM signers WHERE id = :id"), {"id": view.signers[0].id}
    ).one()
    assert (row.display_name, row.host_user_id) == ("Alex Doe", "u1")


def test_an_unknown_signing_order_is_refused(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)

    with pytest.raises(ValidationFailed) as seen:
        bench.create(db, host, PATIENT_CONSENT, signing_order="whenever")
    assert seen.value.code == "signing_order_invalid"
