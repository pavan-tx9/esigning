"""The three shipped sample templates, and the script that claims to produce them.

Two things are being checked. That the templates are usable: they pass intake, their definitions
validate against their own PDFs, and a full prepare/sign/certificate/finalize round trip works on
them. And that they are *reproducible*: regenerating into a temporary directory must produce the
same bytes, so nobody can hand-edit a committed PDF and leave the generator lying about it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from uuid import UUID

import pytest

from esign.contracts import Capture, DocumentService, FieldDef, SignerStamp
from esign.documents import definitions_from_json
from esign.documents.codec import TemplateDefinitions
from tests.documents.conftest import certificate_summary
from tests.documents.helpers import handwriting_png

TEMPLATE_DIR = Path(__file__).resolve().parents[3] / "templates"
KEYS = ("patient_consent", "hipaa_acknowledgement", "procedure_consent")


def load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("esign_template_generator", TEMPLATE_DIR / "generate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def definitions_for(key: str) -> TemplateDefinitions:
    return definitions_from_json(json.loads((TEMPLATE_DIR / f"{key}.json").read_text()))


def test_all_three_templates_ship() -> None:
    for key in KEYS:
        assert (TEMPLATE_DIR / f"{key}.pdf").is_file(), key
        assert (TEMPLATE_DIR / f"{key}.json").is_file(), key


@pytest.mark.parametrize("key", KEYS)
def test_each_template_passes_intake_and_its_own_definitions(documents: DocumentService, key: str) -> None:
    info = documents.inspect_template_pdf((TEMPLATE_DIR / f"{key}.pdf").read_bytes())
    decoded = definitions_for(key)
    documents.validate_definitions(info, decoded.fields, decoded.prefill_fields, decoded.signer_roles)


@pytest.mark.parametrize("key", KEYS)
def test_each_definition_document_declares_an_approved_document_type(key: str) -> None:
    from esign.config import Settings

    document = json.loads((TEMPLATE_DIR / f"{key}.json").read_text())
    assert document["key"] == key
    assert Settings().is_approved_document_type(document["document_type"])


def test_the_procedure_consent_has_three_roles_in_sequence() -> None:
    roles = definitions_for("procedure_consent").signer_roles
    assert [role.key for role in roles] == ["patient", "witness", "clinician"]
    assert [role.order_index for role in roles] == [0, 1, 2]
    assert [role.requires_reauth for role in roles] == [False, False, True]


def test_the_patient_consent_allows_a_guardian_capacity() -> None:
    roles = definitions_for("patient_consent").signer_roles
    assert "guardian" in roles[0].allowed_capacities


def test_the_hipaa_acknowledgement_has_exactly_one_signer() -> None:
    assert len(definitions_for("hipaa_acknowledgement").signer_roles) == 1


def test_regenerating_reproduces_the_committed_files_byte_for_byte(tmp_path: Path) -> None:
    generator = load_generator()
    generator.write(tmp_path)
    for key in KEYS:
        for suffix in ("pdf", "json"):
            committed = (TEMPLATE_DIR / f"{key}.{suffix}").read_bytes()
            regenerated = (tmp_path / f"{key}.{suffix}").read_bytes()
            assert regenerated == committed, f"{key}.{suffix} does not match its generator"


@pytest.mark.parametrize("key", KEYS)
def test_a_full_round_trip_works_on_every_sample(documents: DocumentService, key: str) -> None:
    """Prepare with chart data, sign every role, build the certificate, finalize."""
    template = (TEMPLATE_DIR / f"{key}.pdf").read_bytes()
    decoded = definitions_for(key)
    prefill = {field.key: f"value for {field.key}" for field in decoded.prefill_fields}

    current = documents.prepare(template, decoded.prefill_fields, prefill)
    png = documents.sanitize_signature_png(handwriting_png())

    for index, role in enumerate(decoded.signer_roles):
        fields: list[FieldDef] = [field for field in decoded.fields if field.signer_role == role.key]
        captures = [
            Capture(field_id=field.id, kind="drawn", image_png=png)
            if field.type in ("signature", "initials")
            else Capture(field_id=field.id, checked=True)
            if field.type == "checkbox"
            else Capture(field_id=field.id, text_value="x")
            for field in fields
            if field.type != "date_signed"
        ]
        stamp = SignerStamp(
            signer_id=UUID(int=index + 1),
            display_name=f"Signer {index}",
            capacity=role.allowed_capacities[0],
            on_behalf_of_label=None,
            signed_at=datetime(2026, 3, 17, 14, 30 + index, tzinfo=UTC),
        )
        current = documents.apply_signer_marks(current, fields, captures, stamp)

    final = documents.finalize(current, documents.build_certificate(certificate_summary()))
    assert final.startswith(b"%PDF")


@pytest.mark.parametrize("key", KEYS)
def test_every_declared_prefill_key_is_required_or_explicitly_optional(key: str) -> None:
    """A prefill field nobody fills leaves a blank on a legal document; make the choice explicit."""
    for field in definitions_for(key).prefill_fields:
        assert isinstance(field.required, bool)


@pytest.mark.parametrize("key", KEYS)
def test_no_sample_template_carries_a_real_name_or_identifier(key: str) -> None:
    """Sample content is checked into the repository, so it must not look like a real record."""
    body = (TEMPLATE_DIR / f"{key}.pdf").read_bytes().lower()
    for forbidden in (b"mrn", b"ssn", b"date of birth:"):
        assert forbidden not in body
