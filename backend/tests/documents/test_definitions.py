"""Definition validation. The contract says "raises ValidationFailed listing every problem"."""

from __future__ import annotations

import pytest

from esign.contracts import (
    DocumentService,
    FieldDef,
    PrefillFieldDef,
    Rect,
    SignerRoleDef,
    TemplatePdfInfo,
    ValidationFailed,
)

INFO = TemplatePdfInfo(page_count=2, page_sizes=((612.0, 792.0), (612.0, 792.0)), sha256=b"\x00" * 32)


def role(key: str = "patient", order: int = 0) -> SignerRoleDef:
    return SignerRoleDef(
        key=key, label=key.title(), allowed_capacities=("self",), requires_reauth=False, order_index=order
    )


def signature(field_id: str = "patient_signature", signer_role: str = "patient", page: int = 1) -> FieldDef:
    return FieldDef(
        id=field_id,
        type="signature",
        page=page,
        rect=Rect(x=72, y=100, w=200, h=44),
        signer_role=signer_role,
    )


def test_a_sound_definition_passes(documents: DocumentService) -> None:
    documents.validate_definitions(INFO, [signature()], [], [role()])


def test_initials_satisfy_the_signing_requirement(documents: DocumentService) -> None:
    field = FieldDef(
        id="patient_initials", type="initials", page=1, rect=Rect(x=72, y=100, w=96, h=36), signer_role="patient"
    )
    documents.validate_definitions(INFO, [field], [], [role()])


def problems_from(documents: DocumentService, **kwargs: object) -> str:
    fields = kwargs.get("fields", [signature()])
    prefill = kwargs.get("prefill", [])
    roles = kwargs.get("roles", [role()])
    with pytest.raises(ValidationFailed) as excinfo:
        documents.validate_definitions(INFO, fields, prefill, roles)  # type: ignore[arg-type]
    assert excinfo.value.code == "template_definitions_invalid"
    return str(excinfo.value)


def test_a_rect_off_the_page_is_reported(documents: DocumentService) -> None:
    field = FieldDef(
        id="off_page", type="signature", page=1, rect=Rect(x=500, y=100, w=200, h=44), signer_role="patient"
    )
    assert "does not fit inside page 1" in problems_from(documents, fields=[field])


def test_a_page_out_of_range_is_reported(documents: DocumentService) -> None:
    assert "outside 1..2" in problems_from(documents, fields=[signature(page=7)])


def test_a_role_without_a_signature_field_is_reported(documents: DocumentService) -> None:
    message = problems_from(documents, fields=[signature()], roles=[role(), role("witness", 1)])
    assert "'witness': has no signature or initials field" in message


def test_a_field_referencing_an_unknown_role_is_reported(documents: DocumentService) -> None:
    message = problems_from(documents, fields=[signature(signer_role="ghost")])
    assert "undeclared signer role 'ghost'" in message


def test_duplicate_field_ids_are_reported(documents: DocumentService) -> None:
    message = problems_from(documents, fields=[signature(), signature()])
    assert "declared 2 times" in message


def test_duplicate_order_indexes_are_reported(documents: DocumentService) -> None:
    """Two roles at the same position make sequential signing ambiguous, so it is a definition bug."""
    message = problems_from(
        documents,
        fields=[signature(), signature("witness_signature", "witness")],
        roles=[role("patient", 0), role("witness", 0)],
    )
    assert "sequential order is ambiguous" in message


def test_every_problem_is_reported_at_once(documents: DocumentService) -> None:
    """A host that has to republish once per problem has been made to do our job."""
    fields = [
        FieldDef(id="Bad Id", type="signature", page=9, rect=Rect(x=-5, y=0, w=1, h=1), signer_role="ghost"),
    ]
    message = problems_from(documents, fields=fields, roles=[role(), role("witness", 1)])
    for fragment in (
        "id must match",
        "outside 1..2",
        "undeclared signer role 'ghost'",
        "'patient': has no signature or initials field",
        "'witness': has no signature or initials field",
    ):
        assert fragment in message, fragment


def test_prefill_key_colliding_with_a_field_id_is_reported(documents: DocumentService) -> None:
    prefill = [PrefillFieldDef(key="patient_signature", page=1, rect=Rect(x=72, y=600, w=200, h=14))]
    assert "collides with a field" in problems_from(documents, prefill=prefill)


def test_empty_roles_are_reported(documents: DocumentService) -> None:
    assert "at least one role is required" in problems_from(documents, fields=[], roles=[])


def test_a_hairline_rect_is_reported(documents: DocumentService) -> None:
    field = FieldDef(id="sliver", type="signature", page=1, rect=Rect(x=72, y=100, w=200, h=1), signer_role="patient")
    assert "smaller than 4pt" in problems_from(documents, fields=[field])


def test_a_non_finite_rect_is_reported(documents: DocumentService) -> None:
    field = FieldDef(
        id="nan_rect",
        type="signature",
        page=1,
        rect=Rect(x=float("nan"), y=100, w=200, h=44),
        signer_role="patient",
    )
    assert "not a finite number" in problems_from(documents, fields=[field])


def test_an_unknown_field_type_is_reported(documents: DocumentService) -> None:
    field = FieldDef(
        id="weird",
        type="hologram",  # type: ignore[arg-type]
        page=1,
        rect=Rect(x=72, y=100, w=200, h=44),
        signer_role="patient",
    )
    assert "unknown field type" in problems_from(documents, fields=[field, signature()])


def test_a_bad_prefill_font_size_is_reported(documents: DocumentService) -> None:
    prefill = [PrefillFieldDef(key="patient_name", page=1, rect=Rect(x=72, y=600, w=200, h=14), font_size=0)]
    assert "font_size must be between 0 and 72" in problems_from(documents, prefill=prefill)


def test_validation_is_against_displayed_sizes(documents: DocumentService) -> None:
    """A landscape page's rects are checked against the landscape extent, not the portrait one."""
    landscape = TemplatePdfInfo(page_count=1, page_sizes=((792.0, 612.0),), sha256=b"\x00" * 32)
    wide = FieldDef(
        id="wide_signature", type="signature", page=1, rect=Rect(x=600, y=100, w=180, h=44), signer_role="patient"
    )
    documents.validate_definitions(landscape, [wide], [], [role()])

    tall = FieldDef(
        id="tall_signature", type="signature", page=1, rect=Rect(x=10, y=560, w=180, h=100), signer_role="patient"
    )
    with pytest.raises(ValidationFailed):
        documents.validate_definitions(landscape, [tall], [], [role()])
