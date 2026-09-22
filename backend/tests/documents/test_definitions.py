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


def clinician_role(*, requires_reauth: bool) -> SignerRoleDef:
    return SignerRoleDef(
        key="clinician",
        label="Clinician",
        allowed_capacities=("clinician",),
        requires_reauth=requires_reauth,
        order_index=0,
    )


def test_a_clinician_role_that_does_not_reauthenticate_is_refused(documents: DocumentService) -> None:
    """``docs/ehr-esignature-developer-guide.pdf``: "Re-authenticate clinicians at the moment of
    signing", repeated in its Definition of Done.

    ``requires_reauth`` defaults to ``false`` and nothing tied it to the clinician capacity, so this
    was enforced only by convention in ``templates/procedure_consent.json``. A host template with
    ``"allowed_capacities": ["clinician"]`` and ``requires_reauth`` omitted produced clinician
    signatures with no ``auth.reauthenticated`` event and a certificate presenting that as expected.
    """
    message = problems_from(
        documents,
        fields=[signature("clinician_signature", "clinician")],
        roles=[clinician_role(requires_reauth=False)],
    )
    assert "role 'clinician': a role that allows the clinician capacity must set requires_reauth: true" in message


def test_a_clinician_role_that_reauthenticates_passes(documents: DocumentService) -> None:
    documents.validate_definitions(
        INFO,
        [signature("clinician_signature", "clinician")],
        [],
        [clinician_role(requires_reauth=True)],
    )


def test_a_role_that_merely_allows_other_capacities_is_unaffected(documents: DocumentService) -> None:
    """Only the clinician capacity carries the requirement; a witness or guardian does not."""
    role_def = SignerRoleDef(
        key="witness",
        label="Witness",
        allowed_capacities=("witness", "interpreter"),
        requires_reauth=False,
        order_index=0,
    )
    documents.validate_definitions(INFO, [signature("witness_signature", "witness")], [], [role_def])


# --------------------------------------------------------------------------- the allowlist agrees


def test_the_id_pattern_is_the_audit_trails_own_slug() -> None:
    """One pattern, two enforcement points, and they must not drift apart.

    A role key and a field id declared here are written into the append-only audit trail --
    ``session.created``, ``session.rejected``, ``signer.signed``, ``signer.declined`` carry the
    role key, ``signer.signed.data.captures[].field_id`` the field id -- where the allowlist
    validates them against ``Slug``. An id this accepted and the allowlist refused would create an
    envelope that can never be signed *and* never be recorded as having failed: two events already
    in a trail with no delete path, two stored blobs, and a 422 saying only "the request is not
    valid". Addendum 2 made that reachable from a request body rather than from a template somebody
    published, which is why this is asserted rather than assumed.
    """
    from typing import get_args

    from esign.audit.events import Slug
    from esign.documents.definitions import ID_PATTERN

    (constraints,) = [meta for meta in get_args(Slug)[1:] if getattr(meta, "pattern", None)]
    assert ID_PATTERN.pattern == constraints.pattern


@pytest.mark.parametrize("key", ["2nd_clinician", "_cosigner", "Clinician", "co-signer", ""])
def test_a_key_the_audit_trail_would_refuse_is_refused_here(documents: DocumentService, key: str) -> None:
    role_def = SignerRoleDef(
        key=key, label="Second clinician", allowed_capacities=("self",), requires_reauth=False, order_index=0
    )
    with pytest.raises(ValidationFailed):
        documents.validate_definitions(INFO, [signature("a_signature", key)], [], [role_def])
