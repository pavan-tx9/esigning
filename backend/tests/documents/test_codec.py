"""The jsonb codec. Strict in, faithful out.

These definitions come back out of Postgres and decide where a signature is drawn on a document
that is then sealed forever, so a loose decoder is a correctness problem, not a style one.
"""

from __future__ import annotations

from typing import Any

import pytest

from esign.contracts import FieldDef, PrefillFieldDef, Rect, SignerRoleDef, ValidationFailed
from esign.documents.codec import (
    definitions_from_json,
    definitions_to_json,
    fields_from_json,
    prefill_fields_from_json,
    signer_roles_from_json,
)

FIELDS = [
    FieldDef(
        id="patient_signature",
        type="signature",
        page=2,
        rect=Rect(x=72.5, y=100.0, w=200.0, h=44.0),
        signer_role="patient",
        required=True,
        label="Patient signature",
    )
]
PREFILL = [PrefillFieldDef(key="patient_name", page=1, rect=Rect(x=1, y=2, w=3, h=4), font_size=9.5, multiline=True)]
ROLES = [
    SignerRoleDef(
        key="patient",
        label="Patient",
        allowed_capacities=("self", "guardian"),
        requires_reauth=False,
        order_index=0,
    )
]


def test_round_trip_is_lossless() -> None:
    encoded = definitions_to_json(FIELDS, PREFILL, ROLES)
    decoded = definitions_from_json(encoded)
    assert decoded.fields == FIELDS
    assert decoded.prefill_fields == PREFILL
    assert decoded.signer_roles == ROLES


def test_optional_field_keys_default() -> None:
    decoded = fields_from_json(
        [{"id": "a_field", "type": "text", "page": 1, "rect": {"x": 0, "y": 0, "w": 10, "h": 10}, "signer_role": "p"}]
    )
    assert decoded[0].required is True
    assert decoded[0].label == ""


@pytest.mark.parametrize(
    "payload",
    [
        {"id": "x", "type": "signature", "page": 1, "rect": {"x": 0, "y": 0, "w": 1, "h": 1}},  # no signer_role
        {"id": "x", "type": "signature", "page": 1, "rect": {"x": 0, "y": 0, "w": 1}, "signer_role": "p"},
        {"id": "x", "type": "wat", "page": 1, "rect": {"x": 0, "y": 0, "w": 1, "h": 1}, "signer_role": "p"},
        {"id": "x", "type": "signature", "page": "1", "rect": {"x": 0, "y": 0, "w": 1, "h": 1}, "signer_role": "p"},
        {
            "id": "x",
            "type": "signature",
            "page": 1,
            "rect": {"x": 0, "y": 0, "w": 1, "h": 1},
            "signer_role": "p",
            "surprise": True,
        },
    ],
)
def test_malformed_fields_are_refused(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        fields_from_json([payload])
    assert excinfo.value.code == "template_definitions_malformed"


def test_a_boolean_is_not_an_integer_page() -> None:
    """``True`` is an ``int`` in Python. It is not a page number."""
    with pytest.raises(ValidationFailed):
        fields_from_json(
            [
                {
                    "id": "x",
                    "type": "signature",
                    "page": True,
                    "rect": {"x": 0, "y": 0, "w": 1, "h": 1},
                    "signer_role": "p",
                }
            ]
        )


def test_unknown_capacity_is_refused() -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        signer_roles_from_json(
            [
                {
                    "key": "patient",
                    "label": "Patient",
                    "allowed_capacities": ["self", "notary"],
                    "requires_reauth": False,
                    "order_index": 0,
                }
            ]
        )
    assert "notary" in str(excinfo.value)


def test_a_role_must_declare_every_key() -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        signer_roles_from_json([{"key": "patient", "label": "Patient", "allowed_capacities": []}])
    assert "missing key(s)" in str(excinfo.value)


def test_non_list_input_is_refused() -> None:
    for decoder in (fields_from_json, prefill_fields_from_json, signer_roles_from_json):
        with pytest.raises(ValidationFailed):
            decoder({"not": "a list"})


def test_the_error_path_names_the_offending_entry() -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        fields_from_json(
            [
                {"id": "ok", "type": "text", "page": 1, "rect": {"x": 0, "y": 0, "w": 1, "h": 1}, "signer_role": "p"},
                {"id": "bad", "type": "text", "page": 1, "rect": "nope", "signer_role": "p"},
            ]
        )
    assert "fields[1].rect" in str(excinfo.value)
