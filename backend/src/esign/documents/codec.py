"""JSON <-> definition dataclasses.

``template_versions.fields``, ``.prefill_fields`` and ``.signer_roles`` are ``jsonb`` columns, and
the sample templates ship their definitions as JSON files. Both need the same decoder, and it has
to be strict: a definition that decodes loosely puts a signature field somewhere nobody intended,
on a document that is then frozen and sealed.

So: unknown keys are refused, missing keys are refused, types are checked, and every failure is a
:class:`~esign.contracts.ValidationFailed` naming the offending path. Decoding does *not* check
that the definitions make sense together -- that is
:func:`esign.documents.definitions.validate_definitions`, which runs against the PDF as well.
"""

from __future__ import annotations

from typing import Any, Final, get_args

from esign.contracts import (
    Capacity,
    FieldDef,
    FieldType,
    PrefillFieldDef,
    Rect,
    SignerRoleDef,
    ValidationFailed,
)

__all__ = [
    "TemplateDefinitions",
    "definitions_from_json",
    "definitions_to_json",
    "fields_from_json",
    "fields_to_json",
    "prefill_fields_from_json",
    "prefill_fields_to_json",
    "signer_roles_from_json",
    "signer_roles_to_json",
]

_FIELD_TYPES: Final[frozenset[str]] = frozenset(get_args(FieldType))
_CAPACITIES: Final[frozenset[str]] = frozenset(get_args(Capacity))

_FIELD_KEYS: Final[frozenset[str]] = frozenset({"id", "type", "page", "rect", "signer_role", "required", "label"})
_PREFILL_KEYS: Final[frozenset[str]] = frozenset({"key", "page", "rect", "font_size", "required", "multiline"})
_ROLE_KEYS: Final[frozenset[str]] = frozenset({"key", "label", "allowed_capacities", "requires_reauth", "order_index"})
_RECT_KEYS: Final[frozenset[str]] = frozenset({"x", "y", "w", "h"})


class TemplateDefinitions(dict[str, Any]):
    """The decoded triple, kept as a plain mapping so callers can destructure it."""

    @property
    def fields(self) -> list[FieldDef]:
        return list(self["fields"])

    @property
    def prefill_fields(self) -> list[PrefillFieldDef]:
        return list(self["prefill_fields"])

    @property
    def signer_roles(self) -> list[SignerRoleDef]:
        return list(self["signer_roles"])


def _fail(path: str, why: str) -> ValidationFailed:
    return ValidationFailed(f"{path}: {why}", code="template_definitions_malformed")


def _mapping(value: Any, path: str, allowed: frozenset[str], required: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(path, "expected an object")
    keys = set(value)
    unknown = sorted(keys - allowed)
    if unknown:
        raise _fail(path, f"unknown key(s): {', '.join(unknown)}")
    missing = sorted(required - keys)
    if missing:
        raise _fail(path, f"missing key(s): {', '.join(missing)}")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise _fail(path, "expected a string")
    return value


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(path, "expected an integer")
    return value


def _number(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _fail(path, "expected a number")
    return float(value)


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(path, "expected a boolean")
    return value


def _rect(value: Any, path: str) -> Rect:
    raw = _mapping(value, path, _RECT_KEYS, _RECT_KEYS)
    return Rect(
        x=_number(raw["x"], f"{path}.x"),
        y=_number(raw["y"], f"{path}.y"),
        w=_number(raw["w"], f"{path}.w"),
        h=_number(raw["h"], f"{path}.h"),
    )


def _sequence(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise _fail(path, "expected a list")
    return value


# --------------------------------------------------------------------------- decode


def fields_from_json(value: Any, path: str = "fields") -> list[FieldDef]:
    out: list[FieldDef] = []
    for index, item in enumerate(_sequence(value, path)):
        here = f"{path}[{index}]"
        raw = _mapping(item, here, _FIELD_KEYS, frozenset({"id", "type", "page", "rect", "signer_role"}))
        field_type = _string(raw["type"], f"{here}.type")
        if field_type not in _FIELD_TYPES:
            raise _fail(f"{here}.type", f"unknown field type {field_type!r}")
        out.append(
            FieldDef(
                id=_string(raw["id"], f"{here}.id"),
                type=field_type,  # type: ignore[arg-type]
                page=_integer(raw["page"], f"{here}.page"),
                rect=_rect(raw["rect"], f"{here}.rect"),
                signer_role=_string(raw["signer_role"], f"{here}.signer_role"),
                required=_boolean(raw.get("required", True), f"{here}.required"),
                label=_string(raw.get("label", ""), f"{here}.label"),
            )
        )
    return out


def prefill_fields_from_json(value: Any, path: str = "prefill_fields") -> list[PrefillFieldDef]:
    out: list[PrefillFieldDef] = []
    for index, item in enumerate(_sequence(value, path)):
        here = f"{path}[{index}]"
        raw = _mapping(item, here, _PREFILL_KEYS, frozenset({"key", "page", "rect"}))
        out.append(
            PrefillFieldDef(
                key=_string(raw["key"], f"{here}.key"),
                page=_integer(raw["page"], f"{here}.page"),
                rect=_rect(raw["rect"], f"{here}.rect"),
                font_size=_number(raw.get("font_size", 10.0), f"{here}.font_size"),
                required=_boolean(raw.get("required", True), f"{here}.required"),
                multiline=_boolean(raw.get("multiline", False), f"{here}.multiline"),
            )
        )
    return out


def signer_roles_from_json(value: Any, path: str = "signer_roles") -> list[SignerRoleDef]:
    out: list[SignerRoleDef] = []
    for index, item in enumerate(_sequence(value, path)):
        here = f"{path}[{index}]"
        raw = _mapping(item, here, _ROLE_KEYS | {"required"}, _ROLE_KEYS)
        capacities: list[Capacity] = []
        for position, capacity in enumerate(_sequence(raw["allowed_capacities"], f"{here}.allowed_capacities")):
            name = _string(capacity, f"{here}.allowed_capacities[{position}]")
            if name not in _CAPACITIES:
                raise _fail(f"{here}.allowed_capacities[{position}]", f"unknown capacity {name!r}")
            capacities.append(name)  # type: ignore[arg-type]
        out.append(
            SignerRoleDef(
                key=_string(raw["key"], f"{here}.key"),
                label=_string(raw["label"], f"{here}.label"),
                allowed_capacities=tuple(capacities),
                requires_reauth=_boolean(raw["requires_reauth"], f"{here}.requires_reauth"),
                order_index=_integer(raw["order_index"], f"{here}.order_index"),
                required=_boolean(raw["required"], f"{here}.required") if "required" in raw else True,
            )
        )
    return out


def definitions_from_json(document: Any, path: str = "definitions") -> TemplateDefinitions:
    """Decode a whole ``{fields, prefill_fields, signer_roles, ...}`` document."""
    if not isinstance(document, dict):
        raise _fail(path, "expected an object")
    return TemplateDefinitions(
        fields=fields_from_json(document.get("fields", []), f"{path}.fields"),
        prefill_fields=prefill_fields_from_json(document.get("prefill_fields", []), f"{path}.prefill_fields"),
        signer_roles=signer_roles_from_json(document.get("signer_roles", []), f"{path}.signer_roles"),
    )


# --------------------------------------------------------------------------- encode


def _rect_json(rect: Rect) -> dict[str, float]:
    return {"x": rect.x, "y": rect.y, "w": rect.w, "h": rect.h}


def fields_to_json(fields: list[FieldDef]) -> list[dict[str, Any]]:
    return [
        {
            "id": field.id,
            "type": field.type,
            "page": field.page,
            "rect": _rect_json(field.rect),
            "signer_role": field.signer_role,
            "required": field.required,
            "label": field.label,
        }
        for field in fields
    ]


def prefill_fields_to_json(prefill_fields: list[PrefillFieldDef]) -> list[dict[str, Any]]:
    return [
        {
            "key": prefill.key,
            "page": prefill.page,
            "rect": _rect_json(prefill.rect),
            "font_size": prefill.font_size,
            "required": prefill.required,
            "multiline": prefill.multiline,
        }
        for prefill in prefill_fields
    ]


def signer_roles_to_json(signer_roles: list[SignerRoleDef]) -> list[dict[str, Any]]:
    return [
        {
            "key": role.key,
            "label": role.label,
            "allowed_capacities": list(role.allowed_capacities),
            "requires_reauth": role.requires_reauth,
            "order_index": role.order_index,
            "required": role.required,
        }
        for role in signer_roles
    ]


def definitions_to_json(
    fields: list[FieldDef],
    prefill_fields: list[PrefillFieldDef],
    signer_roles: list[SignerRoleDef],
) -> dict[str, Any]:
    return {
        "signer_roles": signer_roles_to_json(signer_roles),
        "fields": fields_to_json(fields),
        "prefill_fields": prefill_fields_to_json(prefill_fields),
    }
