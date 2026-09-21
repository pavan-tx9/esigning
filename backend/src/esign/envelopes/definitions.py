"""Template definitions, read back out of ``template_versions`` jsonb.

The documents module writes these columns; this module only reads them, and reads them
defensively: a malformed definition is a template problem, not a signer problem, so it surfaces
as ``ValidationFailed`` with a code that names the column rather than blowing up mid-signature.

Nothing here touches the database or the clock.
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
    "CAPACITIES",
    "FIELD_TYPES",
    "SIGNABLE_FIELD_TYPES",
    "parse_field_defs",
    "parse_prefill_fields",
    "parse_signer_roles",
]

FIELD_TYPES: Final[frozenset[str]] = frozenset(get_args(FieldType))
CAPACITIES: Final[frozenset[str]] = frozenset(get_args(Capacity))

#: Field types a signer supplies a capture for. ``date_signed`` is filled by the server from the
#: clock and ``text``/``checkbox`` carry values, so only these two accept a signature mark.
SIGNABLE_FIELD_TYPES: Final[frozenset[str]] = frozenset({"signature", "initials"})


def parse_field_defs(raw: Any) -> tuple[FieldDef, ...]:
    items = _require_list(raw, "fields")
    return tuple(_field_def(item, index) for index, item in enumerate(items))


def parse_prefill_fields(raw: Any) -> tuple[PrefillFieldDef, ...]:
    items = _require_list(raw, "prefill_fields")
    return tuple(_prefill_field_def(item, index) for index, item in enumerate(items))


def parse_signer_roles(raw: Any) -> tuple[SignerRoleDef, ...]:
    items = _require_list(raw, "signer_roles")
    roles = tuple(_signer_role_def(item, index) for index, item in enumerate(items))
    if not roles:
        raise ValidationFailed("template declares no signer roles", code="template_definitions_invalid")
    keys = [role.key for role in roles]
    if len(set(keys)) != len(keys):
        raise ValidationFailed("template declares a duplicate signer role", code="template_definitions_invalid")
    return roles


# --------------------------------------------------------------------------- internals


def _bad(detail: str) -> ValidationFailed:
    """Definition problems name the column and the index, never a value: values may be PHI."""
    return ValidationFailed(detail, code="template_definitions_invalid")


def _require_list(raw: Any, column: str) -> list[Any]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise _bad(f"{column} is not a list")
    return raw


def _require_mapping(item: Any, column: str, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise _bad(f"{column}[{index}] is not an object")
    return item


def _str(item: dict[str, Any], key: str, column: str, index: int, *, required: bool = True) -> str:
    value = item.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise _bad(f"{column}[{index}].{key} is not a string")
    return value


def _int(item: dict[str, Any], key: str, column: str, index: int) -> int:
    value = item.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _bad(f"{column}[{index}].{key} is not an integer")
    return value


def _bool(item: dict[str, Any], key: str, column: str, index: int, *, default: bool) -> bool:
    value = item.get(key, default)
    if not isinstance(value, bool):
        raise _bad(f"{column}[{index}].{key} is not a boolean")
    return value


def _float(item: dict[str, Any], key: str, column: str, index: int, *, default: float | None = None) -> float:
    value = item.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _bad(f"{column}[{index}].{key} is not a number")
    return float(value)


def _rect(item: dict[str, Any], column: str, index: int) -> Rect:
    raw = item.get("rect")
    if not isinstance(raw, dict):
        raise _bad(f"{column}[{index}].rect is not an object")
    return Rect(
        x=_float(raw, "x", f"{column}[{index}].rect", 0),
        y=_float(raw, "y", f"{column}[{index}].rect", 0),
        w=_float(raw, "w", f"{column}[{index}].rect", 0),
        h=_float(raw, "h", f"{column}[{index}].rect", 0),
    )


def _field_def(item: Any, index: int) -> FieldDef:
    data = _require_mapping(item, "fields", index)
    field_type = _str(data, "type", "fields", index)
    if field_type not in FIELD_TYPES:
        raise _bad(f"fields[{index}].type is not a known field type")
    return FieldDef(
        id=_str(data, "id", "fields", index),
        type=field_type,  # type: ignore[arg-type]  # guarded by FIELD_TYPES above
        page=_int(data, "page", "fields", index),
        rect=_rect(data, "fields", index),
        signer_role=_str(data, "signer_role", "fields", index),
        required=_bool(data, "required", "fields", index, default=True),
        label=_str(data, "label", "fields", index, required=False),
    )


def _prefill_field_def(item: Any, index: int) -> PrefillFieldDef:
    data = _require_mapping(item, "prefill_fields", index)
    return PrefillFieldDef(
        key=_str(data, "key", "prefill_fields", index),
        page=_int(data, "page", "prefill_fields", index),
        rect=_rect(data, "prefill_fields", index),
        font_size=_float(data, "font_size", "prefill_fields", index, default=10.0),
        required=_bool(data, "required", "prefill_fields", index, default=True),
        multiline=_bool(data, "multiline", "prefill_fields", index, default=False),
    )


def _signer_role_def(item: Any, index: int) -> SignerRoleDef:
    data = _require_mapping(item, "signer_roles", index)
    raw_capacities = data.get("allowed_capacities")
    if not isinstance(raw_capacities, list) or not raw_capacities:
        raise _bad(f"signer_roles[{index}].allowed_capacities is empty or not a list")
    capacities: list[Capacity] = []
    for capacity in raw_capacities:
        if not isinstance(capacity, str) or capacity not in CAPACITIES:
            raise _bad(f"signer_roles[{index}].allowed_capacities holds an unknown capacity")
        capacities.append(capacity)  # type: ignore[arg-type]  # guarded by CAPACITIES above
    return SignerRoleDef(
        key=_str(data, "key", "signer_roles", index),
        label=_str(data, "label", "signer_roles", index),
        allowed_capacities=tuple(capacities),
        requires_reauth=_bool(data, "requires_reauth", "signer_roles", index, default=False),
        order_index=_int(data, "order_index", "signer_roles", index),
        required=_bool(data, "required", "signer_roles", index, default=True),
    )
