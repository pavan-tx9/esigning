"""Validation of a template version's field, prefill and role definitions.

These definitions are published once and then frozen, and every envelope built from the version
inherits whatever is wrong with them. So the check is exhaustive and reports *every* problem in a
single :class:`~esign.contracts.ValidationFailed`: a host that fixes one problem, republishes and
learns about the next one has been made to do our work.

Problem strings name ids and keys, which are template metadata chosen by the host and are not PHI.
Field *labels* and prefill *values* are never echoed.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Final, get_args

from esign.contracts import (
    Capacity,
    FieldDef,
    FieldType,
    PrefillFieldDef,
    Rect,
    SignerRoleDef,
    TemplatePdfInfo,
    ValidationFailed,
)
from esign.documents.geometry import MIN_RECT_SIDE, PageGeometry

__all__ = [
    "ID_PATTERN",
    "MAX_LABEL_CHARS",
    "MIN_MARK_RECT_HEIGHT",
    "MIN_MARK_RECT_WIDTH",
    "validate_definitions",
]

ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9_]+$")
MAX_ID_CHARS: Final[int] = 64
MAX_LABEL_CHARS: Final[int] = 120
MAX_FIELDS: Final[int] = 500
MAX_ROLES: Final[int] = 10

_FIELD_TYPES: Final[frozenset[str]] = frozenset(get_args(FieldType))
_CAPACITIES: Final[frozenset[str]] = frozenset(get_args(Capacity))
#: Field types that stand in for an act of signing and therefore satisfy "every role signs".
_SIGNING_TYPES: Final[frozenset[str]] = frozenset({"signature", "initials"})

#: A signature or initials field carries a caption naming the signer, the UTC time and the signer
#: id, and the id is never abbreviated (see ``stamping``). That sets a floor on how narrow such a
#: field may be: a template that declares one narrower is rejected here rather than producing a
#: document whose caption had to be cut to fit.
MIN_MARK_RECT_WIDTH: Final[float] = 80.0
#: Tall enough for the mark plus its caption band.
MIN_MARK_RECT_HEIGHT: Final[float] = 28.0


def _fake_geometry(width: float, height: float) -> PageGeometry:
    """A geometry for a page we only know the displayed size of."""
    return PageGeometry(index=0, rotate=0, x0=0.0, y0=0.0, x1=width, y1=height)


def _check_rect(
    problems: list[str],
    what: str,
    page: int,
    rect: Rect,
    info: TemplatePdfInfo,
) -> None:
    if not isinstance(page, int) or page < 1 or page > info.page_count:
        problems.append(f"{what}: page {page} is outside 1..{info.page_count}")
        return
    if page - 1 >= len(info.page_sizes):
        problems.append(f"{what}: no recorded size for page {page}")
        return
    for name, value in (("x", rect.x), ("y", rect.y), ("w", rect.w), ("h", rect.h)):
        if value != value or value in (float("inf"), float("-inf")):  # NaN or infinity
            problems.append(f"{what}: rect.{name} is not a finite number")
            return
    if rect.w < MIN_RECT_SIDE or rect.h < MIN_RECT_SIDE:
        problems.append(f"{what}: rect is smaller than {MIN_RECT_SIDE:g}pt in one dimension")
        return
    width, height = info.page_sizes[page - 1]
    if not _fake_geometry(width, height).contains(rect):
        problems.append(
            f"{what}: rect ({rect.x:g},{rect.y:g},{rect.w:g}x{rect.h:g}) "
            f"does not fit inside page {page} ({width:g}x{height:g})"
        )


def validate_definitions(
    info: TemplatePdfInfo,
    fields: list[FieldDef],
    prefill_fields: list[PrefillFieldDef],
    signer_roles: list[SignerRoleDef],
) -> None:
    """Implements ``DocumentService.validate_definitions``."""
    problems: list[str] = []

    # ------------------------------------------------------------------ roles
    if not signer_roles:
        problems.append("signer_roles: at least one role is required")
    if len(signer_roles) > MAX_ROLES:
        problems.append(f"signer_roles: at most {MAX_ROLES} roles are supported")

    role_keys: list[str] = []
    for role in signer_roles:
        key = role.key
        role_keys.append(key)
        what = f"role {key!r}"
        if not ID_PATTERN.match(key) or len(key) > MAX_ID_CHARS:
            problems.append(f"{what}: key must match [a-z0-9_]+ and be at most {MAX_ID_CHARS} characters")
        if not role.label.strip():
            problems.append(f"{what}: label is required")
        if len(role.label) > MAX_LABEL_CHARS:
            problems.append(f"{what}: label is longer than {MAX_LABEL_CHARS} characters")
        if not role.allowed_capacities:
            problems.append(f"{what}: allowed_capacities is empty")
        for capacity in role.allowed_capacities:
            if capacity not in _CAPACITIES:
                problems.append(f"{what}: unknown capacity {capacity!r}")
        if "clinician" in role.allowed_capacities and not role.requires_reauth:
            # The developer guide makes this a requirement, not a preference: "Re-authenticate
            # clinicians at the moment of signing", and its Definition of Done repeats it. A
            # published template that allows the clinician capacity without re-authentication would
            # produce clinician signatures with no ``auth.reauthenticated`` anywhere in the trail
            # and a certificate printing that as normal, so it is refused here.
            problems.append(f"{what}: a role that allows the clinician capacity must set requires_reauth: true")
        if not isinstance(role.order_index, int) or role.order_index < 0:
            problems.append(f"{what}: order_index must be a non-negative integer")

    for key, count in Counter(role_keys).items():
        if count > 1:
            problems.append(f"role {key!r}: declared {count} times")

    order_indexes = [role.order_index for role in signer_roles]
    for index, count in Counter(order_indexes).items():
        if count > 1:
            problems.append(
                f"signer_roles: order_index {index} is used by {count} roles; sequential order is ambiguous"
            )

    known_roles = set(role_keys)

    # ------------------------------------------------------------------ fields
    if len(fields) > MAX_FIELDS:
        problems.append(f"fields: at most {MAX_FIELDS} fields are supported")

    field_ids: list[str] = []
    roles_with_signature: set[str] = set()
    for fld in fields:
        field_ids.append(fld.id)
        what = f"field {fld.id!r}"
        if not ID_PATTERN.match(fld.id) or len(fld.id) > MAX_ID_CHARS:
            problems.append(f"{what}: id must match [a-z0-9_]+ and be at most {MAX_ID_CHARS} characters")
        if fld.type not in _FIELD_TYPES:
            problems.append(f"{what}: unknown field type {fld.type!r}")
        if len(fld.label) > MAX_LABEL_CHARS:
            problems.append(f"{what}: label is longer than {MAX_LABEL_CHARS} characters")
        if fld.signer_role not in known_roles:
            problems.append(f"{what}: references undeclared signer role {fld.signer_role!r}")
        elif fld.type in _SIGNING_TYPES:
            roles_with_signature.add(fld.signer_role)
        if fld.type in _SIGNING_TYPES and (fld.rect.w < MIN_MARK_RECT_WIDTH or fld.rect.h < MIN_MARK_RECT_HEIGHT):
            problems.append(
                f"{what}: a {fld.type} field must be at least "
                f"{MIN_MARK_RECT_WIDTH:g}x{MIN_MARK_RECT_HEIGHT:g}pt so its caption fits without abbreviating "
                "the signer id"
            )
        _check_rect(problems, what, fld.page, fld.rect, info)

    for field_id, count in Counter(field_ids).items():
        if count > 1:
            problems.append(f"field {field_id!r}: declared {count} times")

    for key in role_keys:
        if key not in roles_with_signature:
            problems.append(f"role {key!r}: has no signature or initials field")

    # ------------------------------------------------------------------ prefill
    prefill_keys: list[str] = []
    for prefill in prefill_fields:
        prefill_keys.append(prefill.key)
        what = f"prefill {prefill.key!r}"
        if not ID_PATTERN.match(prefill.key) or len(prefill.key) > MAX_ID_CHARS:
            problems.append(f"{what}: key must match [a-z0-9_]+ and be at most {MAX_ID_CHARS} characters")
        if prefill.font_size <= 0 or prefill.font_size > 72:
            problems.append(f"{what}: font_size must be between 0 and 72")
        _check_rect(problems, what, prefill.page, prefill.rect, info)

    for key, count in Counter(prefill_keys).items():
        if count > 1:
            problems.append(f"prefill {key!r}: declared {count} times")

    overlap = set(prefill_keys) & set(field_ids)
    for key in sorted(overlap):
        problems.append(f"prefill {key!r}: collides with a field of the same id")

    if problems:
        raise ValidationFailed("; ".join(sorted(problems)), code="template_definitions_invalid")
