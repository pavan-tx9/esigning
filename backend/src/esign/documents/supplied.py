"""Host-supplied documents (Addendum 2): reading a report's signature block, and stripping it back.

A template is published once and its fields are declared by hand. A host document is generated per
patient and arrives with the signature block already drawn into it, so the field definitions have
to be *read out of the file*. Two operations, in that order:

* :func:`resolve_named_fields` turns the PDF's own AcroForm widgets into ``FieldDef``s by name, in
  displayed-page coordinates -- the coordinate system ``Rect`` is defined in (SPEC section 6), so a
  rotated or offset-origin page means the same thing here as it does for a template.
* :func:`flatten_supplied` produces the bytes that become revision 1: widgets, annotations and the
  form itself gone, page content untouched, nothing new embedded.

Both are pure. Given the same bytes they return the same answer, which is what lets revision 1's
hash be evidence rather than a property of the moment it was built.

Two rules worth stating out loud, because they are what keeps this from being a guess:

* **Nothing is inferred from position.** A widget becomes a field because its *name* says which
  role it belongs to, never because it sits near the bottom of the last page. A widget no role
  claims is dropped here and removed from the bytes by :func:`flatten_supplied`; it never becomes
  a field by accident.
* **The host's strings stay out of the error.** ``fields_unresolved`` names the signer roles the
  host declared in its own request body and nothing from inside the file: a widget name in a
  per-patient report is host-generated text of unknown provenance, and an error message goes into
  logs and back over the wire.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, NumberObject

from esign.contracts import FieldDef, FieldType, Rect, SignerRoleDef, ValidationFailed
from esign.documents.definitions import MAX_ID_CHARS, MAX_LABEL_CHARS
from esign.documents.geometry import PageGeometry
from esign.documents.pdfutil import geometries, open_reader, sanitize_document, to_bytes, writer_from_bytes

__all__ = ["flatten_supplied", "resolve_named_fields"]

#: Suffix spellings a widget name may end with, and the ``FieldType`` each one means. Longest
#: first, so ``x_date_signed`` is a ``date_signed`` field named ``x`` and not a ``date`` field
#: named ``x_signed``.
_TYPE_SUFFIXES: Final[tuple[tuple[str, FieldType], ...]] = (
    ("date_signed", "date_signed"),
    ("signature", "signature"),
    ("initials", "initials"),
    ("checkbox", "checkbox"),
    ("date", "date_signed"),
    ("text", "text"),
)

#: The short spelling, ``<role_key>_<suffix>``, is deliberately a closed set: it is the one form
#: where a single underscore separates the role from the type, so anything else after a single
#: underscore (``patient_address``) is not a field of ours and is dropped rather than guessed at.
_SHORT_SUFFIXES: Final[dict[str, FieldType]] = {
    "signature": "signature",
    "initials": "initials",
    "date": "date_signed",
    "date_signed": "date_signed",
}

#: What a role has to resolve to for the document to be signable by it: a *signature* field.
#:
#: This is deliberately stricter than ``validate_definitions``, which accepts a role whose only
#: mark is initials (the base spec's rule, written for templates a person authored field by
#: field). Here nobody authored anything: a role's mark is whatever a report generator happened to
#: name a widget, and "the physician initialled the report" is not what a 30-page clinical
#: sign-off is for. Both the addendum ("at least one signature field") and
#: ``DocumentService.resolve_named_fields`` say signature, and the refusal names the role, so a
#: host that really does want an initials-only role has an accurate error and the explicit-rects
#: mode to say so in as many words.
_SIGNING_TYPES: Final[frozenset[str]] = frozenset({"signature"})

#: The values a form collects, as opposed to the marks a signer makes. These are the only fields
#: whose ``required`` comes from the widget's own ``/Ff``: a mark or the date beside it is the
#: document asking for it, whatever flag the generator happened to set.
_VALUE_TYPES: Final[frozenset[str]] = frozenset({"text", "checkbox"})

#: What a field's generated label says it is. Labels are shown in the signing UI, so they are built
#: from the role label the host declared in the request body rather than from the widget's name.
_TYPE_WORDS: Final[dict[str, str]] = {
    "signature": "signature",
    "initials": "initials",
    "date_signed": "date signed",
    "text": "field",
    "checkbox": "checkbox",
}

#: ``/FT`` to the field type meant when the name carries no suffix of its own.
_FT_TYPES: Final[dict[str, FieldType]] = {"/Btn": "checkbox", "/Tx": "text", "/Ch": "text", "/Sig": "signature"}

#: ``/Ff`` bit 2 (PDF 12.7.3.1): the field must have a value before the form is submitted.
_FIELD_FLAG_REQUIRED: Final[int] = 1 << 1

#: A ``/Parent`` chain deeper than this is either malformed or a cycle. The walk is bounded rather
#: than trusted, because the file is the host's and the chain is whatever it says it is.
_MAX_PARENT_DEPTH: Final[int] = 32

_NON_ID: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9_]+")


def _resolve(value: Any) -> Any:
    return value.get_object() if isinstance(value, IndirectObject) else value


def _normalise(raw: str) -> str:
    """A widget's name as a field id: lowercase, ``[a-z0-9_]`` only.

    Partial field names are joined with ``.`` per the PDF spec, and a generator may use characters
    an id cannot hold, so every run of anything else collapses to a single underscore. Two widgets
    whose names differ only in those characters therefore collide; :func:`_unique` breaks the tie,
    and the ids stay inside ``[a-z0-9_]+`` where ``validate_definitions`` needs them.
    """
    return _NON_ID.sub("_", raw.lower()).strip("_")


def _number(value: Any) -> float | None:
    resolved = _resolve(value)
    if isinstance(resolved, NumberObject | int | float):
        return float(resolved)
    return None


@dataclass(frozen=True)
class _Widget:
    """One widget annotation, already placed in displayed-page coordinates."""

    name: str  # normalised
    page: int  # 1-based
    rect: Rect
    ft: str  # "/Tx", "/Btn", ... or "" when the field declares none
    required: bool


def _inherited(annot: DictionaryObject, key: str) -> Any:
    """Look ``key`` up the ``/Parent`` chain. ``/FT`` and ``/Ff`` are inheritable, and a widget
    that is one kid of a field usually carries neither itself."""
    node: Any = annot
    for _ in range(_MAX_PARENT_DEPTH):
        if not isinstance(node, DictionaryObject):
            return None
        if key in node:
            return _resolve(node.get(key))
        node = _resolve(node.get("/Parent"))
    return None


def _qualified_name(annot: DictionaryObject) -> str:
    """The widget's fully qualified field name (PDF 12.7.3.2), normalised to an id.

    A widget may be the field itself (``/T`` on the annotation) or one of a field's kids (``/T`` on
    an ancestor), and both shapes are produced by ordinary report generators. Walking the chain and
    joining with ``.`` is what makes ``clinician.signature`` and ``clinician_signature`` the same
    field to us, which is what a host would reasonably expect.
    """
    parts: list[str] = []
    node: Any = annot
    for _ in range(_MAX_PARENT_DEPTH):
        if not isinstance(node, DictionaryObject):
            break
        title = _resolve(node.get("/T"))
        if isinstance(title, str) and title:
            parts.append(str(title))
        node = _resolve(node.get("/Parent"))
    parts.reverse()
    return _normalise(".".join(parts))


def _displayed_rect(geometry: PageGeometry, annot: DictionaryObject) -> Rect | None:
    """The widget's ``/Rect`` in displayed coordinates, or ``None`` if it has no usable one.

    ``/Rect`` is in the page's own user space. Every corner is converted rather than two, so a
    ``/Rotate`` of 90 or 270 -- where the corner that was bottom-left is no longer bottom-left --
    still yields the box a reader sees, and a non-zero ``MediaBox``/``CropBox`` origin is subtracted
    by the same conversion.
    """
    raw = _resolve(annot.get("/Rect"))
    if not isinstance(raw, ArrayObject | list) or len(raw) != 4:
        return None
    values = [_number(item) for item in raw]
    if any(value is None for value in values):
        return None
    x0, y0, x1, y1 = (float(value) for value in values if value is not None)
    corners = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
    displayed = [geometry.to_displayed(x, y) for x, y in corners]
    dx0 = min(point[0] for point in displayed)
    dx1 = max(point[0] for point in displayed)
    dy0 = min(point[1] for point in displayed)
    dy1 = max(point[1] for point in displayed)
    if dx1 - dx0 <= 0 or dy1 - dy0 <= 0:
        return None
    return Rect(x=dx0, y=dy0, w=dx1 - dx0, h=dy1 - dy0)


def _widgets(pdf: bytes) -> list[_Widget]:
    """Every widget annotation in the document, in page order then annotation order.

    Read from the *pages*, not from ``/AcroForm /Fields``: a field's page is only knowable from the
    page that lists it (``/P`` is optional), and a field the page tree does not reference is not
    drawn anywhere, so it is not a place a signer could sign.
    """
    reader = open_reader(pdf)
    pages = list(reader.pages)
    geometry_of = geometries(pages)
    found: list[_Widget] = []

    for geometry, page in zip(geometry_of, pages, strict=True):
        annots = _resolve(page.get("/Annots"))
        if not isinstance(annots, ArrayObject | list):
            continue
        for ref in list(annots):
            annot = _resolve(ref)
            if not isinstance(annot, DictionaryObject):
                continue
            subtype = annot.get("/Subtype")
            if not isinstance(subtype, NameObject) or str(subtype) != "/Widget":
                continue
            name = _qualified_name(annot)
            rect = _displayed_rect(geometry, annot)
            if not name or rect is None:
                continue
            ft = _inherited(annot, "/FT")
            flags = _inherited(annot, "/Ff")
            found.append(
                _Widget(
                    name=name,
                    page=geometry.index + 1,
                    rect=rect,
                    ft=str(ft) if isinstance(ft, NameObject) else "",
                    required=bool(int(flags) & _FIELD_FLAG_REQUIRED)
                    if isinstance(flags, NumberObject | int)
                    else False,
                )
            )
    return found


def _type_from_remainder(remainder: str, ft: str) -> FieldType:
    """The type meant by what follows ``<role_key>__``.

    ``clinician__attestation_signature`` is a signature; ``clinician__signature`` is too. With no
    recognised suffix the widget's own ``/FT`` decides, and a field that declares nothing is text --
    the only type that cannot silently turn into someone's mark.
    """
    for suffix, field_type in _TYPE_SUFFIXES:
        if remainder == suffix or remainder.endswith(f"_{suffix}"):
            return field_type
    return _FT_TYPES.get(ft, "text")


def _claim(name: str, role_keys: list[str], ft: str) -> tuple[str, FieldType] | None:
    """Which role owns a widget called ``name``, and what type of field it is.

    Longest role key first, so a document with roles ``clinician`` and ``clinician_2`` gives
    ``clinician_2_signature`` to the role that actually spelled it. The ``__`` form is tried for
    every role before the short form is tried for any, because ``<role>__...`` is unambiguous and
    ``<role>_signature`` is not when another role's key ends in ``_signature``'s first characters.
    """
    for key in role_keys:
        prefix = f"{key}__"
        if name.startswith(prefix):
            remainder = name[len(prefix) :]
            if remainder:
                return key, _type_from_remainder(remainder, ft)
    for key in role_keys:
        prefix = f"{key}_"
        if name.startswith(prefix):
            short = _SHORT_SUFFIXES.get(name[len(prefix) :])
            if short is not None:
                return key, short
    return None


def _unique(candidate: str, taken: set[str]) -> str:
    """``candidate``, shortened to fit and suffixed until it is not already used.

    Ids have to be unique within the envelope and no longer than ``validate_definitions`` allows.
    A host whose report puts the same field name on two pages gets two fields rather than a
    rejection, because two widgets *are* two places to sign.
    """
    base = candidate[:MAX_ID_CHARS] or "field"
    if base not in taken:
        return base
    for index in range(2, 1000):
        suffix = f"_{index}"
        attempt = f"{base[: MAX_ID_CHARS - len(suffix)]}{suffix}"
        if attempt not in taken:
            return attempt
    raise ValidationFailed(  # pragma: no cover - 999 widgets sharing one normalised name
        "the document has too many fields with the same name", code="fields_unresolved"
    )


def resolve_named_fields(pdf: bytes, signer_roles: list[SignerRoleDef]) -> list[FieldDef]:
    """Implements ``DocumentService.resolve_named_fields``."""
    if not signer_roles:
        raise ValidationFailed("no signer roles were declared", code="fields_unresolved")

    # Longest first: see ``_claim``. Sorting by key as well keeps the order deterministic when two
    # role keys are the same length, so the same document always resolves the same way.
    role_keys = sorted({role.key for role in signer_roles}, key=lambda key: (-len(key), key))
    labels = {role.key: role.label for role in signer_roles}

    fields: list[FieldDef] = []
    taken: set[str] = set()
    signing_roles: set[str] = set()

    for widget in _widgets(pdf):
        claimed = _claim(widget.name, role_keys, widget.ft)
        if claimed is None:
            continue  # not ours: dropped here, and removed from the bytes by flatten_supplied
        role_key, field_type = claimed
        field_id = _unique(widget.name, taken)
        taken.add(field_id)
        if field_type in _SIGNING_TYPES:
            signing_roles.add(role_key)
        # A mark and the date beside it are the document asking for them; only the host's own
        # ``/Ff`` decides whether a text or checkbox field has to be filled in.
        required = widget.required if field_type in _VALUE_TYPES else True
        label = f"{labels.get(role_key, role_key)} {_TYPE_WORDS[field_type]}"[:MAX_LABEL_CHARS]
        fields.append(
            FieldDef(
                id=field_id,
                type=field_type,
                page=widget.page,
                rect=widget.rect,
                signer_role=role_key,
                required=required,
                label=label,
            )
        )

    missing = sorted({role.key for role in signer_roles} - signing_roles)
    if missing:
        # Role keys come from the request body the host just sent, so naming them tells the
        # integrator what to fix. Widget names come from inside the file and stay there.
        raise ValidationFailed(
            f"the document has no signature field for signer role(s): {', '.join(missing)}",
            code="fields_unresolved",
        )
    return fields


def flatten_supplied(pdf: bytes) -> bytes:
    """Implements ``DocumentService.flatten_supplied``."""
    before = len(open_reader(pdf).pages)
    writer = writer_from_bytes(pdf)
    # ``flatten_annotations=False`` is the whole difference from ``prepare``. Burning a widget's
    # appearance into the page would draw the empty signature box -- ink the host did not put in
    # the report -- into the bytes that are about to be hashed as "what the signer was shown". The
    # widgets are removed, not printed.
    sanitize_document(writer, flatten_annotations=False)
    out = to_bytes(writer)

    after = len(open_reader(out).pages)
    if after != before:
        # Measured on the produced bytes rather than on the writer, because the claim being checked
        # is about what will be stored and hashed, not about what was intended.
        raise ValidationFailed(
            "flattening the supplied document changed its page count",
            code="supplied_flatten_changed_pages",
        )
    return out
