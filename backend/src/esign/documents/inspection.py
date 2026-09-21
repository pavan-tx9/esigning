"""Template intake: what a host is allowed to upload.

A template is the one place the host hands us a whole PDF, so it is the one place an attacker (or
a careless integrator) could smuggle in something active. The check is a walk of the whole object
graph rather than a look at the handful of places these features are normally declared, because
"normally" is doing no work in a security check: ``/JavaScript`` reachable from an annotation's
additional-actions dictionary is still JavaScript.

Everything is fail-closed. Anything unparseable, anything encrypted, anything already signed and
anything active is rejected; the reasons are collected so a host fixing a template learns all of
them at once, and every reason is a stable code with no input echoed back.
"""

from __future__ import annotations

import hashlib
from typing import Any, Final

from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject

from esign.config import Settings
from esign.contracts import TemplatePdfInfo, ValidationFailed
from esign.documents.pdfutil import geometries, open_reader

__all__ = ["inspect_template"]

#: Action types that make the reader do something other than go to a page in this document.
_FORBIDDEN_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "/JavaScript",
        "/Launch",
        "/GoToR",
        "/GoToE",
        "/SubmitForm",
        "/ImportData",
        "/ResetForm",
        "/Movie",
        "/Sound",
        "/Rendition",
        "/RichMediaExecute",
        "/SetOCGState",
        "/Trans",
        "/Hide",
        "/Named",
        "/Thread",
    }
)

#: Annotation subtypes that carry executable or external content.
_FORBIDDEN_SUBTYPES: Final[frozenset[str]] = frozenset(
    {"/Movie", "/Screen", "/RichMedia", "/3D", "/FileAttachment", "/Sound", "/PrinterMark"}
)

#: Keys whose mere presence means the feature is there.
_FORBIDDEN_KEYS: Final[dict[str, str]] = {
    "/JS": "javascript",
    "/JavaScript": "javascript",  # the catalog's JavaScript name tree
    "/XFA": "xfa",
    "/EmbeddedFiles": "embedded_file",
    "/EF": "embedded_file",
    "/AA": "javascript",  # additional-actions dictionaries exist to run actions
    "/SigFlags": "already_signed",
    "/ByteRange": "already_signed",
    "/DocMDP": "already_signed",
}

#: How many objects the walk will visit before giving up. A hostile PDF can be a very large graph.
_MAX_NODES: Final[int] = 200_000

#: Most-specific first. The raised error reports the first of these that was found, so the code a
#: host sees is stable and does not depend on set iteration order or on alphabetical luck.
_CODE_MESSAGES: Final[dict[str, str]] = {
    "already_signed": "template is already signed",
    "xfa": "template contains an XFA form",
    "javascript": "template contains JavaScript or an action trigger",
    "forbidden_action": "template contains a forbidden action",
    "embedded_file": "template contains an embedded file",
    "embedded_stream": "template contains an embedded file stream",
    "forbidden_annotation": "template contains a multimedia or attachment annotation",
    "unreadable_object": "template contains an unreadable object",
    "too_complex": "template object graph is too large to inspect",
}


def _resolve(value: Any) -> Any:
    return value.get_object() if isinstance(value, IndirectObject) else value


def _walk(root: Any, problems: set[str]) -> None:
    """Depth-first over the object graph, recording every forbidden feature found.

    Only indirect references are de-duplicated, because only they can form a cycle: direct objects
    are a tree by construction. Shared subtrees are therefore visited more than once, which the
    node budget bounds.
    """
    seen: set[tuple[int, int]] = set()
    stack: list[Any] = [root]
    visited = 0

    while stack:
        node = stack.pop()
        visited += 1
        if visited > _MAX_NODES:
            problems.add("too_complex")
            return

        if isinstance(node, IndirectObject):
            ref = (node.idnum, node.generation)
            if ref in seen:
                continue
            seen.add(ref)
            try:
                node = node.get_object()
            except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
                problems.add("unreadable_object")
                continue

        if isinstance(node, DictionaryObject):
            for key, code in _FORBIDDEN_KEYS.items():
                if key in node:
                    problems.add(code)

            subtype = node.get("/Subtype")
            if isinstance(subtype, NameObject) and str(subtype) in _FORBIDDEN_SUBTYPES:
                problems.add("forbidden_annotation")
            if isinstance(subtype, NameObject) and str(subtype) == "/Widget":
                field_type = _resolve(node.get("/FT"))
                if isinstance(field_type, NameObject) and str(field_type) == "/Sig":
                    problems.add("already_signed")

            node_type = node.get("/Type")
            if isinstance(node_type, NameObject):
                type_name = str(node_type)
                if type_name == "/Sig":
                    problems.add("already_signed")
                elif type_name == "/EmbeddedFile":
                    problems.add("embedded_stream")
                elif type_name == "/Filespec":
                    problems.add("embedded_file")

            # An action dictionary is not required to carry /Type, so ``/S`` is checked wherever it
            # appears rather than only under ``/Type /Action``.
            action = _resolve(node.get("/S"))
            if isinstance(action, NameObject) and str(action) in _FORBIDDEN_ACTIONS:
                problems.add("javascript" if str(action) == "/JavaScript" else "forbidden_action")

            field_type = _resolve(node.get("/FT"))
            if isinstance(field_type, NameObject) and str(field_type) == "/Sig":
                problems.add("already_signed")

            stack.extend(node.values())
        elif isinstance(node, ArrayObject | list):
            stack.extend(node)


def inspect_template(pdf: bytes, settings: Settings) -> TemplatePdfInfo:
    """Implements ``DocumentService.inspect_template_pdf``."""
    if len(pdf) > settings.max_template_bytes:
        raise ValidationFailed("template exceeds the maximum size", code="template_too_large")

    reader = open_reader(pdf)
    if reader.is_encrypted:
        raise ValidationFailed("template is encrypted", code="pdf_encrypted")

    page_count = len(reader.pages)
    if page_count == 0:
        raise ValidationFailed("template has no pages", code="pdf_no_pages")
    if page_count > settings.max_template_pages:
        raise ValidationFailed("template exceeds the maximum page count", code="template_too_many_pages")

    problems: set[str] = set()
    try:
        _walk(reader.trailer, problems)
    except RecursionError:  # pragma: no cover - the walk is iterative; belt and braces
        problems.add("too_complex")

    if problems:
        ranked = [code for code in _CODE_MESSAGES if code in problems]
        primary = ranked[0] if ranked else sorted(problems)[0]
        others = ", ".join(ranked[1:])
        message = _CODE_MESSAGES.get(primary, "template contains an unsupported feature")
        if others:
            # Stable codes only -- nothing from the file itself goes into the message.
            message = f"{message} (also: {others})"
        raise ValidationFailed(message, code=f"template_{primary}")

    sizes = tuple(geo.displayed_size for geo in geometries(reader.pages))
    return TemplatePdfInfo(page_count=page_count, page_sizes=sizes, sha256=hashlib.sha256(pdf).digest())
