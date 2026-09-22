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
#:
#: ``/SigFlags`` says the form *has* signature fields, not that any of them was signed, so it is a
#: ``signature_field`` and not an ``already_signed``: a report generator that placed a slot with
#: ``/FT /Sig`` sets it, and telling that integrator their freshly generated file is "already
#: signed" sends them looking for a signature that was never there. ``/ByteRange`` and ``/DocMDP``
#: belong to a signature that exists.
_FORBIDDEN_KEYS: Final[dict[str, str]] = {
    "/JS": "javascript",
    "/JavaScript": "javascript",  # the catalog's JavaScript name tree
    "/XFA": "xfa",
    "/EmbeddedFiles": "embedded_file",
    "/EF": "embedded_file",
    "/AA": "javascript",  # additional-actions dictionaries exist to run actions
    "/SigFlags": "signature_field",
    "/ByteRange": "already_signed",
    "/DocMDP": "already_signed",
}

#: Annotation subtypes that carry no ink of their own, so removing one changes nothing a reader
#: sees. The same exemption ``pdfutil._flatten_page_annotations`` makes, for the same reason.
_INKLESS_SUBTYPES: Final[frozenset[str]] = frozenset({"/Widget", "/Link", "/Popup"})

#: ``/F`` bits 2 and 6 (PDF 12.5.3): Hidden and NoView. Neither is drawn by any reader.
_ANNOT_HIDDEN: Final[int] = 1 << 1
_ANNOT_NOVIEW: Final[int] = 1 << 5

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
    # Below the active-content codes deliberately: these two are about what the document *is*
    # rather than about what it would do, so a file with both a script and a signature field is
    # reported as the script.
    "signature_field": "document contains an AcroForm signature field; use a text widget named <role_key>_signature",
    "annotation_not_removable": "document contains a visible annotation; bake the mark into the page content",
    "unreadable_object": "template contains an unreadable object",
    "content_unreadable": "template has a page whose content stream cannot be decoded",
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

            # A signature *field*, whether it is the widget or the field above it. An empty
            # placeholder is refused as such; one that holds a value is a signature.
            field_type = _resolve(node.get("/FT"))
            if isinstance(field_type, NameObject) and str(field_type) == "/Sig":
                problems.add("already_signed" if _resolve(node.get("/V")) is not None else "signature_field")

            stack.extend(node.values())
        elif isinstance(node, ArrayObject | list):
            stack.extend(node)


def _has_inked_annotation(reader: Any) -> bool:
    """Whether any page carries a visible annotation that is not a widget.

    A ``/FreeText``, ``/Stamp``, ``/Square``, ``/Ink`` or ``/Highlight`` with an appearance stream
    is ink a reader draws: an "AMENDED -- see addendum" note, a redaction box, a PROVISIONAL stamp.
    ``flatten_supplied`` removes every annotation without rendering anything, by design and by the
    addendum's own words, so a document like that would be accepted, silently stripped of that
    mark, and the result stored as the bytes the clinician read and attested to. The template path
    refuses the mirror-image loss in ``_flatten_page_annotations``; this refuses this one, at
    intake, where the host can still fix the file.

    Read from the pages rather than the object graph: an annotation the page tree does not
    reference is not drawn, and this check is about what a reader would see.
    """
    for page in reader.pages:
        annots = _resolve(page.get("/Annots"))
        if not isinstance(annots, ArrayObject | list):
            continue
        for ref in list(annots):
            annot = _resolve(ref)
            if not isinstance(annot, DictionaryObject):
                continue
            subtype = annot.get("/Subtype")
            if isinstance(subtype, NameObject) and str(subtype) in _INKLESS_SUBTYPES:
                continue
            if _resolve(annot.get("/AP")) is None:
                continue  # nothing to draw, so nothing is lost by dropping it
            flags = _resolve(annot.get("/F"))
            flag_value = int(flags) if isinstance(flags, int) else 0
            if flag_value & (_ANNOT_HIDDEN | _ANNOT_NOVIEW):
                continue  # no reader draws it, so removing it takes nothing away
            return True
    return False


def _content_streams_decode(reader: Any) -> bool:
    """Whether every page's content stream can actually be decoded.

    pypdf caps zlib output, so a stream that inflates past the cap raises ``LimitReachedError``
    here rather than returning something huge -- which is what makes this a cheap check and not a
    decompression bomb of its own.
    """
    try:
        for page in reader.pages:
            contents = page.get_contents()
            if contents is not None:
                contents.get_data()
    except Exception:
        # Any failure to decode is the same answer to the host: this template cannot be drawn on.
        return False
    return True


def inspect_template(pdf: bytes, settings: Settings, *, reject_inked_annotations: bool = False) -> TemplatePdfInfo:
    """Implements ``DocumentService.inspect_template_pdf``.

    ``reject_inked_annotations`` is the one rule that differs between the callers rather than
    only the bounds. A template's annotations are burned into the page before anything is stored
    (``prepare``), so their ink survives; a supplied document's are removed without being drawn
    (``flatten_supplied``, as the addendum specifies), so ink that is not a widget has to be
    refused here instead. See :func:`_has_inked_annotation`.
    """
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
    if not _content_streams_decode(reader):
        # The walk never decodes a content stream, so a page whose compressed content inflates past
        # pypdf's output cap used to publish happily and then fail at ``POST /v1/envelopes``, where
        # stamping is the first thing that decodes it. Refuse the template at upload instead: it is
        # the host's file and the host can fix it.
        problems.add("content_unreadable")
    if reject_inked_annotations and _has_inked_annotation(reader):
        problems.add("annotation_not_removable")

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
