"""Stand-ins for the sibling modules the envelope service depends on.

These are fakes, not mocks: they do the real thing in the simplest way that is still honest.

- ``FakeBlobService`` really writes files and really re-hashes on read, so ``IntegrityFailure``
  is reachable by corrupting a file rather than by patching a method.
- ``FakeAuditLog`` really serialises per stream with ``pg_advisory_xact_lock``, really chains
  hashes and really inserts into ``audit_events``, so the concurrency test proves something.
- ``FakeIdentityService`` really writes ``consent_texts``, ``signing_sessions`` and
  ``reauth_attestations``, because the schema's foreign keys point at them.
- ``FakeDocumentService`` produces deterministic pseudo-PDF bytes and enforces the same
  preconditions the real one promises, so "the service checks it too" is a real claim.

Nothing here is imported by ``src``. If a fake and the contract disagree, the contract wins.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.audit.events import validate_event_data
from esign.clock import Clock
from esign.contracts import (
    Actor,
    AdoptedRevokeReason,
    AdoptedSignature,
    AdoptedSignatureKind,
    ArchiveCoverSummary,
    AuditEvent,
    AuthContext,
    AuthMethod,
    BlobKind,
    BlobRef,
    Capture,
    CertificateSummary,
    ChainReport,
    ConsentText,
    EventType,
    FieldDef,
    Forbidden,
    Host,
    IntegrityFailure,
    KioskContext,
    NotFound,
    PrefillFieldDef,
    ReauthEvidence,
    Rect,
    RequestContext,
    SealResult,
    SealUnavailable,
    SealValidation,
    SessionInfo,
    SignerRoleDef,
    SignerStamp,
    StreamType,
    TemplatePdfInfo,
    Unauthorized,
    ValidationFailed,
    is_opaque_id,
)
from esign.documents.definitions import MAX_LABEL_CHARS
from esign.ids import advisory_lock_key, new_id

# --------------------------------------------------------------------------- blobs


class FakeBlobService:
    """Content-addressed, write-once, on the filesystem, with a row in ``blobs``.

    The row matters: ``envelopes.presented_sha256``, ``document_revisions.sha256`` and
    ``signature_captures.image_sha256`` are all foreign keys into that table, so a fake that only
    kept bytes in a dict would let the tests pass against a schema that would reject them.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)
        self.puts: list[tuple[BlobKind, datetime | None]] = []

    def _path(self, sha256: bytes) -> Path:
        return self._root / sha256.hex()

    def put(self, db: Session, data: bytes, *, kind: BlobKind, retain_until: datetime | None = None) -> BlobRef:
        sha = hashlib.sha256(data).digest()
        path = self._path(sha)
        if not path.exists():
            path.write_bytes(data)
        db.execute(
            text(
                "INSERT INTO blobs (sha256, size_bytes, kind, storage_key, retain_until) "
                "VALUES (:sha, :size, :kind, :key, :retain) ON CONFLICT (sha256) DO NOTHING"
            ),
            {"sha": sha, "size": len(data), "kind": kind, "key": sha.hex(), "retain": retain_until},
        )
        self.puts.append((kind, retain_until))
        return BlobRef(sha256=sha, size_bytes=len(data), kind=kind)

    def get(self, db: Session, sha256: bytes) -> bytes:
        _ = db
        path = self._path(sha256)
        if not path.exists():
            raise NotFound("no such blob", code="blob_not_found")
        data = path.read_bytes()
        if hashlib.sha256(data).digest() != sha256:
            raise IntegrityFailure("stored bytes do not match their hash", code="integrity_failure")
        return data

    def exists(self, db: Session, sha256: bytes) -> bool:
        _ = db
        return self._path(sha256).exists()

    def corrupt(self, sha256: bytes) -> None:
        """Flip the stored bytes without touching the hash, as a failing disk would."""
        path = self._path(sha256)
        path.write_bytes(path.read_bytes() + b"\n% tampered")

    def retain_until_for(self, sha256: bytes, db: Session) -> datetime | None:
        row = db.execute(text("SELECT retain_until FROM blobs WHERE sha256 = :sha"), {"sha": sha256}).one()
        value: datetime | None = row.retain_until
        return None if value is None else value.astimezone(UTC)


# --------------------------------------------------------------------------- audit


def _canonical(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in sorted(value.items())}
    if isinstance(value, list | tuple):
        return [_canonical(v) for v in value]
    return value


class FakeAuditLog:
    """A simple hash chain in the real table, validating ``data`` through the audit module's
    allowlist -- the one definition both sides are held to."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def append(
        self,
        db: Session,
        *,
        stream_type: StreamType,
        stream_id: UUID,
        event_type: EventType,
        actor: Actor | None = None,
        ctx: RequestContext | None = None,
        document_sha256: bytes | None = None,
        data: dict[str, Any] | None = None,
    ) -> AuditEvent:
        actor = actor or Actor()
        ctx = ctx or RequestContext()
        # The allowlist has one definition (esign.audit.events). Validating against it here is
        # what keeps this module and the audit module from disagreeing about a key name until the
        # first real envelope: a payload the real log would refuse fails these tests too.
        data = validate_event_data(event_type, data)
        for value in (actor.user_id, actor.on_behalf_of):
            if value is not None and not is_opaque_id(value):
                raise ValidationFailed("actor identifier is not opaque", code="audit_actor_invalid")
        db.execute(
            text("SELECT pg_advisory_xact_lock(:key)"),
            {"key": advisory_lock_key(f"audit:{stream_type}", stream_id)},
        )
        head = db.execute(
            text(
                "SELECT sequence, event_hash FROM audit_events "
                "WHERE stream_type = :st AND stream_id = :sid ORDER BY sequence DESC LIMIT 1"
            ),
            {"st": stream_type, "sid": stream_id},
        ).one_or_none()
        sequence = 1 if head is None else int(head.sequence) + 1
        prev = bytes(32) if head is None else bytes(head.event_hash)
        occurred_at = self._clock.now()

        payload = {
            "id": str(new_id()),
            "stream_type": stream_type,
            "stream_id": str(stream_id),
            "sequence": sequence,
            "event_type": str(event_type),
            "actor": _canonical(
                {
                    "user_id": actor.user_id,
                    "role": actor.role,
                    "capacity": actor.capacity,
                    "on_behalf_of": actor.on_behalf_of,
                }
            ),
            "ctx": _canonical(
                {
                    "ip": ctx.ip,
                    "user_agent": ctx.user_agent,
                    "auth_method": ctx.auth_method,
                    "session_id": ctx.session_id,
                }
            ),
            "document_sha256": None if document_sha256 is None else document_sha256.hex(),
            "data": _canonical(data or {}),
            "occurred_at": _canonical(occurred_at),
            "prev_event_hash": prev.hex(),
        }
        event_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).digest()
        event_id = UUID(str(payload["id"]))

        db.execute(
            text(
                "INSERT INTO audit_events (id, stream_type, stream_id, sequence, event_type, actor_user_id, "
                "  actor_role, actor_capacity, on_behalf_of, auth_method, session_id, ip, user_agent, "
                "  document_sha256, data, occurred_at, prev_event_hash, event_hash) "
                "VALUES (:id, :st, :sid, :seq, :et, :au, :ar, :ac, :obo, :am, :sess, :ip, :ua, :doc, "
                "  CAST(:data AS jsonb), :at, :prev, :hash)"
            ),
            {
                "id": event_id,
                "st": stream_type,
                "sid": stream_id,
                "seq": sequence,
                "et": str(event_type),
                "au": actor.user_id,
                "ar": actor.role,
                "ac": actor.capacity,
                "obo": actor.on_behalf_of,
                "am": ctx.auth_method,
                "sess": ctx.session_id,
                "ip": ctx.ip,
                "ua": ctx.user_agent,
                "doc": document_sha256,
                "data": json.dumps(_canonical(data or {}), sort_keys=True),
                "at": occurred_at,
                "prev": prev,
                "hash": event_hash,
            },
        )
        return AuditEvent(
            id=event_id,
            stream_type=stream_type,
            stream_id=stream_id,
            sequence=sequence,
            event_type=event_type,
            actor=actor,
            ctx=ctx,
            document_sha256=document_sha256,
            data=dict(data or {}),
            occurred_at=occurred_at,
            prev_event_hash=prev,
            event_hash=event_hash,
        )

    def list(self, db: Session, stream_type: StreamType, stream_id: UUID) -> list[AuditEvent]:
        rows = db.execute(
            text(
                "SELECT id, sequence, event_type, actor_user_id, actor_role, actor_capacity, on_behalf_of, "
                "  auth_method, session_id, ip, user_agent, document_sha256, data, occurred_at, "
                "  prev_event_hash, event_hash FROM audit_events "
                "WHERE stream_type = :st AND stream_id = :sid ORDER BY sequence"
            ),
            {"st": stream_type, "sid": stream_id},
        ).all()
        return [
            AuditEvent(
                id=row.id if isinstance(row.id, UUID) else UUID(str(row.id)),
                stream_type=stream_type,
                stream_id=stream_id,
                sequence=int(row.sequence),
                event_type=EventType(str(row.event_type)),
                actor=Actor(
                    user_id=row.actor_user_id,
                    role=row.actor_role,
                    capacity=row.actor_capacity,
                    on_behalf_of=row.on_behalf_of,
                ),
                ctx=RequestContext(
                    ip=None if row.ip is None else str(row.ip),
                    user_agent=row.user_agent,
                    auth_method=row.auth_method,
                    session_id=row.session_id,
                ),
                document_sha256=None if row.document_sha256 is None else bytes(row.document_sha256),
                data=dict(row.data or {}),
                occurred_at=row.occurred_at.astimezone(UTC),
                prev_event_hash=bytes(row.prev_event_hash),
                event_hash=bytes(row.event_hash),
            )
            for row in rows
        ]

    def verify(self, db: Session, stream_type: StreamType, stream_id: UUID) -> ChainReport:
        events = self.list(db, stream_type, stream_id)
        problems: list[str] = []
        expected_prev = bytes(32)
        for index, event in enumerate(events, start=1):
            if event.sequence != index:
                problems.append(f"sequence gap at {event.sequence}")
            if event.prev_event_hash != expected_prev:
                problems.append(f"chain break at {event.sequence}")
            expected_prev = event.event_hash
        return ChainReport(
            ok=not problems,
            event_count=len(events),
            head_hash=events[-1].event_hash if events else None,
            problems=tuple(problems),
        )


# --------------------------------------------------------------------------- documents


#: Addendum 2. The shape of a pseudo host document, so the fake can be as picky as the real
#: service about things the envelope service is supposed to notice. A supplied document is
#:
#:     %PDF-1.7\n% supplied pages=25 widgets=clinician_signature,clinician_date problems=
#:
#: and the fake reads its own header rather than inventing an answer: the page count is what the
#: document says it is, the widgets are the AcroForm the host left in it, and ``problems=`` is how
#: a test asks for a hygiene rejection without needing a real malformed PDF (the real rejections
#: are the documents module's own tests).
_SUPPLIED_HEADER = re.compile(rb"% supplied ([^\n]*)")

#: ``<role>_signature`` and friends, and the general ``<role>__<field_id>`` with an optional type
#: suffix. The real resolver's naming rules, in the smallest form that exercises them.
_WIDGET_TYPES: dict[str, str] = {
    "signature": "signature",
    "initials": "initials",
    "date": "date_signed",
}

#: The word a generated label ends with, per field type. Kept the same as
#: ``esign.documents.supplied._TYPE_WORDS`` so a label that reaches the envelope tests through the
#: fake is spelled the way the real resolver spells it.
_LABEL_WORDS: dict[str, str] = {
    "signature": "signature",
    "initials": "initials",
    "date_signed": "date signed",
    "text": "field",
    "checkbox": "checkbox",
}


def supplied_pdf(
    *,
    pages: int = 25,
    widgets: tuple[str, ...] = ("clinician_signature", "clinician_date"),
    problems: tuple[str, ...] = (),
) -> bytes:
    """A pseudo host document in the shape ``FakeDocumentService`` understands."""
    header = f"% supplied pages={pages} widgets={','.join(widgets)} problems={','.join(problems)}"
    return b"%PDF-1.7\n" + header.encode() + b"\n% body\n"


def _claimed_by(name: str, roles: dict[str, SignerRoleDef]) -> tuple[str | None, str]:
    """Which role a widget named ``name`` belongs to, and what kind of field it becomes.

    ``<role_key>__<field_id>`` first, because a role key may itself contain an underscore and the
    double underscore is the unambiguous spelling; then ``<role_key>_<type>``. A widget no role
    claims returns ``(None, ...)`` and is dropped.
    """
    role_key, sep, rest = name.partition("__")
    if sep and role_key in roles:
        suffix = rest.rpartition("_")[2]
        return role_key, _WIDGET_TYPES.get(suffix, "text")
    for suffix, field_type in _WIDGET_TYPES.items():
        if name.endswith(f"_{suffix}") and name[: -len(suffix) - 1] in roles:
            return name[: -len(suffix) - 1], field_type
    return None, "text"


def _supplied_header(pdf: bytes) -> dict[str, str] | None:
    found = _SUPPLIED_HEADER.search(pdf)
    if found is None:
        return None
    out: dict[str, str] = {}
    for part in found.group(1).decode().split(" "):
        key, _, value = part.partition("=")
        out[key] = value
    return out


class FakeDocumentService:
    """Deterministic pseudo-PDFs.

    ``apply_signer_marks`` enforces the preconditions the real contract promises, so a test that
    passes here would also have been caught downstream -- which is the point: the service must not
    be *relying* on that, and the tests assert the service refuses first. Addendum 2's three
    methods are written the same way: the page count, the widget names and the flattening are read
    from the document rather than assumed, so a test that lies about one of them fails here too.
    """

    def __init__(self, settings: Any = None) -> None:
        self.pages = 3
        self.prepared_with: list[dict[str, str]] = []
        self.marks: list[tuple[UUID, tuple[str, ...]]] = []
        self.sanitized = 0
        self._settings = settings
        #: Addendum 2: make ``flatten_supplied`` lose a page, which the contract says it must
        #: refuse to do.
        self.flatten_drops_a_page = False
        self.flattened = 0

    def inspect_template_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        return TemplatePdfInfo(
            page_count=self.pages,
            page_sizes=tuple((612.0, 792.0) for _ in range(self.pages)),
            sha256=hashlib.sha256(pdf).digest(),
        )

    def inspect_scan_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        return self.inspect_template_pdf(pdf)

    # -- Addendum 2 --------------------------------------------------------

    def inspect_supplied_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        """The template hygiene rules under the supplied bounds, with ``supplied_`` codes."""
        header = _supplied_header(pdf)
        if header is None:
            raise ValidationFailed("the supplied document could not be read", code="supplied_unreadable")
        problems = [p for p in header.get("problems", "").split(",") if p]
        if problems:
            raise ValidationFailed("the supplied document was refused", code=f"supplied_{problems[0]}")
        pages = int(header.get("pages", "0"))
        max_bytes = getattr(self._settings, "max_supplied_document_bytes", 25 * 1024 * 1024)
        max_pages = getattr(self._settings, "max_supplied_document_pages", 200)
        if len(pdf) > max_bytes:
            raise ValidationFailed("the supplied document is too large", code="supplied_too_large")
        if pages < 1 or pages > max_pages:
            raise ValidationFailed("the supplied document has too many pages", code="supplied_too_many_pages")
        return TemplatePdfInfo(
            page_count=pages,
            page_sizes=tuple((612.0, 792.0) for _ in range(pages)),
            sha256=hashlib.sha256(pdf).digest(),
        )

    def resolve_named_fields(self, pdf: bytes, signer_roles: list[SignerRoleDef]) -> list[FieldDef]:
        """Map the document's widget names onto the declared roles, dropping the rest."""
        header = _supplied_header(pdf)
        if header is None:
            raise ValidationFailed("the supplied document could not be read", code="supplied_unreadable")
        pages = int(header.get("pages", "0"))
        widgets = [w for w in header.get("widgets", "").split(",") if w]
        by_key = {role.key: role for role in signer_roles}

        fields: list[FieldDef] = []
        for index, name in enumerate(widgets):
            role_key, field_type = _claimed_by(name, by_key)
            if role_key is None:
                continue  # an unmatched widget is dropped here and flattened away below
            fields.append(
                FieldDef(
                    id=name,
                    type=field_type,  # type: ignore[arg-type]  # from _WIDGET_TYPES
                    # The signature block is at the end of a generated report; the widget's own
                    # page is what the real resolver reads, and here that is the last one.
                    page=pages,
                    rect=Rect(x=72.0, y=120.0 + 60.0 * index, w=220.0, h=48.0),
                    signer_role=role_key,
                    # The label the signing UI shows is built from the role label the host
                    # declared in the *request body*, never from the widget's name inside the
                    # file -- `esign.documents.supplied` does exactly this, and a fake that
                    # echoed the file's names would teach the envelope tests the opposite.
                    label=f"{by_key[role_key].label} {_LABEL_WORDS[field_type]}"[:MAX_LABEL_CHARS],
                )
            )
        unresolved = sorted(
            role.key
            for role in signer_roles
            # A *signature*, not merely a mark: the real resolver is stricter here than
            # ``validate_definitions`` is, because a named-resolution role's mark is whatever a
            # generator called a widget (`esign.documents.supplied._SIGNING_TYPES`).
            if not any(f.signer_role == role.key and f.type == "signature" for f in fields)
        )
        if unresolved:
            # The roles, never the widget names: the host chose those and the message would echo them.
            raise ValidationFailed(
                f"no signature field was found for {', '.join(unresolved)}", code="fields_unresolved"
            )
        return fields

    def flatten_supplied(self, pdf: bytes) -> bytes:
        """Widgets gone, page content untouched, page count unchanged."""
        header = _supplied_header(pdf)
        if header is None:
            raise ValidationFailed("the supplied document could not be read", code="supplied_unreadable")
        pages = int(header.get("pages", "0")) - (1 if self.flatten_drops_a_page else 0)
        if pages != int(header.get("pages", "0")):
            raise ValidationFailed("flattening changed the page count", code="supplied_flatten_changed_pages")
        self.flattened += 1
        rewritten = _SUPPLIED_HEADER.sub(f"% supplied pages={pages} widgets= problems=".encode(), pdf)
        return rewritten + b"\n% flattened"

    def validate_definitions(
        self,
        info: TemplatePdfInfo,
        fields: list[FieldDef],
        prefill_fields: list[PrefillFieldDef],
        signer_roles: list[Any],
    ) -> None:
        """The clauses the envelope service leans on, in the smallest honest form.

        Not the real validator (that has its own tests): page within the document, rect inside the
        page as the document reports it, every field pointing at a declared role, every role
        carrying a signature. Those four are what ``create_from_document`` promises it runs before
        anything is written, so the fake has to be able to refuse them.
        """
        _ = prefill_fields
        declared = {role.key for role in signer_roles}
        problems: list[str] = []
        for definition in fields:
            what = f"field {definition.id!r}"
            if definition.page < 1 or definition.page > info.page_count:
                problems.append(f"{what}: page {definition.page} is outside 1..{info.page_count}")
                continue
            width, height = info.page_sizes[definition.page - 1]
            rect = definition.rect
            if rect.x < 0 or rect.y < 0 or rect.x + rect.w > width or rect.y + rect.h > height:
                problems.append(f"{what}: rect does not fit inside page {definition.page}")
            if definition.signer_role not in declared:
                problems.append(f"{what}: references undeclared signer role {definition.signer_role!r}")
        for role in signer_roles:
            if not any(f.signer_role == role.key and f.type in ("signature", "initials") for f in fields):
                problems.append(f"role {role.key!r}: has no signature or initials field")
        if problems:
            raise ValidationFailed("; ".join(sorted(problems)), code="template_definitions_invalid")

    def prepare(self, template_pdf: bytes, prefill_fields: list[PrefillFieldDef], prefill: dict[str, str]) -> bytes:
        self.prepared_with.append(dict(prefill))
        merged = "".join(f"{f.key}={prefill.get(f.key, '')};" for f in prefill_fields)
        return template_pdf + b"\n% prepared " + merged.encode()

    def sanitize_signature_png(self, data: bytes) -> bytes:
        if not data.startswith(b"\x89PNG"):
            raise ValidationFailed("not a PNG", code="validation_failed")
        if len(data) < 12:
            raise ValidationFailed("blank canvas", code="validation_failed")
        self.sanitized += 1
        return b"\x89PNG\r\n\x1a\n" + hashlib.sha256(data).digest()  # re-encoded, metadata gone

    def apply_signer_marks(
        self, pdf: bytes, fields: list[FieldDef], captures: list[Capture], stamp: SignerStamp
    ) -> bytes:
        mine = {f.id for f in fields}
        for capture in captures:
            if capture.field_id not in mine:
                raise ValidationFailed("capture targets another signer's field", code="validation_failed")
        captured = {c.field_id for c in captures}
        for f in fields:
            if f.required and f.type not in ("date_signed",) and f.id not in captured:
                raise ValidationFailed("required field has no capture", code="validation_failed")
        self.marks.append((stamp.signer_id, tuple(sorted(captured))))
        caption = f"{stamp.display_name}|{stamp.capacity}|{stamp.on_behalf_of_label}|{stamp.signed_at.isoformat()}"
        body = "".join(sorted(f"{c.field_id}:{c.kind}" for c in captures))
        dates = "".join(sorted(f.id for f in fields if f.type == "date_signed"))
        return (
            pdf + f"\n% signed {stamp.signer_id} {body} dates[{dates}]={stamp.signed_at.isoformat()} {caption}".encode()
        )

    def build_certificate(self, summary: CertificateSummary) -> bytes:
        self.last_summary = summary
        return b"%PDF-certificate " + summary.envelope_id.bytes + summary.audit_head_hash

    def build_archive_cover(self, summary: ArchiveCoverSummary) -> bytes:
        # TODO(addendum-1 A, paper archives): a deterministic pseudo cover page.
        _ = summary
        raise NotImplementedError("Addendum 1 A (paper archives): FakeDocumentService.build_archive_cover")

    def page_count(self, pdf: bytes) -> int:
        header = _supplied_header(pdf)
        base = self.pages if header is None else int(header.get("pages", "0"))
        return base + (1 if b"% certificate" in pdf else 0)

    def finalize(self, pdf: bytes, certificate_pdf: bytes) -> bytes:
        return pdf + b"\n% certificate\n" + certificate_pdf


# --------------------------------------------------------------------------- sealing


class FakeSealer:
    """A sealer you can break on purpose.

    ``fail_times`` makes the next N attempts raise ``SealUnavailable``; ``bad_validation`` makes it
    return a seal that does not validate, which is the more interesting failure.
    """

    def __init__(self, clock: Clock, *, profile: str = "PAdES-B-T") -> None:
        self._clock = clock
        self.profile = profile
        self.fail_times = 0
        self.bad_validation = False
        self.seal_calls = 0
        self.validate_calls = 0

    def seal(self, pdf: bytes, *, reason: str, envelope_id: UUID) -> SealResult:
        self.seal_calls += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise SealUnavailable("the key service is unreachable", code="kms_unavailable")
        _ = (reason, envelope_id)
        return SealResult(
            sealed_pdf=pdf + b"\n% sealed",
            profile=self.profile,  # type: ignore[arg-type]
            signer_cert_sha256=hashlib.sha256(b"seal-cert").digest(),
            timestamp_time=self._clock.now(),
        )

    def validate(self, pdf: bytes) -> SealValidation:
        self.validate_calls += 1
        intact = pdf.endswith(b"\n% sealed") and not self.bad_validation
        return SealValidation(
            intact=intact,
            covers_whole_document=intact,
            trusted=intact,
            timestamp_valid=intact,
            profile=self.profile if intact else None,  # type: ignore[arg-type]
            signer_cert_sha256=hashlib.sha256(b"seal-cert").digest() if intact else None,
            signing_time=self._clock.now() if intact else None,
            problems=() if intact else ("the signature does not cover the document",),
        )


# --------------------------------------------------------------------------- identity


@dataclass
class _SessionRecord:
    info: SessionInfo
    revoked: bool = False


#: Everything ``adopted_signatures`` holds, in the order :func:`_adopted` reads it.
_ADOPTED_COLUMNS = (
    "id, host_id, host_user_id, kind, image_sha256, typed_text, created_in_envelope_id, "
    "created_by_session_id, created_at, revoked_at, revoke_reason"
)


def _adopted(row: Any) -> AdoptedSignature:
    return AdoptedSignature(
        id=UUID(str(row.id)),
        host_id=UUID(str(row.host_id)),
        host_user_id=str(row.host_user_id),
        kind=cast(AdoptedSignatureKind, str(row.kind)),
        image_sha256=None if row.image_sha256 is None else bytes(row.image_sha256),
        typed_text=None if row.typed_text is None else str(row.typed_text),
        created_in_envelope_id=UUID(str(row.created_in_envelope_id)),
        created_by_session_id=UUID(str(row.created_by_session_id)),
        created_at=row.created_at.astimezone(UTC),
        revoked_at=None if row.revoked_at is None else row.revoked_at.astimezone(UTC),
        revoke_reason=cast(AdoptedRevokeReason | None, None if row.revoke_reason is None else str(row.revoke_reason)),
    )


class FakeIdentityService:
    """Real rows for everything the envelope schema points at by foreign key."""

    def __init__(self, settings: Any, clock: Clock) -> None:
        self._settings = settings
        self._clock = clock
        self._consents: dict[str, ConsentText] = {}
        self._sessions: dict[UUID, _SessionRecord] = {}
        self.revoked_signers: list[UUID] = []

    # -- consent -----------------------------------------------------------
    def seed_consent(
        self, db: Session, *, version: str, locale: str = "en-US", body: str = "Disclosure."
    ) -> ConsentText:
        consent = ConsentText(
            id=new_id(),
            version=version,
            locale=locale,
            body=body,
            body_sha256=hashlib.sha256(body.encode()).digest(),
        )
        db.execute(
            text(
                "INSERT INTO consent_texts (id, version, locale, body, body_sha256, effective_at) "
                "VALUES (:id, :version, :locale, :body, :sha, :at)"
            ),
            {
                "id": consent.id,
                "version": consent.version,
                "locale": consent.locale,
                "body": consent.body,
                "sha": consent.body_sha256,
                "at": self._clock.now(),
            },
        )
        self._consents[locale] = consent
        return consent

    def current_consent(self, db: Session, locale: str) -> ConsentText:
        _ = db
        consent = self._consents.get(locale)
        if consent is None:
            raise NotFound("no consent text", code="consent_not_found")
        return consent

    def get_consent(self, db: Session, consent_text_id: UUID) -> ConsentText:
        row = db.execute(
            text("SELECT id, version, locale, body, body_sha256 FROM consent_texts WHERE id = :id"),
            {"id": consent_text_id},
        ).one_or_none()
        if row is None:
            raise NotFound("no consent text", code="consent_not_found")
        return ConsentText(
            id=row.id if isinstance(row.id, UUID) else UUID(str(row.id)),
            version=str(row.version),
            locale=str(row.locale),
            body=str(row.body),
            body_sha256=bytes(row.body_sha256),
        )

    # -- hosts and sessions -------------------------------------------------
    def authenticate_host(self, db: Session, bearer: str) -> Host:
        _ = (db, bearer)
        raise Unauthorized("not implemented in tests", code="unauthorized")

    def create_session(
        self,
        db: Session,
        *,
        signer_id: UUID,
        auth: AuthContext,
        kiosk: KioskContext | None,
        ctx: RequestContext,
    ) -> tuple[str, SessionInfo]:
        signer_row = db.execute(
            text(
                "SELECT s.envelope_id AS envelope_id, s.host_user_id AS host_user_id, e.host_id AS host_id "
                "FROM signers s JOIN envelopes e ON e.id = s.envelope_id WHERE s.id = :id"
            ),
            {"id": signer_id},
        ).one()
        envelope_id = signer_row.envelope_id
        session_id = new_id()
        expires_at = self._clock.now() + timedelta(seconds=self._settings.session_ttl_seconds)
        self.revoke_sessions(db, signer_id)
        db.execute(
            text(
                "INSERT INTO signing_sessions (id, signer_id, token_hash, auth_method, auth_time, "
                "  kiosk_staff_user_id, kiosk_identity_check, ip, user_agent, created_at, expires_at) "
                "VALUES (:id, :signer, :token, :method, :auth_time, :staff, :check, :ip, :ua, :now, :expires)"
            ),
            {
                "id": session_id,
                "signer": signer_id,
                "token": hashlib.sha256(f"est_{session_id}".encode()).digest(),
                "method": auth.method,
                "auth_time": auth.auth_time,
                "staff": kiosk.staff_user_id if kiosk else None,
                "check": kiosk.identity_check if kiosk else None,
                "ip": ctx.ip,
                "ua": ctx.user_agent,
                "now": self._clock.now(),
                "expires": expires_at,
            },
        )
        host_id = signer_row.host_id
        info = SessionInfo(
            id=session_id,
            signer_id=signer_id,
            envelope_id=envelope_id if isinstance(envelope_id, UUID) else UUID(str(envelope_id)),
            auth=auth,
            kiosk=kiosk,
            expires_at=expires_at,
            host_id=host_id if isinstance(host_id, UUID) else UUID(str(host_id)),
            host_user_id=str(signer_row.host_user_id),
        )
        self._sessions[session_id] = _SessionRecord(info=info)
        return f"est_{session_id}", info

    def authenticate_session(self, db: Session, bearer: str) -> SessionInfo:
        session_id = UUID(bearer.removeprefix("est_"))
        record = self._sessions.get(session_id)
        row = db.execute(
            text("SELECT revoked_at, expires_at FROM signing_sessions WHERE id = :id"), {"id": session_id}
        ).one_or_none()
        if record is None or row is None or row.revoked_at is not None or row.expires_at <= self._clock.now():
            raise Unauthorized("unknown, expired or revoked", code="unauthorized")
        return record.info

    def revoke_sessions(self, db: Session, signer_id: UUID, *, except_session_id: UUID | None = None) -> int:
        self.revoked_signers.append(signer_id)
        result = db.execute(
            text(
                "UPDATE signing_sessions SET revoked_at = :at WHERE signer_id = :id AND revoked_at IS NULL "
                "AND (CAST(:keep AS uuid) IS NULL OR id <> CAST(:keep AS uuid))"
            ),
            {"id": signer_id, "at": self._clock.now(), "keep": except_session_id},
        )
        return int(getattr(result, "rowcount", 0) or 0)

    # -- re-authentication --------------------------------------------------
    def attest_reauth(self, db: Session, *, host: Host, session_id: UUID, auth: AuthContext) -> SessionInfo:
        _ = host
        info = next(record.info for record in self._sessions.values() if record.info.id == session_id)
        # Whose attestation this is, as ``0700`` records it: from the session, never the request.
        db.execute(
            text(
                "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at, host_id, host_user_id) "
                "VALUES (:id, :session, :method, :auth_time, :at, :host_id, :host_user_id)"
            ),
            {
                "id": new_id(),
                "session": session_id,
                "method": auth.method,
                "auth_time": auth.auth_time,
                "at": self._clock.now(),
                "host_id": info.host_id,
                "host_user_id": info.host_user_id,
            },
        )
        return info

    def fresh_reauth(self, db: Session, session_id: UUID) -> ReauthEvidence | None:
        """This session's own attestation first; with the span on, the same user's most recent one
        on another of their sessions (``scope="span"``), within both windows -- the same
        resolution order as the real service, so the envelope tests can exercise a queue."""
        now = self._clock.now()
        own = self._fake_attestation(db, session_id, now=now, span=False)
        if own is not None or self._settings.reauth_span_seconds <= 0:
            return own
        return self._fake_attestation(db, session_id, now=now, span=True)

    def _fake_attestation(self, db: Session, session_id: UUID, *, now: datetime, span: bool) -> ReauthEvidence | None:
        asking = next(record.info for record in self._sessions.values() if record.info.id == session_id)
        if span:
            sql = (
                "SELECT id, method, auth_time FROM reauth_attestations "
                "WHERE host_id = :host_id AND host_user_id = :host_user_id AND session_id <> :id "
                "ORDER BY auth_time DESC LIMIT 1"
            )
        else:
            sql = "SELECT id, method, auth_time FROM reauth_attestations WHERE session_id = :id ORDER BY auth_time DESC LIMIT 1"
        row = db.execute(
            text(sql), {"id": session_id, "host_id": asking.host_id, "host_user_id": asking.host_user_id}
        ).one_or_none()
        if row is None:
            return None
        auth_time = row.auth_time.astimezone(UTC)
        age = (now - auth_time).total_seconds()
        window = self._settings.reauth_max_age_seconds
        if span:
            window = min(window, self._settings.reauth_span_seconds)
        if age < 0 or age > window:
            return None
        return ReauthEvidence(
            attestation_id=row.id if isinstance(row.id, UUID) else UUID(str(row.id)),
            method=cast(AuthMethod, str(row.method)),
            auth_time=auth_time,
            scope="span" if span else "session",
        )

    # -- adopted signatures (Addendum 1 B) ----------------------------------
    #: Real rows, like the sessions: ``signature_captures.adopted_signature_id`` is a foreign key
    #: into ``adopted_signatures``, so a fake that kept these in a dict would let the envelope
    #: tests pass against a schema that would reject what they wrote.
    def get_adopted_signature(self, db: Session, *, host_id: UUID, host_user_id: str) -> AdoptedSignature | None:
        row = db.execute(
            text(
                f"SELECT {_ADOPTED_COLUMNS} FROM adopted_signatures "  # a fixed column list
                "WHERE host_id = :host AND host_user_id = :user AND revoked_at IS NULL"
            ),
            {"host": host_id, "user": host_user_id},
        ).one_or_none()
        return None if row is None else _adopted(row)

    def adopt_signature(
        self,
        db: Session,
        session_id: UUID,
        *,
        kind: AdoptedSignatureKind,
        image_sha256: bytes | None = None,
        typed_text: str | None = None,
    ) -> AdoptedSignature:
        info = next(record.info for record in self._sessions.values() if record.info.id == session_id)
        if info.kiosk is not None:
            raise Forbidden("a shared tablet does not keep a signature", code="adoption_not_allowed")
        self.revoke_adopted_signature(db, host_id=info.host_id, host_user_id=info.host_user_id, reason="replaced")
        adopted_id = new_id()
        now = self._clock.now()
        db.execute(
            text(
                "INSERT INTO adopted_signatures (id, host_id, host_user_id, kind, image_sha256, typed_text, "
                "  created_in_envelope_id, created_by_session_id, created_at) "
                "VALUES (:id, :host, :user, :kind, :image, :typed, :envelope, :session, :now)"
            ),
            {
                "id": adopted_id,
                "host": info.host_id,
                "user": info.host_user_id,
                "kind": kind,
                "image": image_sha256,
                "typed": typed_text,
                "envelope": info.envelope_id,
                "session": session_id,
                "now": now,
            },
        )
        return AdoptedSignature(
            id=adopted_id,
            host_id=info.host_id,
            host_user_id=info.host_user_id,
            kind=kind,
            image_sha256=image_sha256,
            typed_text=typed_text,
            created_in_envelope_id=info.envelope_id,
            created_by_session_id=session_id,
            created_at=now,
        )

    def revoke_adopted_signature(
        self, db: Session, *, host_id: UUID, host_user_id: str, reason: AdoptedRevokeReason
    ) -> AdoptedSignature | None:
        row = db.execute(
            text(
                "UPDATE adopted_signatures SET revoked_at = :now, revoke_reason = :reason "
                "WHERE host_id = :host AND host_user_id = :user AND revoked_at IS NULL "
                f"RETURNING {_ADOPTED_COLUMNS}"  # a fixed column list
            ),
            {"now": self._clock.now(), "reason": reason, "host": host_id, "user": host_user_id},
        ).one_or_none()
        return None if row is None else _adopted(row)


# --------------------------------------------------------------------------- log capture


class LogCapture:
    """Everything the structured logger rendered during a test, as parsed JSON.

    A plain class, not a dataclass: structlog and pytest both put a sink in a ``weakref``, which
    needs it to stay hashable.
    """

    def __init__(self) -> None:
        self.lines: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def write(self, value: str) -> int:
        stripped = value.strip()
        if stripped:
            with self._lock:
                try:
                    self.lines.append(json.loads(stripped))
                except json.JSONDecodeError:
                    self.lines.append({"raw": stripped})
        return len(value)

    def flush(self) -> None:
        return None

    def text(self) -> str:
        with self._lock:
            return json.dumps(self.lines)


def forbidden_strings(*values: str | None) -> tuple[str, ...]:
    return tuple(v for v in values if v)
