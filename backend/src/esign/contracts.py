"""Shared contracts between modules.

This file is the seam that lets modules be built in parallel. Every module implements or
consumes these types and nothing else from a sibling module. Do not change a signature here
without updating docs/SPEC.md; module agents must not edit this file at all -- if a contract
is wrong or missing something, say so in your report.

Addendum 1 (docs/SPEC-ADDENDUM-1.md) added paper archives, adopted signatures and the
re-authentication span. Its types and methods are marked ``Addendum 1`` below; migration
``0700_addendum_1.sql`` is their schema.

Conventions:
- All hashes are raw 32-byte SHA-256 digests (``bytes``), hex only at API and log boundaries.
- All datetimes are timezone-aware UTC. Time comes from ``Clock``, never from ``datetime.now``.
- ``db`` is a ``sqlalchemy.orm.Session`` inside a transaction owned by the caller. Contract
  functions never commit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from typing import Any, Final, Literal, Protocol
from uuid import UUID

from sqlalchemy.orm import Session

# --------------------------------------------------------------------------- primitives


class Clock(Protocol):
    def now(self) -> datetime: ...


class EsignError(Exception):
    """Base for expected failures. ``code`` is a stable machine string safe to log and return."""

    code: str = "error"
    http_status: int = 400

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message or self.code)
        if code:
            self.code = code


class NotFound(EsignError):
    code = "not_found"
    http_status = 404


class Unauthorized(EsignError):
    code = "unauthorized"
    http_status = 401


class Forbidden(EsignError):
    code = "forbidden"
    http_status = 403


class Conflict(EsignError):
    """The request is valid but not in the current state (wrong status, out of order, replay)."""

    code = "conflict"
    http_status = 409


class ValidationFailed(EsignError):
    code = "validation_failed"
    http_status = 422


class RateLimited(EsignError):
    """``retry_after_seconds`` is set by the limiter when it knows; the API sends it as Retry-After."""

    code = "rate_limited"
    http_status = 429

    def __init__(self, message: str = "", *, code: str | None = None, retry_after_seconds: int | None = None) -> None:
        super().__init__(message, code=code)
        self.retry_after_seconds = retry_after_seconds


class IntegrityFailure(EsignError):
    """Stored evidence does not match its recorded hash. Never swallow this."""

    code = "integrity_failure"
    http_status = 500


class SealUnavailable(EsignError):
    """KMS, timestamp authority or revocation source unreachable. Retryable: the envelope stays
    ``completed_pending_seal`` and the seal job backs off. Never fall back to an unsealed result."""

    code = "seal_unavailable"
    http_status = 503


class StorageUnavailable(EsignError):
    """Blob store unreachable, or refusing for a reason that is not about this content.
    Retryable, exactly like ``SealUnavailable``: nothing may report the document as stored."""

    code = "storage_unavailable"
    http_status = 503


# An identifier the host chose (signer ``host_user_id``, kiosk staff id, ``patient_ref``). It reaches
# the audit trail as ``actor_user_id`` / ``on_behalf_of``, so it must be opaque: no whitespace (not a
# name) and not shaped like a date of birth or a social security number. Checked where the value
# enters the system (envelope creation, session creation) *and* again by the audit log.
OPAQUE_ID_PATTERN: Final[str] = r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$"
_OPAQUE_ID_RE: Final = re.compile(OPAQUE_ID_PATTERN)
_PII_SHAPES: Final = (
    re.compile(r"^\d{4}-\d{1,2}-\d{1,2}$"),  # a date: 1970-01-01
    re.compile(r"^\d{1,2}-\d{1,2}-\d{4}$"),  # a date the other way round
    re.compile(r"^\d{3}-\d{2}-\d{4}$"),  # a US social security number
)


def is_opaque_id(value: str) -> bool:
    """True when ``value`` looks like an identifier and not like a fact about a person."""
    return bool(_OPAQUE_ID_RE.match(value)) and not any(shape.match(value) for shape in _PII_SHAPES)


# --------------------------------------------------------------------------- template definitions

FieldType = Literal["signature", "initials", "date_signed", "text", "checkbox"]
Capacity = Literal["self", "guardian", "proxy", "witness", "interpreter", "clinician"]


@dataclass(frozen=True)
class Rect:
    """PDF user-space points, origin bottom-left of the page as displayed (after /Rotate)."""

    x: float
    y: float
    w: float
    h: float


@dataclass(frozen=True)
class FieldDef:
    id: str  # stable within a template version, [a-z0-9_]+
    type: FieldType
    page: int  # 1-based
    rect: Rect
    signer_role: str
    required: bool = True
    label: str = ""  # accessible name shown in the UI; must not contain PHI


@dataclass(frozen=True)
class PrefillFieldDef:
    key: str  # key in the prefill dict supplied at envelope creation
    page: int
    rect: Rect
    font_size: float = 10.0
    required: bool = True
    multiline: bool = False


@dataclass(frozen=True)
class SignerRoleDef:
    key: str  # e.g. "patient", "guardian", "witness", "clinician"
    label: str
    allowed_capacities: tuple[Capacity, ...]
    requires_reauth: bool  # True for clinician attestations
    order_index: int  # used when signing_order == "sequential"
    required: bool = True  # False: an envelope may omit this role (optional witness, interpreter)


@dataclass(frozen=True)
class TemplatePdfInfo:
    page_count: int
    page_sizes: tuple[tuple[float, float], ...]  # (width, height) in points, as displayed
    sha256: bytes


# --------------------------------------------------------------------------- documents (esign.documents)

#: ``adopted`` (Addendum 1 B) applies a signature the signer saved in an earlier session. The
#: client sends the saved signature's id and nothing else; the envelope service resolves the stored
#: image or text and records the capture as ``adopted`` with that id, so the trail says which saved
#: signature was applied rather than a ``drawn``/``typed`` the client could have chosen.
CaptureKind = Literal["drawn", "typed", "click", "adopted"]
SealProfile = Literal["PAdES-B-T", "PAdES-B-LT", "PAdES-B-LTA"]

#: Addendum 1 A. ``electronic`` is everything the base spec describes; ``paper_archive`` is a scan
#: of a document signed in ink, filed by the host with an attestation and sealed like any other.
EnvelopeKind = Literal["electronic", "paper_archive"]

#: Addendum 1 C. ``session``: the attestation was made for the session the signature happened in.
#: ``span``: it was borrowed from another session of the same user on the same host, within
#: ``REAUTH_SPAN_SECONDS`` of its ``auth_time``.
ReauthScope = Literal["session", "span"]


@dataclass(frozen=True)
class Capture:
    """One signer input for one field. Two shapes share the type, and they never mix:

    - a *signature* capture (signature and initials fields) has a ``kind`` and, depending on it,
      an ``image_png`` or a ``typed_text``; ``checked`` and ``text_value`` are ``None``.
    - a *value* capture (checkbox and text fields) has ``checked`` or ``text_value`` and no
      ``kind``, ``image_png`` or ``typed_text``.

    The trail records a signature's ``kind`` and a value field's type, so a ``kind`` on a checkbox
    would let the client choose what the audit trail says. The constructor refuses the mixture, so
    the mistake cannot be written; whether a given field takes a given shape is the envelope
    service's decision, made against the template.

    Addendum 1 B: an ``adopted`` capture carries ``adopted_signature_id`` and, on the wire, nothing
    else. The envelope service checks the saved signature belongs to this signer's
    ``(host_id, host_user_id)``, is not revoked, and is not being used from a kiosk session, then
    fills ``image_png`` or ``typed_text`` from the stored row before stamping. A client-supplied
    payload next to ``adopted_signature_id`` is refused at the API edge; here only the pairing is
    enforced, because the constructor cannot tell who filled the payload.
    """

    field_id: str
    kind: CaptureKind | None = None  # signature and initials fields only; None for checkbox/text
    image_png: bytes | None = None  # sanitized PNG, drawn or adopted(drawn)
    typed_text: str | None = None  # typed or adopted(typed)
    checked: bool | None = None  # checkbox fields
    text_value: str | None = None  # text fields
    adopted_signature_id: UUID | None = None  # adopted only, and required for it

    def __post_init__(self) -> None:
        has_signature_payload = self.kind is not None or self.image_png is not None or self.typed_text is not None
        has_value = self.checked is not None or self.text_value is not None
        if has_signature_payload and has_value:
            raise ValueError("a capture is either a signature (kind) or a value (checked/text_value), never both")
        if self.kind is None and (self.image_png is not None or self.typed_text is not None):
            raise ValueError("a signature payload needs a kind")
        if self.checked is not None and self.text_value is not None:
            raise ValueError("a capture carries a checked value or a text value, not both")
        if (self.kind == "adopted") != (self.adopted_signature_id is not None):
            raise ValueError("an adopted capture names the saved signature, and only an adopted capture does")

    @property
    def is_signature(self) -> bool:
        return self.kind is not None


@dataclass(frozen=True)
class SignerStamp:
    """Caption printed under each signature: who, in what capacity, when, and the signer id."""

    signer_id: UUID
    display_name: str
    capacity: Capacity
    on_behalf_of_label: str | None
    signed_at: datetime


@dataclass(frozen=True)
class CertificateSigner:
    signer_id: UUID
    display_name: str
    role_label: str
    capacity: Capacity
    auth_method: str
    reauth_method: str | None
    consent_version: str
    viewed_at: datetime
    consented_at: datetime
    signed_at: datetime
    ip: str | None
    user_agent: str | None
    kiosk_staff_user_id: str | None = None
    kiosk_identity_check: str | None = None
    # Addendum 1 C. Both come from ``signer.signed`` (``reauth_scope``, and ``reauth_at`` is the
    # attestation's ``auth_time``); ``None`` for a role that does not re-authenticate. The
    # certificate prints "re-authenticated at <reauth_at> for this document" for ``session`` and
    # "... in an earlier session, N seconds before signing" for ``span``.
    reauth_scope: ReauthScope | None = None
    reauth_at: datetime | None = None
    # Addendum 1 B. Set when the signer applied a saved signature: ``signer.signed`` carries the
    # id, ``adopted_at`` is that row's ``created_at``, so the certificate can say "signed with a
    # saved signature adopted on <date>".
    adopted_signature_id: UUID | None = None
    adopted_at: datetime | None = None


#: Addendum 1 A. What the attesting staff member says about the scan. ``true_copy`` is the only
#: statement there is: "this scan is a complete and accurate copy of the paper document".
AttestationStatement = Literal["true_copy"]
OriginalDisposition = Literal["retained", "returned_to_signer", "destroyed_per_policy"]


@dataclass(frozen=True)
class PaperSigner:
    """Who signed the paper, as the host states it. Printed on the cover page and the certificate;
    stored in ``envelopes.attestation``; never in audit data (``archive.attested`` records the
    count only)."""

    display_name: str
    capacity: Capacity


@dataclass(frozen=True)
class Attestation:
    """Addendum 1 A: the host's attestation for a paper archive. The staff member is identified
    by an opaque ``staff_user_id`` (``is_opaque_id``), which is what reaches the audit trail; the
    display name is for the cover page and certificate only."""

    staff_user_id: str
    staff_display_name: str
    statement: AttestationStatement
    original_disposition: OriginalDisposition
    paper_signers: tuple[PaperSigner, ...]


@dataclass(frozen=True)
class CertificateSummary:
    """Input for the certificate of completion. Deliberately minimal: no patient identifiers
    beyond signer display names, no chart data.

    Addendum 1 A: for a ``paper_archive`` there is no template (``template_key`` and
    ``template_version`` are ``None``), ``signers`` is empty and ``attestation`` is set; the
    certificate prints the attestation in place of the signer table, ``created_at`` is when the
    scan was filed and ``completed_at`` is when it was attested (``envelopes.attested_at``).
    ``presented_sha256`` and ``final_revision_sha256`` are both the scan's hash. Everything an
    archive certificate says beyond this (paper signing date, disposition) is on the cover page,
    which is inside the same sealed bytes."""

    envelope_id: UUID
    document_type: str
    template_key: str | None
    template_version: int | None
    seal_profile: SealProfile  # the *configured* profile; the one achieved is in document.sealed
    presented_sha256: bytes
    final_revision_sha256: bytes  # last signer-applied revision, before the certificate is appended
    created_at: datetime
    completed_at: datetime
    signers: tuple[CertificateSigner, ...]
    audit_event_count: int
    audit_head_hash: bytes  # event_hash of the last event included
    kind: EnvelopeKind = "electronic"
    attestation: Attestation | None = None  # paper_archive only, and required for it


@dataclass(frozen=True)
class ArchiveCoverSummary:
    """Addendum 1 A: input for the cover page that precedes a scan inside the sealed bytes."""

    envelope_id: UUID
    document_type: str
    paper_signed_on: date
    attestation: Attestation
    attested_at: datetime
    scan_sha256: bytes
    scan_page_count: int


class DocumentService(Protocol):
    def inspect_template_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        """Reject (ValidationFailed) PDFs that are encrypted, already signed, contain JavaScript,
        XFA, embedded files or launch actions, or exceed configured size/page limits."""

    def inspect_scan_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        """Addendum 1 A: exactly the rules of ``inspect_template_pdf`` -- no encryption, scripts,
        XFA, embedded files or existing signatures -- under ``MAX_SCAN_BYTES`` / ``MAX_SCAN_PAGES``
        instead of the template bounds. Image-only pages are expected and fine. The error codes
        say ``scan`` where the template ones say ``template`` (``scan_too_large``,
        ``scan_too_many_pages``, ``scan_encrypted``, ...), so a host reading them knows they are
        about the file it just sent."""

    def validate_definitions(
        self,
        info: TemplatePdfInfo,
        fields: list[FieldDef],
        prefill_fields: list[PrefillFieldDef],
        signer_roles: list[SignerRoleDef],
    ) -> None:
        """Rects inside their page, ids unique, every role has at least one signature field, every
        field references a declared role. Raises ValidationFailed listing every problem."""

    def prepare(self, template_pdf: bytes, prefill_fields: list[PrefillFieldDef], prefill: dict[str, str]) -> bytes:
        """Merge chart data into the template and flatten. Output has no form fields."""

    def sanitize_signature_png(self, data: bytes) -> bytes:
        """Decode, bound dimensions and size, strip metadata, re-encode. Raises ValidationFailed
        for anything that is not a plausible signature image (including a blank canvas)."""

    def apply_signer_marks(
        self, pdf: bytes, fields: list[FieldDef], captures: list[Capture], stamp: SignerStamp
    ) -> bytes:
        """Stamp this signer's captures and caption onto the current revision. ``fields`` is the
        subset for this signer. Raises ValidationFailed if a required field has no capture or a
        capture targets a field that is not this signer's."""

    def build_certificate(self, summary: CertificateSummary) -> bytes:
        """The certificate of completion (SPEC section 6). For ``summary.kind == "paper_archive"``
        the archive variant: no signer table, the attestation (staff member, statement,
        disposition, the paper signers by name and capacity) in its place, and the sentence that
        the seal proves the scan is unchanged since filing, not that the ink is genuine."""

    def build_archive_cover(self, summary: ArchiveCoverSummary) -> bytes:
        """Addendum 1 A: exactly one page, to be placed *before* the scan. It states, in plain
        words: "Scanned copy of a document signed on paper", the document type, the paper signing
        date, who attested and when (``attestation.staff_display_name``, ``attested_at``), the
        disposition of the original, the paper signers, the scan's SHA-256 as lowercase hex, the
        envelope id, and that the seal proves the scan has not changed since it was filed and who
        filed it -- not that the ink signature is genuine. Embedded fonts, no form fields, no
        scripts, like every other page this service produces. The envelope service composes the
        archive with ``finalize``: ``finalize(cover, scan)`` puts the cover first, and
        ``finalize(that, certificate)`` produces the bytes to be sealed."""

    def page_count(self, pdf: bytes) -> int:
        """Pages in a PDF this service produced. Raises ValidationFailed if it cannot be read."""

    def finalize(self, pdf: bytes, certificate_pdf: bytes) -> bytes:
        """Append the certificate pages and return the exact bytes to be sealed. The second
        argument is any PDF this service accepted (``build_archive_cover`` says how an archive
        is composed from the cover, the scan and the certificate with two calls)."""


# --------------------------------------------------------------------------- sealing (esign.sealing)

@dataclass(frozen=True)
class SealResult:
    sealed_pdf: bytes
    profile: SealProfile
    signer_cert_sha256: bytes
    timestamp_time: datetime


@dataclass(frozen=True)
class SealValidation:
    intact: bool  # the signed byte ranges hash correctly
    covers_whole_document: bool  # nothing was appended after the seal
    trusted: bool  # chain validates to a configured trust root
    timestamp_valid: bool
    profile: SealProfile | None
    signer_cert_sha256: bytes | None
    signing_time: datetime | None
    problems: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        # Fail closed: any reported problem denies the seal, whatever the four flags say.
        return (
            self.intact
            and self.covers_whole_document
            and self.trusted
            and self.timestamp_valid
            and not self.problems
        )


class Sealer(Protocol):
    def seal(self, pdf: bytes, *, reason: str, envelope_id: UUID) -> SealResult:
        """Apply the organisation seal as a certification signature that permits no further
        changes. The envelope id is recorded inside the signature dictionary (``/Location``) so
        the seal is bound to the envelope it completes. Raises ValidationFailed for malformed
        input and SealUnavailable for retryable infrastructure failures; IntegrityFailure
        propagates unchanged."""

    def validate(self, pdf: bytes) -> SealValidation:
        """Never raises for a bad document: a tampered or unsigned PDF returns a failing result."""


# --------------------------------------------------------------------------- storage (esign.storage)

#: ``scan_pdf`` (Addendum 1 A) is the host's scan of a paper-signed document, as received and
#: after ``inspect_template_pdf``'s hygiene check; it is a paper archive's revision 1 (kind ``scan``).
BlobKind = Literal[
    "template_pdf", "presented_pdf", "revision_pdf", "final_unsealed_pdf", "sealed_pdf", "signature_image",
    "scan_pdf",
]


@dataclass(frozen=True)
class BlobRef:
    sha256: bytes
    size_bytes: int
    kind: BlobKind


class BlobService(Protocol):
    def put(self, db: Session, data: bytes, *, kind: BlobKind, retain_until: datetime | None = None) -> BlobRef:
        """Write-once and idempotent by content hash. The backend must refuse to overwrite.
        The caller computes ``retain_until`` (``Settings.retain_until(document_type, now)``); when
        omitted the configured default retention applies. Raises StorageUnavailable when the
        backend cannot be reached."""

    def get(self, db: Session, sha256: bytes) -> bytes:
        """Re-hashes on read; raises IntegrityFailure on mismatch, NotFound if absent."""

    def exists(self, db: Session, sha256: bytes) -> bool: ...


# --------------------------------------------------------------------------- audit (esign.audit)

StreamType = Literal["envelope", "template", "system"]


class EventType(StrEnum):
    TEMPLATE_PUBLISHED = "template.published"
    TEMPLATE_RETIRED = "template.retired"
    ENVELOPE_CREATED = "envelope.created"
    DOCUMENT_PREPARED = "document.prepared"
    SESSION_CREATED = "session.created"
    SESSION_REJECTED = "session.rejected"
    DOCUMENT_PRESENTED = "document.presented"
    DOCUMENT_VIEWED = "document.viewed"
    CONSENT_ACCEPTED = "consent.accepted"
    REAUTH_ATTESTED = "auth.reauthenticated"
    SIGNER_SIGNED = "signer.signed"
    SIGNER_DECLINED = "signer.declined"
    ENVELOPE_DECLINED = "envelope.declined"
    ENVELOPE_COMPLETED = "envelope.completed"
    DOCUMENT_FINALIZED = "document.finalized"
    SEAL_FAILED = "seal.failed"
    DOCUMENT_SEALED = "document.sealed"
    DOCUMENT_STORED = "document.stored"
    DOCUMENT_DOWNLOADED = "document.downloaded"
    ENVELOPE_VOIDED = "envelope.voided"
    ENVELOPE_EXPIRED = "envelope.expired"
    ENVELOPE_SUPERSEDED = "envelope.superseded"
    VERIFICATION_PERFORMED = "verification.performed"
    # Addendum 1 A: the scan was filed (data: document_type, page_count, scan hash) and attested
    # (data: staff_user_id, statement, original_disposition, paper_signer_count, and
    # attested_detail_sha256 -- one digest over the attesting name, the ordered paper signers and
    # paper_signed_on, so those facts are bound by the chain without ever being in it; never a
    # name). Then the existing document.finalized / document.sealed / document.stored follow.
    ARCHIVE_CREATED = "archive.created"
    ARCHIVE_ATTESTED = "archive.attested"
    # Addendum 1 B: on the envelope stream of the session the signature was saved in (data:
    # adopted_signature_id, kind, the image or typed-text digest), and on the system stream when
    # one is revoked (data: adopted_signature_id, host_id, host_user_id, reason).
    SIGNATURE_ADOPTED = "signature.adopted"
    SIGNATURE_ADOPTION_REVOKED = "signature.adoption_revoked"


ActorRole = Literal["patient", "clinician", "staff", "host", "system"]


@dataclass(frozen=True)
class Actor:
    user_id: str | None = None  # opaque (see is_opaque_id)
    role: ActorRole | None = None
    capacity: Capacity | None = None
    on_behalf_of: str | None = None  # opaque


@dataclass(frozen=True)
class RequestContext:
    """Captured server-side from the request. Never populated from client-supplied JSON."""

    ip: str | None = None
    user_agent: str | None = None
    auth_method: str | None = None
    session_id: UUID | None = None


@dataclass(frozen=True)
class AuditEvent:
    id: UUID
    stream_type: StreamType
    stream_id: UUID
    sequence: int
    event_type: EventType
    actor: Actor
    ctx: RequestContext
    document_sha256: bytes | None
    data: dict[str, Any]  # canonical JSON primitives: bytes as lowercase hex, UUIDs and timestamps as strings
    occurred_at: datetime
    prev_event_hash: bytes
    event_hash: bytes


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    event_count: int
    head_hash: bytes | None
    problems: tuple[str, ...] = ()  # e.g. "sequence gap after 4", "hash mismatch at 7"


class AuditLog(Protocol):
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
        """Serialises writers per stream, assigns the next sequence, chains the hash. ``data`` is
        validated against a per-event-type allowlist so PHI cannot enter the trail by accident.
        The allowlist has exactly one definition, ``esign.audit.events.EVENT_DATA_MODELS``; values
        are passed as Python objects (``bytes`` hashes, ``UUID``, aware ``datetime``) and come back
        canonicalised. Raises ValidationFailed (``audit_data_invalid``, ``audit_actor_invalid``)
        for a refused payload, and IntegrityFailure (``audit_clock_regression``) when the clock
        is behind the head of the stream: a 500-class refusal, not a transient to retry."""

    def list(self, db: Session, stream_type: StreamType, stream_id: UUID) -> list[AuditEvent]: ...

    def verify(self, db: Session, stream_type: StreamType, stream_id: UUID) -> ChainReport: ...


# --------------------------------------------------------------------------- identity (esign.identity)


@dataclass(frozen=True)
class Host:
    id: UUID
    name: str
    allowed_origins: tuple[str, ...]


AuthMethod = Literal["password", "password+mfa", "sso", "portal_otp", "pin", "staff_verified"]
IdentityCheck = Literal["photo_id", "dob_and_name", "known_to_staff", "wristband"]


@dataclass(frozen=True)
class AuthContext:
    """The host's attestation of how the user authenticated. The host backend is trusted because
    it holds the API key; the browser is never the source of these values."""

    method: AuthMethod
    auth_time: datetime


@dataclass(frozen=True)
class KioskContext:
    staff_user_id: str
    identity_check: IdentityCheck


@dataclass(frozen=True)
class SessionInfo:
    id: UUID
    signer_id: UUID
    envelope_id: UUID
    auth: AuthContext
    kiosk: KioskContext | None
    expires_at: datetime
    # Addendum 1: whose session this is, as the host identifies them. The saved-signature routes
    # and the re-authentication span are keyed on this pair, and it must come from the session's
    # signer row, never from the request.
    host_id: UUID
    host_user_id: str


@dataclass(frozen=True)
class ConsentText:
    id: UUID
    version: str
    locale: str
    body: str
    body_sha256: bytes


@dataclass(frozen=True)
class ReauthEvidence:
    """Addendum 1 C: the attestation a signature is recorded under. ``attestation_id`` is the
    ``reauth_attestations`` row; ``scope`` says whether it was made for this session or borrowed
    from another session of the same user on the same host within the span. ``signer.signed``
    records all of it, plus the attestation's age at the moment of signing."""

    attestation_id: UUID
    method: AuthMethod
    auth_time: datetime
    scope: ReauthScope


AdoptedSignatureKind = Literal["drawn", "typed"]
AdoptedRevokeReason = Literal["replaced", "user", "host"]


@dataclass(frozen=True)
class AdoptedSignature:
    """Addendum 1 B: a signature a signer saved for their next session. ``image_sha256`` names a
    ``signature_image`` blob for ``drawn``; ``typed_text`` is the text for ``typed``. Rows are
    never deleted; a replaced or removed one is revoked with a reason and stays, because a
    ``signature_captures`` row may still point at it."""

    id: UUID
    host_id: UUID
    host_user_id: str
    kind: AdoptedSignatureKind
    image_sha256: bytes | None
    typed_text: str | None
    created_in_envelope_id: UUID
    created_by_session_id: UUID
    created_at: datetime
    revoked_at: datetime | None = None
    revoke_reason: AdoptedRevokeReason | None = None

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None


class IdentityService(Protocol):
    def authenticate_host(self, db: Session, bearer: str) -> Host:
        """Constant-time comparison on the key hash. Raises Unauthorized."""

    def create_session(
        self, db: Session, *, signer_id: UUID, auth: AuthContext, kiosk: KioskContext | None, ctx: RequestContext
    ) -> tuple[str, SessionInfo]:
        """Returns the opaque token exactly once. Revokes any earlier live session for the signer.
        Rejects an ``auth_time`` older than the configured maximum or in the future. Raises
        ValidationFailed with code ``auth_too_old``, ``auth_time_in_future``, ``invalid_auth_time``,
        ``unsupported_auth_method``, ``kiosk_context_required`` or ``invalid_kiosk_context``, and
        NotFound (``signer_not_found``) for an unknown signer. Writes no audit event: the API
        layer appends ``session.created`` / ``session.rejected`` (SPEC section 3)."""

    def authenticate_session(self, db: Session, bearer: str) -> SessionInfo:
        """Raises Unauthorized for unknown, expired or revoked tokens; all three are indistinguishable
        to the caller."""

    def revoke_sessions(self, db: Session, signer_id: UUID, *, except_session_id: UUID | None = None) -> int:
        """Revoke the signer's live sessions, optionally sparing one (the session a signer signed
        from survives for the copy download). Returns how many were revoked."""

    def attest_reauth(self, db: Session, *, host: Host, session_id: UUID, auth: AuthContext) -> SessionInfo:
        """Record the host's re-authentication attestation. A session belonging to another host is
        NotFound (``session_not_found``), never Forbidden. Returns the session so the caller can
        append ``auth.reauthenticated`` to the right stream."""

    def fresh_reauth(self, db: Session, session_id: UUID) -> ReauthEvidence | None:
        """The attestation that covers a signature in this session right now, or ``None``.

        Resolution order (Addendum 1 C): the most recent usable attestation made *for this
        session* (``scope="session"``); otherwise, only when ``REAUTH_SPAN_SECONDS`` is greater
        than zero, the most recent one for the same ``(host_id, host_user_id)`` on any of that
        user's sessions whose ``auth_time`` is within the span (``scope="span"``). A different
        user or a different host never matches, and a row written before ``0700`` (no
        ``host_id``) is never borrowed.

        Usable means, in every scope: ``auth_time`` within ``REAUTH_MAX_AGE_SECONDS`` of now and
        not in the future, the session it was made for not revoked or expired, and the session
        being asked about live. With the span off (the default) the answer is exactly what it was
        before the addendum: this session's own attestation or nothing."""

    def get_adopted_signature(self, db: Session, *, host_id: UUID, host_user_id: str) -> AdoptedSignature | None:
        """Addendum 1 B: the one live (unrevoked) saved signature for this user on this host, or
        ``None``. A pure lookup: the caller is responsible for asking only about the user it is
        acting for -- the API resolves the pair from ``SessionInfo`` for a signer and from the
        path plus the authenticated host for a host, and the envelope service from the signer
        row. The image blob it names is served only to a session with the same pair."""

    def adopt_signature(
        self,
        db: Session,
        session_id: UUID,
        *,
        kind: AdoptedSignatureKind,
        image_sha256: bytes | None = None,
        typed_text: str | None = None,
    ) -> AdoptedSignature:
        """Addendum 1 B: save the signature adopted in this session for the session's own
        ``(host_id, host_user_id)``. Only the signer, from inside their own session: there is no
        host path to this. Enforces that the session exists and is live (Unauthorized otherwise),
        that it is not a kiosk session (Forbidden ``adoption_not_allowed``: a patient on a shared
        tablet must not leave a signature behind), that the session's signer has signed
        (Conflict ``signature_not_applied``: the row is created after the signature succeeds, in
        the same transaction), and that ``kind`` matches its payload -- ``drawn`` with an
        ``image_sha256`` naming an existing ``signature_image`` blob the sign path already stored,
        ``typed`` with ``typed_text`` within ``MAX_TYPED_SIGNATURE_CHARS`` (ValidationFailed
        ``invalid_adopted_signature``). An existing live row for the user is revoked with reason
        ``replaced`` in the same transaction, so at most one is ever live. Writes no audit event:
        the API layer appends ``signature.adopted`` to the envelope stream (and
        ``signature.adoption_revoked`` to the system stream for the replaced row) in the same
        transaction, as it does for the session events (SPEC section 3)."""

    def revoke_adopted_signature(
        self, db: Session, *, host_id: UUID, host_user_id: str, reason: AdoptedRevokeReason
    ) -> AdoptedSignature | None:
        """Addendum 1 B: revoke the user's live saved signature, setting ``revoked_at`` and
        ``revoke_reason`` once (the trigger allows no other change to the row). Returns the row as
        revoked, or ``None`` when the user had none -- idempotent, and another host's user is
        indistinguishable from a user with no saved signature. ``reason`` is ``user`` from the
        signer's own session, ``host`` from the host API; ``replaced`` is reserved for
        ``adopt_signature``. Writes no audit event: the API layer appends
        ``signature.adoption_revoked`` to the system stream in the same transaction."""

    def current_consent(self, db: Session, locale: str) -> ConsentText: ...

    def get_consent(self, db: Session, consent_text_id: UUID) -> ConsentText: ...


class RateLimiter(Protocol):
    def hit(self, key: str, *, limit: int, window_seconds: int) -> None:
        """Raises RateLimited when the key exceeds ``limit`` hits in the window."""


# --------------------------------------------------------------------------- envelopes (esign.envelopes)

EnvelopeStatus = Literal[
    "created", "in_progress", "completed_pending_seal", "sealed", "declined", "voided", "expired"
]
SignerStatus = Literal["pending", "viewed", "consented", "signed", "declined"]


#: SPEC section 9: signers decline with one of these, never with free text.
DECLINE_REASON_CODES: Final[tuple[str, ...]] = (
    "prefers_paper",
    "needs_more_time",
    "disagrees_with_terms",
    "needs_interpreter",
    "incorrect_information",
    "not_the_right_signer",
    "wants_to_ask_a_question",
    "other",
)


#: Why a host voids an envelope. Closed for the same reason: a host-invented code ("wrong_dx_hiv")
#: would be free text with underscores, and it is written to the audit trail and the logs.
VOID_REASON_CODES: Final[tuple[str, ...]] = (
    "entered_in_error",
    "wrong_patient",
    "wrong_template",
    "incorrect_information",
    "duplicate",
    "patient_request",
    "signed_on_paper",
    "other",
)


@dataclass(frozen=True)
class NewSigner:
    role_key: str
    host_user_id: str
    display_name: str
    capacity: Capacity
    on_behalf_of: str | None = None


@dataclass(frozen=True)
class NewEnvelope:
    template_key: str
    template_version: int | None  # None = latest published
    patient_ref: str
    host_document_ref: str | None
    signing_order: Literal["sequential", "parallel"]
    signers: tuple[NewSigner, ...]
    prefill: dict[str, str] = field(default_factory=dict)  # PHI: used once to prepare, never stored
    expires_at: datetime | None = None
    supersedes_envelope_id: UUID | None = None


@dataclass(frozen=True)
class NewArchive:
    """Addendum 1 A: a scan of a paper-signed document, filed by the host. The scan bytes travel
    beside this (``EnvelopeService.create_archive``), not inside it."""

    patient_ref: str  # opaque (is_opaque_id), like NewEnvelope.patient_ref
    document_type: str  # must be an approved document type
    host_document_ref: str | None
    paper_signed_on: date  # the date on the paper; not a fact about a person, never in audit data
    attestation: Attestation
    supersedes_envelope_id: UUID | None = None


@dataclass(frozen=True)
class SignerView:
    id: UUID
    role_key: str
    role_label: str
    display_name: str
    capacity: Capacity
    order_index: int
    requires_reauth: bool
    status: SignerStatus


@dataclass(frozen=True)
class EnvelopeView:
    """Addendum 1 A: for ``kind == "paper_archive"`` there is no template and no signer, so
    ``template_key``, ``template_version`` and ``signing_order`` are ``None`` and ``signers`` is
    empty; ``paper_signed_on`` and ``attested_at`` are set. For ``electronic`` the two are ``None``
    and the rest is as before."""

    id: UUID
    status: EnvelopeStatus
    document_type: str
    template_key: str | None
    template_version: int | None
    signing_order: str | None
    signers: tuple[SignerView, ...]
    presented_sha256: bytes | None
    sealed_sha256: bytes | None
    expires_at: datetime
    supersedes_envelope_id: UUID | None
    superseded_by_envelope_id: UUID | None
    current_revision_sha256: bytes | None = None
    created_at: datetime | None = None
    host_id: UUID | None = None
    kind: EnvelopeKind = "electronic"
    paper_signed_on: date | None = None
    attested_at: datetime | None = None


@dataclass(frozen=True)
class SigningFieldView:
    id: str
    type: FieldType
    page: int
    rect: Rect
    required: bool
    label: str


@dataclass(frozen=True)
class SigningView:
    """Everything the signing UI needs for one session (SPEC section 9, ``GET /v1/signing/session``)."""

    envelope_id: UUID
    envelope_status: EnvelopeStatus
    document_type: str
    title: str
    page_count: int
    expires_at: datetime
    signer: SignerView
    on_behalf_of_label: str | None
    reauth_valid_until: datetime | None  # from fresh_reauth: covers a span attestation too
    other_signers: tuple[tuple[str, SignerStatus], ...]  # (role_label, status); never a name
    fields: tuple[SigningFieldView, ...]  # this signer's fields only
    #: Addendum 1 C: which attestation ``reauth_valid_until`` rests on; ``None`` when there is none.
    reauth_scope: ReauthScope | None = None
    #: Addendum 1 C: that attestation's ``auth_time`` -- when the signer confirmed their identity --
    #: so the UI can say "you confirmed your identity at HH:MM" rather than infer it. ``None``
    #: exactly when ``reauth_valid_until`` is.
    reauth_at: datetime | None = None


WebhookEvent = Literal[
    "envelope.completed", "envelope.sealed", "envelope.declined", "envelope.voided", "envelope.expired"
]


class EnvelopeNotifier(Protocol):
    def envelope_event(self, db: Session, *, event: WebhookEvent, envelope: EnvelopeView) -> None:
        """Called by the envelope service inside the transaction that made the change, so a
        notification is queued if and only if the change commits. Payloads carry ids, statuses
        and hashes only."""


class ArchiveCreator(Protocol):
    """Addendum 1 A: the ``esign.archives`` module, as ``EnvelopeService.create_archive`` sees it.

    ``esign.runtime`` builds the archives module and injects it into the envelope service like
    every other collaborator; the envelope service delegates ``create_archive`` here and owns
    everything from ``completed_pending_seal`` onwards (the seal, the certificate, the webhook,
    voiding, verification), which it already does for both kinds.
    """

    def create(self, db: Session, host: Host, spec: NewArchive, scan: bytes, ctx: RequestContext) -> UUID:
        """File the scan and return the new envelope's id, in the caller's transaction. Enforces
        and records exactly what ``EnvelopeService.create_archive`` documents."""


class EnvelopeService(Protocol):
    """Owns every envelope and signer state transition. Each method locks the envelope row,
    checks the transition is legal, applies it, and appends the audit event in the same
    transaction. Illegal transitions raise Conflict and change nothing."""

    def create(self, db: Session, host: Host, spec: NewEnvelope, ctx: RequestContext) -> EnvelopeView: ...

    def create_archive(self, db: Session, host: Host, spec: NewArchive, scan: bytes, ctx: RequestContext) -> EnvelopeView:
        """Addendum 1 A: file a scan of a paper-signed document as a ``paper_archive`` envelope.

        Enforces: ``document_type`` approved (ValidationFailed ``document_type_not_approved``),
        ``patient_ref`` opaque (``patient_ref_invalid``, as ``create`` says it) and
        ``attestation.staff_user_id`` opaque (``host_user_id_invalid``),
        ``paper_signed_on`` not after today (``paper_signed_on_in_future``), at least one paper
        signer, and the scan passing the template hygiene rules under ``MAX_SCAN_BYTES`` /
        ``MAX_SCAN_PAGES`` (``inspect_template_pdf``: no encryption, scripts, XFA, embedded files
        or existing signatures; image-only pages are expected). ``supersedes_envelope_id`` follows
        the same rules as ``create`` (a sealed envelope of this host, of either kind, not already
        superseded; ``envelope.superseded`` on the old stream).

        In one transaction: stores the scan write-once (blob ``scan_pdf``, revision 1 of kind
        ``scan``, retention by ``document_type``), inserts the envelope with ``kind =
        paper_archive``, no template, no signers, ``presented_sha256`` and
        ``current_revision_sha256`` both the scan's hash, ``attested_at = now``; appends
        ``archive.created`` (actor: the host) then ``archive.attested`` (actor: the staff member,
        role ``staff``); moves it ``created -> completed_pending_seal`` and enqueues the seal job,
        attempting it once inline like the last signature does. ``seal_pending`` then builds the
        cover (``build_archive_cover``), the archive certificate, finalizes cover + scan +
        certificate and seals as for any envelope. Returns the view with ``kind =
        "paper_archive"``."""

    def get(self, db: Session, host: Host, envelope_id: UUID) -> EnvelopeView: ...

    def assert_signer_may_start(self, db: Session, host: Host, envelope_id: UUID, signer_id: UUID) -> None:
        """Called before a session is created: envelope live, signer not finished, and for
        sequential order every earlier signer has signed."""

    def present(self, db: Session, session: SessionInfo, ctx: RequestContext) -> bytes:
        """Returns the current revision bytes and records document.presented with its hash."""

    def signing_view(self, db: Session, session: SessionInfo) -> SigningView: ...

    def record_viewed(self, db: Session, session: SessionInfo, pages_viewed: int, ctx: RequestContext) -> None:
        """``pages_viewed`` must equal the page count of the bytes this session was served."""

    def accept_consent(
        self, db: Session, session: SessionInfo, consent_version: str, ctx: RequestContext, *, locale: str | None = None
    ) -> None:
        """``locale`` is the language the signer read the disclosure in; the consent recorded is
        the current text for that locale (falling back to the default locale)."""

    def sign(self, db: Session, session: SessionInfo, captures: list[Capture], ctx: RequestContext) -> EnvelopeView:
        """Requires viewed + consented, and a fresh re-authentication when the role demands it.
        Applies marks to the current revision, stores the new revision, and when this was the last
        signer moves the envelope to completed_pending_seal and enqueues the seal job.

        Addendum 1 C: the re-authentication is whatever ``fresh_reauth`` returns, and
        ``signer.signed`` records its ``reauth_attestation_id``, ``reauth_scope`` and
        ``reauth_age_seconds`` (now minus ``auth_time``, at the moment of signing) beside
        ``reauth_method``; a role that does not re-authenticate records none of them.

        Addendum 1 B: an ``adopted`` capture is resolved through ``get_adopted_signature`` for the
        signer's own ``(host_id, host_user_id)``; it is refused (Forbidden
        ``adopted_signature_unavailable``) when the id is not that user's live saved signature,
        and always from a kiosk session. The stored image or text is stamped, the
        ``signature_captures`` row is written
        with ``kind = adopted`` and ``adopted_signature_id``, the trail's ``CaptureRef`` carries the
        image or text digest, and ``signer.signed.adopted_signature_id`` names the row."""

    def decline(self, db: Session, session: SessionInfo, reason_code: str, ctx: RequestContext) -> EnvelopeView: ...

    def void(self, db: Session, host: Host, envelope_id: UUID, reason_code: str, ctx: RequestContext) -> EnvelopeView:
        """Only while ``created`` or ``in_progress``. An envelope that is complete and waiting for
        its seal cannot be voided: it stays pending until the seal succeeds (fail closed). A sealed envelope is corrected by creating a new envelope with
        ``supersedes_envelope_id``; the sealed document itself is never touched.

        Addendum 1 A: a ``paper_archive`` may be voided while ``created`` or
        ``completed_pending_seal`` -- nobody signed anything electronically and the seal has not
        happened -- but never once ``sealed``. A seal job for a voided archive finds the envelope
        not pending and does nothing."""

    def expire_due(self, db: Session) -> int: ...

    def seal_pending(self, db: Session, envelope_id: UUID) -> EnvelopeView:
        """Build certificate, finalize, seal, validate the result, store, mark sealed. Raises
        SealUnavailable or StorageUnavailable so the job runner can back off. Before raising it
        records ``seal.failed`` and the job's backoff in a *separate, committed* transaction
        (the ``new_session`` factory given at construction), because the caller is about to roll
        ``db`` back and the evidence of the failure has to survive that.

        IntegrityFailure escapes likewise (a stored revision that does not re-hash, a broken audit
        chain) and no retry can fix it: the envelope still stays ``completed_pending_seal`` and
        ``seal.failed`` is still recorded with its error code, so a worker must treat it as a
        recorded failure to surface to an operator, never as a reason to skip the record or to
        report the document complete (SPEC section 3: pending, recorded, loud). Any other exception
        is a bug and is handled the same way."""

    def may_download_copy(self, db: Session, session: SessionInfo) -> bool: ...

    def signer_copy(self, db: Session, session: SessionInfo, ctx: RequestContext) -> bytes | None:
        """The sealed PDF for a signer who has signed, recording document.downloaded. ``None``
        while the envelope is ``completed_pending_seal``. Conflict (``envelope_not_complete``)
        while other signers are outstanding; Forbidden for a signer who has not signed."""

    def sealed_document(self, db: Session, host: Host, envelope_id: UUID, ctx: RequestContext) -> bytes:
        """The sealed PDF for the host, recording document.downloaded. Conflict (``not_sealed``)
        until the envelope is sealed."""
