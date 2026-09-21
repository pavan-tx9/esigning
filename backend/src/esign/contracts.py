"""Shared contracts between modules.

This file is the seam that lets modules be built in parallel. Every module implements or
consumes these types and nothing else from a sibling module. Do not change a signature here
without updating docs/SPEC.md; module agents must not edit this file at all -- if a contract
is wrong or missing something, say so in your report.

Conventions:
- All hashes are raw 32-byte SHA-256 digests (``bytes``), hex only at API and log boundaries.
- All datetimes are timezone-aware UTC. Time comes from ``Clock``, never from ``datetime.now``.
- ``db`` is a ``sqlalchemy.orm.Session`` inside a transaction owned by the caller. Contract
  functions never commit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Protocol
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
    code = "rate_limited"
    http_status = 429


class IntegrityFailure(EsignError):
    """Stored evidence does not match its recorded hash. Never swallow this."""

    code = "integrity_failure"
    http_status = 500


class SealUnavailable(EsignError):
    """KMS, timestamp authority or revocation source unreachable. Retryable: the envelope stays
    ``completed_pending_seal`` and the seal job backs off. Never fall back to an unsealed result."""

    code = "seal_unavailable"
    http_status = 503


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


@dataclass(frozen=True)
class TemplatePdfInfo:
    page_count: int
    page_sizes: tuple[tuple[float, float], ...]  # (width, height) in points, as displayed
    sha256: bytes


# --------------------------------------------------------------------------- documents (esign.documents)

CaptureKind = Literal["drawn", "typed", "click"]


@dataclass(frozen=True)
class Capture:
    field_id: str
    kind: CaptureKind
    image_png: bytes | None = None  # sanitized PNG, drawn only
    typed_text: str | None = None  # typed only
    checked: bool | None = None  # checkbox fields
    text_value: str | None = None  # text fields


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


@dataclass(frozen=True)
class CertificateSummary:
    """Input for the certificate of completion. Deliberately minimal: no patient identifiers
    beyond signer display names, no chart data."""

    envelope_id: UUID
    document_type: str
    template_key: str
    template_version: int
    presented_sha256: bytes
    final_revision_sha256: bytes  # last signer-applied revision, before the certificate is appended
    created_at: datetime
    completed_at: datetime
    signers: tuple[CertificateSigner, ...]
    audit_event_count: int
    audit_head_hash: bytes  # event_hash of the last event included


class DocumentService(Protocol):
    def inspect_template_pdf(self, pdf: bytes) -> TemplatePdfInfo:
        """Reject (ValidationFailed) PDFs that are encrypted, already signed, contain JavaScript,
        XFA, embedded files or launch actions, or exceed configured size/page limits."""

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

    def build_certificate(self, summary: CertificateSummary) -> bytes: ...

    def finalize(self, pdf: bytes, certificate_pdf: bytes) -> bytes:
        """Append the certificate pages and return the exact bytes to be sealed."""


# --------------------------------------------------------------------------- sealing (esign.sealing)

SealProfile = Literal["PAdES-B-T", "PAdES-B-LT", "PAdES-B-LTA"]


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
        return self.intact and self.covers_whole_document and self.trusted and self.timestamp_valid


class Sealer(Protocol):
    def seal(self, pdf: bytes, *, reason: str, envelope_id: UUID) -> SealResult:
        """Apply the organisation seal as a certification signature that permits no further
        changes. Raises SealUnavailable for retryable infrastructure failures."""

    def validate(self, pdf: bytes) -> SealValidation:
        """Never raises for a bad document: a tampered or unsigned PDF returns a failing result."""


# --------------------------------------------------------------------------- storage (esign.storage)

BlobKind = Literal[
    "template_pdf", "presented_pdf", "revision_pdf", "final_unsealed_pdf", "sealed_pdf", "signature_image"
]


@dataclass(frozen=True)
class BlobRef:
    sha256: bytes
    size_bytes: int
    kind: BlobKind


class BlobService(Protocol):
    def put(self, db: Session, data: bytes, *, kind: BlobKind, retain_until: datetime | None = None) -> BlobRef:
        """Write-once and idempotent by content hash. The backend must refuse to overwrite."""

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


@dataclass(frozen=True)
class Actor:
    user_id: str | None = None
    role: str | None = None  # "patient" | "clinician" | "staff" | "host" | "system"
    capacity: str | None = None
    on_behalf_of: str | None = None


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
    data: dict[str, Any]
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
        validated against a per-event-type allowlist so PHI cannot enter the trail by accident."""

    def list(self, db: Session, stream_type: StreamType, stream_id: UUID) -> list[AuditEvent]: ...

    def verify(self, db: Session, stream_type: StreamType, stream_id: UUID) -> ChainReport: ...


# --------------------------------------------------------------------------- identity (esign.identity)


@dataclass(frozen=True)
class Host:
    id: UUID
    name: str
    allowed_origins: tuple[str, ...]


@dataclass(frozen=True)
class AuthContext:
    """The host's attestation of how the user authenticated. The host backend is trusted because
    it holds the API key; the browser is never the source of these values."""

    method: str  # "password" | "password+mfa" | "sso" | "portal_otp" | "pin" | "staff_verified"
    auth_time: datetime


@dataclass(frozen=True)
class KioskContext:
    staff_user_id: str
    identity_check: str  # "photo_id" | "dob_and_name" | "known_to_staff" | "wristband"


@dataclass(frozen=True)
class SessionInfo:
    id: UUID
    signer_id: UUID
    envelope_id: UUID
    auth: AuthContext
    kiosk: KioskContext | None
    expires_at: datetime


@dataclass(frozen=True)
class ConsentText:
    id: UUID
    version: str
    locale: str
    body: str
    body_sha256: bytes


class IdentityService(Protocol):
    def authenticate_host(self, db: Session, bearer: str) -> Host:
        """Constant-time comparison on the key hash. Raises Unauthorized."""

    def create_session(
        self, db: Session, *, signer_id: UUID, auth: AuthContext, kiosk: KioskContext | None, ctx: RequestContext
    ) -> tuple[str, SessionInfo]:
        """Returns the opaque token exactly once. Revokes any earlier live session for the signer.
        Rejects an ``auth_time`` older than the configured maximum or in the future."""

    def authenticate_session(self, db: Session, bearer: str) -> SessionInfo:
        """Raises Unauthorized for unknown, expired or revoked tokens; all three are indistinguishable
        to the caller."""

    def revoke_sessions(self, db: Session, signer_id: UUID) -> None: ...

    def attest_reauth(self, db: Session, *, session_id: UUID, auth: AuthContext) -> None: ...

    def fresh_reauth(self, db: Session, session_id: UUID) -> AuthContext | None:
        """The most recent attestation if it is within REAUTH_MAX_AGE_SECONDS, else None."""

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
    id: UUID
    status: EnvelopeStatus
    document_type: str
    template_key: str
    template_version: int
    signing_order: str
    signers: tuple[SignerView, ...]
    presented_sha256: bytes | None
    sealed_sha256: bytes | None
    expires_at: datetime
    supersedes_envelope_id: UUID | None
    superseded_by_envelope_id: UUID | None


class EnvelopeService(Protocol):
    """Owns every envelope and signer state transition. Each method locks the envelope row,
    checks the transition is legal, applies it, and appends the audit event in the same
    transaction. Illegal transitions raise Conflict and change nothing."""

    def create(self, db: Session, host: Host, spec: NewEnvelope, ctx: RequestContext) -> EnvelopeView: ...

    def get(self, db: Session, host: Host, envelope_id: UUID) -> EnvelopeView: ...

    def assert_signer_may_start(self, db: Session, host: Host, envelope_id: UUID, signer_id: UUID) -> None:
        """Called before a session is created: envelope live, signer not finished, and for
        sequential order every earlier signer has signed."""

    def present(self, db: Session, session: SessionInfo, ctx: RequestContext) -> bytes:
        """Returns the current revision bytes and records document.presented with its hash."""

    def record_viewed(self, db: Session, session: SessionInfo, ctx: RequestContext) -> None: ...

    def accept_consent(self, db: Session, session: SessionInfo, consent_version: str, ctx: RequestContext) -> None: ...

    def sign(self, db: Session, session: SessionInfo, captures: list[Capture], ctx: RequestContext) -> EnvelopeView:
        """Requires viewed + consented, and a fresh re-authentication when the role demands it.
        Applies marks to the current revision, stores the new revision, and when this was the last
        signer moves the envelope to completed_pending_seal and enqueues the seal job."""

    def decline(self, db: Session, session: SessionInfo, reason_code: str, ctx: RequestContext) -> EnvelopeView: ...

    def void(self, db: Session, host: Host, envelope_id: UUID, reason_code: str, ctx: RequestContext) -> EnvelopeView:
        """Only before sealing. A sealed envelope is corrected by creating a new envelope with
        ``supersedes_envelope_id``; the sealed document itself is never touched."""

    def expire_due(self, db: Session) -> int: ...

    def seal_pending(self, db: Session, envelope_id: UUID) -> EnvelopeView:
        """Build certificate, finalize, seal, validate the result, store, mark sealed. Raises
        SealUnavailable (after recording seal.failed) so the job runner can back off."""
