"""The allowed shape of ``audit_events.data``, one model per :class:`EventType`.

SPEC section 4: ``data`` is validated per event type against an allowlist of keys and value
shapes -- ids, enums, hashes, versions, counts and error codes. Names, dates of birth, free text
and prefill values can never appear, and unknown keys are rejected.

That rule is enforced mechanically here rather than remembered:

* every model sets ``extra="forbid"``, so a key nobody declared is an error, not a passenger;
* every model is ``strict``, so a string is never quietly coerced into a hash, a count or a
  timestamp -- a 32-character name would otherwise validate as a 32-byte digest;
* every free-form-looking string is a constrained pattern. :data:`OpaqueId` forbids whitespace,
  which is what stops a display name ("Jane Doe") being passed where a host user id belongs;
* there is no ``str`` field anywhere without a pattern, and no field that accepts arbitrary text.

Validation failures raise :class:`ValidationFailed` with a message built only from field *names*
and error *kinds*. The rejected value never appears in the message, because that message is
allowed to reach a log and the value is exactly the thing we suspect of being PHI.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any, Final, Literal, get_args
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from pydantic.functional_validators import AfterValidator

from esign.audit.canonical import canonical_value
from esign.contracts import (
    OPAQUE_ID_PATTERN,
    AdoptedRevokeReason,
    AdoptedSignatureKind,
    AttestationStatement,
    BlobKind,
    Capacity,
    EventType,
    OriginalDisposition,
    ReauthScope,
    SealProfile,
    ValidationFailed,
    is_opaque_id,
)

__all__ = [
    "ACTOR_ROLES",
    "AUTH_METHOD_PATTERN",
    "EVENT_DATA_MODELS",
    "OPAQUE_ID_PATTERN",
    "EventData",
    "declared_data_keys",
    "is_opaque_id",
    "validate_event_data",
]


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


#: A server-recorded instant. Timezone-aware only; a date of birth is not one of these -- no model
#: below has a date field that a caller could point at a patient.
Timestamp = Annotated[datetime, AfterValidator(_require_aware)]

#: A raw SHA-256 digest. Exactly 32 bytes, and (strict mode) actually ``bytes``.
Sha256 = Annotated[bytes, Field(min_length=32, max_length=32)]

#: A machine token from a closed vocabulary we control: role keys, field ids, document types,
#: reason codes, error codes.
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]

#: A template or host-chosen key. Hyphens allowed, still no spaces and no case surprises.
KeySlug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")]

#: A version label such as ``2026-09``.
VersionLabel = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]

#: A BCP 47-ish locale such as ``en-US``.
Locale = Annotated[str, StringConstraints(pattern=r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$")]

#: An identifier the host chose: a signer's host user id, a staff user id, a patient reference.
#: Opaque to us, and -- because whitespace is forbidden -- not a human name. The pattern and the
#: refused shapes (dates, social security numbers) have one definition, in ``esign.contracts``, so
#: the modules that accept these values check them the same way the trail does.


def _check_opaque(value: str) -> str:
    if not is_opaque_id(value):
        raise ValueError("value is not an opaque identifier")
    return value


OpaqueId = Annotated[str, StringConstraints(pattern=OPAQUE_ID_PATTERN), AfterValidator(_check_opaque)]

#: How a request authenticated, as the server saw it: an :data:`AuthMethod`, ``api_key`` for a
#: host call, ``session_token`` for a signer call, ``system`` for the worker.
AUTH_METHOD_PATTERN: Final[str] = r"^[a-z][a-z0-9_+.-]{0,63}$"

#: The five roles :class:`~esign.contracts.Actor` documents. Nothing else may act.
ACTOR_ROLES: Final[frozenset[str]] = frozenset({"patient", "clinician", "staff", "host", "system"})

#: A non-negative count. Bounded so a bug cannot write an absurd number into the evidence.
Count = Annotated[int, Field(ge=0, le=1_000_000)]

#: A 1-based ordinal (revision number, page number, attempt).
Ordinal = Annotated[int, Field(ge=1, le=1_000_000)]

#: A size in bytes.
ByteSize = Annotated[int, Field(ge=0, le=1 << 40)]

#: A duration in seconds.
Seconds = Annotated[int, Field(ge=0, le=31_536_000)]

AuthMethod = Literal["password", "password+mfa", "sso", "portal_otp", "pin", "staff_verified"]
IdentityCheck = Literal["photo_id", "dob_and_name", "known_to_staff", "wristband"]
SigningOrder = Literal["sequential", "parallel"]
#: How a field was filled: the four signature capture kinds (``adopted`` is a saved signature
#: applied again, Addendum 1 B), or the field type for the two non-signature fields (which carry
#: no capture kind on the wire).
CaptureKindName = Literal["drawn", "typed", "click", "adopted", "checkbox", "text"]
#: ``scan`` is a paper archive's revision 1 (Addendum 1 A).
RevisionKind = Literal["presented", "signer_applied", "final_unsealed", "sealed", "scan"]
Audience = Literal["signer", "host"]
KeyBackend = Literal["local", "aws_kms"]


class EventData(BaseModel):
    """Base for every ``data`` shape. Frozen, strict, and closed to unknown keys."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


# --------------------------------------------------------------------------- templates


class TemplatePublishedData(EventData):
    template_id: UUID
    template_key: KeySlug
    template_version: Ordinal
    template_version_id: UUID
    pdf_sha256: Sha256
    page_count: Ordinal
    field_count: Count
    signer_role_count: Count


class TemplateRetiredData(EventData):
    template_id: UUID
    template_key: KeySlug
    template_version: Ordinal
    template_version_id: UUID


# --------------------------------------------------------------------------- envelope lifecycle


class EnvelopeCreatedData(EventData):
    host_id: UUID
    template_key: KeySlug
    template_version: Ordinal
    template_version_id: UUID
    document_type: Slug
    signing_order: SigningOrder
    signer_count: Ordinal
    expires_at: Timestamp
    supersedes_envelope_id: UUID | None = None


class DocumentPreparedData(EventData):
    """Revision 1 exists. ``document_sha256`` on the row carries its hash."""

    revision_no: Ordinal
    revision_kind: RevisionKind
    page_count: Ordinal
    size_bytes: ByteSize
    prefill_field_count: Count


class SessionCreatedData(EventData):
    signer_id: UUID
    role_key: Slug
    auth_method: AuthMethod
    auth_time: Timestamp
    expires_at: Timestamp
    kiosk: bool
    kiosk_staff_user_id: OpaqueId | None = None
    kiosk_identity_check: IdentityCheck | None = None


class SessionRejectedData(EventData):
    """A session was refused: stale ``auth_time``, wrong order, envelope not live."""

    signer_id: UUID
    role_key: Slug
    reason_code: Slug


class DocumentPresentedData(EventData):
    signer_id: UUID
    revision_no: Ordinal
    page_count: Ordinal
    size_bytes: ByteSize


class DocumentViewedData(EventData):
    signer_id: UUID
    pages_viewed: Ordinal
    page_count: Ordinal


class ConsentAcceptedData(EventData):
    signer_id: UUID
    consent_text_id: UUID
    consent_version: VersionLabel
    locale: Locale
    body_sha256: Sha256


class ReauthAttestedData(EventData):
    signer_id: UUID
    method: AuthMethod
    auth_time: Timestamp


class CaptureRef(BaseModel):
    """Which field was filled and how, and a digest of what was captured.

    No captured *value*: the mark itself is in the PDF, and a typed signature is a name. The two
    digests are what tie the row in ``signature_captures`` -- the raw drawn PNG, the typed text --
    to the append-only, hash-chained trail. Without them the only record of the raw input was a
    mutable row that no check could contradict.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    field_id: Slug
    kind: CaptureKindName
    #: The drawn PNG as stored (content-addressed), for a ``drawn`` capture.
    image_sha256: Sha256 | None = None
    #: SHA-256 of the typed text as stored, for a ``typed`` capture. A digest, never the name.
    typed_text_sha256: Sha256 | None = None


class SignerSignedData(EventData):
    signer_id: UUID
    role_key: Slug
    capacity: Capacity
    consent_version: VersionLabel
    reauth_used: bool
    reauth_method: AuthMethod | None = None
    #: Addendum 1 C: *which* attestation covered this signature, whether it was made in this
    #: session or borrowed from another within the span, and how old it was at signing. All three
    #: are set together when ``reauth_used``; none otherwise.
    reauth_attestation_id: UUID | None = None
    reauth_scope: ReauthScope | None = None
    reauth_age_seconds: Seconds | None = None
    #: Addendum 1 B: the saved signature applied by an ``adopted`` capture, when there was one.
    adopted_signature_id: UUID | None = None
    #: What this signer was shown, what they signed on top of, and what came out. In a parallel
    #: envelope another signer may move the document between the first two; that has to be visible.
    presented_sha256: Sha256
    base_revision_sha256: Sha256
    revision_no: Ordinal
    revision_sha256: Sha256
    capture_count: Ordinal
    # ``strict=False`` only so callers can pass plain dicts -- they must not have to import a
    # model out of this package. The nested model's own fields stay strict.
    captures: tuple[CaptureRef, ...] = Field(strict=False)


class SignerDeclinedData(EventData):
    signer_id: UUID
    role_key: Slug
    reason_code: Slug


class EnvelopeDeclinedData(EventData):
    """The envelope-level fact that follows a signer's decline: the envelope itself is over."""

    signer_id: UUID
    reason_code: Slug


class EnvelopeCompletedData(EventData):
    signer_count: Ordinal
    revision_no: Ordinal
    final_revision_sha256: Sha256


class DocumentFinalizedData(EventData):
    """The certificate of completion has been appended; these are the bytes about to be sealed."""

    certificate_sha256: Sha256
    page_count: Ordinal
    size_bytes: ByteSize
    audit_event_count: Count
    audit_head_hash: Sha256


class SealFailedData(EventData):
    error_code: Slug
    attempt: Ordinal
    retry_in_seconds: Seconds


class DocumentSealedData(EventData):
    seal_profile: SealProfile
    key_backend: KeyBackend
    signer_cert_sha256: Sha256
    timestamp_time: Timestamp
    size_bytes: ByteSize


class DocumentStoredData(EventData):
    blob_kind: BlobKind
    size_bytes: ByteSize
    retain_until: Timestamp


class DocumentDownloadedData(EventData):
    blob_kind: BlobKind
    audience: Audience
    size_bytes: ByteSize


class EnvelopeVoidedData(EventData):
    reason_code: Slug


class EnvelopeExpiredData(EventData):
    """Nothing to record beyond the event itself; ``occurred_at`` is the fact."""


class EnvelopeSupersededData(EventData):
    superseded_by_envelope_id: UUID


class VerificationPerformedData(EventData):
    ok: bool
    audit_ok: bool
    audit_event_count: Count
    audit_head_hash: Sha256 | None = None
    seal_intact: bool | None = None
    seal_trusted: bool | None = None
    seal_covers_whole_document: bool | None = None
    seal_timestamp_valid: bool | None = None
    seal_profile: SealProfile | None = None
    blobs_checked: Count = 0
    problem_count: Count = 0


# --------------------------------------------------------------------------- addendum 1


class ArchiveCreatedData(EventData):
    """Addendum 1 A: a scan of a paper-signed document was filed. ``document_sha256`` on the row
    is the scan's hash too. No ``paper_signed_on``: it is a date, and this file keeps date-shaped
    values out of the trail; the cover page inside the sealed bytes states it."""

    host_id: UUID
    document_type: Slug
    page_count: Ordinal
    size_bytes: ByteSize
    scan_sha256: Sha256
    supersedes_envelope_id: UUID | None = None


class ArchiveAttestedData(EventData):
    """Addendum 1 A: who attested the scan and what they said. The staff member by opaque id;
    the paper signers by count only, because their names are PHI."""

    staff_user_id: OpaqueId
    statement: AttestationStatement
    original_disposition: OriginalDisposition
    paper_signer_count: Ordinal


class SignatureAdoptedData(EventData):
    """Addendum 1 B: a signer saved the signature they adopted. The digest ties the saved ink or
    text to the chain, exactly as :class:`CaptureRef` does for a capture."""

    signer_id: UUID
    adopted_signature_id: UUID
    kind: AdoptedSignatureKind
    image_sha256: Sha256 | None = None
    typed_text_sha256: Sha256 | None = None


class SignatureAdoptionRevokedData(EventData):
    """Addendum 1 B, on the ``system`` stream: a saved signature stopped being offered."""

    host_id: UUID
    host_user_id: OpaqueId
    adopted_signature_id: UUID
    reason: AdoptedRevokeReason


#: Every event type has a declared shape. There is no default and no fallback: a new member of
#: :class:`EventType` without an entry here fails at import, not in production.
EVENT_DATA_MODELS: Final[Mapping[EventType, type[EventData]]] = {
    EventType.TEMPLATE_PUBLISHED: TemplatePublishedData,
    EventType.TEMPLATE_RETIRED: TemplateRetiredData,
    EventType.ENVELOPE_CREATED: EnvelopeCreatedData,
    EventType.DOCUMENT_PREPARED: DocumentPreparedData,
    EventType.SESSION_CREATED: SessionCreatedData,
    EventType.SESSION_REJECTED: SessionRejectedData,
    EventType.DOCUMENT_PRESENTED: DocumentPresentedData,
    EventType.DOCUMENT_VIEWED: DocumentViewedData,
    EventType.CONSENT_ACCEPTED: ConsentAcceptedData,
    EventType.REAUTH_ATTESTED: ReauthAttestedData,
    EventType.SIGNER_SIGNED: SignerSignedData,
    EventType.SIGNER_DECLINED: SignerDeclinedData,
    EventType.ENVELOPE_DECLINED: EnvelopeDeclinedData,
    EventType.ENVELOPE_COMPLETED: EnvelopeCompletedData,
    EventType.DOCUMENT_FINALIZED: DocumentFinalizedData,
    EventType.SEAL_FAILED: SealFailedData,
    EventType.DOCUMENT_SEALED: DocumentSealedData,
    EventType.DOCUMENT_STORED: DocumentStoredData,
    EventType.DOCUMENT_DOWNLOADED: DocumentDownloadedData,
    EventType.ENVELOPE_VOIDED: EnvelopeVoidedData,
    EventType.ENVELOPE_EXPIRED: EnvelopeExpiredData,
    EventType.ENVELOPE_SUPERSEDED: EnvelopeSupersededData,
    EventType.VERIFICATION_PERFORMED: VerificationPerformedData,
    EventType.ARCHIVE_CREATED: ArchiveCreatedData,
    EventType.ARCHIVE_ATTESTED: ArchiveAttestedData,
    EventType.SIGNATURE_ADOPTED: SignatureAdoptedData,
    EventType.SIGNATURE_ADOPTION_REVOKED: SignatureAdoptionRevokedData,
}

_MISSING = sorted(member.value for member in EventType if member not in EVENT_DATA_MODELS)
if _MISSING:  # pragma: no cover - import-time guard
    raise RuntimeError(f"audit event types with no declared data shape: {_MISSING}")


def declared_data_keys(event_type: EventType) -> frozenset[str]:
    """The exact key set a stored ``data`` object for this event type must have.

    :func:`validate_event_data` always writes every declared field (absent ones as ``null``), so
    a stored object with a different key set was not written by this code.
    """
    return frozenset(EVENT_DATA_MODELS[event_type].model_fields)


_SAFE_LOC = str.maketrans(dict.fromkeys("\n\r\t\"'`", "_"))


def _describe(error_location: tuple[int | str, ...]) -> str:
    """A field path safe to put in a message: names and indices only, bounded, no quoting tricks."""
    parts = [str(part)[:40].translate(_SAFE_LOC) for part in error_location] or ["<root>"]
    return ".".join(parts)


def validate_event_data(event_type: EventType, data: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate ``data`` for ``event_type`` and return it as canonical JSON primitives.

    The returned dict is what gets stored *and* what gets hashed, so the row and the hash can
    never drift apart. Raises :class:`ValidationFailed` -- with no input values in the message --
    for an unknown key, a wrong type, a name where an id belongs, or anything else the model
    refuses.
    """
    model = EVENT_DATA_MODELS.get(event_type)
    if model is None:  # pragma: no cover - the import-time guard makes this unreachable
        raise ValidationFailed(f"no audit data shape for event type {event_type.value}")
    try:
        validated = model.model_validate(dict(data or {}))
    except ValidationError as exc:
        problems = sorted({f"{_describe(err['loc'])} ({err['type']})" for err in exc.errors()})
        raise ValidationFailed(
            f"audit data rejected for {event_type.value}: " + "; ".join(problems[:10]),
            code="audit_data_invalid",
        ) from None
    canonical = canonical_value(validated.model_dump())
    if not isinstance(canonical, dict):  # pragma: no cover - model_dump always yields a dict
        raise ValidationFailed(f"audit data for {event_type.value} did not canonicalise to an object")
    return canonical


#: Exposed for tests and for anyone auditing the vocabulary: every closed value set in one place.
CLOSED_VOCABULARIES: Final[Mapping[str, tuple[str, ...]]] = {
    "auth_method": get_args(AuthMethod),
    "identity_check": get_args(IdentityCheck),
    "signing_order": get_args(SigningOrder),
    "capture_kind": get_args(CaptureKindName),
    "revision_kind": get_args(RevisionKind),
    "audience": get_args(Audience),
    "key_backend": get_args(KeyBackend),
    "capacity": get_args(Capacity),
    "blob_kind": get_args(BlobKind),
    "seal_profile": get_args(SealProfile),
    "reauth_scope": get_args(ReauthScope),
    "adopted_signature_kind": get_args(AdoptedSignatureKind),
    "adopted_revoke_reason": get_args(AdoptedRevokeReason),
    "attestation_statement": get_args(AttestationStatement),
    "original_disposition": get_args(OriginalDisposition),
}
