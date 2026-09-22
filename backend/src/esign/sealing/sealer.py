"""PAdES sealing and validation.

One seal per document, applied once, at the end: a certification signature with DocMDP level 1
("no changes permitted") over the signed document plus its certificate of completion.

Two rules run through everything here.

**Never fail open.** If KMS, the timestamp authority or the revocation source cannot be reached,
``seal`` raises :class:`SealUnavailable` and produces nothing. There is no branch that returns an
unsigned document, a document without a timestamp, or a document sealed at a weaker profile than
the one configured. If the achieved profile does not match the requested one, that is a failure,
not a downgrade.

**Never trust the document.** ``validate`` takes its trust roots from settings and only from
settings. A certificate embedded in the file is material for building a path, never a reason to
believe one -- and the same holds for the revocation data in the document security store, which
``validate`` does read (that is why ``PAdES-B-LT`` embeds it: so revocation can be decided offline
years from now) but reads as evidence to check the chain against, under ``hard-fail``, rooted in the
configured trust store. ``validate`` never raises: a shredded, unsigned or forged PDF comes back as
a failing :class:`SealValidation` with a problem string saying exactly what was wrong.
"""

from __future__ import annotations

import binascii
import io
import re
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID

from asn1crypto import cms as asn1_cms  # type: ignore[import-untyped]
from asn1crypto import x509 as asn1_x509
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.ades.report import AdESFailure, AdESIndeterminate
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.fields import MDPPerm, SigSeedSubFilter, enumerate_sig_fields
from pyhanko.sign.validation import (
    EmbeddedPdfSignature,
    PdfSignatureStatus,
    SignatureCoverageLevel,
    read_certification_data,
    validate_pdf_signature,
)
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko.sign.validation.errors import NoDSSFoundError, ValidationInfoReadingError
from pyhanko_certvalidator import ValidationContext

from esign.config import Settings
from esign.contracts import (
    Clock,
    IntegrityFailure,
    SealProfile,
    SealResult,
    SealUnavailable,
    SealValidation,
    ValidationFailed,
)
from esign.logging import get_logger

from .keys import SigningMaterial, cert_sha256, load_signing_material, load_trust_roots
from .problems import Problem
from .timestamps import build_timestamper

__all__ = ["SEAL_FIELD_NAME", "PadesSealer"]

log = get_logger(__name__)

#: The single signature field this service ever creates.
SEAL_FIELD_NAME: Final = "EsignSeal"

#: Digest used for the signature and the timestamp imprint.
_MD_ALGORITHM: Final = "sha256"

#: Upper bound on the caller-supplied ``reason`` string that goes into the signature dictionary.
_MAX_REASON_LENGTH: Final = 200

#: Control characters are not a reason; nor are bidi overrides. Both exist to make a PDF viewer
#: display something other than what the bytes say.
_REASON_FORBIDDEN: Final = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]")

#: How far ahead of our own clock a timestamp may claim to be before we call it a forgery.
_FUTURE_TIMESTAMP_TOLERANCE: Final = timedelta(minutes=5)

#: Profiles that must embed revocation information.
_LONG_TERM_PROFILES: Final[frozenset[str]] = frozenset({"PAdES-B-LT", "PAdES-B-LTA"})

#: AdES sub-indications that mean a certificate in the chain was withdrawn. ``REVOKED_NO_POE`` and
#: ``REVOKED_CA_NO_POE`` are "revoked, and we cannot prove the signature predates the revocation",
#: which for a seal is the same answer: do not believe it.
_REVOKED_INDICATIONS: Final[frozenset[object]] = frozenset(
    {
        AdESFailure.REVOKED,
        AdESIndeterminate.REVOKED_NO_POE,
        AdESIndeterminate.REVOKED_CA_NO_POE,
    }
)

#: Sub-indications that mean revocation could not be decided from what the document carries.
_REVOCATION_UNKNOWN_INDICATIONS: Final[frozenset[object]] = frozenset(
    {
        AdESIndeterminate.TRY_LATER,
        AdESIndeterminate.REVOCATION_OUT_OF_BOUNDS_NO_POE,
        AdESIndeterminate.OUT_OF_BOUNDS_NOT_REVOKED,
    }
)

#: Problems that mean "this document is not locked down", which is what ``covers_whole_document``
#: asserts. See the note where it is set.
_STRUCTURAL: Final[frozenset[str]] = frozenset(
    {
        Problem.MULTIPLE_SIGNATURES,
        Problem.NOT_A_CERTIFICATION_SIGNATURE,
        Problem.CERTIFICATION_PERMITS_CHANGES,
    }
)


class PadesSealer:
    """The ``Sealer`` implementation. Build it with :func:`esign.sealing.build_sealer`."""

    def __init__(self, settings: Settings, clock: Clock) -> None:
        self._settings = settings
        self._clock = clock
        self._material: SigningMaterial | None = None

    # ----------------------------------------------------------------- sealing

    def seal(self, pdf: bytes, *, reason: str, envelope_id: UUID) -> SealResult:
        """Apply the organisation seal. Raises ``ValidationFailed`` or ``SealUnavailable`` only."""
        clean_reason = _check_reason(reason)
        _reject_unsealable(pdf)

        profile: SealProfile = self._settings.seal_profile
        material = self._signing_material()
        timestamper = build_timestamper(self._settings, self._clock, material)
        validation_context = self._signing_validation_context(material, profile)

        try:
            writer = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=True)
            meta = signers.PdfSignatureMetadata(
                field_name=SEAL_FIELD_NAME,
                md_algorithm=_MD_ALGORITHM,
                reason=clean_reason,
                # Binds the seal to the envelope it completes: the id is inside the signed bytes.
                location=f"envelope:{envelope_id}",
                subfilter=SigSeedSubFilter.PADES,
                certify=True,
                docmdp_permissions=MDPPerm.NO_CHANGES,
                embed_validation_info=profile in _LONG_TERM_PROFILES,
                use_pades_lta=profile == "PAdES-B-LTA",
                validation_context=validation_context,
            )
            output = signers.sign_pdf(writer, meta, material.signer, timestamper=timestamper)
            sealed = output.getvalue()
        except (ValidationFailed, SealUnavailable):
            raise
        except IntegrityFailure:
            # Nothing in this call graph raises it today, but ``IntegrityFailure`` means stored
            # evidence does not match its hash, and contracts.py says never to swallow it. It must
            # not be flattened into a retryable "seal unavailable" by the catch-all below.
            raise
        except PdfError as exc:
            # The writer choked on the input we were handed, not on the infrastructure.
            raise ValidationFailed("the document could not be prepared for sealing", code="malformed_pdf") from exc
        except Exception as exc:
            # Contract: nothing but ValidationFailed and SealUnavailable escapes `seal`. Anything
            # unexpected is treated as "we did not seal", which keeps the envelope pending.
            log.error("seal.failed", envelope_id=envelope_id, error_code="seal_unavailable", seal_profile=profile)
            raise SealUnavailable("sealing failed", code="seal_unavailable") from exc

        timestamp_time = self._confirm_seal(sealed, profile, envelope_id)

        log.info(
            "seal.applied",
            envelope_id=envelope_id,
            seal_profile=profile,
            key_backend=material.backend,
            cert_sha256=material.signing_cert_sha256,
            size_bytes=len(sealed),
        )
        return SealResult(
            sealed_pdf=sealed,
            profile=profile,
            signer_cert_sha256=material.signing_cert_sha256,
            timestamp_time=timestamp_time,
        )

    # ----------------------------------------------------------------- validation

    def validate(self, pdf: bytes) -> SealValidation:
        """Re-check a sealed document against the configured trust roots. Never raises."""
        try:
            return self._validate(pdf)
        except Exception:  # the contract is that nothing escapes validate()
            log.error("seal.validate_error", problem=Problem.VALIDATION_ERROR)
            return _failed(Problem.VALIDATION_ERROR)

    def _validate(self, pdf: bytes) -> SealValidation:
        try:
            trust_roots = load_trust_roots(self._settings.trust_roots_path)
        except (OSError, ValueError):
            # Without trust roots nothing can be trusted. That is a failure, not a pass.
            log.error("seal.trust_roots_unavailable", problem=Problem.TRUST_ROOTS_UNAVAILABLE)
            return _failed(Problem.TRUST_ROOTS_UNAVAILABLE)

        try:
            reader = PdfFileReader(io.BytesIO(pdf), strict=False)
        except (PdfError, ValueError, OSError):
            return _failed(Problem.MALFORMED_PDF)

        if reader.security_handler is not None:
            return _failed(Problem.ENCRYPTED_PDF)

        try:
            signatures = list(reader.embedded_regular_signatures)
        except Exception:
            # Damaged bytes surface as anything from a PdfError to a decimal parse error. Which
            # half is broken still matters: a CMS container that will not decode is a different
            # story from a document whose objects no longer read.
            return _failed(
                Problem.SIGNATURE_MALFORMED if not _signature_container_parses(pdf) else Problem.MALFORMED_PDF
            )

        if not signatures:
            return _failed(Problem.NOT_SIGNED)

        problems: list[str] = []
        if len(signatures) > 1:
            # Our seal is the only signature that may ever be present. Report it and keep going,
            # so the caller also learns whether the first one was even intact.
            problems.append(Problem.MULTIPLE_SIGNATURES)

        signature = signatures[0]
        claimed_time = _signature_timestamp(signature)
        context, context_problems = self._validating_context(reader, trust_roots, claimed_time)
        problems.extend(context_problems)

        try:
            status = validate_pdf_signature(
                signature,
                signer_validation_context=context,
                ts_validation_context=context,
            )
        except Exception:
            # The CMS decoded (the signature objects were built above), so whatever broke here
            # belongs to the document rather than to the signature.
            return _failed(Problem.MALFORMED_PDF, *problems)

        revocation = _revocation_problems(status)
        problems.extend(revocation)
        problems.extend(self._certification_problems(reader, signature))
        intact = bool(status.intact and status.valid)
        if not status.intact:
            problems.append(Problem.BYTE_RANGE_DIGEST_MISMATCH)
        elif not status.valid:
            problems.append(Problem.SIGNATURE_INVALID)

        covers, coverage_problems = _coverage(pdf, reader, status)
        problems.extend(coverage_problems)

        trusted = bool(status.trusted)
        if intact and not trusted and not revocation:
            # A revoked certificate is untrusted too, but "revoked" is the reason; saying both
            # would blur the one story that matters into the generic one.
            problems.append(Problem.UNTRUSTED_CHAIN)

        timestamp_valid, signing_time, timestamp_problems = self._timestamp(status)
        problems.extend(timestamp_problems)

        return SealValidation(
            intact=intact,
            # ``SealValidation.ok`` already refuses any result that carries a problem. The problems
            # in _STRUCTURAL additionally clear this flag, because they all say the same thing --
            # the document is not locked against further change -- and a reader of the flags alone
            # should see that too.
            covers_whole_document=covers and not any(problem in _STRUCTURAL for problem in problems),
            trusted=trusted,
            timestamp_valid=timestamp_valid,
            profile=_detect_profile(reader, timestamp_present=status.timestamp_validity is not None),
            signer_cert_sha256=cert_sha256(status.signing_cert),
            signing_time=signing_time,
            problems=tuple(dict.fromkeys(problems)),
        )

    # ----------------------------------------------------------------- internals

    def _signing_material(self) -> SigningMaterial:
        """Key material, loaded once and kept. Loading failures are ``SealUnavailable``."""
        if self._material is None:
            self._material = load_signing_material(self._settings)
        return self._material

    def _signing_validation_context(self, material: SigningMaterial, profile: SealProfile) -> ValidationContext:
        """The context pyHanko uses to gather revocation info while signing.

        ``hard-fail`` on purpose for the long-term profiles: if revocation information cannot be
        assembled, sealing must fail rather than quietly emit a file with an empty DSS that claims
        to be B-LT.
        """
        trust_roots = list(self._signing_trust_roots(material))
        if profile == "PAdES-B-T":
            return ValidationContext(
                trust_roots=trust_roots,
                allow_fetching=False,
                revocation_mode="soft-fail",
                moment=self._clock.now(),
            )

        crls = list(material.dev_pki.crls) if material.dev_pki is not None else []
        return ValidationContext(
            trust_roots=trust_roots,
            # The dev PKI ships its own CRLs, so nothing needs fetching. A KMS deployment has a
            # real CA whose revocation endpoints must be reachable; failures there surface as
            # SealUnavailable, which is the point.
            allow_fetching=material.dev_pki is None,
            crls=crls,
            revocation_mode="hard-fail",
            moment=None if material.dev_pki is None else self._clock.now(),
        )

    def _signing_trust_roots(self, material: SigningMaterial) -> tuple[asn1_x509.Certificate, ...]:
        """Roots used while *building* the seal, to gather revocation info for our own chain.

        The configured trust store is the authority here too, so that a document is sealed against
        the same roots it will later be validated against. The chain's own tail is a fallback for
        a deployment that has not laid the trust store down yet.
        """
        try:
            return load_trust_roots(self._settings.trust_roots_path)
        except (OSError, ValueError):
            return tuple(material.chain[-1:]) if material.chain else ()

    def _validating_context(
        self,
        reader: PdfFileReader,
        trust_roots: tuple[asn1_x509.Certificate, ...],
        claimed_time: datetime | None,
    ) -> tuple[ValidationContext, list[str]]:
        """Point-in-time validation context, built from the document's own revocation data.

        A seal has to keep validating for the whole retention period, long after the signing
        certificate expires, so the chain is checked at the time the RFC 3161 authority attests
        rather than at today's date. That time is taken from the document, so it is capped: a
        token claiming a time beyond our own clock is rejected outright below.

        The revocation data is the reason ``PAdES-B-LT`` embeds a document security store in the
        first place: so that "was this certificate revoked when it signed?" can be answered offline
        years later, with no CRL or OCSP endpoint still standing. ``validate_pdf_signature`` does
        *not* read the DSS by itself -- so a bare soft-fail context meant the embedded data was
        never consulted by anything: not by ``Sealer.validate`` right after sealing, not by
        ``esign verify``, not by ``GET /verification``. A seal made with a certificate revoked
        before its timestamp validated clean. So the store is loaded and the context is built from
        it, under ``hard-fail``: "we could not tell" is not a pass.

        A document with no store is soft-fail -- but only when a long-term profile was not the
        expectation. ``PAdES-B-T`` is the dev and test profile and carries no revocation data by
        design; a deployment configured for ``B-LT`` that is handed a document without a store gets
        ``revocation_unknown``, not a shrug.
        """
        now = self._clock.now()
        moment = claimed_time if claimed_time is not None and claimed_time <= now else now
        kwargs: dict[str, object] = {
            "trust_roots": list(trust_roots),
            # Never: a validator that reaches the network answers a different question every time
            # it runs, and stops answering at all once the endpoints are gone.
            "allow_fetching": False,
            "moment": moment,
        }
        store = _read_dss(reader)
        if store is None:
            if self._settings.seal_profile in _LONG_TERM_PROFILES:
                log.error("seal.revocation_data_missing", problem=Problem.REVOCATION_UNKNOWN)
                return ValidationContext(revocation_mode="soft-fail", **kwargs), [Problem.REVOCATION_UNKNOWN]  # type: ignore[arg-type]
            return ValidationContext(revocation_mode="soft-fail", **kwargs), []  # type: ignore[arg-type]
        return store.as_validation_context({**kwargs, "revocation_mode": "hard-fail"}), []

    def _certification_problems(self, reader: PdfFileReader, signature: EmbeddedPdfSignature) -> list[str]:
        certification = read_certification_data(reader)
        if certification is None:
            return [Problem.NOT_A_CERTIFICATION_SIGNATURE]
        if certification.author_sig != signature.sig_object:
            return [Problem.NOT_A_CERTIFICATION_SIGNATURE]
        if certification.permission != MDPPerm.NO_CHANGES:
            return [Problem.CERTIFICATION_PERMITS_CHANGES]
        return []

    def _timestamp(self, status: PdfSignatureStatus) -> tuple[bool, datetime | None, list[str]]:
        """``signing_time`` is only ever an attested time.

        A signature also carries a ``signingTime`` the signer wrote itself, and a timestamp token
        that did not verify still contains a time. Neither is evidence of when anything happened,
        so neither is reported: when the timestamp fails, ``signing_time`` is ``None``.
        """
        ts = status.timestamp_validity
        if ts is None:
            return False, None, [Problem.TIMESTAMP_MISSING]
        if not (ts.intact and ts.valid and ts.trusted):
            return False, None, [Problem.TIMESTAMP_INVALID]
        attested = ts.timestamp.astimezone(UTC)
        if attested > self._clock.now() + _FUTURE_TIMESTAMP_TOLERANCE:
            # A trusted authority does not stamp the future. Something is wrong with one of the
            # two clocks, and we are not the one to assume it is ours.
            return False, None, [Problem.TIMESTAMP_INVALID]
        return True, attested, []

    def _confirm_seal(self, sealed: bytes, profile: SealProfile, envelope_id: UUID) -> datetime:
        """Check the file we just produced really is what we promised, or refuse to return it."""
        try:
            reader = PdfFileReader(io.BytesIO(sealed), strict=False)
            signatures = list(reader.embedded_regular_signatures)
            certification = read_certification_data(reader)
            has_document_timestamp = bool(reader.embedded_timestamp_signatures)
            has_dss = "/DSS" in reader.root
            timestamp_time = _signature_timestamp(signatures[0]) if signatures else None
            # Read the envelope binding back out of the signed bytes rather than trusting that we
            # asked for it: SPEC section 5 makes ``/Location`` the link between this seal and the
            # envelope it completes, and a binding nobody ever checks is not evidence.
            location = signatures[0].sig_object.get("/Location") if signatures else None
        except (PdfError, ValueError, KeyError, IndexError) as exc:
            raise SealUnavailable("the sealed output could not be re-read", code="seal_unavailable") from exc

        failure = _post_condition_failure(
            signatures=len(signatures),
            certification_permission=None if certification is None else certification.permission,
            timestamp_time=timestamp_time,
            has_dss=has_dss,
            has_document_timestamp=has_document_timestamp,
            profile=profile,
            location=None if location is None else str(location),
            envelope_id=envelope_id,
        )
        if failure is not None or timestamp_time is None:
            log.error(
                "seal.profile_not_achieved",
                envelope_id=envelope_id,
                seal_profile=profile,
                problem=failure or Problem.TIMESTAMP_MISSING,
            )
            raise SealUnavailable(
                "the seal did not achieve the configured profile",
                code="seal_profile_not_achieved",
            )
        return timestamp_time


# --------------------------------------------------------------------------- free functions


def _post_condition_failure(
    *,
    signatures: int,
    certification_permission: MDPPerm | None,
    timestamp_time: datetime | None,
    has_dss: bool,
    has_document_timestamp: bool,
    profile: SealProfile,
    location: str | None,
    envelope_id: UUID,
) -> str | None:
    if signatures != 1:
        return Problem.MULTIPLE_SIGNATURES if signatures > 1 else Problem.NOT_SIGNED
    if certification_permission is None:
        return Problem.NOT_A_CERTIFICATION_SIGNATURE
    if certification_permission != MDPPerm.NO_CHANGES:
        return Problem.CERTIFICATION_PERMITS_CHANGES
    if location != f"envelope:{envelope_id}":
        return Problem.LOCATION_MISMATCH
    if timestamp_time is None:
        return Problem.TIMESTAMP_MISSING
    if profile in _LONG_TERM_PROFILES and not has_dss:
        return Problem.VALIDATION_ERROR
    if profile == "PAdES-B-LTA" and not has_document_timestamp:
        return Problem.VALIDATION_ERROR
    return None


def _read_dss(reader: PdfFileReader) -> DocumentSecurityStore | None:
    """The document's own security store, or ``None`` when it has none (or an unreadable one)."""
    try:
        return DocumentSecurityStore.read_dss(reader)
    except (NoDSSFoundError, ValidationInfoReadingError, PdfError, ValueError, KeyError):
        return None


def _revocation_problems(status: PdfSignatureStatus) -> list[str]:
    """What the validator concluded about revocation, in this module's vocabulary.

    ``trusted`` alone does not say which question failed, and "revoked" and "unknown" are very
    different stories to tell a court: one says the key was withdrawn before it signed, the other
    says the evidence needed to decide is not in the file.
    """
    if status.revocation_details is not None:
        return [Problem.CERTIFICATE_REVOKED]
    indication = status.trust_problem_indic
    if indication in _REVOKED_INDICATIONS:
        return [Problem.CERTIFICATE_REVOKED]
    if indication in _REVOCATION_UNKNOWN_INDICATIONS:
        return [Problem.REVOCATION_UNKNOWN]
    return []


def _check_reason(reason: str) -> str:
    text = reason.strip()
    if not text or len(text) > _MAX_REASON_LENGTH or _REASON_FORBIDDEN.search(text):
        raise ValidationFailed("the sealing reason is empty, too long or contains control characters")
    return text


def _reject_unsealable(pdf: bytes) -> None:
    """The input must be an unencrypted PDF that nobody has signed and that holds no sig fields."""
    try:
        reader = PdfFileReader(io.BytesIO(pdf), strict=False)
        if reader.security_handler is not None:
            raise ValidationFailed("an encrypted PDF cannot be sealed", code="encrypted_pdf")
        if reader.embedded_signatures:
            raise ValidationFailed("this document is already signed", code="already_signed")
        if any(True for _ in enumerate_sig_fields(reader)):
            raise ValidationFailed("this document already has signature fields", code="already_signed")
    except ValidationFailed:
        raise
    except (PdfError, ValueError, KeyError, OSError) as exc:
        raise ValidationFailed("the document is not a readable PDF", code="malformed_pdf") from exc


def _coverage(pdf: bytes, reader: PdfFileReader, status: PdfSignatureStatus) -> tuple[bool, list[str]]:
    """Does the signature account for every byte in the file?

    ``ENTIRE_FILE`` is the easy yes. A B-LT or B-LTA seal legitimately carries later revisions
    holding the document security store and archive timestamps, which pyHanko classifies as
    ``LTA_UPDATES``; anything above that level is someone editing a document that says no changes
    are permitted. When the classification is unavailable we fail closed rather than assume.
    """
    problems: list[str] = []
    if _has_unaccounted_tail(pdf, reader):
        # Bytes past the end of the last revision a reader recognises are invisible to the diff
        # analysis -- a whole second PDF can hide there -- and nobody signed them.
        problems.append(Problem.CONTENT_APPENDED_AFTER_SEAL)

    coverage = status.coverage
    if coverage == SignatureCoverageLevel.ENTIRE_FILE:
        return not problems, problems

    if coverage != SignatureCoverageLevel.ENTIRE_REVISION:
        problems.append(Problem.CONTENT_APPENDED_AFTER_SEAL)
        if status.docmdp_ok is False:
            problems.append(Problem.DOCMDP_VIOLATION)
        return False, problems

    level = status.modification_level
    if level is None:
        problems.append(Problem.COVERAGE_UNDETERMINED)
        return False, problems
    if level > ModificationLevel.LTA_UPDATES:
        problems.append(Problem.CONTENT_APPENDED_AFTER_SEAL)
    if not status.docmdp_ok:
        problems.append(Problem.DOCMDP_VIOLATION)
    return not problems, problems


def _signature_container_parses(pdf: bytes) -> bool:
    """Do the bytes in the first ``/Contents <...>`` decode as a CMS object?

    Only used to choose between two failure labels once something has already gone wrong, so it
    is deliberately literal-minded: find the hex string, unwrap it, ask asn1crypto.
    """
    marker = pdf.find(b"/Contents <")
    if marker < 0:
        return False
    start = pdf.find(b"<", marker) + 1
    end = pdf.find(b">", start)
    if start <= 0 or end < 0:
        return False
    try:
        raw = binascii.unhexlify(pdf[start:end].strip())
        decoded = asn1_cms.ContentInfo.load(raw.rstrip(b"\x00"))
        _ = decoded.native
    except Exception:
        return False
    return True


def _has_unaccounted_tail(pdf: bytes, reader: PdfFileReader) -> bool:
    """Is there anything in the file past the terminator of the last revision the reader saw?

    Concatenating a second PDF onto a sealed one leaves the reader -- and therefore pyHanko's
    diff analysis -- looking only at the first document, because the final ``startxref`` still
    points into it. Another tool may well show the second. So the check is positional: find where
    the last known revision ends, find its ``%%EOF``, and require nothing but whitespace after.
    """
    try:
        xrefs = reader.xrefs
        last_end = max(
            xrefs.get_xref_container_info(revision).end_location for revision in range(xrefs.total_revisions)
        )
    except Exception:
        last_end = 0

    marker = pdf.find(b"%%EOF", last_end)
    if marker < 0:
        # No end-of-file marker after the last revision at all.
        return True
    return pdf[marker + len(b"%%EOF") :].strip() != b""


def _signature_timestamp(signature: EmbeddedPdfSignature) -> datetime | None:
    """The time the RFC 3161 authority attested, read straight out of the token.

    Reading it does not mean believing it: the token's own signature and chain are checked by
    ``validate``, and the time is capped by our clock before it is used for anything.
    """
    try:
        unsigned = signature.signer_info["unsigned_attrs"]
        if not unsigned or unsigned.native is None:
            return None
        for attribute in unsigned:
            if attribute["type"].native != "signature_time_stamp_token":
                continue
            token = attribute["values"][0]
            if not isinstance(token, asn1_cms.ContentInfo):
                token = asn1_cms.ContentInfo.load(token.dump())
            tst_info = token["content"]["encap_content_info"]["content"].parsed
            generated: datetime = tst_info["gen_time"].native
            if generated.tzinfo is None:
                # A time with no zone is not evidence of anything. Refuse to guess one.
                return None
            return generated.astimezone(UTC)
    except (ValueError, KeyError, TypeError, IndexError):
        return None
    return None


def _detect_profile(reader: PdfFileReader, *, timestamp_present: bool) -> SealProfile | None:
    if not timestamp_present:
        return None
    if reader.embedded_timestamp_signatures:
        return "PAdES-B-LTA"
    if "/DSS" in reader.root:
        return "PAdES-B-LT"
    return "PAdES-B-T"


def _failed(*problems: str) -> SealValidation:
    return SealValidation(
        intact=False,
        covers_whole_document=False,
        trusted=False,
        timestamp_valid=False,
        profile=None,
        signer_cert_sha256=None,
        signing_time=None,
        problems=tuple(dict.fromkeys(problems)),
    )
