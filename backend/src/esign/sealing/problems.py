"""The vocabulary ``Sealer.validate`` reports failures in.

Every string here is stable, machine-readable and safe to log, put in an audit event or show in a
verification report. They exist as constants so that a test can assert on the exact reason a
document failed rather than on "it failed somehow": a flipped byte and an untrusted CA are very
different stories to tell a court, and the codebase should not be able to confuse them.
"""

from __future__ import annotations

from typing import Final

__all__ = ["PROBLEMS", "Problem"]


class Problem:
    """Namespace of problem strings. Not an enum: these travel as plain strings."""

    #: The bytes are not a PDF, or are damaged badly enough that no reader can open them.
    MALFORMED_PDF: Final = "malformed_pdf"

    #: The PDF is encrypted; the seal covers cleartext bytes and nothing else.
    ENCRYPTED_PDF: Final = "encrypted_pdf"

    #: No signature at all -- including a document whose signature was stripped out.
    NOT_SIGNED: Final = "not_signed"

    #: More than one regular signature. Our seal is the only one there may ever be.
    MULTIPLE_SIGNATURES: Final = "multiple_signatures"

    #: The signature object itself will not parse (a byte flipped inside the CMS container).
    SIGNATURE_MALFORMED: Final = "signature_malformed"

    #: The signed byte ranges no longer hash to the value in the signature: content was altered.
    BYTE_RANGE_DIGEST_MISMATCH: Final = "byte_range_digest_mismatch"

    #: The CMS signature does not verify under the signer's public key.
    SIGNATURE_INVALID: Final = "signature_invalid"

    #: Bytes exist that the signature does not cover, and they are not an LTA update.
    CONTENT_APPENDED_AFTER_SEAL: Final = "content_appended_after_seal"

    #: The signature covers a revision, but the diff could not be classified. Fail closed.
    COVERAGE_UNDETERMINED: Final = "coverage_undetermined"

    #: The document was changed in a way DocMDP level 1 forbids.
    DOCMDP_VIOLATION: Final = "docmdp_violation"

    #: The signature is an ordinary approval signature, not a certification signature.
    NOT_A_CERTIFICATION_SIGNATURE: Final = "not_a_certification_signature"

    #: Certified, but at a permission level that allows changes.
    CERTIFICATION_PERMITS_CHANGES: Final = "certification_permits_changes"

    #: The chain does not reach a root in the configured trust roots. Embedded certs never count.
    UNTRUSTED_CHAIN: Final = "untrusted_chain"

    #: The configured trust roots could not be read, so nothing can be trusted. Fail closed.
    TRUST_ROOTS_UNAVAILABLE: Final = "trust_roots_unavailable"

    #: No RFC 3161 signature timestamp is embedded.
    TIMESTAMP_MISSING: Final = "timestamp_missing"

    #: A timestamp is present but does not verify, or its TSA is not trusted.
    TIMESTAMP_INVALID: Final = "timestamp_invalid"

    #: A certificate in the chain was revoked -- and, for a seal, revoked at or before the time the
    #: timestamp authority attested. A compromised or superseded seal key produces a document that
    #: is intact, chains to a trusted root, and must still not be believed.
    CERTIFICATE_REVOKED: Final = "certificate_revoked"

    #: Revocation could not be decided: a long-term document with no document security store, or a
    #: store that does not cover the chain. The whole point of embedding validation info is that
    #: this question is answerable offline years later, so "we could not tell" is a failure.
    REVOCATION_UNKNOWN: Final = "revocation_unknown"

    #: The signature dictionary's ``/Location`` is not ``envelope:<id>`` for the envelope this seal
    #: was meant to complete. The binding SPEC section 5 requires is absent or names something else.
    LOCATION_MISMATCH: Final = "location_mismatch"

    #: Validation itself broke in a way we did not anticipate. Never a pass.
    VALIDATION_ERROR: Final = "validation_error"


PROBLEMS: Final[frozenset[str]] = frozenset(
    value for name, value in vars(Problem).items() if not name.startswith("_") and isinstance(value, str)
)
