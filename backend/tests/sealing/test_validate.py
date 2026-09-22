"""Validation: every way a sealed document can be wrong, and the name we give it.

This is the file a sceptical reviewer reads first. A seal is only worth something if the
validator says no to a document that has been edited, re-signed, stripped, or signed by someone
else's CA -- and says *which* of those happened, because they are very different stories.
"""

from __future__ import annotations

import binascii
import io
from datetime import timedelta
from uuid import uuid4

import pytest
from asn1crypto import cms  # type: ignore[import-untyped]
from pyhanko.sign.fields import MDPPerm
from pypdf import PdfReader, PdfWriter

from esign.clock import FixedClock
from esign.contracts import Sealer, SealValidation
from esign.sealing import PROBLEMS, Problem, build_sealer
from tests.conftest import FROZEN_NOW
from tests.sealing.conftest import Pki, make_pdf, make_settings
from tests.sealing.helpers import revoke_seal_certificate, sign_with


@pytest.fixture
def sealed(sealer: Sealer) -> bytes:
    return sealer.seal(make_pdf(pages=2), reason="Envelope completed", envelope_id=uuid4()).sealed_pdf


def flip(data: bytes, offset: int) -> bytes:
    mutated = bytearray(data)
    mutated[offset] ^= 0x01
    return bytes(mutated)


def contents_span(data: bytes) -> tuple[int, int]:
    """Start and end of the hex-encoded CMS container in ``/Contents <...>``."""
    marker = data.find(b"/Contents <")
    start = data.find(b"<", marker) + 1
    return start, data.find(b">", start)


def assert_failed(report: SealValidation, *expected: str) -> None:
    assert report.ok is False
    assert set(report.problems) <= PROBLEMS, f"undocumented problem string in {report.problems}"
    for problem in expected:
        assert problem in report.problems, f"expected {problem}, got {report.problems}"


# --------------------------------------------------------------------------- a clean seal


def test_a_clean_seal_reports_no_problems(sealer: Sealer, sealed: bytes) -> None:
    assert sealer.validate(sealed).problems == ()


# --------------------------------------------------------------------------- flipped bytes


@pytest.mark.parametrize("offset", [200, 600, 800, 1500])
def test_flipping_a_byte_of_document_content_breaks_the_digest(sealer: Sealer, sealed: bytes, offset: int) -> None:
    """These offsets are inside the original document, which the seal covers byte for byte."""
    report = sealer.validate(flip(sealed, offset))
    assert_failed(report, Problem.BYTE_RANGE_DIGEST_MISMATCH)
    assert report.intact is False


@pytest.mark.parametrize("offset", [100, 400, 1000, 1200])
def test_flipping_a_byte_that_breaks_parsing_is_still_caught(sealer: Sealer, sealed: bytes, offset: int) -> None:
    """Damage that stops the file parsing must fail, not raise and not squeak through."""
    assert_failed(sealer.validate(flip(sealed, offset)), Problem.MALFORMED_PDF)


@pytest.mark.parametrize("part", ["signature", "certificate", "header"])
def test_flipping_a_byte_inside_the_signature_container_is_caught(sealer: Sealer, sealed: bytes, part: str) -> None:
    """A forged CMS blob is not a slightly-worse signature; it is not a signature.

    The container is the one region a signature cannot cover, so the test aims at the bytes the
    CMS actually depends on: the signature value, the signing certificate, and the outer header.
    """
    start, end = contents_span(sealed)
    container = binascii.unhexlify(sealed[start:end].strip())
    content = cms.ContentInfo.load(container.rstrip(b"\x00"))
    signed_data = content["content"]

    if part == "signature":
        target = bytes(signed_data["signer_infos"][0]["signature"].native)
    elif part == "certificate":
        target = signed_data["certificates"][0].chosen.dump()[:64]
    else:
        target = container[:8]

    position = container.find(target)
    assert position >= 0, "could not locate the region to corrupt"
    # Two hex characters per byte, so a byte at `position` starts at `start + 2 * position`.
    report = sealer.validate(flip(sealed, start + 2 * position + 1))
    assert report.ok is False
    assert set(report.problems) <= PROBLEMS
    assert report.problems != ()


def test_flipping_a_byte_in_the_trailer_is_caught(sealer: Sealer, sealed: bytes) -> None:
    report = sealer.validate(flip(sealed, len(sealed) - 20))
    assert report.ok is False
    assert report.problems != ()


def test_truncating_the_file_is_caught(sealer: Sealer, sealed: bytes) -> None:
    assert_failed(sealer.validate(sealed[: len(sealed) // 2]), Problem.MALFORMED_PDF)


def test_every_single_byte_flip_in_the_first_kilobyte_is_caught(sealer: Sealer, sealed: bytes) -> None:
    """A spot check that nothing in the header region slips through unnoticed."""
    for offset in range(0, 1024, 97):
        assert sealer.validate(flip(sealed, offset)).ok is False, offset


# --------------------------------------------------------------------------- appended content


def test_bytes_appended_after_the_final_eof_are_caught(sealer: Sealer, sealed: bytes) -> None:
    """They change nothing a reader renders -- and nobody signed them, so they do not belong."""
    assert_failed(sealer.validate(sealed + b"\n% added later\n"), Problem.CONTENT_APPENDED_AFTER_SEAL)


def test_an_incremental_update_appended_after_the_seal_is_caught(sealer: Sealer, sealed: bytes) -> None:
    writer = PdfWriter(io.BytesIO(sealed), incremental=True)
    writer.add_blank_page(width=200, height=200)
    buffer = io.BytesIO()
    writer.write(buffer)

    report = sealer.validate(buffer.getvalue())
    assert report.ok is False
    assert report.covers_whole_document is False
    assert set(report.problems) & {Problem.CONTENT_APPENDED_AFTER_SEAL, Problem.DOCMDP_VIOLATION}


def test_rewriting_the_whole_file_is_caught(sealer: Sealer, sealed: bytes) -> None:
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(sealed)))
    writer.add_blank_page(width=200, height=200)
    buffer = io.BytesIO()
    writer.write(buffer)

    report = sealer.validate(buffer.getvalue())
    assert report.ok is False
    assert report.covers_whole_document is False


def test_pyhanko_itself_refuses_to_append_to_our_seal(dev_pki: Pki, sealed: bytes) -> None:
    """DocMDP level 1 is not advisory: a conforming signer will not add a second signature."""
    from pyhanko.sign.general import SigningError

    with pytest.raises(SigningError, match="forbids all changes"):
        sign_with(dev_pki, sealed, field_name="Afterwards", certify=False)


def test_a_document_with_two_signatures_is_refused(sealer: Sealer, dev_pki: Pki, pdf: bytes) -> None:
    """Whatever produced it, a file carrying two signatures is not a document we sealed."""
    once = sign_with(dev_pki, pdf, field_name="First", certify=False)
    twice = sign_with(dev_pki, once, field_name="Second", certify=False)
    report = sealer.validate(twice)
    assert_failed(report, Problem.MULTIPLE_SIGNATURES)
    assert report.covers_whole_document is False


# --------------------------------------------------------------------------- removed evidence


def test_a_stripped_signature_is_reported_as_unsigned(sealer: Sealer, sealed: bytes) -> None:
    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(sealed)).pages:
        writer.add_page(page)
    buffer = io.BytesIO()
    writer.write(buffer)

    assert_failed(sealer.validate(buffer.getvalue()), Problem.NOT_SIGNED)


@pytest.mark.parametrize("payload", [b"", b"not a pdf", b"%PDF-1.7\ntruncated"])
def test_rubbish_is_reported_as_malformed_not_as_valid(sealer: Sealer, payload: bytes) -> None:
    assert_failed(sealer.validate(payload), Problem.MALFORMED_PDF)


# --------------------------------------------------------------------------- trust


def test_a_seal_from_another_pki_is_intact_but_untrusted(
    sealer: Sealer, foreign_sealer: Sealer, dev_pki: Pki, foreign_pki: Pki, pdf: bytes
) -> None:
    """The document carries a full, valid chain. That is exactly why it must not be believed.

    The two hierarchies even share their subject names, so this also pins down that trust is
    decided by key, not by what a certificate calls itself.
    """
    assert dev_pki.pki.root_cert.subject == foreign_pki.pki.root_cert.subject

    foreign = foreign_sealer.seal(pdf, reason="Envelope completed", envelope_id=uuid4())
    assert foreign_sealer.validate(foreign.sealed_pdf).ok is True

    report = sealer.validate(foreign.sealed_pdf)
    assert_failed(report, Problem.UNTRUSTED_CHAIN)
    assert report.intact is True
    assert report.trusted is False


def test_a_seal_still_validates_years_later(dev_pki: Pki, sealed: bytes) -> None:
    """Retention is ten years; a signing certificate is not. Validation is point-in-time.

    The chain is checked at the moment the timestamp authority attested, so a seal keeps
    validating after its own certificate has expired -- which is the whole reason for the
    timestamp being there.
    """
    much_later = FixedClock(FROZEN_NOW + timedelta(days=365 * 9))
    report = build_sealer(make_settings(dev_pki), much_later).validate(sealed)
    assert report.problems == ()
    assert report.ok is True
    assert report.signing_time == FROZEN_NOW


def test_missing_trust_roots_fail_closed(dev_pki: Pki, clock: FixedClock, sealed: bytes) -> None:
    """No trust roots means nothing is trusted -- never "trust whatever is in the file"."""
    settings = make_settings(dev_pki, trust_roots_path=dev_pki.directory / "absent.pem")
    report = build_sealer(settings, clock).validate(sealed)
    assert_failed(report, Problem.TRUST_ROOTS_UNAVAILABLE)
    assert report.trusted is False


def test_empty_trust_roots_fail_closed(dev_pki: Pki, clock: FixedClock, sealed: bytes, tmp_path: object) -> None:
    empty = dev_pki.directory / "empty-roots.pem"
    empty.write_bytes(b"")
    settings = make_settings(dev_pki, trust_roots_path=empty)
    assert_failed(build_sealer(settings, clock).validate(sealed), Problem.TRUST_ROOTS_UNAVAILABLE)


# --------------------------------------------------------------------------- the wrong kind of signature


def test_an_approval_signature_is_not_a_seal(sealer: Sealer, dev_pki: Pki, pdf: bytes) -> None:
    approval = sign_with(dev_pki, pdf, certify=False)
    assert_failed(sealer.validate(approval), Problem.NOT_A_CERTIFICATION_SIGNATURE)


def test_a_certification_that_still_allows_form_filling_is_refused(sealer: Sealer, dev_pki: Pki, pdf: bytes) -> None:
    lenient = sign_with(dev_pki, pdf, certify=True, permissions=MDPPerm.FILL_FORMS)
    assert_failed(sealer.validate(lenient), Problem.CERTIFICATION_PERMITS_CHANGES)


def test_a_signature_without_a_timestamp_is_refused(sealer: Sealer, dev_pki: Pki, pdf: bytes) -> None:
    """Without a trusted time there is no proof of *when*, which is half the evidence."""
    untimed = sign_with(dev_pki, pdf, timestamp=False)
    report = sealer.validate(untimed)
    assert_failed(report, Problem.TIMESTAMP_MISSING)
    assert report.timestamp_valid is False
    # The signer's own claim about when it signed is not reported as a signing time.
    assert report.signing_time is None


def test_a_timestamp_from_the_future_is_refused(dev_pki: Pki, sealed: bytes) -> None:
    """A trusted authority does not stamp the future; if it claims to, we do not believe it."""
    earlier = FixedClock(FROZEN_NOW - timedelta(days=1))
    report = build_sealer(make_settings(dev_pki), earlier).validate(sealed)
    assert_failed(report, Problem.TIMESTAMP_INVALID)
    assert report.timestamp_valid is False
    assert report.signing_time is None


# --------------------------------------------------------------------------- the contract itself


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "zeros",
        "head_only",
        "byte_range_renamed",
        "eof_markers_removed",
        "reversed",
        "doubled",
    ],
)
def test_mangled_documents_fail_without_raising(sealer: Sealer, sealed: bytes, mutation: str) -> None:
    """``Sealer.validate`` promises a failing report, never an exception."""
    payloads = {
        "empty": b"",
        "zeros": b"\x00" * 64,
        "head_only": sealed[:10],
        "byte_range_renamed": sealed.replace(b"/ByteRange", b"/ByteRunge"),
        "eof_markers_removed": sealed.replace(b"%%EOF", b""),
        "reversed": bytes(reversed(sealed)),
        "doubled": sealed + sealed,
    }
    report = sealer.validate(payloads[mutation])
    assert report.ok is False
    assert report.problems != ()
    assert set(report.problems) <= PROBLEMS


def test_stripping_the_trailing_newline_is_not_treated_as_tampering(sealer: Sealer, sealed: bytes) -> None:
    """Honesty cuts both ways: whitespace after the final %%EOF is not content."""
    assert sealer.validate(sealed.rstrip()).ok is True


def test_validating_the_same_bytes_twice_gives_the_same_answer(sealer: Sealer, sealed: bytes) -> None:
    first, second = sealer.validate(sealed), sealer.validate(sealed)
    assert first == second


# --------------------------------------------------------------------------- revocation


def test_a_seal_whose_certificate_was_revoked_before_it_signed_is_refused(
    sealer: Sealer, dev_pki: Pki, sealed: bytes
) -> None:
    """A compromised or superseded seal key. The document is otherwise perfect.

    ``PAdES-B-LT`` embeds revocation information precisely so this question can be answered offline
    years later. Nothing used to ask it: the validating context carried no CRLs, no OCSP responses
    and ``soft-fail``, and ``validate_pdf_signature`` does not read the document security store by
    itself -- so a seal made with a revoked certificate came back ``trusted=True, ok=True``.
    """
    revoked = revoke_seal_certificate(dev_pki, sealed, revoked_at=FROZEN_NOW - timedelta(hours=1))

    report = sealer.validate(revoked)
    assert_failed(report, Problem.CERTIFICATE_REVOKED)
    # Intact and self-covering: nothing but the revocation data can refuse this document.
    assert report.intact is True
    assert report.covers_whole_document is True
    assert report.trusted is False
    # "Revoked" is the story, not the generic "untrusted".
    assert Problem.UNTRUSTED_CHAIN not in report.problems


def test_a_long_term_deployment_refuses_a_document_with_no_revocation_data(
    sealer: Sealer, dev_pki: Pki, pdf: bytes
) -> None:
    """Configured for ``PAdES-B-LT``, handed a document with no document security store.

    The signature is intact, trusted and timestamped; what is missing is the evidence needed to say
    whether the certificate was revoked. For a long-term profile "we could not tell" is a failure,
    not a pass, because there is no endpoint left to ask years from now.
    """
    without_dss = sign_with(dev_pki, pdf)
    assert b"/DSS" not in without_dss

    report = sealer.validate(without_dss)
    assert_failed(report, Problem.REVOCATION_UNKNOWN)
    assert report.intact is True
    assert report.profile == "PAdES-B-T"


def test_a_short_term_deployment_still_accepts_its_own_documents(dev_pki: Pki, clock: FixedClock, pdf: bytes) -> None:
    """``PAdES-B-T`` is the explicit dev and test profile and carries no revocation data by design.

    SPEC section 5 allows it only as an explicit setting, never as a silent downgrade -- so a
    deployment that set it gets soft-fail, and one that did not gets ``revocation_unknown`` above.
    """
    settings = make_settings(dev_pki, seal_profile="PAdES-B-T")
    short_term = build_sealer(settings, clock)
    result = short_term.seal(pdf, reason="Envelope completed", envelope_id=uuid4())

    assert result.profile == "PAdES-B-T"
    report = short_term.validate(result.sealed_pdf)
    assert report.problems == ()
    assert report.ok is True
