"""Sealing a document, and what the result has to be.

SPEC section 5: a certification signature, DocMDP "no changes", an RFC 3161 timestamp, and the
profile actually achieved reported back. These tests hold the sealer to all four.
"""

from __future__ import annotations

import hashlib
import io
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import MDPPerm
from pyhanko.sign.validation import read_certification_data

from esign.clock import FixedClock
from esign.config import SealProfileName, Settings
from esign.contracts import Sealer, SealUnavailable, ValidationFailed
from esign.sealing import SEAL_FIELD_NAME, Problem, build_sealer
from tests.conftest import FROZEN_NOW
from tests.sealing.conftest import Pki, make_pdf, make_settings
from tests.sealing.helpers import sign_with

PROFILES: tuple[SealProfileName, ...] = ("PAdES-B-T", "PAdES-B-LT", "PAdES-B-LTA")


@pytest.fixture(params=PROFILES)
def profile(request: pytest.FixtureRequest) -> SealProfileName:
    return request.param  # type: ignore[no-any-return]


def test_seal_then_validate_is_ok_for_every_profile(dev_pki: Pki, clock: FixedClock, profile: SealProfileName) -> None:
    sealer = build_sealer(make_settings(dev_pki, seal_profile=profile), clock)
    result = sealer.seal(make_pdf(pages=2), reason="Envelope completed", envelope_id=uuid4())

    assert result.profile == profile
    report = sealer.validate(result.sealed_pdf)
    assert report.problems == ()
    assert report.ok is True
    assert report.intact and report.covers_whole_document and report.trusted and report.timestamp_valid
    assert report.profile == profile


def test_reports_the_certificate_that_actually_signed(sealer: Sealer, dev_pki: Pki, pdf: bytes) -> None:
    result = sealer.seal(pdf, reason="Envelope completed", envelope_id=uuid4())
    expected = hashlib.sha256(dev_pki.pki.seal_cert.public_bytes(serialization.Encoding.DER)).digest()
    assert result.signer_cert_sha256 == expected
    assert sealer.validate(result.sealed_pdf).signer_cert_sha256 == expected


def test_timestamp_comes_from_the_authority_not_the_wall_clock(dev_pki: Pki) -> None:
    """Evidence is only as good as its times, and the time is the TSA's, taken from our Clock."""
    clock = FixedClock(FROZEN_NOW)
    sealer = build_sealer(make_settings(dev_pki), clock)
    result = sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
    assert result.timestamp_time == FROZEN_NOW
    assert sealer.validate(result.sealed_pdf).signing_time == FROZEN_NOW


def test_seal_is_a_certification_signature_permitting_no_changes(sealer: Sealer, pdf: bytes) -> None:
    result = sealer.seal(pdf, reason="Envelope completed", envelope_id=uuid4())
    reader = PdfFileReader(io.BytesIO(result.sealed_pdf))
    certification = read_certification_data(reader)
    assert certification is not None
    assert certification.permission == MDPPerm.NO_CHANGES


def test_seal_adds_exactly_one_signature(sealer: Sealer, pdf: bytes) -> None:
    result = sealer.seal(pdf, reason="Envelope completed", envelope_id=uuid4())
    reader = PdfFileReader(io.BytesIO(result.sealed_pdf))
    signatures = reader.embedded_regular_signatures
    assert len(signatures) == 1
    assert signatures[0].field_name == SEAL_FIELD_NAME


def test_seal_does_not_mutate_its_input(sealer: Sealer, pdf: bytes) -> None:
    before = bytes(pdf)
    sealer.seal(pdf, reason="Envelope completed", envelope_id=uuid4())
    assert pdf == before


def test_sealing_the_same_document_twice_produces_two_valid_seals(sealer: Sealer, pdf: bytes) -> None:
    """The seal job may run more than once; each attempt must stand on its own."""
    first = sealer.seal(pdf, reason="Envelope completed", envelope_id=uuid4())
    second = sealer.seal(pdf, reason="Envelope completed", envelope_id=uuid4())
    assert sealer.validate(first.sealed_pdf).ok
    assert sealer.validate(second.sealed_pdf).ok


def test_an_unsealed_document_is_reported_as_unsigned(sealer: Sealer, pdf: bytes) -> None:
    report = sealer.validate(pdf)
    assert report.ok is False
    assert report.problems == (Problem.NOT_SIGNED,)
    assert report.profile is None
    assert report.signer_cert_sha256 is None


def test_long_term_profiles_embed_validation_information(dev_pki: Pki, clock: FixedClock) -> None:
    """B-LT claims embedded revocation data. If it is not there, the claim is a lie."""
    sealer = build_sealer(make_settings(dev_pki, seal_profile="PAdES-B-LT"), clock)
    result = sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
    reader = PdfFileReader(io.BytesIO(result.sealed_pdf))
    assert "/DSS" in reader.root
    assert not reader.embedded_timestamp_signatures


def test_lta_adds_a_document_timestamp(dev_pki: Pki, clock: FixedClock) -> None:
    sealer = build_sealer(make_settings(dev_pki, seal_profile="PAdES-B-LTA"), clock)
    result = sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
    reader = PdfFileReader(io.BytesIO(result.sealed_pdf))
    assert reader.embedded_timestamp_signatures


def test_b_t_is_an_explicit_choice_not_a_downgrade(dev_pki: Pki, clock: FixedClock) -> None:
    """A B-T seal is only ever produced when SEAL_PROFILE says so, and it says so in the result."""
    sealer = build_sealer(make_settings(dev_pki, seal_profile="PAdES-B-T"), clock)
    result = sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
    assert result.profile == "PAdES-B-T"
    reader = PdfFileReader(io.BytesIO(result.sealed_pdf))
    assert "/DSS" not in reader.root


# --------------------------------------------------------------------------- refusing bad input


def test_already_signed_documents_are_refused(sealer: Sealer, dev_pki: Pki, pdf: bytes) -> None:
    """Appending a second signature to a certified document is not something we do."""
    signed = sign_with(dev_pki, pdf, field_name="SomeoneElse", certify=False)
    with pytest.raises(ValidationFailed) as caught:
        sealer.seal(signed, reason="Envelope completed", envelope_id=uuid4())
    assert caught.value.code == "already_signed"


def test_documents_with_empty_signature_fields_are_refused(sealer: Sealer, pdf: bytes) -> None:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.fields import SigFieldSpec, append_signature_field

    writer = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
    append_signature_field(writer, SigFieldSpec(sig_field_name="Waiting", on_page=0, box=(10, 10, 100, 50)))
    buffer = io.BytesIO()
    writer.write(buffer)  # type: ignore[no-untyped-call]

    with pytest.raises(ValidationFailed) as caught:
        sealer.seal(buffer.getvalue(), reason="Envelope completed", envelope_id=uuid4())
    assert caught.value.code == "already_signed"


def test_encrypted_documents_are_refused(sealer: Sealer, pdf: bytes) -> None:
    from pypdf import PdfReader, PdfWriter

    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(pdf)))
    writer.encrypt("not-a-real-password")
    buffer = io.BytesIO()
    writer.write(buffer)

    with pytest.raises(ValidationFailed) as caught:
        sealer.seal(buffer.getvalue(), reason="Envelope completed", envelope_id=uuid4())
    assert caught.value.code == "encrypted_pdf"


@pytest.mark.parametrize("payload", [b"", b"not a pdf at all", b"%PDF-1.7\nbroken"])
def test_malformed_input_is_refused(sealer: Sealer, payload: bytes) -> None:
    with pytest.raises(ValidationFailed) as caught:
        sealer.seal(payload, reason="Envelope completed", envelope_id=uuid4())
    assert caught.value.code == "malformed_pdf"


@pytest.mark.parametrize("reason", ["", "   ", "x" * 201, "line\nbreak", "bell\x07"])
def test_the_reason_string_is_bounded(sealer: Sealer, pdf: bytes, reason: str) -> None:
    """The reason ends up inside the signature dictionary, so it is checked like any input."""
    with pytest.raises(ValidationFailed):
        sealer.seal(pdf, reason=reason, envelope_id=uuid4())


# --------------------------------------------------------------------------- infrastructure


def test_a_missing_dev_pki_is_seal_unavailable_not_an_unsealed_document(tmp_path: object) -> None:
    settings = make_settings(None)
    sealer = build_sealer(settings, FixedClock(FROZEN_NOW))
    with pytest.raises(SealUnavailable) as caught:
        sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
    assert caught.value.code == "seal_key_unavailable"


def test_an_unreachable_timestamp_authority_is_seal_unavailable(dev_pki: Pki, clock: FixedClock) -> None:
    """TSA down: nothing is produced, and the caller is told to retry. Never an unstamped seal."""
    settings = make_settings(dev_pki, tsa_url="http://127.0.0.1:9/tsa", tsa_timeout_seconds=1.0)
    sealer = build_sealer(settings, clock)
    with pytest.raises(SealUnavailable):
        sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())


def test_production_without_a_timestamp_authority_refuses_to_seal(dev_pki: Pki, clock: FixedClock) -> None:
    """The in-process dummy authority is a development convenience, never a production fallback."""
    settings = make_settings(dev_pki, app_env="prod", tsa_url="")
    sealer = build_sealer(settings, clock)
    with pytest.raises(SealUnavailable) as caught:
        sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
    assert caught.value.code == "tsa_not_configured"


def test_settings_are_read_per_sealer_not_from_the_environment(dev_pki: Pki, clock: FixedClock) -> None:
    """Two sealers with different profiles must not share state through a cached settings object."""
    b_t: Settings = make_settings(dev_pki, seal_profile="PAdES-B-T")
    b_lt: Settings = make_settings(dev_pki, seal_profile="PAdES-B-LT")
    assert build_sealer(b_t, clock).seal(make_pdf(), reason="r", envelope_id=uuid4()).profile == "PAdES-B-T"
    assert build_sealer(b_lt, clock).seal(make_pdf(), reason="r", envelope_id=uuid4()).profile == "PAdES-B-LT"


def test_a_retry_after_an_infrastructure_failure_succeeds(dev_pki: Pki, clock: FixedClock, pdf: bytes) -> None:
    """SPEC section 12: TSA down leaves the envelope pending, and a later attempt seals it."""
    envelope_id = uuid4()
    down = build_sealer(make_settings(dev_pki, tsa_url="http://127.0.0.1:9/tsa", tsa_timeout_seconds=1.0), clock)
    with pytest.raises(SealUnavailable):
        down.seal(pdf, reason="Envelope completed", envelope_id=envelope_id)

    clock.advance(60)
    recovered = build_sealer(make_settings(dev_pki), clock)
    result = recovered.seal(pdf, reason="Envelope completed", envelope_id=envelope_id)
    assert recovered.validate(result.sealed_pdf).ok is True
    assert result.timestamp_time == clock.now()


@pytest.mark.parametrize("reason", ["bidi ‮override", "zero​width", "c1 \u0085control"])
def test_reasons_that_would_misrepresent_the_document_are_refused(sealer: Sealer, pdf: bytes, reason: str) -> None:
    """The reason is rendered by PDF viewers; it does not get to lie about what was signed."""
    with pytest.raises(ValidationFailed):
        sealer.seal(pdf, reason=reason, envelope_id=uuid4())


def test_development_on_the_local_key_still_gets_the_in_process_authority(dev_pki: Pki, clock: FixedClock) -> None:
    """The allowance that remains: ``APP_ENV=dev`` on the dev PKI's own key, offline."""
    sealer = build_sealer(make_settings(dev_pki, app_env="dev", tsa_url=""), clock)
    result = sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
    assert result.timestamp_time == clock.now()
