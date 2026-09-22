"""The certificate of completion: what a court reads when nobody here is available to explain."""

from __future__ import annotations

import io
import re
from dataclasses import replace

from pypdf import PdfReader

from esign.contracts import CertificateSummary, DocumentService, SealProfile
from tests.documents.conftest import certificate_summary


def text_of(pdf: bytes) -> str:
    return "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)


def test_the_certificate_carries_every_field_spec_6_requires(documents: DocumentService) -> None:
    summary = certificate_summary()
    text = text_of(documents.build_certificate(summary))

    assert str(summary.envelope_id) in text
    assert summary.document_type in text
    assert f"{summary.template_key} v{summary.template_version}" in text
    assert summary.presented_sha256.hex() in re.sub(r"\s+", "", text)
    assert summary.final_revision_sha256.hex() in re.sub(r"\s+", "", text)
    assert str(summary.audit_event_count) in text
    assert summary.audit_head_hash.hex() in re.sub(r"\s+", "", text)
    assert "PAdES" in text


def test_every_signer_is_described_in_full(documents: DocumentService) -> None:
    summary = certificate_summary(signers=3)
    text = text_of(documents.build_certificate(summary))
    for signer in summary.signers:
        assert signer.display_name in text
        assert signer.role_label in text
        assert signer.capacity in text
        assert str(signer.signer_id) in text
        assert signer.auth_method in text
        assert signer.consent_version in text
        assert signer.viewed_at.strftime("%Y-%m-%d %H:%M:%S") in text
        assert signer.consented_at.strftime("%Y-%m-%d %H:%M:%S") in text
        assert signer.signed_at.strftime("%Y-%m-%d %H:%M:%S") in text
        assert (signer.ip or "") in text
        assert (signer.user_agent or "")[:20] in text
        if signer.reauth_method:
            assert signer.reauth_method in text
        if signer.kiosk_staff_user_id:
            assert signer.kiosk_staff_user_id in text
            assert (signer.kiosk_identity_check or "") in text


def test_a_signer_without_reauth_says_so_rather_than_leaving_a_blank(documents: DocumentService) -> None:
    text = text_of(documents.build_certificate(certificate_summary(signers=1)))
    assert "not required" in text


def test_it_explains_how_to_verify(documents: DocumentService) -> None:
    text = text_of(documents.build_certificate(certificate_summary()))
    assert "esign verify" in text
    assert "trust root" in text


def test_it_paginates_for_many_signers(documents: DocumentService) -> None:
    few = PdfReader(io.BytesIO(documents.build_certificate(certificate_summary(signers=1)))).pages
    many = PdfReader(io.BytesIO(documents.build_certificate(certificate_summary(signers=14)))).pages
    assert len(few) == 1
    assert len(many) > len(few)
    assert "(continued)" in many[1].extract_text()


def test_every_page_is_numbered(documents: DocumentService) -> None:
    pages = PdfReader(io.BytesIO(documents.build_certificate(certificate_summary(signers=14)))).pages
    for index, page in enumerate(pages, start=1):
        assert f"Page {index}" in page.extract_text()


def test_no_signer_block_is_silently_dropped_when_it_spans_a_page_break(documents: DocumentService) -> None:
    """Pagination must not swallow a signer: all of them, on however many pages it takes."""
    summary = certificate_summary(signers=20)
    text = text_of(documents.build_certificate(summary))
    for signer in summary.signers:
        assert str(signer.signer_id) in text


def test_the_seal_profile_printed_is_the_one_in_the_summary(documents: DocumentService) -> None:
    """The caller passes the *configured* profile (contracts.py); the page never reads settings."""
    profiles: tuple[SealProfile, ...] = ("PAdES-B-T", "PAdES-B-LT", "PAdES-B-LTA")
    for profile in profiles:
        summary = replace(certificate_summary(), seal_profile=profile)
        assert profile in text_of(documents.build_certificate(summary))


def test_the_certificate_has_nothing_interactive(documents: DocumentService) -> None:
    reader = PdfReader(io.BytesIO(documents.build_certificate(certificate_summary())))
    assert "/AcroForm" not in reader.root_object
    for page in reader.pages:
        assert "/Annots" not in page


def test_the_certificate_is_deterministic(documents: DocumentService) -> None:
    summary = certificate_summary(signers=5)
    assert documents.build_certificate(summary) == documents.build_certificate(summary)


def test_nothing_but_the_summary_reaches_the_page(documents: DocumentService) -> None:
    """The input has no chart data in it, which is how "no chart data" is enforced.

    This test pins the shape: if a future change starts pulling from somewhere else, the field
    list on ``CertificateSummary`` is the thing that has to change first, in ``contracts.py``,
    which no module may edit on its own.
    """
    fields = set(CertificateSummary.__dataclass_fields__)
    assert fields == {
        "envelope_id",
        "document_type",
        "template_key",
        "template_version",
        "seal_profile",
        "presented_sha256",
        "final_revision_sha256",
        "created_at",
        "completed_at",
        "signers",
        "audit_event_count",
        "audit_head_hash",
        # Addendum 1 A: the archive variant. `attestation` names the staff member and the paper
        # signers, which is the same class of data as a signer's display name: it is on the page
        # and nowhere else.
        "kind",
        "attestation",
        # Addendum 2: where revision 1 came from. `host_document_ref` is the host's own reference
        # for the document it supplied -- opaque, and already in `document.supplied` on the trail
        # this page is built from, so it is not a new place for chart data to arrive from.
        "source",
        "host_document_ref",
    }


def test_a_long_display_name_does_not_run_off_the_page(documents: DocumentService) -> None:
    summary = certificate_summary(signers=1)
    long_name = "Wolfeschlegelsteinhausenbergerdorff " * 4
    signer = summary.signers[0]
    stretched = CertificateSummary(
        **{
            **{key: getattr(summary, key) for key in CertificateSummary.__dataclass_fields__},
            "signers": (type(signer)(**{**signer.__dict__, "display_name": long_name}),),
        }
    )
    text = text_of(documents.build_certificate(stretched))
    assert "Wolfeschlegelstein" in text
