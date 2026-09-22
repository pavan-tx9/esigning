"""What the report claims, and what it refuses to claim."""

from __future__ import annotations

import io
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from pypdf import PdfReader
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from esign.config import Settings
from esign.contracts import CertificateSigner, CertificateSummary, SealValidation
from esign.documents import build_document_service
from esign.storage import content_key
from esign.verification import Check, VerificationReport
from tests.e2e.conftest import Ehr, World

GOOD_SEAL = SealValidation(
    intact=True, covers_whole_document=True, trusted=True, timestamp_valid=True,
    profile="PAdES-B-LT", signer_cert_sha256=b"\x01" * 32, signing_time=None,
)  # fmt: skip


def _report(status: str, checks: tuple[Check, ...], seal: SealValidation | None) -> VerificationReport:
    return VerificationReport(
        envelope_id=uuid4(), envelope_status=status, checks=checks,
        audit_event_count=3, audit_head_hash=b"\x02" * 32, blobs_checked=1, seal=seal,
    )  # fmt: skip


def test_skipped_is_never_complete_and_failed_is_never_ok() -> None:
    passed = Check("audit_chain", "passed")
    assert _report("sealed", (passed,), GOOD_SEAL).complete
    assert not _report("sealed", (passed, Check("seal", "skipped", "why")), GOOD_SEAL).complete
    assert not _report("in_progress", (passed,), None).complete
    assert _report("in_progress", (passed,), None).ok

    failed = _report("sealed", (passed, Check("seal_trusted", "failed", "untrusted_chain")), GOOD_SEAL)
    assert not failed.ok and not failed.complete
    assert failed.problems == ("seal_trusted: untrusted_chain",)
    assert failed.to_json()["problems"] == ["seal_trusted: untrusted_chain"]

    # A validator that reports a problem is not ok, whatever its four flags say.
    doubtful = SealValidation(**{**GOOD_SEAL.__dict__, "problems": ("multiple_signatures",)})
    assert not doubtful.ok and not _report("sealed", (passed,), doubtful).complete


def test_a_pointer_that_disagrees_with_the_revisions_is_reported(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("patient_consent")
    other = ehr.create_envelope("hipaa_acknowledgement")
    with world.sessions() as db:
        db.execute(
            text("UPDATE envelopes SET current_revision_sha256 = :sha WHERE id = :id"),
            {"sha": bytes.fromhex(other["presented_sha256"]), "id": envelope["id"]},
        )
        db.commit()
    report = ehr.verification(envelope["id"])
    failed = [c["name"] for c in report["checks"] if c["status"] == "failed"]
    assert failed == ["envelope_current_revision_pointer"]
    assert {c["name"] for c in report["checks"] if c["status"] == "skipped"} == {
        "seal",
        "seal_bound_to_envelope",
        "sealed_pages_match_final_revision",
        "certificate_head_hash",
    }


def _long_certificate(settings: Settings) -> tuple[bytes, str]:
    """A certificate for ten signers with long labels, and the head hash printed on it.

    Ten is reachable: ``MAX_ROLES`` is ten and an envelope may carry one signer per role.
    """
    head = bytes(range(32, 64))
    summary = CertificateSummary(
        envelope_id=UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        document_type="procedure_consent",
        template_key="procedure_consent",
        template_version=3,
        seal_profile="PAdES-B-LT",
        presented_sha256=bytes(range(32)),
        final_revision_sha256=bytes(range(64, 96)),
        created_at=datetime(2026, 3, 17, 9, 0, tzinfo=UTC),
        completed_at=datetime(2026, 3, 17, 13, 30, tzinfo=UTC),
        signers=tuple(
            CertificateSigner(
                signer_id=UUID(int=index + 1),
                display_name=f"Signer Number {index} With A Long Name",
                role_label=f"Consulting {'sub' * 20}specialist number {index}"[:120],
                capacity="clinician",
                auth_method="password+mfa",
                reauth_method="sso",
                consent_version="2026-09",
                viewed_at=datetime(2026, 3, 17, 13, 0, tzinfo=UTC),
                consented_at=datetime(2026, 3, 17, 13, 5, tzinfo=UTC),
                signed_at=datetime(2026, 3, 17, 13, 10, tzinfo=UTC),
                ip="203.0.113.7",
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
                "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
                kiosk_staff_user_id=f"staff-000{index}",
                kiosk_identity_check="photo_id",
            )
            for index in range(10)
        ),
        audit_event_count=41,
        audit_head_hash=head,
    )
    return build_document_service(settings).build_certificate(summary), head.hex()


def test_the_head_hash_is_found_however_long_the_certificate_runs(settings_no_db: Settings) -> None:
    """The head hash is printed near the *top* of the certificate, and the certificate paginates.

    ``_check_certificate_head`` searched only ``reader.pages[-4:]``, so a genuine document whose
    certificate ran past four pages reported ``certificate_head_hash_in_document: failed``, made
    ``GET .../verification`` answer ``ok: false``, made ``esign verify`` exit 1, and appended
    ``verification.performed`` with ``ok: false`` to an append-only trail -- for a document whose
    seal, hashes and chain were all sound.
    """
    certificate, head = _long_certificate(settings_no_db)
    pages = PdfReader(io.BytesIO(certificate)).pages
    assert len(pages) >= 5, "this test needs a certificate longer than the old four-page window"

    def printed(selection: Sequence[Any]) -> str:
        return re.sub(r"\s+", "", "".join(page.extract_text() or "" for page in selection)).lower()

    # What the old window saw, and what every page sees.
    assert head not in printed(pages[-4:])
    assert head in printed(pages)


def test_a_seal_made_for_one_envelope_does_not_verify_against_another(
    ehr: Ehr, world: World, owner_engine: Engine
) -> None:
    """SPEC section 5: ``/Location = envelope:<id>`` binds the seal to the envelope it completes.

    Nothing read it back, so the binding was written-down intent rather than evidence. This is the
    one check a verifier holding only the sealed PDF and an envelope id can run.
    """
    from esign.verification import Verifier

    first = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(first, "patient")
    payload = patient.review_and_consent()
    assert patient.sign(payload, key="sign-bound-a").status_code == 200

    second = ehr.create_envelope("hipaa_acknowledgement")
    other = ehr.open_session(second, "patient")
    other_payload = other.review_and_consent()
    assert other.sign(other_payload, key="sign-bound-b").status_code == 200

    # Point the second envelope at the first one's sealed bytes. Only someone who can disable the
    # append-only trigger gets this far, which is exactly who these checks are for.
    with owner_engine.begin() as conn:
        sealed = conn.execute(
            text("SELECT sealed_sha256 FROM envelopes WHERE id = :id"), {"id": first["id"]}
        ).scalar_one()
        conn.execute(text("ALTER TABLE document_revisions DISABLE TRIGGER USER"))
        conn.execute(
            text("UPDATE document_revisions SET sha256 = :sha WHERE envelope_id = :id AND kind = 'sealed'"),
            {"sha": sealed, "id": second["id"]},
        )
        conn.execute(text("ALTER TABLE document_revisions ENABLE TRIGGER USER"))
        conn.execute(
            text("UPDATE envelopes SET sealed_sha256 = :sha WHERE id = :id"),
            {"sha": sealed, "id": second["id"]},
        )

    verifier = Verifier(audit=world.rt.audit, blobs=world.rt.blobs, sealer=world.rt.sealer)
    with world.sessions() as db:
        report = verifier.verify_envelope(db, UUID(second["id"]))
        db.commit()
    failed = {c.name for c in report.checks if c.status == "failed"}
    # The seal itself is genuine and validates; what fails is that it is somebody else's.
    assert report.seal is not None and report.seal.ok
    assert "seal_bound_to_envelope" in failed
    # And the trail catches the same swap independently, which is why this was never an open hole.
    assert "trail_sealed_hash" in failed
    assert report.ok is False


def test_a_signer_row_rewritten_after_sealing_is_reported(ehr: Ehr, world: World) -> None:
    """``signers`` is UPDATE-able by the runtime role and is where the certificate's dates came
    from. The seal refuses on a disagreement; this is the same comparison for an envelope that was
    already sealed when the row changed."""
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    assert patient.sign(payload, key="sign-drifted-row").status_code == 200

    with world.sessions() as db:
        db.execute(
            text("UPDATE signers SET signed_at = signed_at - interval '2 hours' WHERE envelope_id = :id"),
            {"id": envelope["id"]},
        )
        db.commit()

    report = ehr.verification(envelope["id"])
    failed = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert "signer_rows_match_trail" in failed
    assert "signer.signed" in failed["signer_rows_match_trail"]
    assert report["ok"] is False


def test_a_corrupted_drawn_signature_image_is_reported(ehr: Ehr, world: World) -> None:
    """``signature_captures`` is the raw ink, before it was scaled into the page.

    The stamped revision covers how the mark *appears*; nothing used to re-check the input itself,
    so a drawn signature could rot on disk unnoticed.
    """
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    assert patient.sign(payload, key="sign-drawn").status_code == 200

    clean = ehr.verification(envelope["id"])
    assert {c["name"] for c in clean["checks"] if c["status"] == "passed"} >= {"capture_images_intact"}

    with world.sessions() as db:
        sha = db.execute(
            text(
                "SELECT c.image_sha256 FROM signature_captures c JOIN signers s ON s.id = c.signer_id "
                "WHERE s.envelope_id = :id AND c.image_sha256 IS NOT NULL"
            ),
            {"id": envelope["id"]},
        ).scalar_one()
    path = Path(world.settings.blob_fs_root) / content_key(bytes(sha))
    path.chmod(0o600)
    path.write_bytes(b"not the signature that was drawn")

    report = ehr.verification(envelope["id"])
    failed = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert "capture_images_intact" in failed
    assert "integrity_failure" in failed["capture_images_intact"]
    assert report["ok"] is False


def test_the_app_role_cannot_repoint_or_delete_a_capture(ehr: Ehr, world: World, owner_engine: Engine) -> None:
    """Two lines of defence over the raw input, like every other piece of evidence (``0502``)."""
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    assert patient.sign(payload, key="sign-immutable-capture").status_code == 200

    with world.sessions() as db:
        for statement in (
            "UPDATE signature_captures SET image_sha256 = NULL",
            "DELETE FROM signature_captures",
        ):
            with pytest.raises(DBAPIError) as refused:
                db.execute(text(statement))
                db.commit()
            assert "permission denied" in str(refused.value.orig)
            db.rollback()

    # And the owner role, which the grants do not stop, hits the trigger.
    with pytest.raises(DBAPIError) as caught, owner_engine.begin() as conn:
        conn.execute(text("DELETE FROM signature_captures"))
    assert "append-only" in str(caught.value.orig)


def test_a_finalized_document_whose_pages_are_not_the_signed_ones_is_reported(
    ehr: Ehr, world: World, owner_engine: Engine
) -> None:
    """``finalize`` rebuilds the document with pypdf, so ``final_unsealed`` does not *contain*
    revision N's bytes.

    A verifier could prove the seal covers ``final_unsealed`` and that revision N re-hashes, and
    still not that the pages inside the seal are revision N's pages. The only link was the trail's
    word for it; now it is recomputed.
    """
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    assert patient.sign(payload, key="sign-page-link").status_code == 200
    assert ehr.verification(envelope["id"])["complete"] is True

    # Point the last signed revision at the *presented* one: the same document without the
    # signature. Every hash still re-checks; the pages inside the seal no longer match.
    with owner_engine.begin() as conn:
        presented = conn.execute(
            text("SELECT presented_sha256 FROM envelopes WHERE id = :id"), {"id": envelope["id"]}
        ).scalar_one()
        conn.execute(text("ALTER TABLE document_revisions DISABLE TRIGGER USER"))
        conn.execute(
            text("UPDATE document_revisions SET sha256 = :sha WHERE envelope_id = :id AND kind = 'signer_applied'"),
            {"sha": presented, "id": envelope["id"]},
        )
        conn.execute(text("ALTER TABLE document_revisions ENABLE TRIGGER USER"))

    report = ehr.verification(envelope["id"])
    failed = {c["name"] for c in report["checks"] if c["status"] == "failed"}
    assert "sealed_pages_match_final_revision" in failed
    assert report["ok"] is False


def test_a_capture_the_trail_records_cannot_quietly_disappear(ehr: Ehr, world: World, owner_engine: Engine) -> None:
    """``signer.signed`` records a digest of the raw input, so the row can be contradicted.

    Before this it recorded only ``field_id`` and ``kind``: the blob hash on the row appeared in no
    append-only record at all, so repointing or removing a capture was undetectable.
    """
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    assert patient.sign(payload, key="sign-tied-capture").status_code == 200
    assert ehr.verification(envelope["id"])["complete"] is True

    # Only someone who can disable the trigger gets this far, which is who the digest is for.
    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE signature_captures DISABLE TRIGGER USER"))
        conn.execute(
            text("DELETE FROM signature_captures WHERE signer_id IN (SELECT id FROM signers WHERE envelope_id = :id)"),
            {"id": envelope["id"]},
        )
        conn.execute(text("ALTER TABLE signature_captures ENABLE TRIGGER USER"))

    report = ehr.verification(envelope["id"])
    failed = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert "captures_match_trail" in failed
    assert "is gone" in failed["captures_match_trail"]
    assert report["ok"] is False
