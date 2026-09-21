"""What the report claims, and what it refuses to claim."""

from __future__ import annotations

from uuid import uuid4

from esign.contracts import SealValidation
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
    from sqlalchemy import text

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
    assert {c["name"] for c in report["checks"] if c["status"] == "skipped"} == {"seal", "certificate_head_hash"}
