"""What the verification report says about a host-supplied document (Addendum 2).

A host document is the one source whose revision 1 is a *transformation*: the host sent a PDF, the
service flattened it, the signer saw the result. The report has to be able to re-check both ends
of that step, and to say which end went wrong -- otherwise "we flattened what you sent us" is an
assertion about bytes nobody can produce any more. These tests break one thing at a time and read
which check fails.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from esign.storage import content_key
from tests.documents.helpers import NamedWidget, generated_report
from tests.e2e.conftest import Ehr, World

PAGES = 6


def _report(pages: int = PAGES, *, widgets: bool = True) -> bytes:
    block = (NamedWidget(name="clinician_signature", rect=(54, 96, 294, 146), page=pages),) if widgets else ()
    return generated_report(pages=pages, widgets=block)


def _supplied(ehr: Ehr, envelope_id: str) -> dict[str, object]:
    event = next(e for e in ehr.audit(envelope_id) if e["event_type"] == "document.supplied")
    data: dict[str, object] = event["data"]
    return data


def _failed(report: dict[str, object]) -> dict[str, str]:
    checks: list[dict[str, str]] = report["checks"]  # type: ignore[assignment]
    return {c["name"]: c["detail"] for c in checks if c["status"] == "failed"}


def test_an_untouched_host_document_verifies_and_runs_the_new_checks(ehr: Ehr) -> None:
    envelope = ehr.create_host_document_envelope(_report())
    report = ehr.verification(envelope["id"])

    assert report["ok"], report["problems"]
    passed = {c["name"] for c in report["checks"] if c["status"] == "passed"}
    assert {"supplied_document_recorded", "supplied_upload_intact", "supplied_revision_matches_trail"} <= passed
    # Not sealed yet, so the seal checks are skipped and the report is not "complete".
    assert not report["complete"]


def test_a_template_envelope_does_not_grow_the_new_checks(ehr: Ehr) -> None:
    envelope = ehr.create_envelope("patient_consent")
    names = {c["name"] for c in ehr.verification(envelope["id"])["checks"]}
    assert not any(name.startswith("supplied_") for name in names)
    # ...and the template checks still describe revision 1 by its own name.
    assert "revision_1_presented_hash" in names


def test_a_swapped_upload_is_reported_and_revision_one_is_not_blamed(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_host_document_envelope(_report())
    upload_sha = bytes.fromhex(str(_supplied(ehr, envelope["id"])["upload_sha256"]))

    path = world.settings.blob_fs_root / content_key(upload_sha)
    path.chmod(0o600)
    path.write_bytes(_report(widgets=False))

    failed = _failed(ehr.verification(envelope["id"]))
    assert set(failed) == {"supplied_upload_intact"}
    assert "integrity_failure" in failed["supplied_upload_intact"]


def test_the_upload_cannot_be_restamped_as_some_other_kind_of_blob(ehr: Ehr, owner_engine: Engine) -> None:
    """``supplied_upload_intact`` also compares ``blobs.kind``. Nothing can reach that comparison
    through the database, which is the stronger answer: ``blobs`` is append-only against the app
    role *and* against the owner, so an upload cannot be restamped as a template at all."""
    envelope = ehr.create_host_document_envelope(_report())
    upload_sha = bytes.fromhex(str(_supplied(ehr, envelope["id"])["upload_sha256"]))
    with pytest.raises(DBAPIError) as refused, owner_engine.begin() as conn:
        conn.execute(text("UPDATE blobs SET kind = 'template_pdf' WHERE sha256 = :sha"), {"sha": upload_sha})
    assert "append-only" in str(refused.value)
    assert ehr.verification(envelope["id"])["ok"]


def test_a_missing_upload_blob_is_reported_rather_than_passed_over(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_host_document_envelope(_report())
    upload_sha = bytes.fromhex(str(_supplied(ehr, envelope["id"])["upload_sha256"]))
    path = world.settings.blob_fs_root / content_key(upload_sha)
    path.chmod(0o600)
    path.unlink()

    failed = _failed(ehr.verification(envelope["id"]))
    assert "supplied_upload_intact" in failed
    # The upload the trail names is simply not there any more, and the report says so instead of
    # reporting a document whose two ends were never compared.
    assert "blob_missing" in failed["supplied_upload_intact"]


def test_a_repointed_presented_hash_disagrees_with_document_supplied(ehr: Ehr, world: World) -> None:
    """``envelopes.presented_sha256`` is UPDATE-able by the runtime role; ``document.supplied``
    is not. A pointer moved to another envelope's revision is a finding in three checks."""
    envelope = ehr.create_host_document_envelope(_report())
    other = ehr.create_host_document_envelope(_report(pages=5))
    with world.sessions() as db:
        db.execute(
            text("UPDATE envelopes SET presented_sha256 = :sha WHERE id = :id"),
            {"sha": bytes.fromhex(str(other["presented_sha256"])), "id": envelope["id"]},
        )
        db.commit()

    failed = _failed(ehr.verification(envelope["id"]))
    assert "supplied_revision_matches_trail" in failed
    assert "document.supplied" in failed["supplied_revision_matches_trail"]
    assert "envelope_presented_pointer" in failed


def test_the_schema_refuses_a_host_document_that_also_names_a_template(ehr: Ehr, world: World) -> None:
    """``envelope_row_matches_trail`` compares the row's ``template_version_id`` with the trail.
    The schema gets there first: ``envelopes_source_template`` makes the pair unrepresentable, and
    ``envelopes_source_field_definitions`` makes a host document without definitions unrepresentable
    too. The report's comparison is the belt to that braces."""
    template_envelope = ehr.create_envelope("patient_consent")
    envelope = ehr.create_host_document_envelope(_report())
    with world.sessions() as db:
        version_id = db.execute(
            text("SELECT template_version_id FROM envelopes WHERE id = :id"),
            {"id": template_envelope["id"]},
        ).scalar_one()
        for statement, params in (
            ("UPDATE envelopes SET template_version_id = :v WHERE id = :id", {"v": version_id, "id": envelope["id"]}),
            ("UPDATE envelopes SET field_definitions = NULL WHERE id = :id", {"id": envelope["id"]}),
            ("UPDATE envelopes SET source = 'template' WHERE id = :id", {"id": envelope["id"]}),
        ):
            with pytest.raises(DBAPIError):
                db.execute(text(statement), params)
            db.rollback()

    assert ehr.verification(envelope["id"])["ok"]


def test_a_sealed_host_document_is_complete(ehr: Ehr) -> None:
    envelope = ehr.create_host_document_envelope(_report())
    ehr.sign_everyone(envelope, ("clinician",))
    report = ehr.verification(envelope["id"])
    assert report["ok"] and report["complete"], report["problems"]
    assert report["seal"]["ok"]
    # The pages inside the seal are still the signed ones, counted from the ``signer_applied``
    # revision exactly as for a template envelope.
    assert "sealed_pages_match_final_revision" in {c["name"] for c in report["checks"] if c["status"] == "passed"}
