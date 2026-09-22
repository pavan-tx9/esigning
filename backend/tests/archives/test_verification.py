"""What verification catches once an archive is sealed.

The seal proves the scan has not changed since it was filed. These tests are that claim under
attack: the stored scan swapped for another document, its bytes edited on disk, the attestation
rewritten after the fact, the trail tampered with. Each one has to come back as a finding --
``ok: false`` with a named problem -- and never as a passing report or a transport error.
"""

from __future__ import annotations

import json
import os

from sqlalchemy import Engine, text

from esign.storage import content_key
from tests.archives.conftest import attestation, filed, scan_pdf
from tests.e2e.conftest import Ehr, World


def _problems(host: Ehr, envelope_id: str) -> list[str]:
    report = host.verification(envelope_id)
    assert report["ok"] is False, report
    problems: list[str] = report["problems"]
    return problems


def test_a_sealed_archive_verifies_completely(host: Ehr) -> None:
    view = filed(host, scan_pdf(pages=2))
    report = host.verification(view["id"])
    assert report["ok"] and report["complete"], report["problems"]
    names = {check["name"]: check["status"] for check in report["checks"]}
    # The checks that matter for an archive all ran, rather than being skipped for want of a
    # signer or a template.
    for name in (
        "revision_1_scan_hash",
        "envelope_presented_pointer",
        "envelope_current_revision_pointer",
        "trail_presented_hash",
        "envelope_row_matches_trail",
        "sealed_pages_match_final_revision",
        "seal_bound_to_envelope",
        "certificate_head_hash_in_document",
    ):
        assert names.get(name) == "passed", (name, report["checks"])


def test_a_swapped_scan_is_caught(host: Ehr, world: World) -> None:
    """The blob store is content-addressed, so a swapped scan cannot keep its hash. Pointing the
    envelope at a different stored document is the substitution that could -- the pages inside the
    seal are then not the pages that were filed, and the report has to say so."""
    original = filed(host, scan_pdf(pages=2, text="Consent to treatment"))
    other = filed(host, scan_pdf(pages=2, text="Something else entirely"))

    with world.sessions() as db:
        db.execute(
            text("UPDATE envelopes SET presented_sha256 = :sha, current_revision_sha256 = :sha WHERE id = :id"),
            {"sha": bytes.fromhex(other["presented_sha256"]), "id": original["id"]},
        )
        db.commit()

    problems = _problems(host, original["id"])
    assert any("envelope_presented_pointer" in problem for problem in problems), problems
    assert any("envelope_current_revision_pointer" in problem for problem in problems), problems


def test_a_scan_whose_bytes_changed_on_disk_is_caught(host: Ehr, world: World) -> None:
    view = filed(host, scan_pdf(pages=1))
    path = world.settings.blob_fs_root / content_key(bytes.fromhex(view["presented_sha256"]))
    tampered = bytearray(path.read_bytes())
    tampered[len(tampered) // 2] ^= 0x01
    os.chmod(path, 0o644)  # noqa: PTH101 - the file is deliberately read-only
    path.write_bytes(bytes(tampered))

    problems = _problems(host, view["id"])
    assert any("revision_1_scan_hash" in problem and "integrity_failure" in problem for problem in problems), problems
    # And the sealed document, which contains those pages, is no longer vouched for either.
    assert any("sealed_pages_match_final_revision" in problem for problem in problems), problems


def test_a_rewritten_attestation_is_caught(host: Ehr, world: World) -> None:
    """The attestation is what an archive's certificate prints instead of a signer table, so it is
    cross-checked against ``archive.attested`` exactly as a signer row is against
    ``signer.signed``."""
    view = filed(host)
    with world.sessions() as db:
        db.execute(
            text("UPDATE envelopes SET attestation = CAST(:value AS jsonb) WHERE id = :id"),
            {
                "value": json.dumps(
                    attestation(staff_user_id="staff-0001", original_disposition="destroyed_per_policy")
                ),
                "id": view["id"],
            },
        )
        db.commit()

    problems = _problems(host, view["id"])
    assert any("staff_user_id" in problem for problem in problems), problems
    assert any("original_disposition" in problem for problem in problems), problems


def test_a_tampered_archive_audit_row_is_caught(host: Ehr, owner_engine: Engine) -> None:
    """Only someone who can disable the append-only triggers gets this far -- which is exactly
    who the hash chain is for."""
    view = filed(host)
    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        conn.execute(
            text(
                "UPDATE audit_events SET data = jsonb_set(data, '{paper_signer_count}', '9') "
                "WHERE stream_id = :id AND event_type = 'archive.attested'"
            ),
            {"id": view["id"]},
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))

    problems = _problems(host, view["id"])
    assert any("audit_chain" in problem for problem in problems), problems
    # The seal itself is still good: the report says what failed and what did not.
    assert host.verification(view["id"])["seal"]["ok"] is True
