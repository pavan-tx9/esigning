"""What verification catches once an archive is sealed.

The seal proves the scan has not changed since it was filed. These tests are that claim under
attack: the stored scan swapped for another document, its bytes edited on disk, the attestation
rewritten after the fact, the trail tampered with. Each one has to come back as a finding --
``ok: false`` with a named problem -- and never as a passing report or a transport error.
"""

from __future__ import annotations

import json
import os
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine, text

from esign.contracts import IntegrityFailure
from esign.storage import content_key
from tests.archives.conftest import PAPER_SIGNER_NAME, STAFF_NAME, attestation, filed, scan_pdf
from tests.archives.test_void_and_supersede import pending as pending  # the seal-outage world
from tests.e2e.conftest import Ehr, World


def _problems(host: Ehr, envelope_id: str) -> list[str]:
    report = host.verification(envelope_id)
    assert report["ok"] is False, report
    problems: list[str] = report["problems"]
    return problems


def _rewrite_attestation(world: World, envelope_id: str, **overrides: Any) -> None:
    with world.sessions() as db:
        db.execute(
            text("UPDATE envelopes SET attestation = CAST(:value AS jsonb) WHERE id = :id"),
            {"value": json.dumps(attestation(**overrides)), "id": envelope_id},
        )
        db.commit()


def _rewrite_paper_signed_on(world: World, envelope_id: str, value: str) -> None:
    with world.sessions() as db:
        db.execute(
            text("UPDATE envelopes SET paper_signed_on = CAST(:value AS date) WHERE id = :id"),
            {"value": value, "id": envelope_id},
        )
        db.commit()


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


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"staff_display_name": "Somebody Else Entirely"}, id="attesting_staff_name"),
        pytest.param(
            {"paper_signers": [{"display_name": "Somebody Else Entirely", "capacity": "self"}]},
            id="paper_signer_name",
        ),
        pytest.param(
            {"paper_signers": [{"display_name": PAPER_SIGNER_NAME, "capacity": "guardian"}]},
            id="paper_signer_capacity",
        ),
    ],
)
def test_a_rewritten_name_or_capacity_is_caught_although_it_is_never_in_the_trail(
    host: Ehr, world: World, overrides: dict[str, Any]
) -> None:
    """The names are the whole attribution of an archive, and none of them is in the trail as text.

    There is no signer row, no session and no stamped revision behind them: where the paper
    original was destroyed under policy, the attestation is all that remains of it. The four
    comparisons that *do* have a text counterpart -- the opaque staff id, the statement, the
    disposition, the signer count -- all still pass here; only the joint digest over the names and
    the paper date contradicts the row.
    """
    view = filed(host)
    _rewrite_attestation(world, view["id"], **overrides)

    problems = _problems(host, view["id"])
    assert any("attested detail" in problem for problem in problems), problems
    assert not any("staff_user_id" in problem for problem in problems), problems
    assert not any("paper_signer_count" in problem for problem in problems), problems


def test_a_rewritten_paper_signing_date_is_caught(host: Ehr, world: World) -> None:
    """``archive.created`` deliberately keeps no ``paper_signed_on`` -- it is a date about a
    patient -- but the cover page prints the column, so the trail has to be able to contradict it.
    The joint digest does, without putting a brute-forceable bare date in the chain."""
    view = filed(host)
    _rewrite_paper_signed_on(world, view["id"], "2019-01-02")

    problems = _problems(host, view["id"])
    assert any("attested detail" in problem for problem in problems), problems


def test_the_seal_refuses_a_rewritten_attestation_rather_than_printing_it(pending: tuple[World, Ehr]) -> None:
    """``completed_pending_seal`` is an expected, hours-long state whenever KMS, the TSA or storage
    is backing off, and the cover page and certificate are rendered from these mutable columns at
    *seal* time. A rewrite inside that window must stop the seal, not be baked into bytes that can
    never be re-sealed.
    """
    world, host = pending
    view = filed(host)
    assert view["status"] == "completed_pending_seal"

    _rewrite_attestation(world, view["id"], staff_display_name="Somebody Else Entirely")
    _rewrite_paper_signed_on(world, view["id"], "2019-01-02")

    with world.rt.transaction() as db, pytest.raises(IntegrityFailure) as seen:
        world.rt.envelopes.seal_pending(db, UUID(view["id"]))
    assert seen.value.code == "certificate_evidence_mismatch"
    assert host.envelope(view["id"])["status"] == "completed_pending_seal"


def test_an_untouched_archive_agrees_with_its_own_digest(host: Ehr, world: World) -> None:
    """The digest is over the row as filed, not over a copy of itself: rewriting the attestation
    with exactly the same values leaves the report clean."""
    view = filed(host)
    _rewrite_attestation(world, view["id"], staff_display_name=STAFF_NAME)

    assert host.verification(view["id"])["ok"] is True


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
