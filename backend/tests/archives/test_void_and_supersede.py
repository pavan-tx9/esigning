"""Voiding an archive, and correcting one document with another.

An archive may be voided before its seal -- including while it is waiting for one, which an
electronic envelope may never be, because nobody signed anything electronically and the scan is
still the host's. Once sealed it is corrected the way every sealed document is: a new envelope,
of either kind, that supersedes it.

The "waiting for its seal" state is reached honestly, through a key service that is down, rather
than by rewriting the row: that is the state a real outage produces, and it is the one the rule
is about.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from uuid import UUID

import pytest
from sqlalchemy import Engine, text

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import Sealer, SealResult, SealUnavailable, SealValidation
from esign.sealing import build_sealer
from esign.worker import run_once
from tests.archives.conftest import error_code, file_archive, filed, scan_pdf
from tests.e2e.conftest import Ehr, Sessions, World, build_world


class SealOutage:
    """The real sealer behind a key service that never answers."""

    def __init__(self, real: Sealer) -> None:
        self._real = real

    def seal(self, pdf: bytes, *, reason: str, envelope_id: UUID) -> SealResult:
        raise SealUnavailable("the key service did not answer", code="kms_unavailable")

    def validate(self, pdf: bytes) -> SealValidation:
        return self._real.validate(pdf)


@pytest.fixture
def pending(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> Iterator[tuple[World, Ehr]]:
    """A world whose seal always fails, so a filed archive stays ``completed_pending_seal``."""
    world = build_world(
        e2e_settings, clock, app_engine, db_factory, sealer=SealOutage(build_sealer(e2e_settings, clock))
    )
    with world.client:
        yield world, world.host(webhook=True)


def test_an_archive_is_voided_while_it_waits_for_its_seal(pending: tuple[World, Ehr]) -> None:
    world, host = pending
    view = filed(host)
    assert view["status"] == "completed_pending_seal"
    assert host.envelope(view["id"])["status"] == "completed_pending_seal"
    assert "seal.failed" in host.audit_types(view["id"])

    voided = host.post(f"/envelopes/{view['id']}/void", {"reason_code": "entered_in_error"})
    assert voided.status_code == 200, voided.text
    assert voided.json()["status"] == "voided"
    assert "envelope.voided" in host.audit_types(view["id"])

    # The queued job is cancelled with it: nothing retries a document that will never be sealed,
    # and the trail gains no further failures for a decision that has already been made.
    with world.sessions() as db:
        completed = db.execute(
            text("SELECT completed_at FROM seal_jobs WHERE envelope_id = :id"), {"id": view["id"]}
        ).scalar_one()
    assert completed is not None
    tick = run_once(world.rt, send=host.receive)
    assert (tick.sealed, tick.seal_failures) == (0, 0)
    assert host.envelope(view["id"])["status"] == "voided"
    assert host.audit_types(view["id"]).count("seal.failed") == 1


def test_a_voided_archive_notifies_the_host(pending: tuple[World, Ehr]) -> None:
    world, host = pending
    view = filed(host)
    assert host.post(f"/envelopes/{view['id']}/void", {"reason_code": "wrong_patient"}).status_code == 200
    run_once(world.rt, send=host.receive)
    events = [_event(body) for _url, body, _headers in host.deliveries]
    assert events == ["envelope.voided"]


def test_an_unsealed_archive_cannot_be_superseded(pending: tuple[World, Ehr]) -> None:
    _world, host = pending
    view = filed(host)
    refused = file_archive(host, scan_pdf(), supersedes_envelope_id=view["id"])
    assert refused.status_code == 409
    assert error_code(refused) == "supersedes_not_sealed"


def test_an_electronic_envelope_pending_its_seal_still_cannot_be_voided(pending: tuple[World, Ehr]) -> None:
    """The rule the archive relaxes, still in force for everything else (SPEC section 3)."""
    _world, host = pending
    host.publish_template("hipaa_acknowledgement")
    envelope = host.create_envelope("hipaa_acknowledgement", signing_order="parallel")
    patient = host.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    assert patient.sign(payload, key="only-signer").status_code == 200
    assert host.envelope(envelope["id"])["status"] == "completed_pending_seal"

    refused = host.post(f"/envelopes/{envelope['id']}/void", {"reason_code": "entered_in_error"})
    assert refused.status_code == 409
    assert error_code(refused) == "envelope_already_complete"


def test_a_sealed_archive_can_never_be_voided(host: Ehr) -> None:
    view = filed(host)
    assert host.envelope(view["id"])["status"] == "sealed"
    refused = host.post(f"/envelopes/{view['id']}/void", {"reason_code": "entered_in_error"})
    assert refused.status_code == 409
    assert error_code(refused) == "envelope_sealed"


def test_an_archive_supersedes_a_sealed_electronic_envelope(ehr: Ehr) -> None:
    """The paper path after the fact: the patient signed on paper instead, so the electronic
    document is corrected by an archive of what they actually signed."""
    envelope = ehr.create_envelope("hipaa_acknowledgement", signing_order="parallel")
    ehr.sign_everyone(envelope, ("patient",))
    assert ehr.envelope(envelope["id"])["status"] == "sealed"

    archive = filed(ehr, scan_pdf(), supersedes_envelope_id=envelope["id"], document_type="hipaa_acknowledgement")
    assert archive["supersedes_envelope_id"] == envelope["id"]
    assert ehr.envelope(envelope["id"])["superseded_by_envelope_id"] == archive["id"]
    assert "envelope.superseded" in ehr.audit_types(envelope["id"])


def test_an_electronic_envelope_supersedes_a_sealed_archive(ehr: Ehr) -> None:
    """And the other way round: the scan was filed in error and the patient signs properly."""
    archive = filed(ehr, scan_pdf(), document_type="hipaa_acknowledgement")
    assert ehr.envelope(archive["id"])["status"] == "sealed"

    envelope = ehr.create_envelope(
        "hipaa_acknowledgement", signing_order="parallel", supersedes_envelope_id=archive["id"]
    )
    assert envelope["supersedes_envelope_id"] == archive["id"]
    assert ehr.envelope(archive["id"])["superseded_by_envelope_id"] == envelope["id"]
    assert "envelope.superseded" in ehr.audit_types(archive["id"])


def test_an_archive_cannot_supersede_another_hosts_envelope(host: Ehr, world: World) -> None:
    view = filed(host)
    stranger = world.host("Other EHR")
    refused = file_archive(stranger, scan_pdf(), supersedes_envelope_id=view["id"])
    assert refused.status_code == 404
    assert error_code(refused) == "not_found"


def test_one_sealed_archive_is_superseded_only_once(host: Ehr) -> None:
    archive = filed(host)
    assert file_archive(host, scan_pdf(pages=1), supersedes_envelope_id=archive["id"]).status_code == 201
    second = file_archive(host, scan_pdf(pages=3), supersedes_envelope_id=archive["id"])
    assert second.status_code == 409
    assert error_code(second) == "already_superseded"


def _event(body: bytes) -> str:
    payload = json.loads(body)
    return str(payload["event"])
