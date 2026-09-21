"""PHI must not leave the database, the blob store and the PDF.

SPEC section 10 and the hard rules in CLAUDE.md. These tests drive a full envelope through every
transition with values that would be unmistakable if they leaked, then go looking for them in the
three places they could escape to: log lines, audit ``data``, and audit rows generally.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator
from typing import Any

import pytest
import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.audit.events import declared_data_keys
from esign.contracts import Capture, EventType, NewSigner
from esign.logging import LOGGABLE_KEYS, RESERVED_KEYS, configure_logging
from tests.envelopes.conftest import CTX, PROCEDURE_CONSENT, Bench
from tests.envelopes.fakes import LogCapture

PNG = b"\x89PNG\r\n\x1a\n" + b"scribbled signature bytes"

#: Values a real envelope would carry that must never show up outside the database and the PDF.
NAMES = ("Jane Roe-Featherstonehaugh", "Dr Quincy Ravensworth", "Mr Witness Peabody")
PREFILL_VALUE = "1971-04-02 Ward 7 Dr Ravensworth"
PATIENT_REF = "mrn-88812-nonsense"
SECRETS = (*NAMES, PREFILL_VALUE)


class Recorder:
    """Stands in for the module's logger and keeps what it was handed, before any allowlist runs."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _record(self, event: str, **kwargs: Any) -> None:
        self.calls.append((event, kwargs))

    info = warning = error = debug = _record


def drive_everything(bench: Bench, db: Session) -> Any:
    """Create, present, view, consent, sign all three signers, seal. Every transition, once."""
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    bench.consent(db)
    signers = (
        NewSigner("patient", "hu-1", NAMES[0], "self"),
        NewSigner("witness", "hu-2", NAMES[2], "witness"),
        NewSigner("clinician", "hu-3", NAMES[1], "clinician"),
    )
    view = bench.create(
        db,
        host,
        PROCEDURE_CONSENT,
        signers=signers,
        signing_order="sequential",
        patient_ref=PATIENT_REF,
        prefill={"visit_date": PREFILL_VALUE},
    )
    for role_key, captures in (
        ("patient", [Capture("patient_sig", "drawn", image_png=PNG), Capture("patient_ack", "click", checked=True)]),
        ("witness", [Capture("witness_sig", "drawn", image_png=PNG)]),
        ("clinician", [Capture("clinician_sig", "drawn", image_png=PNG)]),
    ):
        session = bench.session(db, bench.signer_id(view, role_key))
        bench.ready_to_sign(db, session)
        if role_key == "clinician":
            bench.reauth(db, session)
        bench.service.sign(db, session, captures, CTX)
    bench.service.seal_pending(db, view.id)
    return host, view


# --------------------------------------------------------------------------- logs


def test_no_log_call_carries_an_unlisted_key(bench: Bench, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """The allowlist is foundation's mechanism; this is this module's side of the bargain.

    The recorder sits where the logger does, so it sees exactly what the service passed -- before
    ``drop_unlisted_keys`` has a chance to save us. A key that is not on the list is a bug here,
    not a near miss.
    """
    recorder = Recorder()
    monkeypatch.setattr("esign.envelopes.service.log", recorder)

    drive_everything(bench, db)

    assert recorder.calls, "the service logged nothing at all"
    for event, kwargs in recorder.calls:
        unlisted = set(kwargs) - LOGGABLE_KEYS - RESERVED_KEYS
        assert not unlisted, f"{event} passed unlisted keys {sorted(unlisted)}"


def test_no_log_call_carries_a_name_or_a_prefill_value(
    bench: Bench, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr("esign.envelopes.service.log", recorder)

    drive_everything(bench, db)

    rendered = json.dumps([(event, {k: str(v) for k, v in kwargs.items()}) for event, kwargs in recorder.calls])
    for secret in (*SECRETS, PATIENT_REF):
        assert secret not in rendered


@pytest.fixture
def rendered_logs(monkeypatch: pytest.MonkeyPatch) -> Iterator[LogCapture]:
    """The real structlog pipeline, rendering into a sink this test owns.

    ``configure_logging`` caches bound loggers, so the module's own ``log`` is swapped for a fresh
    proxy for the duration; otherwise this test's configuration would leak into every later test
    in the process through a logger that is already bound.
    """
    capture = LogCapture()
    configure_logging(level="DEBUG", json_output=True, app_env="test", stream=capture)
    monkeypatch.setattr("esign.envelopes.service.log", structlog.get_logger("esign.envelopes.service"))
    try:
        yield capture
    finally:
        structlog.reset_defaults()
        logging.basicConfig(stream=sys.__stdout__, force=True)


def test_a_full_run_renders_no_phi_through_the_real_logger(
    bench: Bench, db: Session, rendered_logs: LogCapture
) -> None:
    """End to end through the configured structlog pipeline, reading what actually gets printed."""
    drive_everything(bench, db)

    assert rendered_logs.lines, "the configured logger printed nothing"
    rendered = rendered_logs.text()
    for secret in (*SECRETS, PATIENT_REF):
        assert secret not in rendered
    for line in rendered_logs.lines:
        assert "dropped_fields" not in line, f"a log call passed an unlisted key: {line}"
        assert set(line) <= LOGGABLE_KEYS | RESERVED_KEYS


def test_a_seal_failure_logs_no_phi_either(bench: Bench, db: Session, rendered_logs: LogCapture) -> None:
    from esign.contracts import SealUnavailable
    from tests.envelopes.conftest import PATIENT_CONSENT

    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    signers = (NewSigner("patient", "hu-1", NAMES[0], "self"),)
    view = bench.create(
        db, host, PATIENT_CONSENT, signers=signers, patient_ref=PATIENT_REF, prefill={"visit_date": PREFILL_VALUE}
    )
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [Capture("patient_sig", "drawn", image_png=PNG)], CTX)
    bench.sealer.bad_validation = True

    with pytest.raises(SealUnavailable):
        bench.service.seal_pending(db, view.id)

    rendered = rendered_logs.text()
    assert "seal.validation_failed" in rendered
    for secret in (*SECRETS, PATIENT_REF):
        assert secret not in rendered
    for line in rendered_logs.lines:
        assert "dropped_fields" not in line


# --------------------------------------------------------------------------- the audit trail


def test_no_audit_event_data_carries_phi(bench: Bench, db: Session) -> None:
    _host, view = drive_everything(bench, db)
    events = bench.audit.list(db, "envelope", view.id)

    rendered = json.dumps([e.data for e in events])
    for secret in (*SECRETS, PATIENT_REF):
        assert secret not in rendered


def test_every_data_key_is_one_this_module_declares(bench: Bench, db: Session) -> None:
    """The audit module's allowlist is the promise; this checks the code keeps it in a real run."""
    _host, view = drive_everything(bench, db)

    seen: set[str] = set()
    for event in bench.audit.list(db, "envelope", view.id):
        declared = declared_data_keys(event.event_type)
        assert set(event.data) <= declared, f"{event.event_type} carried {sorted(set(event.data) - declared)}"
        seen.add(str(event.event_type))

    assert seen == {
        "envelope.created",
        "document.prepared",
        "document.presented",
        "document.viewed",
        "consent.accepted",
        "signer.signed",
        "envelope.completed",
        "document.finalized",
        "document.sealed",
        "document.stored",
    }


def test_the_declared_keys_contain_nothing_that_could_be_phi() -> None:
    """A reviewer should be able to check the claim by reading one dictionary. So: read it."""
    forbidden_fragments = (
        "name",
        "dob",
        "birth",
        "prefill_value",
        "patient_ref",
        "free_text",
        "note",
        "address",
        "token",
    )
    for event_type in EventType:
        for key in declared_data_keys(event_type):
            assert not any(fragment in key for fragment in forbidden_fragments), f"{event_type}.{key}"


def test_no_audit_row_column_carries_phi(bench: Bench, db: Session) -> None:
    """Not just ``data``: the actor and context columns are written by this module too."""
    _host, view = drive_everything(bench, db)
    rows = db.execute(
        text("SELECT to_jsonb(a.*)::text AS body FROM audit_events a WHERE stream_id = :id"),
        {"id": view.id},
    ).all()
    assert rows

    dumped = " ".join(str(r.body) for r in rows)
    for secret in SECRETS:
        assert secret not in dumped


def test_the_actor_is_the_signer_not_their_name(bench: Bench, db: Session) -> None:
    _host, view = drive_everything(bench, db)
    signed = [e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "signer.signed"]

    assert [e.actor.user_id for e in signed] == ["hu-1", "hu-2", "hu-3"]
    assert [e.actor.role for e in signed] == ["patient", "staff", "clinician"]
    assert [e.actor.capacity for e in signed] == ["self", "witness", "clinician"]


def test_a_guardians_stream_names_the_patient_only_by_reference(bench: Bench, db: Session) -> None:
    from tests.envelopes.conftest import PATIENT_CONSENT

    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    signers = (NewSigner("patient", "hu-9", NAMES[0], "guardian", on_behalf_of=PATIENT_REF),)
    view = bench.create(db, host, PATIENT_CONSENT, signers=signers, patient_ref=PATIENT_REF)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [Capture("patient_sig", "drawn", image_png=PNG)], CTX)

    signed = next(e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "signer.signed")
    assert signed.actor.on_behalf_of == PATIENT_REF  # the opaque host reference, not a name
    assert NAMES[0] not in json.dumps(signed.data)


# --------------------------------------------------------------------------- prefill


def test_prefill_is_never_persisted_outside_the_pdf(bench: Bench, db: Session) -> None:
    _host, view = drive_everything(bench, db)

    tables = ("envelopes", "signers", "document_revisions", "signature_captures", "blobs", "seal_jobs")
    for table in tables:
        rows = db.execute(text(f"SELECT to_jsonb(t.*)::text AS body FROM {table} t")).all()
        dumped = " ".join(str(r.body) for r in rows)
        assert PREFILL_VALUE not in dumped, f"the prefill value reached {table}"

    assert view.presented_sha256 is not None
    assert PREFILL_VALUE.encode() in bench.blobs.get(db, view.presented_sha256)
