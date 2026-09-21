"""Double submission, and the failure rule: never fail open."""

from __future__ import annotations

import threading
from datetime import timedelta
from uuid import UUID

from sqlalchemy import Engine, text

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import Sealer, SealResult, SealUnavailable, SealValidation
from esign.sealing import build_sealer
from esign.worker import run_once
from tests.e2e.conftest import Ehr, Sessions, World, build_world


def _count(world: World, sql: str, **params: object) -> int:
    with world.sessions() as db:
        return int(db.execute(text(sql), params).scalar_one())


def test_a_double_submitted_signature_returns_the_same_response_and_makes_one_revision(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("patient_consent")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()

    missing = patient.post("/sign", {"intent_confirmed": True, "captures": patient.captures(payload)})
    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "idempotency_key_required"

    first = patient.sign(payload, key="tap-1")
    second = patient.sign(payload, key="tap-1")  # the retry after a dropped connection
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()

    revisions = "SELECT count(*) FROM document_revisions WHERE envelope_id = :id AND kind = 'signer_applied'"
    assert _count(world, revisions, id=envelope["id"]) == 1
    assert ehr.audit_types(envelope["id"]).count("signer.signed") == 1

    # However often the connection drops, the retry gets the first answer -- never a 429.
    for _ in range(15):
        assert patient.sign(payload, key="tap-1").json() == first.json()

    # The same key with a different body is a conflict, not a second signature and not a replay.
    different = patient.post(
        "/sign",
        {"intent_confirmed": True, "captures": patient.captures(payload, kind="click")},
        **{"Idempotency-Key": "tap-1"},
    )
    assert different.status_code == 409
    assert different.json()["error"]["code"] == "idempotency_key_reused"
    assert _count(world, revisions, id=envelope["id"]) == 1


def test_two_racing_submissions_with_one_key_sign_once(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()

    results: list[tuple[int, dict[str, object]]] = []
    barrier = threading.Barrier(2)

    def submit() -> None:
        barrier.wait()
        response = patient.sign(payload, key="double-tap")
        results.append((response.status_code, response.json()))

    threads = [threading.Thread(target=submit) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert [status for status, _ in results] == [200, 200]
    assert results[0][1] == results[1][1]
    revisions = "SELECT count(*) FROM document_revisions WHERE envelope_id = :id AND kind = 'signer_applied'"
    assert _count(world, revisions, id=envelope["id"]) == 1
    assert ehr.audit_types(envelope["id"]).count("signer.signed") == 1
    assert ehr.envelope(envelope["id"])["status"] == "sealed"


def test_envelope_creation_is_idempotent_too(ehr: Ehr, world: World) -> None:
    body = ehr.envelope_body("hipaa_acknowledgement")
    first = ehr.post("/envelopes", body, **{"Idempotency-Key": "chart-77120-hipaa"})
    second = ehr.post("/envelopes", body, **{"Idempotency-Key": "chart-77120-hipaa"})
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert _count(world, "SELECT count(*) FROM envelopes") == 1

    changed = ehr.post(
        "/envelopes", {**body, "host_document_ref": "doc-9999"}, **{"Idempotency-Key": "chart-77120-hipaa"}
    )
    assert changed.status_code == 409
    assert changed.json()["error"]["code"] == "idempotency_key_reused"

    # The stored replay holds the envelope's id, not a second copy of anybody's name.
    with world.sessions() as db:
        stored = db.execute(text("SELECT response_body::text FROM idempotency_keys")).scalar_one()
    assert "Okonkwo" not in stored and first.json()["id"] in stored


def test_a_timestamp_authority_outage_leaves_the_envelope_pending_until_the_worker_retries(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    """SPEC 12, with the real sealer: the API process cannot reach its timestamp authority
    (nothing listens on the discard port), so the inline attempt fails closed. A worker whose
    authority is reachable seals it on the retry."""
    broken = e2e_settings.model_copy(update={"tsa_url": "http://127.0.0.1:9/tsa", "tsa_timeout_seconds": 2.0})
    world = build_world(broken, clock, app_engine, db_factory)
    ehr = world.host(webhook=True)
    ehr.publish_template("hipaa_acknowledgement")
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()

    signed = patient.sign(payload, key="signed-during-outage")
    assert signed.status_code == 200  # the signature stands; it is the seal that is pending

    pending = ehr.envelope(envelope["id"])
    assert pending["status"] == "completed_pending_seal"
    assert pending["sealed_sha256"] is None
    # Nothing anywhere reports the document as complete.
    assert patient.get("/copy").status_code == 202
    assert patient.get("/copy").json() == {"status": "sealing"}
    assert ehr.get(f"/envelopes/{envelope['id']}/document").status_code == 409
    assert "document.sealed" not in ehr.audit_types(envelope["id"])
    report = ehr.verification(envelope["id"])
    assert report["ok"] is True and report["complete"] is False

    # seal.failed survived the rollback of the attempt that caused it, with a code and a backoff.
    events = ehr.get(f"/envelopes/{envelope['id']}/audit").json()["events"]
    failed = [e for e in events if e["event_type"] == "seal.failed"]
    assert len(failed) == 1
    assert failed[0]["data"] == {"error_code": "seal_unavailable", "attempt": 1, "retry_in_seconds": 60}
    with world.sessions() as db:
        job = db.execute(
            text("SELECT attempts, last_error_code, locked_at, completed_at, next_attempt_at FROM seal_jobs")
        ).one()
    assert (job.attempts, job.last_error_code, job.locked_at, job.completed_at) == (1, "seal_unavailable", None, None)
    assert job.next_attempt_at == clock.now() + timedelta(minutes=1)
    # The failed attempt's unsealed revision went with its transaction.
    kinds = "SELECT count(*) FROM document_revisions WHERE envelope_id = :id AND kind IN ('final_unsealed','sealed')"
    assert _count(world, kinds, id=envelope["id"]) == 0

    healthy = build_world(e2e_settings, clock, app_engine, db_factory)

    # Not due yet: the backoff is honoured.
    assert run_once(healthy.rt, send=ehr.receive).sealed == 0
    assert ehr.envelope(envelope["id"])["status"] == "completed_pending_seal"

    # Still down a minute later: second failure, longer wait.
    clock.advance(timedelta(minutes=1))
    assert run_once(world.rt, send=ehr.receive).seal_failures == 1
    events = ehr.get(f"/envelopes/{envelope['id']}/audit").json()["events"]
    assert [e["data"]["retry_in_seconds"] for e in events if e["event_type"] == "seal.failed"] == [60, 300]

    clock.advance(timedelta(minutes=5))
    tick = run_once(healthy.rt, send=ehr.receive)
    assert tick.sealed == 1 and tick.seal_failures == 0

    assert ehr.envelope(envelope["id"])["status"] == "sealed"
    assert patient.get("/copy").status_code == 200
    report = ehr.verification(envelope["id"])
    assert report["ok"] and report["complete"], report["problems"]
    assert run_once(healthy.rt, send=ehr.receive).sealed == 0  # the job is finished


class KmsOutage:
    """The real sealer behind a key service that is down for the first ``failures`` calls."""

    def __init__(self, real: Sealer, failures: int) -> None:
        self._real = real
        self.failures = failures

    def seal(self, pdf: bytes, *, reason: str, envelope_id: UUID) -> SealResult:
        if self.failures > 0:
            self.failures -= 1
            raise SealUnavailable("the key service did not answer", code="kms_unavailable")
        return self._real.seal(pdf, reason=reason, envelope_id=envelope_id)

    def validate(self, pdf: bytes) -> SealValidation:
        return self._real.validate(pdf)


def test_a_kms_outage_leaves_the_envelope_pending_and_two_workers_seal_it_once(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    outage = KmsOutage(build_sealer(e2e_settings, clock), failures=1)
    world = build_world(e2e_settings, clock, app_engine, db_factory, sealer=outage)
    ehr = world.host()
    ehr.publish_template("hipaa_acknowledgement")
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    ehr.sign_everyone(envelope, ("patient",))

    assert ehr.envelope(envelope["id"])["status"] == "completed_pending_seal"
    events = ehr.get(f"/envelopes/{envelope['id']}/audit").json()["events"]
    assert [e["data"]["error_code"] for e in events if e["event_type"] == "seal.failed"] == ["kms_unavailable"]

    # Two workers tick at the same moment. SKIP LOCKED gives the job to exactly one of them.
    clock.advance(timedelta(minutes=1))
    other = build_world(e2e_settings, clock, app_engine, db_factory, sealer=outage)
    ticks = []
    barrier = threading.Barrier(2)

    def tick(target: World) -> None:
        barrier.wait()
        ticks.append(run_once(target.rt, send=ehr.receive))

    threads = [threading.Thread(target=tick, args=(w,)) for w in (world, other)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert sorted(t.sealed for t in ticks) == [0, 1]
    assert sum(t.seal_failures for t in ticks) == 0
    assert ehr.envelope(envelope["id"])["status"] == "sealed"
    assert ehr.audit_types(envelope["id"]).count("document.sealed") == 1
    assert _count(world, "SELECT count(*) FROM document_revisions WHERE kind = 'sealed'") == 1
    assert ehr.verification(envelope["id"])["complete"] is True
