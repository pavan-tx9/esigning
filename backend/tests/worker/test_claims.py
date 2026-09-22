"""Seal job claims: taken by one worker, honoured by the rest, taken over when the worker died."""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import Engine, text

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import SealResult, SealUnavailable, SealValidation
from esign.worker import claim_seal_jobs, run_once, seal_one
from tests.e2e.conftest import Sessions, build_world


class DownSealer:
    def seal(self, pdf: bytes, *, reason: str, envelope_id: UUID) -> SealResult:
        raise SealUnavailable("the key service did not answer", code="kms_unavailable")

    def validate(self, pdf: bytes) -> SealValidation:  # pragma: no cover - never reached
        raise AssertionError("nothing was sealed, so nothing is validated")


def test_a_claim_is_exclusive_until_it_goes_stale(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    down = build_world(e2e_settings, clock, app_engine, db_factory, sealer=DownSealer())
    ehr = down.host()
    ehr.publish_template("hipaa_acknowledgement")
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    ehr.sign_everyone(envelope, ("patient",))  # the inline attempt fails: job due in one minute
    clock.advance(timedelta(minutes=1))

    stale_after = timedelta(seconds=e2e_settings.seal_job_lock_timeout_seconds)
    with down.sessions() as db:
        now = clock.now()
        first = claim_seal_jobs(db, now=now, stale_before=now - stale_after, limit=10)
        db.commit()
    assert [str(i) for i in first] == [envelope["id"]]

    # A worker claimed it and then died. Nobody else touches it while the claim is fresh...
    healthy = build_world(e2e_settings, clock, app_engine, db_factory)
    assert run_once(healthy.rt, send=ehr.receive).sealed == 0
    clock.advance(stale_after - timedelta(seconds=1))
    assert run_once(healthy.rt, send=ehr.receive).sealed == 0
    # ...and once it is stale, the next worker takes it over and finishes the job.
    clock.advance(timedelta(seconds=2))
    assert run_once(healthy.rt, send=ehr.receive).sealed == 1
    assert ehr.envelope(envelope["id"])["status"] == "sealed"


def test_repeated_failures_follow_the_backoff_schedule(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    down = build_world(e2e_settings, clock, app_engine, db_factory, sealer=DownSealer())
    ehr = down.host()
    ehr.publish_template("hipaa_acknowledgement")
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    ehr.sign_everyone(envelope, ("patient",))

    for wait in (60, 300, 900, 3600, 3600):
        clock.advance(wait)
        assert run_once(down.rt, send=ehr.receive).seal_failures == 1
    events = ehr.get(f"/envelopes/{envelope['id']}/audit").json()["events"]
    waits = [e["data"]["retry_in_seconds"] for e in events if e["event_type"] == "seal.failed"]
    assert waits == [60, 300, 900, 3600, 3600, 3600]  # SPEC 3: 1m, 5m, 15m, 1h, then hourly
    assert ehr.envelope(envelope["id"])["status"] == "completed_pending_seal"
    assert ehr.get(f"/envelopes/{envelope['id']}/document").status_code == 409


def test_sealing_something_that_is_not_pending_is_settled_not_retried(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    world = build_world(e2e_settings, clock, app_engine, db_factory)
    ehr = world.host()
    ehr.publish_template("hipaa_acknowledgement")
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    ehr.sign_everyone(envelope, ("patient",))
    assert ehr.envelope(envelope["id"])["status"] == "sealed"

    assert seal_one(world.rt, UUID(envelope["id"])) is True  # already sealed: nothing to do, no second seal
    assert ehr.audit_types(envelope["id"]).count("document.sealed") == 1
    with world.sessions() as db:
        assert db.execute(text("SELECT count(*) FROM seal_jobs WHERE completed_at IS NULL")).scalar_one() == 0

    open_envelope = ehr.create_envelope("hipaa_acknowledgement")
    assert seal_one(world.rt, UUID(open_envelope["id"])) is False  # not complete: refused, not sealed
    assert ehr.envelope(open_envelope["id"])["status"] == "created"


def test_a_failure_while_settling_a_refused_job_does_not_escape(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``seal_one`` promises never to raise for an expected failure.

    ``POST /v1/signing/sign`` calls it after the signing transaction has committed, so an exception
    here becomes a 500 for a signature that *was* recorded; in the worker, ``run_once`` has no
    per-job guard, so the whole tick aborts. Both recovery helpers open a transaction of their own,
    and an exception raised inside an ``except`` clause is not caught by its sibling.
    """
    world = build_world(e2e_settings, clock, app_engine, db_factory)
    ehr = world.host()
    ehr.publish_template("hipaa_acknowledgement")
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    ehr.sign_everyone(envelope, ("patient",))  # sealed inline; the job is finished

    def exploding(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("the database went away while settling the job")

    monkeypatch.setattr("esign.worker._settle_refused_job", exploding)
    # Sealing an already-sealed envelope is a Conflict, which routes into _settle_refused_job.
    assert seal_one(world.rt, UUID(envelope["id"])) is False


def test_a_failure_while_backing_a_job_off_does_not_escape(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions, monkeypatch: pytest.MonkeyPatch
) -> None:
    down = build_world(e2e_settings, clock, app_engine, db_factory, sealer=DownSealer())
    ehr = down.host()
    ehr.publish_template("hipaa_acknowledgement")
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    ehr.sign_everyone(envelope, ("patient",))

    def exploding(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("the database went away while backing the job off")

    monkeypatch.setattr("esign.worker._ensure_backed_off", exploding)
    clock.advance(timedelta(minutes=1))
    assert seal_one(down.rt, UUID(envelope["id"]), claimed_at=clock.now()) is False
