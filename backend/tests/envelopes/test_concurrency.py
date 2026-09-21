"""Two people signing at once.

These use ``db_factory``: real sessions on separate connections whose commits really commit. The
rolled-back ``db`` fixture cannot express a row lock between two transactions, and a test that
cannot express one cannot prove the envelope row lock does anything.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import Capture, Conflict, EnvelopeView, SealUnavailable, SessionInfo
from esign.envelopes import repository as repo
from tests.envelopes.conftest import CTX, HIPAA_PAIR, PATIENT_CONSENT, Bench

PNG = b"\x89PNG\r\n\x1a\n" + b"scribbled signature bytes"
SessionFactory = Callable[[], AbstractContextManager[Session]]


def sig(field_id: str) -> Capture:
    return Capture(field_id=field_id, kind="drawn", image_png=PNG)


def run_together(tasks: list[Callable[[], Any]]) -> list[Any]:
    """Run every task on its own thread, released from a barrier so they really overlap."""
    barrier = threading.Barrier(len(tasks))
    results: list[Any] = [None] * len(tasks)

    def runner(index: int, task: Callable[[], Any]) -> None:
        barrier.wait(timeout=10)
        try:
            results[index] = ("ok", task())
        except BaseException as exc:  # the test inspects whatever came back
            results[index] = ("raised", exc)

    threads = [threading.Thread(target=runner, args=(i, t)) for i, t in enumerate(tasks)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive(), "a thread is still waiting on a lock; this is a deadlock"
    return results


def ready_parallel_pair(bench: Bench, db_factory: SessionFactory) -> tuple[EnvelopeView, SessionInfo, SessionInfo]:
    """A two-signer parallel envelope with both signers presented, viewed and consented."""
    with db_factory() as setup:
        host = bench.host(setup)
        bench.template(setup, host, HIPAA_PAIR)
        bench.consent(setup)
        view = bench.create(setup, host, HIPAA_PAIR, signing_order="parallel")
        patient = bench.session(setup, bench.signer_id(view, "patient"))
        witness = bench.session(setup, bench.signer_id(view, "witness"))
        bench.ready_to_sign(setup, patient)
        bench.ready_to_sign(setup, witness)
        setup.commit()
    return view, patient, witness


def test_two_threads_signing_one_parallel_envelope_serialise(
    committing_bench: Bench, db_factory: SessionFactory
) -> None:
    """SPEC 12: parallel signers serialise correctly.

    Both signatures land, each on its own revision number, and the envelope completes exactly
    once -- which is the whole job of the ``SELECT ... FOR UPDATE`` on the envelope row.
    """
    bench = committing_bench
    view, patient, witness = ready_parallel_pair(bench, db_factory)

    def sign_as(session: SessionInfo, field_id: str) -> str:
        with db_factory() as db:
            result = bench.service.sign(db, session, [sig(field_id)], CTX)
            db.commit()
            return result.status

    outcomes = run_together(
        [
            lambda: sign_as(patient, "patient_sig"),
            lambda: sign_as(witness, "witness_sig"),
        ]
    )
    assert all(kind == "ok" for kind, _ in outcomes), outcomes
    assert sorted(value for _, value in outcomes) == ["completed_pending_seal", "in_progress"]

    with db_factory() as check:
        assert bench.status(check, view.id) == "completed_pending_seal"
        assert bench.revisions(check, view.id) == [
            (1, "presented"),
            (2, "signer_applied"),
            (3, "signer_applied"),
        ]
        statuses = (
            check.execute(text("SELECT status FROM signers WHERE envelope_id = :id"), {"id": view.id}).scalars().all()
        )
        assert statuses == ["signed", "signed"]


def test_concurrent_signatures_leave_a_gapless_audit_chain(committing_bench: Bench, db_factory: SessionFactory) -> None:
    bench = committing_bench
    view, patient, witness = ready_parallel_pair(bench, db_factory)

    def sign_as(session: SessionInfo, field_id: str) -> None:
        with db_factory() as db:
            bench.service.sign(db, session, [sig(field_id)], CTX)
            db.commit()

    run_together(
        [
            lambda: sign_as(patient, "patient_sig"),
            lambda: sign_as(witness, "witness_sig"),
        ]
    )

    with db_factory() as check:
        report = bench.audit.verify(check, "envelope", view.id)
        assert report.ok, report.problems
        events = bench.audit.list(check, "envelope", view.id)
        assert [e.sequence for e in events] == list(range(1, len(events) + 1))
        assert [str(e.event_type) for e in events].count("envelope.completed") == 1
        assert [str(e.event_type) for e in events].count("signer.signed") == 2


def test_the_second_signer_signs_on_top_of_the_first(committing_bench: Bench, db_factory: SessionFactory) -> None:
    """Whoever goes second must build on the revision the first one produced, not on revision 1."""
    bench = committing_bench
    view, patient, witness = ready_parallel_pair(bench, db_factory)

    def sign_as(session: SessionInfo, field_id: str) -> None:
        with db_factory() as db:
            bench.service.sign(db, session, [sig(field_id)], CTX)
            db.commit()

    run_together(
        [
            lambda: sign_as(patient, "patient_sig"),
            lambda: sign_as(witness, "witness_sig"),
        ]
    )

    with db_factory() as check:
        signed = [e for e in bench.audit.list(check, "envelope", view.id) if str(e.event_type) == "signer.signed"]
        first, second = sorted(signed, key=lambda e: e.data["revision_no"])
        assert first.data["revision_no"] == 2
        assert second.data["revision_no"] == 3
        # The second signature's base is the first signature's output.
        assert second.data["base_revision_sha256"] == first.document_sha256.hex()  # type: ignore[union-attr]
        # And it is visibly not what that signer was shown, which is why both hashes are recorded.
        assert second.data["presented_sha256"] == view.presented_sha256.hex()  # type: ignore[union-attr]


def test_exactly_one_seal_job_is_enqueued(committing_bench: Bench, db_factory: SessionFactory) -> None:
    bench = committing_bench
    view, patient, witness = ready_parallel_pair(bench, db_factory)

    def sign_as(session: SessionInfo, field_id: str) -> None:
        with db_factory() as db:
            bench.service.sign(db, session, [sig(field_id)], CTX)
            db.commit()

    run_together(
        [
            lambda: sign_as(patient, "patient_sig"),
            lambda: sign_as(witness, "witness_sig"),
        ]
    )

    with db_factory() as check:
        jobs = check.execute(
            text("SELECT count(*) FROM seal_jobs WHERE envelope_id = :id"), {"id": view.id}
        ).scalar_one()
        assert jobs == 1


def test_one_signer_signing_twice_at_once_produces_one_revision(
    committing_bench: Bench, db_factory: SessionFactory
) -> None:
    """A double-submitted signature, racing itself. One wins, one is refused, one revision exists."""
    bench = committing_bench
    with db_factory() as setup:
        host = bench.host(setup)
        bench.template(setup, host, PATIENT_CONSENT)
        bench.consent(setup)
        view = bench.create(setup, host, PATIENT_CONSENT)
        session = bench.session(setup, bench.signer_id(view, "patient"))
        bench.ready_to_sign(setup, session)
        setup.commit()

    def attempt() -> str:
        with db_factory() as db:
            result = bench.service.sign(db, session, [sig("patient_sig")], CTX)
            db.commit()
            return result.status

    outcomes = run_together([attempt, attempt])
    kinds = sorted(kind for kind, _ in outcomes)
    assert kinds == ["ok", "raised"]
    raised = next(value for kind, value in outcomes if kind == "raised")
    assert isinstance(raised, Conflict)

    with db_factory() as check:
        assert bench.revisions(check, view.id) == [(1, "presented"), (2, "signer_applied")]
        assert bench.event_types(check, view.id).count("signer.signed") == 1
        captures = check.execute(
            text("SELECT count(*) FROM signature_captures WHERE signer_id = :id"),
            {"id": bench.signer_id(view, "patient")},
        ).scalar_one()
        assert captures == 1


def test_two_workers_sealing_the_same_envelope(committing_bench: Bench, db_factory: SessionFactory) -> None:
    """Only one seal. The loser is told the envelope is already sealed, not handed a second one."""
    bench = committing_bench
    with db_factory() as setup:
        host = bench.host(setup)
        bench.template(setup, host, PATIENT_CONSENT)
        bench.consent(setup)
        view = bench.create(setup, host, PATIENT_CONSENT)
        session = bench.session(setup, bench.signer_id(view, "patient"))
        bench.ready_to_sign(setup, session)
        bench.service.sign(setup, session, [sig("patient_sig")], CTX)
        setup.commit()

    def attempt() -> str:
        with db_factory() as db:
            result = bench.service.seal_pending(db, view.id)
            db.commit()
            return result.status

    outcomes = run_together([attempt, attempt])
    kinds = sorted(kind for kind, _ in outcomes)
    assert kinds == ["ok", "raised"]
    raised = next(value for kind, value in outcomes if kind == "raised")
    assert isinstance(raised, Conflict)
    assert raised.code == "already_sealed"

    with db_factory() as check:
        assert bench.event_types(check, view.id).count("document.sealed") == 1
        assert bench.revisions(check, view.id) == [
            (1, "presented"),
            (2, "signer_applied"),
            (3, "final_unsealed"),
            (4, "sealed"),
        ]


def test_a_sweep_never_blocks_on_a_row_someone_else_holds(committing_bench: Bench, db_factory: SessionFactory) -> None:
    """``FOR UPDATE SKIP LOCKED``: the expiry sweep steps around a locked envelope.

    Without ``SKIP LOCKED`` this test hangs for as long as the other transaction holds the row,
    which in production is however long a signature takes.
    """
    bench = committing_bench
    with db_factory() as setup:
        host = bench.host(setup)
        bench.template(setup, host, PATIENT_CONSENT)
        held = bench.create(setup, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(minutes=30))
        free = bench.create(setup, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(minutes=30))
        setup.commit()

    bench.clock.advance(timedelta(hours=2))
    locked = threading.Event()
    release = threading.Event()

    def hold_the_row() -> None:
        with db_factory() as db:
            repo.lock_envelope(db, held.id)
            locked.set()
            release.wait(timeout=10)
            db.rollback()

    def sweep() -> int:
        locked.wait(timeout=10)
        with db_factory() as db:
            count = bench.service.expire_due(db)
            db.commit()
            release.set()
            return count

    outcomes = run_together([hold_the_row, sweep])
    release.set()
    assert all(kind == "ok" for kind, _ in outcomes), outcomes
    assert outcomes[1][1] == 1  # the free one expired; the locked one was skipped, not waited on

    with db_factory() as check:
        assert bench.status(check, free.id) == "expired"
        assert bench.status(check, held.id) == "created"


def test_an_envelope_past_its_date_refuses_to_be_signed_before_any_sweep(
    committing_bench: Bench, db_factory: SessionFactory
) -> None:
    """Never fail open: a stopped expiry worker must not be what keeps a lapsed consent signable."""
    bench = committing_bench
    with db_factory() as setup:
        host = bench.host(setup)
        bench.template(setup, host, PATIENT_CONSENT)
        bench.consent(setup)
        view = bench.create(setup, host, PATIENT_CONSENT, expires_at=bench.clock.now() + timedelta(minutes=30))
        signer_id = bench.signer_id(view, "patient")
        session = bench.session(setup, signer_id)
        bench.ready_to_sign(setup, session)
        setup.commit()

    bench.clock.advance(timedelta(hours=2))

    with db_factory() as db:
        # The status column still says in_progress: nothing has swept it yet.
        assert bench.status(db, view.id) == "in_progress"
        for call in (
            lambda: bench.service.present(db, session, CTX),
            lambda: bench.service.record_viewed(db, session, CTX),
            lambda: bench.service.sign(db, session, [sig("patient_sig")], CTX),
            lambda: bench.service.decline(db, session, "prefers_paper", CTX),
            lambda: bench.service.assert_signer_may_start(db, host, view.id, signer_id),
        ):
            with pytest.raises(Conflict) as seen:
                call()
            assert seen.value.code == "envelope_expired"
        db.rollback()


def test_a_seal_failure_recorded_alongside_a_live_transaction_does_not_deadlock(
    committing_bench: Bench, db_factory: SessionFactory
) -> None:
    """The failure record runs in its own session while the failed attempt is still open.

    If ``_seal`` ever starts appending to the envelope's audit stream before the seal validates,
    this is the test that hangs.
    """
    bench = committing_bench
    with db_factory() as setup:
        host = bench.host(setup)
        bench.template(setup, host, PATIENT_CONSENT)
        bench.consent(setup)
        view = bench.create(setup, host, PATIENT_CONSENT)
        session = bench.session(setup, bench.signer_id(view, "patient"))
        bench.ready_to_sign(setup, session)
        bench.service.sign(setup, session, [sig("patient_sig")], CTX)
        setup.commit()

    bench.sealer.fail_times = 1
    with db_factory() as attempt, pytest.raises(SealUnavailable):
        bench.service.seal_pending(attempt, view.id)

    with db_factory() as check:
        failed = [e for e in bench.audit.list(check, "envelope", view.id) if str(e.event_type) == "seal.failed"]
        assert len(failed) == 1
        assert bench.status(check, view.id) == "completed_pending_seal"
