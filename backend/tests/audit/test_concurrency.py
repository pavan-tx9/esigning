"""Concurrent writers on one stream. SPEC section 12: "concurrent appends to one stream produce
a gapless chain".

Real threads, real separate connections, real commits -- the rollback-per-test trick cannot
express this, because the writers have to be able to see each other's committed rows.

The clock ticks on every read. That makes the test stricter than the rule: not only must the
sequence be gapless, the timestamps must come out in the same order as the sequence numbers. That
only holds because ``append`` reads the clock *inside* the per-stream advisory lock.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from esign.audit import build_audit_log
from esign.clock import AdvancingClock
from esign.config import Settings
from esign.contracts import EventType
from tests.audit.helpers import sample_data
from tests.conftest import FROZEN_NOW

SessionFactory = Callable[[], AbstractContextManager[Session]]

THREADS = 8
PER_THREAD = 5


@pytest.mark.slow
def test_concurrent_appends_to_one_stream_produce_a_gapless_chain(
    settings: Settings, db_factory: SessionFactory
) -> None:
    audit = build_audit_log(settings, AdvancingClock(FROZEN_NOW, step=timedelta(milliseconds=1)))
    stream = uuid4()
    start = threading.Barrier(THREADS)
    failures: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            start.wait(timeout=30)
            for _ in range(PER_THREAD):
                with db_factory() as db:
                    audit.append(
                        db,
                        stream_type="envelope",
                        stream_id=stream,
                        event_type=EventType.DOCUMENT_PRESENTED,
                        data=sample_data(EventType.DOCUMENT_PRESENTED),
                    )
                    db.commit()
        except BaseException as exc:
            with lock:
                failures.append(exc)

    threads = [threading.Thread(target=worker, name=f"appender-{index}") for index in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert failures == [], f"{len(failures)} writer(s) failed: {failures[:3]}"

    with db_factory() as db:
        events = audit.list(db, "envelope", stream)
        report = audit.verify(db, "envelope", stream)

    expected = THREADS * PER_THREAD
    assert [event.sequence for event in events] == list(range(1, expected + 1))
    assert len({event.id for event in events}) == expected
    assert len({event.event_hash for event in events}) == expected
    # Every link holds, and the timestamps were taken in sequence order.
    assert report.ok, report.problems
    assert report.event_count == expected
    assert [event.occurred_at for event in events] == sorted(event.occurred_at for event in events)


@pytest.mark.slow
def test_concurrent_appends_to_different_streams_stay_independent(
    settings: Settings, db_factory: SessionFactory
) -> None:
    audit = build_audit_log(settings, AdvancingClock(FROZEN_NOW, step=timedelta(milliseconds=1)))
    streams = [uuid4() for _ in range(4)]
    failures: list[BaseException] = []
    lock = threading.Lock()

    def worker(stream_id: UUID) -> None:
        try:
            for _ in range(PER_THREAD):
                with db_factory() as db:
                    audit.append(
                        db,
                        stream_type="envelope",
                        stream_id=stream_id,
                        event_type=EventType.DOCUMENT_VIEWED,
                        data=sample_data(EventType.DOCUMENT_VIEWED),
                    )
                    db.commit()
        except BaseException as exc:
            with lock:
                failures.append(exc)

    threads = [threading.Thread(target=worker, args=(stream,)) for stream in streams for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert failures == []
    with db_factory() as db:
        for stream in streams:
            report = audit.verify(db, "envelope", stream)
            assert report.ok, (stream, report.problems)
            assert report.event_count == PER_THREAD * 2
