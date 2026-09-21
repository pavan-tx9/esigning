"""The background worker: seal jobs, expiries, webhooks. See docs/SPEC.md section 3.

``run_once`` is one tick and is what the tests drive; ``run_forever`` calls it in a loop. More than
one worker may run at once:

* seal jobs are *claimed* with ``FOR UPDATE SKIP LOCKED`` in a short transaction that commits
  before any sealing starts. The claim is a timestamp (``locked_at``), not a held row lock, because
  the envelope service records ``seal.failed`` from a separate session and must be able to update
  the job row while the attempt's own transaction is still open. A claim older than
  ``SEAL_JOB_LOCK_TIMEOUT_SECONDS`` belongs to a worker that died, and is taken over.
* the attempt itself runs under the envelope row lock, so even two workers holding the same job
  cannot both seal it: the second finds the envelope sealed and stands down.
* expiry takes each envelope's row lock; webhook deliveries are leased the same way as seal jobs.

Never fail open: whatever goes wrong in an attempt, the envelope stays ``completed_pending_seal``,
the failure is recorded, and the job backs off (1m, 5m, 15m, 1h, then hourly).
"""

from __future__ import annotations

import signal
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import FrameType
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import Conflict, EsignError
from esign.envelopes import next_backoff
from esign.logging import get_logger
from esign.runtime import Runtime
from esign.webhooks import HttpSender, Sender, deliver_due

__all__ = ["TickResult", "claim_seal_jobs", "run_forever", "run_once", "seal_one"]

log = get_logger(__name__)


@dataclass(frozen=True)
class TickResult:
    sealed: int = 0
    seal_failures: int = 0
    expired: int = 0
    webhooks_delivered: int = 0
    webhooks_failed: int = 0

    @property
    def idle(self) -> bool:
        return not (
            self.sealed or self.seal_failures or self.expired or self.webhooks_delivered or self.webhooks_failed
        )


def claim_seal_jobs(db: Session, *, now: datetime, stale_before: datetime, limit: int) -> list[UUID]:
    """Claim due jobs for this worker. The caller commits straight away."""
    rows = db.execute(
        text(
            "UPDATE seal_jobs SET locked_at = :now WHERE envelope_id IN ("
            "  SELECT envelope_id FROM seal_jobs "
            "  WHERE completed_at IS NULL AND next_attempt_at <= :now "
            "    AND (locked_at IS NULL OR locked_at < :stale_before) "
            "  ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT :limit) "
            "RETURNING envelope_id"
        ),
        {"now": now, "stale_before": stale_before, "limit": limit},
    ).all()
    return [row.envelope_id for row in rows]


def seal_one(rt: Runtime, envelope_id: UUID, *, claimed_at: datetime | None = None) -> bool:
    """One sealing attempt in one transaction. True when the envelope is sealed afterwards.

    Used by the worker for a claimed job and by the API for the single inline attempt after the
    last signature. It never raises for an expected failure: the envelope service has already
    recorded ``seal.failed`` and backed the job off, from a session of its own, by the time the
    exception reaches here.
    """
    try:
        with rt.transaction() as db:
            rt.envelopes.seal_pending(db, envelope_id)
        return True
    except Conflict as exc:
        # Not in completed_pending_seal. Sealed already (another worker, or the inline attempt)
        # means the job is simply finished; anything else must not be retried every tick.
        return _settle_refused_job(rt, envelope_id, exc.code)
    except Exception as exc:
        code = exc.code if isinstance(exc, EsignError) else "internal_error"
        log.warning("worker.seal_attempt_failed", envelope_id=envelope_id, error_code=code)
        if claimed_at is not None:
            _ensure_backed_off(rt, envelope_id, claimed_at, code)
        return False


def _settle_refused_job(rt: Runtime, envelope_id: UUID, code: str) -> bool:
    """Returns whether the envelope is in fact sealed (which is what the caller wanted)."""
    now = rt.clock.now()
    with rt.transaction() as db:
        status = db.execute(
            text("SELECT status FROM envelopes WHERE id = :id"), {"id": envelope_id}
        ).scalar_one_or_none()
        if status == "sealed":
            db.execute(
                text(
                    "UPDATE seal_jobs SET completed_at = COALESCE(completed_at, :now), locked_at = NULL "
                    "WHERE envelope_id = :id"
                ),
                {"id": envelope_id, "now": now},
            )
        else:
            db.execute(
                text(
                    "UPDATE seal_jobs SET locked_at = NULL, last_error_code = :code, next_attempt_at = :next "
                    "WHERE envelope_id = :id AND completed_at IS NULL"
                ),
                {"id": envelope_id, "code": code, "next": now + timedelta(hours=1)},
            )
            log.error("worker.seal_job_refused", envelope_id=envelope_id, error_code=code, envelope_status=status)
    return bool(status == "sealed")


def _ensure_backed_off(rt: Runtime, envelope_id: UUID, claimed_at: datetime, code: str) -> None:
    """Belt and braces. The envelope service normally records the failure and releases the claim.
    If it could not (its own recording step failed), the claim is still ours: back the job off
    here so it is neither retried in a tight loop nor stuck until the claim goes stale."""
    now = rt.clock.now()
    with rt.transaction() as db:
        row = db.execute(
            text("SELECT attempts, locked_at FROM seal_jobs WHERE envelope_id = :id AND completed_at IS NULL"),
            {"id": envelope_id},
        ).first()
        if row is None or row.locked_at is None or row.locked_at != claimed_at:
            return
        attempts = int(row.attempts) + 1
        db.execute(
            text(
                "UPDATE seal_jobs SET attempts = :attempts, last_error_code = :code, next_attempt_at = :next, "
                "  locked_at = NULL WHERE envelope_id = :id"
            ),
            {"id": envelope_id, "attempts": attempts, "code": code, "next": now + next_backoff(attempts)},
        )
    log.error("worker.seal_failure_unrecorded", envelope_id=envelope_id, error_code=code, attempts=attempts)


def run_once(rt: Runtime, *, send: Sender | None = None, batch: int = 20) -> TickResult:
    """One tick: due seal jobs, then expiries, then webhooks."""
    now = rt.clock.now()
    stale_before = now - timedelta(seconds=rt.settings.seal_job_lock_timeout_seconds)
    with rt.transaction() as db:
        claimed = claim_seal_jobs(db, now=now, stale_before=stale_before, limit=batch)

    sealed = failures = 0
    for envelope_id in claimed:
        if seal_one(rt, envelope_id, claimed_at=now):
            sealed += 1
        else:
            failures += 1

    expired = 0
    while True:
        with rt.transaction() as db:
            swept = rt.envelopes.expire_due(db)
        expired += swept
        if swept == 0:
            break

    # Housekeeping: idempotency keys past their window. A replay after that is a new request,
    # which the envelope service still refuses to turn into a second signature.
    with rt.transaction() as db:
        db.execute(
            text("DELETE FROM idempotency_keys WHERE created_at < :cutoff"),
            {"cutoff": now - timedelta(hours=rt.settings.idempotency_ttl_hours)},
        )

    owned: HttpSender | None = None
    if send is None:
        owned = HttpSender(rt.settings)
        send = owned
    try:
        delivered, undelivered = deliver_due(rt.new_session, send, rt.clock, rt.settings)
    finally:
        if owned is not None:
            owned.close()

    result = TickResult(
        sealed=sealed,
        seal_failures=failures,
        expired=expired,
        webhooks_delivered=delivered,
        webhooks_failed=undelivered,
    )
    if not result.idle:
        log.info("worker.tick", count=sealed + failures + expired + delivered + undelivered)
    return result


def run_forever(rt: Runtime, *, stop: threading.Event | None = None) -> None:
    """Tick until told to stop. SIGINT and SIGTERM finish the current tick and exit cleanly."""
    stop = stop or threading.Event()

    def _stop(_signum: int, _frame: FrameType | None) -> None:
        stop.set()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)

    sender = HttpSender(rt.settings)
    log.info("worker.started", component="worker")
    try:
        while not stop.is_set():
            try:
                result = run_once(rt, send=sender)
            except Exception:
                # The loop outlives a bad tick (database restart, say). Nothing is lost: every
                # job is a row, and the next tick finds it again.
                log.error("worker.tick_failed", component="worker", error_code="internal_error")
                result = TickResult()
            if result.idle:
                stop.wait(rt.settings.worker_poll_seconds)
    finally:
        sender.close()
        log.info("worker.stopped", component="worker")
