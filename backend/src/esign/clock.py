"""Time. Every timestamp in the system comes from a ``Clock``, never from ``datetime.now``.

Evidence is only as good as its times, so they are injected: a test can pin them, and nothing in
the code can accidentally read the wall clock behind the test's back.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from esign.contracts import Clock

__all__ = ["AdvancingClock", "Clock", "FixedClock", "SystemClock", "utc"]


def utc(
    year: int,
    month: int,
    day: int,
    hour: int = 0,
    minute: int = 0,
    second: int = 0,
    microsecond: int = 0,
) -> datetime:
    """A timezone-aware UTC datetime. Convenience for tests and fixtures."""
    return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=UTC)


class SystemClock:
    """The real clock. Always timezone-aware UTC, never naive."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """A clock that stands still until a test moves it.

    Thread-safe: the concurrency tests share one clock across threads.
    """

    def __init__(self, at: datetime) -> None:
        self._lock = threading.Lock()
        self._now = _require_utc(at)

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def set(self, at: datetime) -> None:
        with self._lock:
            self._now = _require_utc(at)

    def advance(self, delta: timedelta | float) -> datetime:
        """Move forward by a ``timedelta`` or a number of seconds; returns the new time."""
        step = delta if isinstance(delta, timedelta) else timedelta(seconds=delta)
        if step < timedelta(0):
            raise ValueError("time does not run backwards; use set() if a test truly needs that")
        with self._lock:
            self._now += step
            return self._now


class AdvancingClock:
    """A clock that ticks by a fixed step on every read.

    Useful where code needs strictly increasing timestamps (audit ``occurred_at`` monotonicity,
    ordering assertions) without a test having to advance it by hand.
    """

    def __init__(self, at: datetime, step: timedelta = timedelta(seconds=1)) -> None:
        if step <= timedelta(0):
            raise ValueError("step must be positive")
        self._lock = threading.Lock()
        self._next = _require_utc(at)
        self._step = step

    def now(self) -> datetime:
        with self._lock:
            value = self._next
            self._next = value + self._step
            return value


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("clock times must be timezone-aware")
    return value.astimezone(UTC)
