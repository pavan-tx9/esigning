"""An in-memory sliding-window rate limiter.

It exists to slow down guessing -- session tokens, consent replays, repeated signing attempts --
not to meter traffic, so it is deliberately simple: one process, one dictionary, no Redis.

Four properties it must actually have:

* **Sliding, not fixed.** A caller cannot get ``2 * limit`` through by straddling a bucket
  boundary, because the window is measured back from now on every hit.
* **Thread safe.** FastAPI runs sync endpoints in a thread pool; two threads hitting the same key
  at the same time must not both see room for the last request.
* **Bounded memory.** Keys are per session and per IP, so a caller choosing keys must not be able
  to grow the table without limit. A key is forgotten only once its own window has fully elapsed;
  the hard cap is a backstop, evicting the least recently hit key.
* **No accidental reset.** Forgetting a key resets its count, so the sweep never drops a key whose
  window is still open.

Time comes from ``Clock``; nothing here reads the wall clock, so a test can prove the window
without sleeping.
"""

from __future__ import annotations

import math
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Final

from esign.contracts import Clock, RateLimited

__all__ = [
    "DEFAULT_MAX_KEYS",
    "Limit",
    "RateLimits",
    "SlidingWindowRateLimiter",
    "host_key",
    "ip_key",
    "session_key",
]

#: Enough for every live session and client address of a busy clinic day, small enough that a
#: key-spraying caller cannot exhaust the process.
DEFAULT_MAX_KEYS: Final = 20_000

#: Keys examined per sweep. The sweep runs from the least recently hit end, so it is amortised.
_SWEEP_BUDGET: Final = 8


@dataclass
class _Bucket:
    window_seconds: int
    times: deque[float] = field(default_factory=deque)


@dataclass(frozen=True)
class Limit:
    """One rule: at most ``limit`` hits in ``window_seconds``."""

    limit: int
    window_seconds: int


class RateLimits:
    """The limits SPEC section 8 asks for, in one place so the API does not invent its own.

    Generous enough that a patient who taps twice, loses signal and retries never meets them;
    tight enough that guessing a 256-bit token, replaying a consent, or opening sessions in a loop
    stops being worth attempting.
    """

    #: Per host: opening signing sessions.
    SESSION_CREATE = Limit(limit=60, window_seconds=60)
    #: Per host: re-authentication attestations.
    REAUTH = Limit(limit=60, window_seconds=60)
    #: Per IP: presenting a token that does not authenticate.
    TOKEN_FAILURE = Limit(limit=20, window_seconds=300)
    #: Per session: accepting consent.
    CONSENT = Limit(limit=10, window_seconds=60)
    #: Per session: signing attempts.
    SIGN = Limit(limit=10, window_seconds=60)


def host_key(scope: str, host_id: object) -> str:
    return f"host:{host_id}:{scope}"


def ip_key(scope: str, ip: str | None) -> str:
    return f"ip:{ip or 'unknown'}:{scope}"


def session_key(scope: str, session_id: object) -> str:
    return f"session:{session_id}:{scope}"


class SlidingWindowRateLimiter:
    """Counts hits per key inside a moving window. Implements ``RateLimiter``."""

    def __init__(self, clock: Clock, *, max_keys: int = DEFAULT_MAX_KEYS) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be positive")
        self._clock = clock
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()

    def hit(self, key: str, *, limit: int, window_seconds: int) -> None:
        """Record one hit against ``key``. Raises ``RateLimited`` once the window is full.

        A rejected hit is not recorded: a caller that keeps hammering does not push its own window
        forward, so it is let back in as soon as the earliest real hit ages out.
        """
        if limit < 1:
            raise ValueError("limit must be positive")
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")

        now = self._clock.now().timestamp()

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(window_seconds=window_seconds)
                self._buckets[key] = bucket
            # One key is only ever used with one window in this codebase. If that stops being
            # true, remember the longest: forgetting a key early would reset its count.
            bucket.window_seconds = max(bucket.window_seconds, window_seconds)
            cutoff = now - window_seconds
            while bucket.times and bucket.times[0] <= cutoff:
                bucket.times.popleft()
            over_limit = len(bucket.times) >= limit
            # When the earliest hit still inside the window ages out, one more is allowed.
            retry_after = max(1, math.ceil(bucket.times[0] + window_seconds - now)) if over_limit else None
            if not over_limit:
                bucket.times.append(now)
            self._buckets.move_to_end(key)
            self._sweep(now)
            if over_limit:
                raise RateLimited("too many requests", retry_after_seconds=retry_after)

    def _sweep(self, now: float) -> None:
        """Forget fully elapsed keys, then enforce the hard cap. Called with the lock held."""
        for stale_key in self._expired_keys(now):
            del self._buckets[stale_key]
        while len(self._buckets) > self._max_keys:
            # Backstop only: the victim is the key nobody has touched for longest.
            self._buckets.popitem(last=False)

    def _expired_keys(self, now: float) -> list[str]:
        expired: list[str] = []
        for index, (candidate, bucket) in enumerate(self._buckets.items()):
            if index >= _SWEEP_BUDGET:
                break
            if not bucket.times or bucket.times[-1] <= now - bucket.window_seconds:
                expired.append(candidate)
        return expired

    def key_count(self) -> int:
        """How many keys are being tracked. For tests and metrics, never for a decision."""
        with self._lock:
            return len(self._buckets)
