"""The sliding window: it has to hold under threads, under time, and under key spraying."""

from __future__ import annotations

import threading

import pytest

from esign.clock import FixedClock
from esign.contracts import RateLimited
from esign.identity import RateLimits, SlidingWindowRateLimiter


def test_hits_up_to_the_limit_pass(limiter: SlidingWindowRateLimiter) -> None:
    for _ in range(5):
        limiter.hit("signer-1", limit=5, window_seconds=60)


def test_the_next_hit_is_refused(limiter: SlidingWindowRateLimiter) -> None:
    for _ in range(5):
        limiter.hit("signer-1", limit=5, window_seconds=60)
    with pytest.raises(RateLimited) as caught:
        limiter.hit("signer-1", limit=5, window_seconds=60)
    assert caught.value.code == "rate_limited"
    assert caught.value.http_status == 429


def test_keys_are_independent(limiter: SlidingWindowRateLimiter) -> None:
    for _ in range(5):
        limiter.hit("a", limit=5, window_seconds=60)
    limiter.hit("b", limit=5, window_seconds=60)


def test_the_window_slides_rather_than_resetting(clock: FixedClock) -> None:
    limiter = SlidingWindowRateLimiter(clock)
    limiter.hit("k", limit=2, window_seconds=60)
    clock.advance(30)
    limiter.hit("k", limit=2, window_seconds=60)
    with pytest.raises(RateLimited):
        limiter.hit("k", limit=2, window_seconds=60)

    clock.advance(31)  # the first hit has aged out, the second has not
    limiter.hit("k", limit=2, window_seconds=60)
    with pytest.raises(RateLimited):
        limiter.hit("k", limit=2, window_seconds=60)


def test_a_fixed_window_boundary_cannot_be_straddled(clock: FixedClock) -> None:
    """Two bursts either side of a round minute must not both go through."""
    limiter = SlidingWindowRateLimiter(clock)
    for _ in range(3):
        limiter.hit("k", limit=3, window_seconds=60)
    clock.advance(59)
    with pytest.raises(RateLimited):
        limiter.hit("k", limit=3, window_seconds=60)


def test_a_refused_hit_does_not_extend_the_window(clock: FixedClock) -> None:
    limiter = SlidingWindowRateLimiter(clock)
    limiter.hit("k", limit=1, window_seconds=60)
    for _ in range(20):
        clock.advance(1)
        with pytest.raises(RateLimited):
            limiter.hit("k", limit=1, window_seconds=60)
    clock.advance(41)  # 61s after the one real hit
    limiter.hit("k", limit=1, window_seconds=60)


def test_time_is_the_injected_clock_only(clock: FixedClock) -> None:
    """Nothing here reads the wall clock: a stopped clock means a window that never moves."""
    limiter = SlidingWindowRateLimiter(clock)
    limiter.hit("k", limit=1, window_seconds=1)
    with pytest.raises(RateLimited):
        limiter.hit("k", limit=1, window_seconds=1)


def test_threads_cannot_both_take_the_last_slot(clock: FixedClock) -> None:
    limiter = SlidingWindowRateLimiter(clock)
    limit = 25
    attempts = 400
    workers = 8
    start = threading.Barrier(workers)
    allowed: list[int] = []
    lock = threading.Lock()

    def run() -> None:
        start.wait()
        taken = 0
        for _ in range(attempts // workers):
            try:
                limiter.hit("shared", limit=limit, window_seconds=300)
            except RateLimited:
                continue
            taken += 1
        with lock:
            allowed.append(taken)

    threads = [threading.Thread(target=run) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(allowed) == limit


def test_memory_is_bounded_by_the_key_cap(clock: FixedClock) -> None:
    limiter = SlidingWindowRateLimiter(clock, max_keys=64)
    for index in range(5000):
        limiter.hit(f"ip:{index}", limit=10, window_seconds=3600)
    assert limiter.key_count() <= 64


def test_a_live_key_is_not_forgotten_while_other_keys_are_busy(clock: FixedClock) -> None:
    """Forgetting a key resets its count, so the sweep must not touch an open window."""
    limiter = SlidingWindowRateLimiter(clock)
    limiter.hit("victim", limit=1, window_seconds=600)
    for index in range(500):
        limiter.hit(f"noise:{index}", limit=10, window_seconds=600)
    with pytest.raises(RateLimited):
        limiter.hit("victim", limit=1, window_seconds=600)


def test_keys_are_forgotten_once_their_window_has_passed(clock: FixedClock) -> None:
    limiter = SlidingWindowRateLimiter(clock)
    for index in range(50):
        limiter.hit(f"k:{index}", limit=5, window_seconds=60)
    assert limiter.key_count() == 50
    clock.advance(61)
    for index in range(50):
        limiter.hit(f"later:{index}", limit=5, window_seconds=60)
    assert limiter.key_count() <= 50 + 8


@pytest.mark.parametrize(("limit", "window"), [(0, 60), (-1, 60), (5, 0), (5, -60)])
def test_nonsense_policies_are_a_programming_error(limiter: SlidingWindowRateLimiter, limit: int, window: int) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        limiter.hit("k", limit=limit, window_seconds=window)


def test_the_shipped_policies_are_sane() -> None:
    for policy in (RateLimits.SESSION_CREATE, RateLimits.REAUTH, RateLimits.TOKEN_FAILURE, RateLimits.SIGN):
        assert policy.limit >= 1
        assert policy.window_seconds >= 1
