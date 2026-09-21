"""Fixtures for the identity tests."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import structlog

import esign.identity
from esign.clock import FixedClock
from esign.config import Settings
from esign.identity import SlidingWindowRateLimiter, SqlIdentityService


@pytest.fixture
def identity(settings: Settings, clock: FixedClock) -> SqlIdentityService:
    """The service under test, on this process's database and the frozen clock."""
    return SqlIdentityService(settings, clock)


@pytest.fixture
def limiter(clock: FixedClock) -> SlidingWindowRateLimiter:
    return SlidingWindowRateLimiter(clock)


@pytest.fixture(autouse=True)
def isolated_logging() -> Iterator[None]:
    """Keep logging configuration from leaking between tests, in either direction.

    ``configure_logging`` binds structlog to the stream it is given and caches the assembled
    logger. Under pytest that stream is the capture buffer of whichever test called it, which is
    closed by the time the next test runs -- so a test that configures logging can otherwise take
    every later test down with it.
    """
    saved: dict[str, Any] = structlog.get_config()
    structlog.reset_defaults()
    try:
        yield
    finally:
        structlog.reset_defaults()
        structlog.configure(**saved)


@pytest.fixture
def module_sources() -> list[tuple[str, str]]:
    """Every Python source file in the identity package, for the mechanical checks."""
    package = Path(esign.identity.__file__).parent
    return [(path.name, path.read_text(encoding="utf-8")) for path in sorted(package.glob("*.py"))]
