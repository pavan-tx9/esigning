"""Fixtures for the audit tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from esign.audit import build_audit_log
from esign.clock import AdvancingClock, FixedClock
from esign.config import Settings
from esign.contracts import AuditLog
from tests.conftest import FROZEN_NOW


@pytest.fixture
def audit(settings: Settings, clock: FixedClock) -> AuditLog:
    """An audit log on a stopped clock. Events share a timestamp, which is legal: the chain
    requires ``occurred_at`` never to go *backwards*, not to be strictly increasing."""
    return build_audit_log(settings, clock)


@pytest.fixture
def ticking_audit(settings: Settings) -> AuditLog:
    """An audit log whose clock moves on every read: for ordering and monotonicity tests."""
    return build_audit_log(settings, AdvancingClock(FROZEN_NOW, step=timedelta(milliseconds=250)))
