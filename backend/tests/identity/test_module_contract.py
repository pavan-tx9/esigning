"""The seam: the factories SPEC section 2 names, and the Protocols in contracts.py.

If the integration agent can build this module from ``Settings`` and a ``Clock`` and call every
method the Protocol declares, the seam holds. Nothing here reaches into a sibling module.
"""

from __future__ import annotations

import inspect

import pytest

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import IdentityService, RateLimiter
from esign.identity import build_identity_service, build_rate_limiter


def test_the_factories_build_something_that_implements_the_protocols(
    settings_no_db: Settings, clock: FixedClock
) -> None:
    identity = build_identity_service(settings_no_db, clock)
    limiter = build_rate_limiter(settings_no_db, clock)

    for protocol, implementation in ((IdentityService, identity), (RateLimiter, limiter)):
        for name, declared in inspect.getmembers(protocol, inspect.isfunction):
            if name.startswith("_"):
                continue
            method = getattr(implementation, name, None)
            assert callable(method), f"{implementation!r} has no {name}"
            assert inspect.signature(method) == inspect.signature(declared).replace(
                parameters=list(inspect.signature(declared).parameters.values())[1:]
            ), f"{name} does not match the contract"


def test_a_broken_proxy_configuration_fails_at_startup_not_mid_request(
    settings_no_db: Settings, clock: FixedClock
) -> None:
    broken = settings_no_db.model_copy(update={"trusted_proxy_cidrs": ("10.0.0.0/8", "not-a-cidr")})
    with pytest.raises(ValueError, match="not appear to be"):
        build_identity_service(broken, clock)


def test_a_broken_default_locale_fails_at_startup(settings_no_db: Settings, clock: FixedClock) -> None:
    broken = settings_no_db.model_copy(update={"default_locale": "not a locale"})
    with pytest.raises(Exception, match="locale"):
        build_identity_service(broken, clock)


def test_the_service_resolves_the_client_address_from_configuration(
    settings_no_db: Settings, clock: FixedClock
) -> None:
    configured = settings_no_db.model_copy(update={"trusted_proxy_cidrs": ("10.0.0.0/8",)})
    identity = build_identity_service(configured, clock)
    assert identity.client_ip("10.0.0.5", "203.0.113.9") == "203.0.113.9"  # type: ignore[attr-defined]
    assert identity.client_ip("203.0.113.9", "10.0.0.5") == "203.0.113.9"  # type: ignore[attr-defined]


def test_each_process_gets_its_own_limiter(settings_no_db: Settings, clock: FixedClock) -> None:
    first = build_rate_limiter(settings_no_db, clock)
    second = build_rate_limiter(settings_no_db, clock)
    assert first is not second


def test_the_module_reads_no_wall_clock(module_sources: list[tuple[str, str]]) -> None:
    """Evidence is only as good as its times, and every time here comes from ``Clock``."""
    for name, source in module_sources:
        for forbidden in ("datetime.now(", "datetime.utcnow(", "time.time(", "date.today("):
            assert forbidden not in source, f"{name} reads the wall clock: {forbidden}"


def test_the_module_imports_no_sibling_module(module_sources: list[tuple[str, str]]) -> None:
    """SPEC section 2: modules depend on contracts and foundation files, never on each other."""
    siblings = ("esign.audit", "esign.storage", "esign.sealing", "esign.documents", "esign.envelopes", "esign.api")
    for name, source in module_sources:
        for sibling in siblings:
            assert sibling not in source, f"{name} reaches into {sibling}"
