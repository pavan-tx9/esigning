"""Host keys, signing sessions, re-authentication and consent. See docs/SPEC.md section 8.

Two factories, as SPEC section 2 requires::

    identity = build_identity_service(settings, clock)
    limiter = build_rate_limiter(settings, clock)

Everything else exported here is for the CLI (``create_host``, ``rotate_host_key``,
``add_consent_text``, ``seed_default_consent``) or for the API layer's request handling
(``client_ip``, the rate-limit policy). No sibling module reaches inside this package.

What this module guarantees:

* A credential exists in plaintext only in the response that mints it. The database holds
  ``sha256(token)`` and nothing else, and comparison is constant time.
* Unknown, expired and revoked session tokens are one indistinguishable failure.
* Every time value comes from ``Clock``. An attestation in the future, too old, or predating its
  session is rejected rather than accepted with a shrug.
* Consent texts are immutable and hash-checked on every read.
"""

from __future__ import annotations

from esign.config import Settings
from esign.contracts import Clock, IdentityService, RateLimiter
from esign.identity.client_ip import client_ip, parse_trusted_proxies
from esign.identity.consent_texts import (
    BundledConsent,
    add_consent_text,
    body_sha256,
    bundled_consent_texts,
    normalise_locale,
    seed_default_consent,
)
from esign.identity.hosts import (
    create_host,
    disable_host,
    normalise_origin,
    rotate_host_key,
    rotate_webhook_secret,
)
from esign.identity.ratelimit import Limit, RateLimits, SlidingWindowRateLimiter, host_key, ip_key, session_key
from esign.identity.service import AUTH_METHODS, IDENTITY_CHECKS, SqlIdentityService
from esign.identity.tokens import HOST_KEY_PREFIX, SESSION_TOKEN_PREFIX

__all__ = [
    "AUTH_METHODS",
    "HOST_KEY_PREFIX",
    "IDENTITY_CHECKS",
    "SESSION_TOKEN_PREFIX",
    "BundledConsent",
    "Limit",
    "RateLimits",
    "SlidingWindowRateLimiter",
    "SqlIdentityService",
    "add_consent_text",
    "body_sha256",
    "build_identity_service",
    "build_rate_limiter",
    "bundled_consent_texts",
    "client_ip",
    "create_host",
    "disable_host",
    "host_key",
    "ip_key",
    "normalise_locale",
    "normalise_origin",
    "parse_trusted_proxies",
    "rotate_host_key",
    "rotate_webhook_secret",
    "seed_default_consent",
    "session_key",
]


def build_identity_service(settings: Settings, clock: Clock) -> IdentityService:
    """The identity service. Holds no per-request state; build one per process."""
    return SqlIdentityService(settings, clock)


def build_rate_limiter(settings: Settings, clock: Clock) -> RateLimiter:  # noqa: ARG001 - settings kept for symmetry
    """The in-memory rate limiter. One per process: its counters are not shared between workers."""
    return SlidingWindowRateLimiter(clock)
