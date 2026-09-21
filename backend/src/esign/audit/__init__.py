"""Append-only, hash-chained audit trail. See docs/SPEC.md section 4.

The trail is the evidence. Every state change in the pipeline writes one event, in the same
transaction as the change, so an envelope can never move without the record that explains why.

Layout:

``canonical.py``  canonical JSON and the event hash. Pure, dependency-free, and documented in
                  ``README.md`` with a worked vector so a chain can be re-checked by hand.
``events.py``     the allowed ``data`` shape for every :class:`~esign.contracts.EventType`.
``log.py``        :class:`~esign.audit.log.PostgresAuditLog`: advisory-locked append, gapless
                  sequence, and a ``verify`` that reports every problem it finds.

Usage::

    audit = build_audit_log(settings, clock)
    audit.append(db, stream_type="envelope", stream_id=envelope_id,
                 event_type=EventType.ENVELOPE_CREATED, actor=actor, ctx=ctx, data={...})
"""

from __future__ import annotations

from esign.audit.canonical import (
    HASHED_FIELDS,
    ZERO_HASH,
    canonical_json,
    compute_event_hash,
    hash_input,
    rfc3339,
)
from esign.audit.events import EVENT_DATA_MODELS, declared_data_keys, validate_event_data
from esign.audit.log import PostgresAuditLog
from esign.config import Settings
from esign.contracts import AuditLog, Clock

__all__ = [
    "EVENT_DATA_MODELS",
    "HASHED_FIELDS",
    "ZERO_HASH",
    "PostgresAuditLog",
    "build_audit_log",
    "canonical_json",
    "compute_event_hash",
    "declared_data_keys",
    "hash_input",
    "rfc3339",
    "validate_event_data",
]


def build_audit_log(settings: Settings, clock: Clock) -> AuditLog:
    """The module's one factory (SPEC section 2). Cheap to call; the result is thread-safe."""
    return PostgresAuditLog(settings, clock)
