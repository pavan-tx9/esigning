"""Envelope and signer state machine. See docs/SPEC.md section 3.

The module is three layers, deliberately separable:

``state``        the transition rules, as pure functions over statuses. No database, no clock.
``repository``   row access, plain SQL against the schema in ``migrations/0001_schema.sql``.
``service``      the ``EnvelopeService`` contract: lock, decide, persist, audit, in one transaction.

``build_envelope_service`` is the module's one entry point (SPEC section 2); everything it needs
from a sibling module arrives as a Protocol through the constructor.
"""

from __future__ import annotations

from esign.envelopes.service import (
    AUDIT_DATA_KEYS,
    DECLINE_REASON_CODES,
    EnvelopeServiceImpl,
    SessionScope,
    build_envelope_service,
)
from esign.envelopes.state import (
    SEAL_BACKOFF_SCHEDULE,
    Command,
    Decision,
    EnvelopeState,
    Refusal,
    SignerState,
    Transition,
    decide,
    next_backoff,
)

__all__ = [
    "AUDIT_DATA_KEYS",
    "DECLINE_REASON_CODES",
    "SEAL_BACKOFF_SCHEDULE",
    "Command",
    "Decision",
    "EnvelopeServiceImpl",
    "EnvelopeState",
    "Refusal",
    "SessionScope",
    "SignerState",
    "Transition",
    "build_envelope_service",
    "decide",
    "next_backoff",
]
