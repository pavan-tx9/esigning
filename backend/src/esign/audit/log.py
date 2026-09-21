"""The hash-chained audit trail over ``audit_events``.

One chain per stream. Writers serialise on a per-stream advisory lock held for the caller's
transaction, so the state change and the event that explains it commit together or not at all.

Three things this module refuses to do, because each of them would quietly cost evidence:

* it never invents a timestamp -- ``occurred_at`` comes from :class:`~esign.contracts.Clock`, and
  a clock that has gone backwards against the head of the stream stops the write instead of
  writing an event that ``verify`` would flag for ever;
* it never accepts a value it has not typed -- ``data`` goes through
  :func:`~esign.audit.events.validate_event_data`, and the actor and request context fields are
  pattern-checked here;
* it never stops verifying at the first problem. :meth:`PostgresAuditLog.verify` walks the whole
  chain and reports everything it found.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Final, get_args
from uuid import UUID

from sqlalchemy import Row, text
from sqlalchemy.orm import Session

from esign.audit.canonical import ZERO_HASH, canonical_json, compute_event_hash
from esign.audit.events import (
    ACTOR_ROLES,
    AUTH_METHOD_PATTERN,
    declared_data_keys,
    is_opaque_id,
    validate_event_data,
)
from esign.config import Settings
from esign.contracts import (
    Actor,
    AuditEvent,
    Capacity,
    ChainReport,
    Clock,
    EventType,
    IntegrityFailure,
    RequestContext,
    StreamType,
    ValidationFailed,
)
from esign.db import advisory_xact_lock
from esign.ids import advisory_lock_key, new_id
from esign.logging import get_logger

__all__ = ["PostgresAuditLog"]

log = get_logger(__name__)

_STREAM_TYPES: Final[frozenset[str]] = frozenset(get_args(StreamType))
_CAPACITIES: Final[frozenset[str]] = frozenset(get_args(Capacity))
_AUTH_METHOD = re.compile(AUTH_METHOD_PATTERN)

#: A user agent beyond this length is a payload, not evidence. Kept, but bounded; the truncation
#: is deliberate and documented rather than silent -- see :meth:`PostgresAuditLog.append`.
MAX_USER_AGENT_CHARS: Final[int] = 512

#: Advisory lock namespace, per stream type, so an envelope stream and a template stream that
#: happen to share a uuid do not serialise against each other.
_LOCK_NAMESPACE: Final[str] = "audit"

_INSERT_SQL: Final[str] = """
INSERT INTO audit_events
  (id, stream_type, stream_id, sequence, event_type, actor_user_id, actor_role, actor_capacity,
   on_behalf_of, auth_method, session_id, ip, user_agent, document_sha256, data, occurred_at,
   prev_event_hash, event_hash)
VALUES (:id, :stream_type, :stream_id, :sequence, :event_type, :actor_user_id, :actor_role,
        :actor_capacity, :on_behalf_of, :auth_method, :session_id, CAST(:ip AS inet), :user_agent,
        :document_sha256, CAST(:data AS jsonb), :occurred_at, :prev_event_hash, :event_hash)
"""

_HEAD_SQL: Final[str] = """
SELECT sequence, event_hash, occurred_at
FROM audit_events
WHERE stream_type = :stream_type AND stream_id = :stream_id
ORDER BY sequence DESC
LIMIT 1
"""

_LIST_SQL: Final[str] = """
SELECT id, stream_type, stream_id, sequence, event_type, actor_user_id, actor_role, actor_capacity,
       on_behalf_of, auth_method, session_id, ip, user_agent, document_sha256, data, occurred_at,
       prev_event_hash, event_hash
FROM audit_events
WHERE stream_type = :stream_type AND stream_id = :stream_id
ORDER BY sequence
"""


def _as_bytes(value: Any) -> bytes | None:
    """psycopg hands back ``bytes`` for ``bytea``; be robust if a driver hands back a buffer."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    raise IntegrityFailure("audit row holds a non-binary value where a hash belongs")


def _hash_fields(
    *,
    event_id: UUID,
    stream_type: str,
    stream_id: UUID,
    sequence: int,
    event_type: str,
    actor_user_id: str | None,
    actor_role: str | None,
    actor_capacity: str | None,
    on_behalf_of: str | None,
    auth_method: str | None,
    session_id: UUID | None,
    ip: str | None,
    user_agent: str | None,
    document_sha256: bytes | None,
    data: Mapping[str, Any],
    occurred_at: datetime,
    prev_event_hash: bytes,
) -> dict[str, Any]:
    """The hash input, keyed exactly as ``audit_events`` is (minus ``event_hash``)."""
    return {
        "actor_capacity": actor_capacity,
        "actor_role": actor_role,
        "actor_user_id": actor_user_id,
        "auth_method": auth_method,
        "data": dict(data),
        "document_sha256": document_sha256,
        "event_type": event_type,
        "id": event_id,
        "ip": ip,
        "occurred_at": occurred_at,
        "on_behalf_of": on_behalf_of,
        "prev_event_hash": prev_event_hash,
        "sequence": sequence,
        "session_id": session_id,
        "stream_id": stream_id,
        "stream_type": stream_type,
        "user_agent": user_agent,
    }


def _fields_from_row(row: Row[Any]) -> dict[str, Any]:
    """The same hash input, rebuilt from a stored row. Used by ``verify`` to re-derive the hash."""
    return _hash_fields(
        event_id=row.id,
        stream_type=row.stream_type,
        stream_id=row.stream_id,
        sequence=row.sequence,
        event_type=row.event_type,
        actor_user_id=row.actor_user_id,
        actor_role=row.actor_role,
        actor_capacity=row.actor_capacity,
        on_behalf_of=row.on_behalf_of,
        auth_method=row.auth_method,
        session_id=row.session_id,
        # ``inet`` comes back as an ipaddress object; its str form is what was hashed.
        ip=None if row.ip is None else str(row.ip),
        user_agent=row.user_agent,
        document_sha256=_as_bytes(row.document_sha256),
        data=row.data,
        occurred_at=row.occurred_at,
        prev_event_hash=_as_bytes(row.prev_event_hash) or ZERO_HASH,
    )


def _event_from_row(row: Row[Any]) -> AuditEvent:
    return AuditEvent(
        id=row.id,
        stream_type=row.stream_type,
        stream_id=row.stream_id,
        sequence=row.sequence,
        event_type=EventType(row.event_type),
        actor=Actor(
            user_id=row.actor_user_id,
            role=row.actor_role,
            capacity=row.actor_capacity,
            on_behalf_of=row.on_behalf_of,
        ),
        ctx=RequestContext(
            ip=None if row.ip is None else str(row.ip),
            user_agent=row.user_agent,
            auth_method=row.auth_method,
            session_id=row.session_id,
        ),
        document_sha256=_as_bytes(row.document_sha256),
        data=dict(row.data),
        occurred_at=row.occurred_at,
        prev_event_hash=_as_bytes(row.prev_event_hash) or ZERO_HASH,
        event_hash=_as_bytes(row.event_hash) or ZERO_HASH,
    )


class PostgresAuditLog:
    """:class:`~esign.contracts.AuditLog` over the ``audit_events`` table.

    Stateless apart from the clock and settings: safe to share across threads and requests. The
    transaction always belongs to the caller, and nothing here commits.
    """

    def __init__(self, settings: Settings, clock: Clock) -> None:
        self._settings = settings
        self._clock = clock

    # ------------------------------------------------------------------ append

    def append(
        self,
        db: Session,
        *,
        stream_type: StreamType,
        stream_id: UUID,
        event_type: EventType,
        actor: Actor | None = None,
        ctx: RequestContext | None = None,
        document_sha256: bytes | None = None,
        data: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append one event to a stream and return it.

        Order matters: validate everything first (so a bad call cannot take a lock), then take the
        per-stream advisory lock, then read the head, then insert. The lock is transaction-scoped,
        so two writers on one stream cannot interleave and the sequence has no gaps.

        ``ctx.user_agent`` is truncated to :data:`MAX_USER_AGENT_CHARS`; the truncated value is
        what is hashed, so the row and its hash still agree.
        """
        if stream_type not in _STREAM_TYPES:
            raise ValidationFailed(f"unknown audit stream type: {_safe(stream_type)}", code="audit_stream_invalid")
        if not isinstance(event_type, EventType):
            raise ValidationFailed("event_type must be an EventType member", code="audit_event_type_invalid")
        if document_sha256 is not None and len(document_sha256) != 32:
            raise ValidationFailed("document_sha256 must be a 32-byte digest", code="audit_hash_invalid")

        actor = actor or Actor()
        ctx = ctx or RequestContext()
        actor_user_id = _opaque(actor.user_id, "actor.user_id")
        actor_role = _member(actor.role, ACTOR_ROLES, "actor.role")
        actor_capacity = _member(actor.capacity, _CAPACITIES, "actor.capacity")
        on_behalf_of = _opaque(actor.on_behalf_of, "actor.on_behalf_of")
        auth_method = _auth_method(ctx.auth_method)
        ip = _ip(ctx.ip)
        user_agent = None if ctx.user_agent is None else ctx.user_agent[:MAX_USER_AGENT_CHARS]
        validated_data = validate_event_data(event_type, data)

        advisory_xact_lock(db, advisory_lock_key(f"{_LOCK_NAMESPACE}:{stream_type}", stream_id))
        head = db.execute(text(_HEAD_SQL), {"stream_type": stream_type, "stream_id": stream_id}).one_or_none()

        # The clock is read *inside* the lock. Read outside it, two concurrent writers could take
        # their timestamps in one order and their sequence numbers in the other, leaving a chain
        # that is gapless but non-monotonic -- and append-only, so uncorrectable.
        occurred_at = self._clock.now()
        if occurred_at.tzinfo is None:
            raise IntegrityFailure("clock returned a naive datetime", code="audit_clock_naive")

        if head is None:
            sequence = 1
            prev_event_hash = ZERO_HASH
        else:
            sequence = int(head.sequence) + 1
            prev_event_hash = _as_bytes(head.event_hash) or ZERO_HASH
            if occurred_at < head.occurred_at:
                # Writing this would leave a chain that verify flags for ever, and the trail is
                # append-only so it could never be corrected. Fail closed instead.
                raise IntegrityFailure(
                    f"clock moved backwards on stream {stream_id}; refusing to append out of order",
                    code="audit_clock_regression",
                )

        event_id = new_id()
        fields = _hash_fields(
            event_id=event_id,
            stream_type=stream_type,
            stream_id=stream_id,
            sequence=sequence,
            event_type=event_type.value,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            actor_capacity=actor_capacity,
            on_behalf_of=on_behalf_of,
            auth_method=auth_method,
            session_id=ctx.session_id,
            ip=ip,
            user_agent=user_agent,
            document_sha256=document_sha256,
            data=validated_data,
            occurred_at=occurred_at,
            prev_event_hash=prev_event_hash,
        )
        event_hash = compute_event_hash(fields)

        db.execute(
            text(_INSERT_SQL),
            {
                "id": event_id,
                "stream_type": stream_type,
                "stream_id": stream_id,
                "sequence": sequence,
                "event_type": event_type.value,
                "actor_user_id": actor_user_id,
                "actor_role": actor_role,
                "actor_capacity": actor_capacity,
                "on_behalf_of": on_behalf_of,
                "auth_method": auth_method,
                "session_id": ctx.session_id,
                "ip": ip,
                "user_agent": user_agent,
                "document_sha256": document_sha256,
                # The canonical text, so the stored row is exactly what was hashed.
                "data": _canonical_data_json(validated_data),
                "occurred_at": occurred_at,
                "prev_event_hash": prev_event_hash,
                "event_hash": event_hash,
            },
        )

        log.info(
            "audit.appended",
            stream_type=stream_type,
            stream_id=stream_id,
            sequence=sequence,
            event_type=event_type.value,
            event_id=event_id,
            event_hash=event_hash,
        )

        return AuditEvent(
            id=event_id,
            stream_type=stream_type,
            stream_id=stream_id,
            sequence=sequence,
            event_type=event_type,
            actor=Actor(user_id=actor_user_id, role=actor_role, capacity=actor_capacity, on_behalf_of=on_behalf_of),
            ctx=RequestContext(ip=ip, user_agent=user_agent, auth_method=auth_method, session_id=ctx.session_id),
            document_sha256=document_sha256,
            data=validated_data,
            occurred_at=occurred_at,
            prev_event_hash=prev_event_hash,
            event_hash=event_hash,
        )

    # ------------------------------------------------------------------ read

    def list(self, db: Session, stream_type: StreamType, stream_id: UUID) -> list[AuditEvent]:
        """Every event on the stream, in sequence order."""
        if stream_type not in _STREAM_TYPES:
            raise ValidationFailed(f"unknown audit stream type: {_safe(stream_type)}", code="audit_stream_invalid")
        rows = db.execute(text(_LIST_SQL), {"stream_type": stream_type, "stream_id": stream_id}).all()
        return [_event_from_row(row) for row in rows]

    def verify(self, db: Session, stream_type: StreamType, stream_id: UUID) -> ChainReport:
        """Re-derive the whole chain from the stored rows and report every problem found.

        Checks, in one pass and without early exit:

        * the sequence starts at 1 and has no gaps or repeats;
        * the first event's ``prev_event_hash`` is 32 zero bytes, and every later one is the
          previous event's ``event_hash``;
        * each ``event_hash`` equals the SHA-256 of the canonical form of its own row, which is
          what makes tampering with *any* column detectable;
        * ``occurred_at`` never moves backwards;
        * ``event_type`` is one we know and ``data`` still matches that type's declared shape.
        """
        if stream_type not in _STREAM_TYPES:
            raise ValidationFailed(f"unknown audit stream type: {_safe(stream_type)}", code="audit_stream_invalid")
        rows = db.execute(text(_LIST_SQL), {"stream_type": stream_type, "stream_id": stream_id}).all()
        problems = _chain_problems(rows)
        head_hash = _as_bytes(rows[-1].event_hash) if rows else None

        report = ChainReport(
            ok=not problems,
            event_count=len(rows),
            head_hash=head_hash,
            problems=tuple(problems),
        )
        log.info(
            "audit.verified",
            stream_type=stream_type,
            stream_id=stream_id,
            ok=report.ok,
            event_count=report.event_count,
            head_hash=head_hash,
            problems=list(report.problems),
        )
        return report


def _chain_problems(rows: Sequence[Row[Any]]) -> list[str]:
    problems: list[str] = []
    expected_sequence = 1
    expected_prev = ZERO_HASH
    previous_occurred_at: datetime | None = None

    for index, row in enumerate(rows):
        sequence = int(row.sequence)
        if index == 0:
            if sequence != 1:
                problems.append(f"sequence starts at {sequence}, expected 1")
        elif sequence != expected_sequence:
            if sequence > expected_sequence:
                problems.append(f"sequence gap after {expected_sequence - 1}")
            else:
                problems.append(f"duplicate or out-of-order sequence {sequence}")
        expected_sequence = sequence + 1

        stored_prev = _as_bytes(row.prev_event_hash) or ZERO_HASH
        if stored_prev != expected_prev:
            problems.append(f"wrong prev_event_hash at {sequence}")

        stored_hash = _as_bytes(row.event_hash) or ZERO_HASH
        try:
            recomputed = compute_event_hash(_fields_from_row(row))
        except (TypeError, ValueError):
            problems.append(f"event at {sequence} cannot be canonicalised")
            recomputed = None
        if recomputed is not None and recomputed != stored_hash:
            problems.append(f"hash mismatch at {sequence}")

        try:
            event_type = EventType(row.event_type)
        except ValueError:
            problems.append(f"unknown event_type at {sequence}")
        else:
            # The stored ``data`` is canonical JSON (hashes as hex, ids as strings), so it cannot
            # be re-run through the strict models. Its *key set* still must be exactly the one
            # that type declares -- that is what catches a key nobody allowed.
            stored_keys = frozenset(row.data) if isinstance(row.data, dict) else frozenset()
            if not isinstance(row.data, dict):
                problems.append(f"data is not an object at {sequence}")
            elif stored_keys != declared_data_keys(event_type):
                problems.append(f"data keys do not match {event_type.value} at {sequence}")

        if previous_occurred_at is not None and row.occurred_at < previous_occurred_at:
            problems.append(f"non-monotonic occurred_at at {sequence}")
        previous_occurred_at = row.occurred_at

        expected_prev = stored_hash

    return problems


def _canonical_data_json(data: Mapping[str, Any]) -> str:
    return canonical_json(dict(data)).decode("utf-8")


def _safe(value: object) -> str:
    """A short, quote-free rendering for an error message. Never the caller's whole input."""
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", str(value))[:40]


def _opaque(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not is_opaque_id(value):
        # Whitespace is the give-away: an id has none, a person's name does. Date-of-birth and
        # social-security shapes are refused by name on top of that.
        raise ValidationFailed(f"{field} is not an opaque identifier", code="audit_actor_invalid")
    return value


def _member(value: str | None, allowed: frozenset[str], field: str) -> str | None:
    if value is None:
        return None
    if value not in allowed:
        raise ValidationFailed(f"{field} is not one of {sorted(allowed)}", code="audit_actor_invalid")
    return value


def _auth_method(value: str | None) -> str | None:
    if value is None:
        return None
    if not _AUTH_METHOD.match(value):
        raise ValidationFailed("ctx.auth_method is not a known method token", code="audit_ctx_invalid")
    return value


def _ip(value: str | None) -> str | None:
    """Normalise to the form Postgres stores, so a re-read hashes to the same bytes."""
    if value is None:
        return None
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        raise ValidationFailed("ctx.ip is not an IP address", code="audit_ctx_invalid") from None
