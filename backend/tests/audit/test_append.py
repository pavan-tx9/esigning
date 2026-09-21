"""Appending to a chain: sequence, chaining, provenance and what the writer refuses."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.audit import build_audit_log
from esign.audit.canonical import HASHED_FIELDS, ZERO_HASH, compute_event_hash
from esign.audit.log import MAX_USER_AGENT_CHARS
from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import (
    Actor,
    AuditLog,
    EventType,
    IntegrityFailure,
    RequestContext,
    ValidationFailed,
)
from tests.audit.helpers import ALL_EVENT_TYPES, DIGEST_A, sample_data


def _created(**over: Any) -> dict[str, Any]:
    return {**sample_data(EventType.ENVELOPE_CREATED), **over}


def test_the_first_event_starts_at_one_with_a_zero_previous_hash(db: Session, audit: AuditLog) -> None:
    stream = uuid4()
    event = audit.append(
        db, stream_type="envelope", stream_id=stream, event_type=EventType.ENVELOPE_CREATED, data=_created()
    )
    assert event.sequence == 1
    assert event.prev_event_hash == ZERO_HASH
    assert len(event.event_hash) == 32


def test_each_event_chains_to_the_one_before_it(db: Session, audit: AuditLog) -> None:
    stream = uuid4()
    first = audit.append(
        db, stream_type="envelope", stream_id=stream, event_type=EventType.ENVELOPE_CREATED, data=_created()
    )
    second = audit.append(
        db,
        stream_type="envelope",
        stream_id=stream,
        event_type=EventType.DOCUMENT_PREPARED,
        data=sample_data(EventType.DOCUMENT_PREPARED),
    )
    assert second.sequence == 2
    assert second.prev_event_hash == first.event_hash
    assert second.event_hash != first.event_hash


def test_streams_are_independent(db: Session, audit: AuditLog) -> None:
    one, two = uuid4(), uuid4()
    audit.append(db, stream_type="envelope", stream_id=one, event_type=EventType.ENVELOPE_CREATED, data=_created())
    other = audit.append(
        db, stream_type="envelope", stream_id=two, event_type=EventType.ENVELOPE_CREATED, data=_created()
    )
    assert other.sequence == 1
    assert other.prev_event_hash == ZERO_HASH


def test_the_same_uuid_on_two_stream_types_is_two_chains(db: Session, audit: AuditLog) -> None:
    shared = uuid4()
    envelope = audit.append(
        db, stream_type="envelope", stream_id=shared, event_type=EventType.ENVELOPE_CREATED, data=_created()
    )
    template = audit.append(
        db,
        stream_type="template",
        stream_id=shared,
        event_type=EventType.TEMPLATE_PUBLISHED,
        data=sample_data(EventType.TEMPLATE_PUBLISHED),
    )
    assert envelope.sequence == template.sequence == 1


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_every_event_type_round_trips_through_the_database_and_still_verifies(
    db: Session, audit: AuditLog, event_type: EventType
) -> None:
    """The jsonb column reparses what we store. This proves the hash survives that."""
    stream = uuid4()
    written = audit.append(
        db,
        stream_type="envelope",
        stream_id=stream,
        event_type=event_type,
        document_sha256=DIGEST_A,
        data=sample_data(event_type),
    )
    (read_back,) = audit.list(db, "envelope", stream)
    assert read_back.event_hash == written.event_hash
    assert read_back.data == written.data
    assert read_back.document_sha256 == DIGEST_A
    assert audit.verify(db, "envelope", stream).ok


def test_the_stored_hash_is_reproducible_from_the_returned_event(db: Session, audit: AuditLog) -> None:
    stream = uuid4()
    event = audit.append(
        db,
        stream_type="envelope",
        stream_id=stream,
        event_type=EventType.ENVELOPE_CREATED,
        actor=Actor(user_id="host-1", role="host"),
        ctx=RequestContext(ip="198.51.100.24", user_agent="UA/1", auth_method="api_key", session_id=uuid4()),
        document_sha256=DIGEST_A,
        data=_created(),
    )
    recomputed = compute_event_hash(
        {
            "actor_capacity": event.actor.capacity,
            "actor_role": event.actor.role,
            "actor_user_id": event.actor.user_id,
            "auth_method": event.ctx.auth_method,
            "data": event.data,
            "document_sha256": event.document_sha256,
            "event_type": event.event_type.value,
            "id": event.id,
            "ip": event.ctx.ip,
            "occurred_at": event.occurred_at,
            "on_behalf_of": event.actor.on_behalf_of,
            "prev_event_hash": event.prev_event_hash,
            "sequence": event.sequence,
            "session_id": event.ctx.session_id,
            "stream_id": event.stream_id,
            "stream_type": event.stream_type,
            "user_agent": event.ctx.user_agent,
        }
    )
    assert recomputed == event.event_hash


def test_the_hashed_field_list_is_exactly_the_stored_columns_minus_the_hash(db: Session) -> None:
    columns = {
        str(row[0])
        for row in db.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = 'audit_events'")
        ).all()
    }
    assert columns == set(HASHED_FIELDS) | {"event_hash"}


def test_occurred_at_comes_from_the_clock_not_the_wall(db: Session, audit: AuditLog, clock: FixedClock) -> None:
    stream = uuid4()
    event = audit.append(
        db, stream_type="envelope", stream_id=stream, event_type=EventType.ENVELOPE_CREATED, data=_created()
    )
    assert event.occurred_at == clock.now()
    stored = db.execute(text("SELECT occurred_at FROM audit_events WHERE id = :id"), {"id": event.id}).scalar_one()
    assert stored == clock.now()


def test_equal_timestamps_are_allowed_but_a_backwards_clock_is_refused(
    db: Session, settings: Settings, clock: FixedClock
) -> None:
    audit = build_audit_log(settings, clock)
    stream = uuid4()
    audit.append(db, stream_type="envelope", stream_id=stream, event_type=EventType.ENVELOPE_CREATED, data=_created())
    # Same instant: legal, the chain requires non-decreasing, not strictly increasing.
    audit.append(
        db,
        stream_type="envelope",
        stream_id=stream,
        event_type=EventType.ENVELOPE_EXPIRED,
        data=sample_data(EventType.ENVELOPE_EXPIRED),
    )
    clock.set(clock.now() - timedelta(seconds=5))
    with pytest.raises(IntegrityFailure) as caught:
        audit.append(
            db,
            stream_type="envelope",
            stream_id=stream,
            event_type=EventType.ENVELOPE_VOIDED,
            data=sample_data(EventType.ENVELOPE_VOIDED),
        )
    assert caught.value.code == "audit_clock_regression"
    assert len(audit.list(db, "envelope", stream)) == 2


def test_request_context_is_recorded_and_normalised(db: Session, audit: AuditLog) -> None:
    stream = uuid4()
    session_id = uuid4()
    event = audit.append(
        db,
        stream_type="envelope",
        stream_id=stream,
        event_type=EventType.ENVELOPE_CREATED,
        ctx=RequestContext(ip="2001:0db8::1", user_agent="UA/2", auth_method="api_key", session_id=session_id),
        data=_created(),
    )
    assert event.ctx.ip == "2001:db8::1"  # as Postgres will render it back
    (stored,) = audit.list(db, "envelope", stream)
    assert stored.ctx.ip == "2001:db8::1"
    assert stored.ctx.session_id == session_id
    assert audit.verify(db, "envelope", stream).ok


@pytest.mark.parametrize("bad_ip", ["not-an-ip", "10.0.0.1/24", "10.0.0.256", ""])
def test_a_malformed_ip_is_refused_rather_than_stored(db: Session, audit: AuditLog, bad_ip: str) -> None:
    with pytest.raises(ValidationFailed):
        audit.append(
            db,
            stream_type="envelope",
            stream_id=uuid4(),
            event_type=EventType.ENVELOPE_CREATED,
            ctx=RequestContext(ip=bad_ip),
            data=_created(),
        )


def test_a_long_user_agent_is_truncated_and_the_hash_matches_what_was_stored(db: Session, audit: AuditLog) -> None:
    stream = uuid4()
    event = audit.append(
        db,
        stream_type="envelope",
        stream_id=stream,
        event_type=EventType.ENVELOPE_CREATED,
        ctx=RequestContext(user_agent="U" * (MAX_USER_AGENT_CHARS + 500)),
        data=_created(),
    )
    assert event.ctx.user_agent is not None
    assert len(event.ctx.user_agent) == MAX_USER_AGENT_CHARS
    assert audit.verify(db, "envelope", stream).ok


def test_an_actor_display_name_is_refused_where_an_id_belongs(db: Session, audit: AuditLog) -> None:
    with pytest.raises(ValidationFailed) as caught:
        audit.append(
            db,
            stream_type="envelope",
            stream_id=uuid4(),
            event_type=EventType.ENVELOPE_CREATED,
            actor=Actor(user_id="Jane Doe", role="patient"),
            data=_created(),
        )
    assert "Jane" not in str(caught.value)


def test_an_unknown_actor_role_is_refused(db: Session, audit: AuditLog) -> None:
    with pytest.raises(ValidationFailed):
        audit.append(
            db,
            stream_type="envelope",
            stream_id=uuid4(),
            event_type=EventType.ENVELOPE_CREATED,
            actor=Actor(role="administrator"),  # type: ignore[arg-type]  # deliberately outside the Literal
            data=_created(),
        )


def test_an_unknown_capacity_is_refused(db: Session, audit: AuditLog) -> None:
    with pytest.raises(ValidationFailed):
        audit.append(
            db,
            stream_type="envelope",
            stream_id=uuid4(),
            event_type=EventType.ENVELOPE_CREATED,
            actor=Actor(capacity="power_of_attorney"),  # type: ignore[arg-type]  # deliberately outside the Literal
            data=_created(),
        )


def test_an_unknown_stream_type_is_refused(db: Session, audit: AuditLog) -> None:
    with pytest.raises(ValidationFailed):
        audit.append(
            db,
            stream_type="chart",  # type: ignore[arg-type]
            stream_id=uuid4(),
            event_type=EventType.ENVELOPE_CREATED,
            data=_created(),
        )


def test_a_document_hash_of_the_wrong_length_is_refused(db: Session, audit: AuditLog) -> None:
    with pytest.raises(ValidationFailed):
        audit.append(
            db,
            stream_type="envelope",
            stream_id=uuid4(),
            event_type=EventType.ENVELOPE_CREATED,
            document_sha256=b"short",
            data=_created(),
        )


def test_data_for_the_wrong_event_type_is_refused(db: Session, audit: AuditLog) -> None:
    with pytest.raises(ValidationFailed):
        audit.append(
            db,
            stream_type="envelope",
            stream_id=uuid4(),
            event_type=EventType.ENVELOPE_VOIDED,
            data=sample_data(EventType.SIGNER_SIGNED),
        )


def test_a_refused_append_writes_nothing(db: Session, audit: AuditLog) -> None:
    stream = uuid4()
    with pytest.raises(ValidationFailed):
        audit.append(
            db,
            stream_type="envelope",
            stream_id=stream,
            event_type=EventType.ENVELOPE_CREATED,
            data={**_created(), "patient_name": "Jane Doe"},
        )
    assert audit.list(db, "envelope", stream) == []


def test_list_returns_events_in_sequence_order(db: Session, ticking_audit: AuditLog) -> None:
    stream = uuid4()
    for _ in range(5):
        ticking_audit.append(
            db,
            stream_type="envelope",
            stream_id=stream,
            event_type=EventType.DOCUMENT_PRESENTED,
            data=sample_data(EventType.DOCUMENT_PRESENTED),
        )
    events = ticking_audit.list(db, "envelope", stream)
    assert [event.sequence for event in events] == [1, 2, 3, 4, 5]
    assert [event.occurred_at for event in events] == sorted(event.occurred_at for event in events)


def test_list_of_an_unknown_stream_is_empty_not_an_error(db: Session, audit: AuditLog) -> None:
    assert audit.list(db, "envelope", uuid4()) == []


def test_append_does_not_commit(db: Session, audit: AuditLog) -> None:
    """The contract: the transaction belongs to the caller."""
    stream = uuid4()
    audit.append(db, stream_type="envelope", stream_id=stream, event_type=EventType.ENVELOPE_CREATED, data=_created())
    db.rollback()
    assert audit.list(db, "envelope", stream) == []
