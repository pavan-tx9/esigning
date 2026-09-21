"""``verify`` against a tampered chain.

These tests have to get past both lines of defence -- the grants and the triggers -- to make the
damage in the first place. They run as ``esign_owner`` with the user triggers briefly off, which
no application code can do (``tests/audit/test_roles.py`` proves the app role cannot, and that the
owner role cannot either without deliberately turning the triggers off).

SPEC section 12: "tampering with any audit column breaks verify; removing a row is reported as a
gap". Every column is covered, and ``verify`` is asserted to report *everything* it found rather
than stopping at the first problem.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from esign.contracts import AuditEvent, AuditLog, EventType, ValidationFailed
from tests.audit.helpers import DIGEST_A, drop_event, sample_data, tamper


def _chain(db: Session, audit: AuditLog, length: int = 4) -> tuple[Any, list[AuditEvent]]:
    stream = uuid4()
    types = [
        EventType.ENVELOPE_CREATED,
        EventType.DOCUMENT_PREPARED,
        EventType.DOCUMENT_PRESENTED,
        EventType.DOCUMENT_VIEWED,
        EventType.CONSENT_ACCEPTED,
        EventType.SIGNER_SIGNED,
    ]
    events = [
        audit.append(
            db,
            stream_type="envelope",
            stream_id=stream,
            event_type=types[index % len(types)],
            document_sha256=DIGEST_A,
            data=sample_data(types[index % len(types)]),
        )
        for index in range(length)
    ]
    return stream, events


def test_a_clean_chain_verifies(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert report.ok
    assert report.problems == ()
    assert report.event_count == len(events)
    assert report.head_hash == events[-1].event_hash


def test_an_empty_stream_verifies_as_empty(owner_db: Session, audit: AuditLog) -> None:
    report = audit.verify(owner_db, "envelope", uuid4())
    assert report.ok
    assert report.event_count == 0
    assert report.head_hash is None


@pytest.mark.parametrize(
    ("column", "value", "cast_to"),
    [
        ("event_type", "envelope.voided", None),
        ("actor_user_id", "host-999", None),
        ("actor_role", "clinician", None),
        ("actor_capacity", "witness", None),
        ("on_behalf_of", "patient-42", None),
        ("auth_method", "sso", None),
        ("session_id", "0f2c9a44-1d3b-4e57-8a66-b1c2d3e4f5a6", "uuid"),
        ("ip", "203.0.113.9", "inet"),
        ("user_agent", "curl/8.0", None),
        ("document_sha256", bytes(32), None),
        ("id", "0f2c9a44-1d3b-4e57-8a66-b1c2d3e4f5a6", "uuid"),
        ("stream_id", "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9", "uuid"),
        ("occurred_at", "2026-03-17T00:00:00+00:00", "timestamptz"),
    ],
)
def test_tampering_with_any_column_breaks_the_hash(
    owner_db: Session, ticking_audit: AuditLog, column: str, value: Any, cast_to: str | None
) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    target = events[2]
    tamper(owner_db, event_id=target.id, column=column, value=value, cast_to=cast_to)

    if column == "stream_id":
        # Moving a row to another stream is a different symptom: this one loses an event.
        report = ticking_audit.verify(owner_db, "envelope", stream)
        assert not report.ok
        assert any("gap" in problem for problem in report.problems)
        return

    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert not report.ok, column
    assert any("hash mismatch at 3" in problem for problem in report.problems), report.problems


def test_tampering_with_data_breaks_the_hash_and_is_reported_as_a_shape_problem(
    owner_db: Session, ticking_audit: AuditLog
) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    target = events[1]
    tamper(
        owner_db,
        event_id=target.id,
        column="data",
        value=json.dumps({**target.data, "patient_name": "Jane Doe"}),
        cast_to="jsonb",
    )
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert not report.ok
    assert any("hash mismatch at 2" in problem for problem in report.problems)
    assert any("data keys do not match" in problem for problem in report.problems)


def test_changing_one_value_inside_data_is_caught_by_the_hash(owner_db: Session, ticking_audit: AuditLog) -> None:
    """The key set is unchanged, so only the hash catches this. It must."""
    stream, events = _chain(owner_db, ticking_audit)
    target = events[3]
    altered = {**target.data, "pages_viewed": 1}
    tamper(owner_db, event_id=target.id, column="data", value=json.dumps(altered), cast_to="jsonb")
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert not report.ok
    assert any("hash mismatch at 4" in problem for problem in report.problems)


def test_an_unknown_event_type_is_reported(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    tamper(owner_db, event_id=events[1].id, column="event_type", value="chart.exported")
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert any("unknown event_type at 2" in problem for problem in report.problems)


def test_removing_a_row_is_reported_as_a_gap(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit, length=5)
    drop_event(owner_db, events[2].id)
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert not report.ok
    assert "sequence gap after 2" in report.problems
    # The chain is also broken where the missing event used to link.
    assert any("wrong prev_event_hash at 4" in problem for problem in report.problems)
    assert report.event_count == 4


def test_removing_the_first_row_is_reported(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    drop_event(owner_db, events[0].id)
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert not report.ok
    assert "sequence starts at 2, expected 1" in report.problems
    assert any("wrong prev_event_hash at 2" in problem for problem in report.problems)


def test_truncating_the_tail_is_not_a_gap_but_is_visible_in_the_head_hash(
    owner_db: Session, ticking_audit: AuditLog
) -> None:
    """Honest about what a hash chain can and cannot prove: a chopped tail still verifies, so
    the head hash recorded on the certificate is what detects it."""
    stream, events = _chain(owner_db, ticking_audit)
    drop_event(owner_db, events[-1].id)
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert report.ok
    assert report.event_count == 3
    assert report.head_hash == events[-2].event_hash
    assert report.head_hash != events[-1].event_hash


def test_a_rewritten_previous_hash_is_reported_as_such(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    tamper(owner_db, event_id=events[2].id, column="prev_event_hash", value=bytes(32))
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert any("wrong prev_event_hash at 3" in problem for problem in report.problems)
    assert any("hash mismatch at 3" in problem for problem in report.problems)


def test_a_non_zero_previous_hash_on_the_first_event_is_reported(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    tamper(owner_db, event_id=events[0].id, column="prev_event_hash", value=bytes([9]) + bytes(31))
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert any("wrong prev_event_hash at 1" in problem for problem in report.problems)


def test_rewriting_an_event_hash_breaks_the_link_to_the_next_event(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    tamper(owner_db, event_id=events[1].id, column="event_hash", value=bytes(32))
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert any("hash mismatch at 2" in problem for problem in report.problems)
    assert any("wrong prev_event_hash at 3" in problem for problem in report.problems)


def test_a_backdated_event_is_reported_as_non_monotonic(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit)
    backdated = events[0].occurred_at - timedelta(hours=1)
    tamper(owner_db, event_id=events[2].id, column="occurred_at", value=backdated)
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert any("non-monotonic occurred_at at 3" in problem for problem in report.problems)
    assert any("hash mismatch at 3" in problem for problem in report.problems)


def test_a_resequenced_row_is_reported(owner_db: Session, ticking_audit: AuditLog) -> None:
    stream, events = _chain(owner_db, ticking_audit, length=5)
    tamper(owner_db, event_id=events[4].id, column="sequence", value=9)
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert not report.ok
    assert any("gap" in problem for problem in report.problems)


def test_verify_reports_every_problem_rather_than_stopping_at_the_first(
    owner_db: Session, ticking_audit: AuditLog
) -> None:
    stream, events = _chain(owner_db, ticking_audit, length=6)
    tamper(owner_db, event_id=events[1].id, column="actor_role", value="clinician")
    tamper(owner_db, event_id=events[3].id, column="user_agent", value="curl/8.0")
    drop_event(owner_db, events[4].id)
    report = ticking_audit.verify(owner_db, "envelope", stream)
    assert not report.ok
    assert any("hash mismatch at 2" in problem for problem in report.problems)
    assert any("hash mismatch at 4" in problem for problem in report.problems)
    assert "sequence gap after 4" in report.problems
    assert len(report.problems) >= 4


def test_verify_of_an_unknown_stream_type_is_refused(owner_db: Session, audit: AuditLog) -> None:
    with pytest.raises(ValidationFailed):
        audit.verify(owner_db, "chart", uuid4())  # type: ignore[arg-type]


def test_a_chain_still_verifies_after_the_triggers_are_turned_back_on(
    owner_db: Session, ticking_audit: AuditLog
) -> None:
    """The tampering helper must not leave the table unprotected for the next test."""
    stream, _ = _chain(owner_db, ticking_audit)
    assert ticking_audit.verify(owner_db, "envelope", stream).ok
    from sqlalchemy import text

    enabled = owner_db.execute(
        text(
            "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
            "WHERE c.relname = 'audit_events' AND NOT t.tgisinternal AND t.tgenabled = 'O'"
        )
    ).scalar_one()
    assert enabled == 2
