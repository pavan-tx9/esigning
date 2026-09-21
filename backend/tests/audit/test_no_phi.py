"""Nothing this module logs or stores may carry PHI.

SPEC section 10: "Logs, metrics, error messages, URLs, webhook payloads and audit ``data`` do
not [hold PHI]". The structured logger drops anything not on its allowlist, so the risk is not a
leak but a silent drop -- a line that says ``dropped_fields`` is a line this module tried to write
something it should not have. These tests assert there are none.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session

import esign.audit.log as audit_log_module
from esign.contracts import Actor, AuditLog, EventType, RequestContext, ValidationFailed
from esign.logging import LOGGABLE_KEYS, RESERVED_KEYS, configure_logging
from tests.audit.helpers import DIGEST_A, sample_data

#: Values a careless caller might pass. None of them may reach a log line or a stored row.
PHI = ("Jane Doe", "1970-01-01", "left knee replacement", "123 Main Street")


@pytest.fixture
def json_logs(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """The real logging configuration, rendering JSON into a buffer this test can read.

    ``configure_logging`` caches bound loggers on first use, so a module-level logger cannot be
    redirected by reconfiguring alone: the module's logger is replaced with a freshly bound one
    for the duration, and put back afterwards.
    """
    buffer = io.StringIO()
    configure_logging(level="DEBUG", json_output=True, app_env="test", stream=buffer)
    monkeypatch.setattr(audit_log_module, "log", structlog.get_logger("tests.audit.capture"))

    def read() -> list[dict[str, Any]]:
        return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip().startswith("{")]

    yield read

    monkeypatch.undo()
    configure_logging(level="INFO", json_output=False, app_env="test")


def test_a_successful_append_logs_only_allowlisted_keys(db: Session, audit: AuditLog, json_logs: Any) -> None:
    audit.append(
        db,
        stream_type="envelope",
        stream_id=uuid4(),
        event_type=EventType.SIGNER_SIGNED,
        actor=Actor(user_id="host-user-1187", role="patient", capacity="self"),
        ctx=RequestContext(ip="198.51.100.24", user_agent="UA/1", auth_method="portal_otp"),
        document_sha256=DIGEST_A,
        data=sample_data(EventType.SIGNER_SIGNED),
    )
    lines = json_logs()
    assert lines, "the append should have logged something"
    for line in lines:
        assert "dropped_fields" not in line, line
        for key in line:
            assert key in LOGGABLE_KEYS | RESERVED_KEYS, key


def test_verify_logs_only_allowlisted_keys(db: Session, audit: AuditLog, json_logs: Any) -> None:
    stream = uuid4()
    audit.append(
        db,
        stream_type="envelope",
        stream_id=stream,
        event_type=EventType.ENVELOPE_CREATED,
        data=sample_data(EventType.ENVELOPE_CREATED),
    )
    audit.verify(db, "envelope", stream)
    for line in json_logs():
        assert "dropped_fields" not in line, line


@pytest.mark.parametrize("value", PHI)
def test_a_rejected_append_does_not_log_or_store_the_rejected_value(
    db: Session, audit: AuditLog, json_logs: Any, value: str
) -> None:
    stream = uuid4()
    with pytest.raises(ValidationFailed) as caught:
        audit.append(
            db,
            stream_type="envelope",
            stream_id=stream,
            event_type=EventType.ENVELOPE_CREATED,
            data={**sample_data(EventType.ENVELOPE_CREATED), "note": value},
        )
    assert value not in str(caught.value)
    rendered = json.dumps(json_logs())
    assert value not in rendered
    assert audit.list(db, "envelope", stream) == []


def test_no_stored_audit_row_can_hold_free_text(db: Session, audit: AuditLog) -> None:
    """Every string that does reach a row is an id, an enum, a hash or a user agent."""
    stream = uuid4()
    for event_type in (EventType.SIGNER_SIGNED, EventType.SESSION_CREATED, EventType.CONSENT_ACCEPTED):
        audit.append(
            db,
            stream_type="envelope",
            stream_id=stream,
            event_type=event_type,
            actor=Actor(user_id="host-user-1187", role="patient", capacity="self"),
            data=sample_data(event_type),
        )
    rows = db.execute(text("SELECT data::text AS data FROM audit_events WHERE stream_id = :s"), {"s": stream}).all()
    for row in rows:
        payload = json.loads(row.data)
        for key, value in payload.items():
            if isinstance(value, str):
                assert " " not in value, f"{key} looks like free text: it contains a space"


def test_the_signer_display_name_has_nowhere_to_go(db: Session, audit: AuditLog) -> None:
    """There is no field, on any event type, that would take a display name."""
    for field in ("display_name", "patient_name", "signer_name", "name", "dob", "date_of_birth"):
        with pytest.raises(ValidationFailed):
            audit.append(
                db,
                stream_type="envelope",
                stream_id=uuid4(),
                event_type=EventType.SIGNER_SIGNED,
                data={**sample_data(EventType.SIGNER_SIGNED), field: "Jane Doe"},
            )
