"""SPEC section 12: "no log line in a full end-to-end run contains a signer name or prefill value".

This module's share of that. Rather than grepping rendered output -- which passes by accident
whenever a log level happens to be off -- every log call this module makes is captured with its
keyword arguments, and then two things are asserted:

1. every key survives :func:`esign.logging.drop_unlisted_keys`, so nothing this module logs is
   silently thrown away *or* silently let through; and
2. no captured value, rendered, contains a name, a prefill value, a typed signature or PDF bytes.

The run underneath is the real pipeline: inspect, prepare, sanitize, sign, certificate, finalize.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from esign.contracts import Capture, DocumentService, FieldDef, PrefillFieldDef, Rect, SignerStamp
from esign.documents import certificate as certificate_module
from esign.documents import definitions as definitions_module
from esign.documents import images as images_module
from esign.documents import inspection as inspection_module
from esign.documents import service as service_module
from esign.documents import stamping as stamping_module
from esign.logging import LOGGABLE_KEYS, RESERVED_KEYS, drop_unlisted_keys
from tests.documents.conftest import certificate_summary
from tests.documents.helpers import handwriting_png, make_pdf

#: Things that must never reach a log line. Distinctive so a substring search is meaningful.
PATIENT_NAME = "Zebediah Quillfeather"
PREFILL_VALUE = "Left total knee replacement, MRN 998877"
TYPED_SIGNATURE = "Zebediah Quillfeather"
GUARDIAN_LABEL = "patient-ref-Quillfeather"


class RecordingLogger:
    """Stands in for a structlog bound logger and keeps every call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _record(self, level: str, event: str, **kwargs: Any) -> None:
        self.calls.append((level, event, kwargs))

    def debug(self, event: str, **kwargs: Any) -> None:
        self._record("debug", event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._record("info", event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._record("warning", event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._record("error", event, **kwargs)

    def exception(self, event: str, **kwargs: Any) -> None:
        self._record("error", event, **kwargs)


LOGGING_MODULES = (
    service_module,
    stamping_module,
    inspection_module,
    definitions_module,
    images_module,
    certificate_module,
)


@pytest.fixture
def captured_logs(monkeypatch: pytest.MonkeyPatch) -> RecordingLogger:
    recorder = RecordingLogger()
    for module in LOGGING_MODULES:
        if hasattr(module, "log"):
            monkeypatch.setattr(module, "log", recorder)
    return recorder


def run_the_pipeline(documents: DocumentService) -> None:
    template = make_pdf(pages=2)
    documents.inspect_template_pdf(template)

    prefill_fields = [
        PrefillFieldDef(key="patient_name", page=1, rect=Rect(x=72, y=600, w=240, h=14)),
        PrefillFieldDef(key="procedure", page=1, rect=Rect(x=72, y=500, w=400, h=60), multiline=True),
    ]
    prepared = documents.prepare(template, prefill_fields, {"patient_name": PATIENT_NAME, "procedure": PREFILL_VALUE})

    png = documents.sanitize_signature_png(handwriting_png())
    fields = [
        FieldDef(
            id="patient_signature",
            type="signature",
            page=1,
            rect=Rect(x=100, y=300, w=220, h=48),
            signer_role="patient",
            label="Patient signature",
        ),
        FieldDef(
            id="patient_date",
            type="date_signed",
            page=1,
            rect=Rect(x=360, y=300, w=150, h=18),
            signer_role="patient",
        ),
    ]
    stamp = SignerStamp(
        signer_id=UUID(int=5),
        display_name=PATIENT_NAME,
        capacity="guardian",
        on_behalf_of_label=GUARDIAN_LABEL,
        signed_at=datetime(2026, 3, 17, 14, 30, tzinfo=UTC),
    )
    signed = documents.apply_signer_marks(
        prepared,
        fields,
        [Capture(field_id="patient_signature", kind="drawn", image_png=png)],
        stamp,
    )
    typed_signed = documents.apply_signer_marks(
        prepared,
        fields,
        [Capture(field_id="patient_signature", kind="typed", typed_text=TYPED_SIGNATURE)],
        stamp,
    )
    assert typed_signed != signed

    certificate = documents.build_certificate(certificate_summary())
    documents.finalize(signed, certificate)


def test_the_module_logs_nothing_the_allowlist_would_drop(
    documents: DocumentService, captured_logs: RecordingLogger
) -> None:
    """A dropped key is a bug on both sides: a missing log line, or a key nobody vetted."""
    run_the_pipeline(documents)
    assert captured_logs.calls, "the pipeline logged nothing at all, so this proves nothing"

    for _level, event, kwargs in captured_logs.calls:
        kept = drop_unlisted_keys(None, "info", {"event": event, **kwargs})
        assert "dropped_fields" not in kept, (event, kept.get("dropped_fields"))
        for key in kwargs:
            assert key in LOGGABLE_KEYS or key in RESERVED_KEYS, (event, key)


def test_no_log_call_carries_a_name_a_prefill_value_or_a_signature(
    documents: DocumentService, captured_logs: RecordingLogger
) -> None:
    run_the_pipeline(documents)

    rendered = json.dumps(
        [
            {"event": event, **drop_unlisted_keys(None, level, dict(kwargs))}
            for level, event, kwargs in captured_logs.calls
        ],
        default=str,
    )
    for secret in (PATIENT_NAME, PREFILL_VALUE, TYPED_SIGNATURE, GUARDIAN_LABEL, "MRN", "998877"):
        assert secret not in rendered, secret


def test_no_log_call_carries_pdf_or_image_bytes(documents: DocumentService, captured_logs: RecordingLogger) -> None:
    run_the_pipeline(documents)
    for _level, event, kwargs in captured_logs.calls:
        for key, value in kwargs.items():
            if isinstance(value, bytes | bytearray):
                # Only hashes are ever logged as bytes, and a hash is exactly 32 of them.
                assert len(value) == 32, (event, key, len(value))
            assert not (isinstance(value, str) and value.startswith("%PDF")), (event, key)


def test_the_capacity_and_ids_that_are_logged_are_the_safe_ones(
    documents: DocumentService, captured_logs: RecordingLogger
) -> None:
    """``capacity`` and ``signer_id`` are deliberately loggable; ``on_behalf_of`` is not."""
    run_the_pipeline(documents)
    events = {event: kwargs for _level, event, kwargs in captured_logs.calls}
    marks = events["documents.marks_applied"]
    assert marks["capacity"] == "guardian"
    assert marks["signer_id"] == UUID(int=5)
    assert "display_name" not in marks
    assert "on_behalf_of" not in marks


def test_a_rejection_message_carries_no_prefill_value(documents: DocumentService) -> None:
    """Error messages go back over the wire and into whatever the host logs."""
    from esign.contracts import ValidationFailed

    with pytest.raises(ValidationFailed) as excinfo:
        documents.prepare(make_pdf(), [], {"secret_key": PREFILL_VALUE})
    message = str(excinfo.value)
    assert PREFILL_VALUE not in message
    assert "secret_key" not in message
