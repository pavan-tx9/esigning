"""Nothing this module logs may be about a patient.

The database and the blob store hold PHI; logs do not. The structured logger drops anything not
on its allowlist, but a dropped key is still a bug -- it means the code tried. So these tests
assert both: the forbidden strings never appear, and the logger never had to drop anything.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from uuid import uuid4

import pytest
import structlog

from esign.clock import FixedClock
from esign.contracts import SealUnavailable, ValidationFailed
from esign.logging import LOGGABLE_KEYS, RESERVED_KEYS, configure_logging
from esign.sealing import build_sealer
from tests.conftest import FROZEN_NOW
from tests.sealing.conftest import PATIENT_NAME, Pki, make_pdf, make_settings

PREFILL_VALUE = "1962-11-04"
REASON = "Envelope completed"


@pytest.fixture
def log_lines() -> Iterator[Callable[[], list[dict[str, object]]]]:
    """The real logging pipeline rendering into a buffer this test owns; returns a reader."""
    buffer = io.StringIO()
    configure_logging(level="DEBUG", json_output=True, app_env="test", stream=buffer)

    def read() -> list[dict[str, object]]:
        return [json.loads(line) for line in buffer.getvalue().splitlines() if line.startswith("{")]

    try:
        yield read
    finally:
        structlog.reset_defaults()


def _exercise_every_path(dev_pki: Pki, tmp_path: Path) -> None:
    """One pass through sealing, validating, and the failures worth logging about."""
    clock = FixedClock(FROZEN_NOW)
    document = make_pdf(text=f"{PATIENT_NAME} {PREFILL_VALUE}")

    sealer = build_sealer(make_settings(dev_pki), clock)
    sealed = sealer.seal(document, reason=REASON, envelope_id=uuid4()).sealed_pdf
    sealer.validate(sealed)
    sealer.validate(sealed + b"\n% appended\n")
    sealer.validate(b"not a pdf")

    # Trust roots gone: fails closed, and says so in the log.
    build_sealer(make_settings(dev_pki, trust_roots_path=tmp_path / "gone.pem"), clock).validate(sealed)

    # Key material gone.
    with pytest.raises(SealUnavailable):
        build_sealer(make_settings(None), clock).seal(document, reason=REASON, envelope_id=uuid4())

    # Timestamp authority unreachable.
    with pytest.raises(SealUnavailable):
        build_sealer(make_settings(dev_pki, tsa_url="http://127.0.0.1:9/tsa"), clock).seal(
            document, reason=REASON, envelope_id=uuid4()
        )

    # Input the caller should never have sent.
    with pytest.raises(ValidationFailed):
        sealer.seal(b"junk", reason=REASON, envelope_id=uuid4())


def test_no_log_line_contains_a_name_a_prefill_value_or_document_bytes(
    dev_pki: Pki, tmp_path: Path, log_lines: Callable[[], list[dict[str, object]]]
) -> None:
    _exercise_every_path(dev_pki, tmp_path)

    rendered = json.dumps(log_lines())
    for forbidden in (PATIENT_NAME, PREFILL_VALUE, REASON, "%PDF"):
        assert forbidden not in rendered, f"{forbidden!r} reached the logs"


def test_the_logger_never_has_to_drop_a_field(
    dev_pki: Pki, tmp_path: Path, log_lines: Callable[[], list[dict[str, object]]]
) -> None:
    """A dropped field means the code tried to log something it should not have."""
    _exercise_every_path(dev_pki, tmp_path)

    written = log_lines()
    assert written, "nothing was logged, so this test would prove nothing"
    for line in written:
        assert "dropped_fields" not in line, line
        assert set(line) <= (LOGGABLE_KEYS | RESERVED_KEYS), line


def test_something_was_actually_logged(
    dev_pki: Pki, tmp_path: Path, log_lines: Callable[[], list[dict[str, object]]]
) -> None:
    """Guards the two tests above against passing because nothing was written at all."""
    _exercise_every_path(dev_pki, tmp_path)

    events = {line.get("event") for line in log_lines()}
    assert "seal.applied" in events
    assert "seal.trust_roots_unavailable" in events
