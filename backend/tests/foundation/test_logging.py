"""The logging allowlist.

The rule is that PHI never reaches a log line. This proves the mechanism that enforces it: a key
that is not on the allowlist does not appear in the rendered output, and neither does its value.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import pytest

from esign.logging import LOGGABLE_KEYS, configure_logging, drop_unlisted_keys, get_logger


def _render(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    out = capsys.readouterr().out.strip().splitlines()
    assert out, "nothing was logged"
    parsed: dict[str, Any] = json.loads(out[-1])
    return parsed


def test_an_unlisted_key_is_dropped_before_rendering() -> None:
    result = drop_unlisted_keys(None, "info", {"event": "signer.signed", "display_name": "Jane Roe"})
    assert "display_name" not in result
    assert "Jane Roe" not in json.dumps(result)


def test_the_dropped_key_is_named_so_a_mistake_is_visible() -> None:
    result = drop_unlisted_keys(None, "info", {"event": "x", "patient_dob": "1970-01-01", "zzz": 1})
    assert result["dropped_fields"] == ["patient_dob", "zzz"]


def test_allowlisted_keys_survive() -> None:
    result = drop_unlisted_keys(None, "info", {"event": "x", "envelope_id": "abc", "error_code": "nope"})
    assert result["envelope_id"] == "abc"
    assert result["error_code"] == "nope"
    assert "dropped_fields" not in result


def test_uuids_and_hashes_are_rendered_as_text() -> None:
    envelope_id = UUID("11111111-2222-4333-8444-555555555555")
    result = drop_unlisted_keys(None, "info", {"event": "x", "envelope_id": envelope_id, "sha256": b"\x01\x02"})
    assert result["envelope_id"] == str(envelope_id)
    assert result["sha256"] == "0102"


def test_a_real_log_line_carries_no_unlisted_value(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="DEBUG", json_output=True, app_env="test")
    log = get_logger("tests.foundation")
    log.info(
        "signer.signed",
        envelope_id="1c9f0e6e-0000-4000-8000-000000000001",
        signer_id="1c9f0e6e-0000-4000-8000-000000000002",
        display_name="Jane Roe",
        date_of_birth="1970-01-01",
        prefill={"diagnosis": "something private"},
        token="est_deadbeef",
    )
    line = _render(capsys)

    assert line["event"] == "signer.signed"
    assert line["envelope_id"] == "1c9f0e6e-0000-4000-8000-000000000001"
    raw = json.dumps(line)
    for secret in ("Jane Roe", "1970-01-01", "something private", "est_deadbeef"):
        assert secret not in raw
    assert set(line["dropped_fields"]) == {"display_name", "date_of_birth", "prefill", "token"}


def test_a_clean_log_line_has_no_dropped_fields_key(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", json_output=True, app_env="test")
    get_logger("tests.foundation").info("document.sealed", envelope_id="e", seal_profile="PAdES-B-T")
    line = _render(capsys)
    assert "dropped_fields" not in line
    assert line["seal_profile"] == "PAdES-B-T"
    assert line["app_env"] == "test"


@pytest.mark.parametrize(
    "forbidden",
    [
        "display_name",
        "patient_name",
        "patient_ref",
        "date_of_birth",
        "dob",
        "prefill",
        "body",
        "request_body",
        "response_body",
        "token",
        "api_key",
        "typed_text",
        "pdf",
        "signature_png",
        "host_user_id",
        "staff_user_id",
        "consent_body",
    ],
)
def test_nothing_that_could_carry_phi_is_on_the_allowlist(forbidden: str) -> None:
    assert forbidden not in LOGGABLE_KEYS
