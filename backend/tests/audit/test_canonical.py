"""The canonical encoding. No database: these are the rules a third party has to reproduce."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from ipaddress import ip_address
from typing import Any
from uuid import UUID

import pytest

from esign.audit.canonical import (
    HASHED_FIELDS,
    ZERO_HASH,
    CanonicalizationError,
    canonical_json,
    canonical_value,
    compute_event_hash,
    hash_input,
    rfc3339,
)
from esign.contracts import EventType


def test_zero_hash_is_thirty_two_zero_bytes() -> None:
    assert bytes(32) == ZERO_HASH
    assert ZERO_HASH.hex() == "0" * 64


def test_keys_are_sorted_recursively_and_there_is_no_whitespace() -> None:
    encoded = canonical_json({"b": 1, "a": {"z": 0, "y": {"n": 2, "m": 3}}})
    assert encoded == b'{"a":{"y":{"m":3,"n":2},"z":0},"b":1}'


def test_key_order_of_the_input_does_not_matter() -> None:
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_bytes_become_lowercase_hex() -> None:
    assert canonical_json({"h": bytes.fromhex("ABCDEF01")}) == b'{"h":"abcdef01"}'


def test_uuids_become_lowercase_strings() -> None:
    value = UUID("0F2C9A44-1D3B-4E57-8A66-B1C2D3E4F5A6")
    assert canonical_json({"id": value}) == b'{"id":"0f2c9a44-1d3b-4e57-8a66-b1c2d3e4f5a6"}'


def test_timestamps_are_utc_with_exactly_six_fractional_digits() -> None:
    assert rfc3339(datetime(2026, 3, 17, 14, 31, 2, 481073, tzinfo=UTC)) == "2026-03-17T14:31:02.481073Z"
    # A whole second still gets six digits: the width is fixed, so the bytes are predictable.
    assert rfc3339(datetime(2026, 3, 17, 14, 31, 2, tzinfo=UTC)) == "2026-03-17T14:31:02.000000Z"


def test_a_non_utc_timestamp_is_converted_not_rejected() -> None:
    eastern = timezone(timedelta(hours=-5))
    assert rfc3339(datetime(2026, 3, 17, 9, 31, 2, 481073, tzinfo=eastern)) == "2026-03-17T14:31:02.481073Z"


def test_a_naive_timestamp_is_refused() -> None:
    with pytest.raises(CanonicalizationError):
        rfc3339(datetime(2026, 3, 17, 14, 31, 2, 481073))


def test_absent_values_are_null_not_omitted() -> None:
    assert canonical_json({"a": None, "b": 1}) == b'{"a":null,"b":1}'


def test_non_ascii_is_utf8_not_escaped() -> None:
    encoded = canonical_json({"ua": "Mozilla/5.0 é"})
    assert "\\u" not in encoded.decode("utf-8")
    assert encoded.decode("utf-8") == '{"ua":"Mozilla/5.0 é"}'


def test_booleans_stay_booleans_and_are_not_treated_as_ints() -> None:
    assert canonical_json({"a": True, "b": 1}) == b'{"a":true,"b":1}'


@pytest.mark.parametrize("value", [1.5, float("nan"), float("inf"), Decimal("1.5")])
def test_floats_and_decimals_are_refused(value: Any) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({"x": value})


def test_unknown_types_are_refused_and_the_message_carries_the_type_not_the_value() -> None:
    class Secret:
        def __repr__(self) -> str:  # pragma: no cover - only reached if the test fails
            return "Jane Doe, DOB 1970-01-01"

    with pytest.raises(CanonicalizationError) as caught:
        canonical_json({"x": Secret()})
    assert "Secret" in str(caught.value)
    assert "Jane" not in str(caught.value)


def test_non_string_keys_are_refused() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({1: "a"})


def test_enums_canonicalise_to_their_value() -> None:
    assert canonical_value(EventType.SIGNER_SIGNED) == "signer.signed"


def test_ip_addresses_canonicalise_the_way_postgres_renders_them() -> None:
    assert canonical_value(ip_address("2001:0db8::1")) == "2001:db8::1"
    assert canonical_value(ip_address("198.51.100.24")) == "198.51.100.24"


def test_sequences_keep_their_order() -> None:
    assert canonical_json({"xs": [3, 1, 2]}) == b'{"xs":[3,1,2]}'


def test_huge_integers_are_refused() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({"n": 2**63})


def _full_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = dict.fromkeys(HASHED_FIELDS)
    fields.update(
        {
            "data": {},
            "event_type": "envelope.expired",
            "id": UUID(int=1),
            "occurred_at": datetime(2026, 3, 17, tzinfo=UTC),
            "prev_event_hash": ZERO_HASH,
            "sequence": 1,
            "stream_id": UUID(int=2),
            "stream_type": "envelope",
        }
    )
    fields.update(overrides)
    return fields


def test_hash_input_covers_every_audit_column_but_the_hash() -> None:
    assert "event_hash" not in HASHED_FIELDS
    assert len(HASHED_FIELDS) == len(set(HASHED_FIELDS)) == 17
    assert list(HASHED_FIELDS) == sorted(HASHED_FIELDS)


def test_hash_input_refuses_a_missing_field() -> None:
    fields = _full_fields()
    del fields["ip"]
    with pytest.raises(CanonicalizationError, match="missing"):
        hash_input(fields)


def test_hash_input_refuses_an_unexpected_field() -> None:
    with pytest.raises(CanonicalizationError, match="unexpected"):
        hash_input({**_full_fields(), "surprise": 1})


def test_changing_any_single_field_changes_the_hash() -> None:
    """The property that makes tampering with any column detectable."""
    baseline = compute_event_hash(_full_fields())
    variations: dict[str, Any] = {
        "actor_capacity": "guardian",
        "actor_role": "clinician",
        "actor_user_id": "host-2",
        "auth_method": "sso",
        "data": {"reason_code": "voided"},
        "document_sha256": bytes(32),
        "event_type": "envelope.voided",
        "id": UUID(int=9),
        "ip": "10.0.0.1",
        "occurred_at": datetime(2026, 3, 17, 0, 0, 0, 1, tzinfo=UTC),
        "on_behalf_of": "patient-7",
        "prev_event_hash": bytes([1]) + bytes(31),
        "sequence": 2,
        "session_id": UUID(int=3),
        "stream_id": UUID(int=4),
        "stream_type": "template",
        "user_agent": "curl/8",
    }
    assert set(variations) == set(HASHED_FIELDS)
    for field, value in variations.items():
        assert compute_event_hash(_full_fields(**{field: value})) != baseline, field


def test_the_hash_is_the_sha256_of_the_canonical_bytes() -> None:
    import hashlib

    fields = _full_fields()
    assert compute_event_hash(fields) == hashlib.sha256(hash_input(fields)).digest()


def test_the_canonical_bytes_are_valid_json_that_round_trips() -> None:
    fields = _full_fields(ip="198.51.100.24", data={"reason_code": "expired"})
    decoded = json.loads(hash_input(fields))
    assert decoded["ip"] == "198.51.100.24"
    assert decoded["prev_event_hash"] == "0" * 64
    assert decoded["occurred_at"].endswith("Z")
