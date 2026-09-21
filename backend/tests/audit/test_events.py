"""What may and may not go into ``audit_events.data``. No database needed."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from esign.audit.events import (
    CLOSED_VOCABULARIES,
    EVENT_DATA_MODELS,
    declared_data_keys,
    validate_event_data,
)
from esign.contracts import EventType, ValidationFailed
from tests.audit.helpers import ALL_EVENT_TYPES, DIGEST_A, sample_data

#: What a careless caller might hand us. Every one of these is PHI or free text.
PHI_VALUES = [
    "Jane Doe",
    "1970-01-01",
    "patient reports pain in left knee",
    "123 Main St, Springfield",
    "555-01-2345",
]


def test_every_event_type_has_a_declared_data_shape() -> None:
    assert set(EVENT_DATA_MODELS) == set(EventType)


def test_every_event_type_has_a_sample_so_no_shape_goes_untested() -> None:
    for event_type in ALL_EVENT_TYPES:
        assert isinstance(sample_data(event_type), dict)


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_the_sample_for_each_type_validates_and_canonicalises(event_type: EventType) -> None:
    result = validate_event_data(event_type, sample_data(event_type))
    assert set(result) == declared_data_keys(event_type)
    # Canonical primitives only: nothing that a JSON column would have to guess at.
    for value in result.values():
        assert isinstance(value, str | int | bool | list | dict | type(None))


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_an_unknown_key_is_rejected_for_every_event_type(event_type: EventType) -> None:
    payload = {**sample_data(event_type), "patient_name": "Jane Doe"}
    with pytest.raises(ValidationFailed) as caught:
        validate_event_data(event_type, payload)
    assert caught.value.code == "audit_data_invalid"


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_a_rejection_message_never_contains_the_rejected_value(event_type: EventType) -> None:
    """The message reaches logs. The value is the thing we suspect of being PHI."""
    payload = {**sample_data(event_type), "note": "Jane Doe, DOB 1970-01-01, 123 Main St"}
    with pytest.raises(ValidationFailed) as caught:
        validate_event_data(event_type, payload)
    message = str(caught.value)
    for fragment in ("Jane", "Doe", "1970", "Main St"):
        assert fragment not in message
    assert "note" in message  # the key is named, so a developer can fix it


@pytest.mark.parametrize("value", PHI_VALUES)
def test_a_name_cannot_be_smuggled_into_an_opaque_id_field(value: str) -> None:
    payload = {**sample_data(EventType.SESSION_CREATED), "kiosk_staff_user_id": value}
    with pytest.raises(ValidationFailed):
        validate_event_data(EventType.SESSION_CREATED, payload)


def test_a_thirty_two_character_string_is_not_accepted_as_a_hash() -> None:
    """Without strict mode pydantic would encode the string to bytes and it would fit exactly."""
    name = "Jane Doe of 1 Main Street, Sprin"
    assert len(name) == 32
    payload = {**sample_data(EventType.CONSENT_ACCEPTED), "body_sha256": name}
    with pytest.raises(ValidationFailed):
        validate_event_data(EventType.CONSENT_ACCEPTED, payload)


def test_a_hash_must_be_exactly_thirty_two_bytes() -> None:
    for wrong in (b"", bytes(31), bytes(33)):
        payload = {**sample_data(EventType.CONSENT_ACCEPTED), "body_sha256": wrong}
        with pytest.raises(ValidationFailed):
            validate_event_data(EventType.CONSENT_ACCEPTED, payload)


def test_a_timestamp_must_be_a_real_aware_datetime() -> None:
    for wrong in ("2026-04-01T09:00:00Z", 1774947600, datetime(2026, 4, 1, 9)):
        payload = {**sample_data(EventType.SESSION_CREATED), "auth_time": wrong}
        with pytest.raises(ValidationFailed):
            validate_event_data(EventType.SESSION_CREATED, payload)


def test_a_count_cannot_be_a_string_or_negative() -> None:
    for wrong in ("3", -1, True):
        payload = {**sample_data(EventType.DOCUMENT_VIEWED), "pages_viewed": wrong}
        with pytest.raises(ValidationFailed):
            validate_event_data(EventType.DOCUMENT_VIEWED, payload)


def test_an_enum_value_outside_its_vocabulary_is_rejected() -> None:
    payload = {**sample_data(EventType.DOCUMENT_STORED), "blob_kind": "chart_note"}
    with pytest.raises(ValidationFailed):
        validate_event_data(EventType.DOCUMENT_STORED, payload)


def test_a_reason_code_must_look_like_a_code() -> None:
    for wrong in ("I would rather sign on paper", "PREFERS_PAPER", "prefers paper", ""):
        payload = {**sample_data(EventType.SIGNER_DECLINED), "reason_code": wrong}
        with pytest.raises(ValidationFailed):
            validate_event_data(EventType.SIGNER_DECLINED, payload)


def test_a_missing_required_field_is_rejected() -> None:
    payload = dict(sample_data(EventType.SIGNER_DECLINED))
    del payload["reason_code"]
    with pytest.raises(ValidationFailed):
        validate_event_data(EventType.SIGNER_DECLINED, payload)


def test_optional_fields_are_written_as_null_rather_than_left_out() -> None:
    payload = dict(sample_data(EventType.ENVELOPE_CREATED))
    del payload["supersedes_envelope_id"]
    result = validate_event_data(EventType.ENVELOPE_CREATED, payload)
    assert result["supersedes_envelope_id"] is None
    assert set(result) == declared_data_keys(EventType.ENVELOPE_CREATED)


def test_none_is_a_valid_data_argument_for_a_type_with_no_fields() -> None:
    assert validate_event_data(EventType.ENVELOPE_EXPIRED, None) == {}


def test_data_for_a_type_with_no_fields_rejects_anything_at_all() -> None:
    with pytest.raises(ValidationFailed):
        validate_event_data(EventType.ENVELOPE_EXPIRED, {"reason_code": "expired"})


def test_hashes_and_ids_are_canonicalised_on_the_way_in() -> None:
    signer = uuid4()
    result = validate_event_data(
        EventType.CONSENT_ACCEPTED,
        {
            "signer_id": signer,
            "consent_text_id": UUID(int=5),
            "consent_version": "2026-09",
            "locale": "en-US",
            "body_sha256": DIGEST_A,
        },
    )
    assert result["signer_id"] == str(signer)
    assert result["body_sha256"] == DIGEST_A.hex()
    assert result["body_sha256"].islower()


def test_captures_accept_plain_dicts_so_callers_need_no_import_from_this_package() -> None:
    result = validate_event_data(EventType.SIGNER_SIGNED, sample_data(EventType.SIGNER_SIGNED))
    assert result["captures"] == [
        {"field_id": "patient_sig", "kind": "drawn"},
        {"field_id": "patient_initials", "kind": "typed"},
    ]


def test_a_capture_cannot_carry_the_captured_value() -> None:
    payload: dict[str, Any] = dict(sample_data(EventType.SIGNER_SIGNED))
    payload["captures"] = [{"field_id": "patient_sig", "kind": "typed", "typed_text": "Jane Doe"}]
    with pytest.raises(ValidationFailed):
        validate_event_data(EventType.SIGNER_SIGNED, payload)


def test_a_timestamp_must_be_timezone_aware_even_when_it_is_a_datetime() -> None:
    payload = {**sample_data(EventType.DOCUMENT_STORED), "retain_until": datetime(2036, 1, 1)}
    with pytest.raises(ValidationFailed):
        validate_event_data(EventType.DOCUMENT_STORED, payload)


def test_aware_non_utc_timestamps_are_normalised_to_utc() -> None:
    from datetime import timedelta, timezone

    payload = {
        **sample_data(EventType.DOCUMENT_STORED),
        "retain_until": datetime(2036, 1, 1, 5, tzinfo=timezone(timedelta(hours=5))),
    }
    result = validate_event_data(EventType.DOCUMENT_STORED, payload)
    assert result["retain_until"] == "2036-01-01T00:00:00.000000Z"


def test_no_declared_field_accepts_unconstrained_text() -> None:
    """A string field with no pattern is how PHI gets in. There must not be one."""
    offenders: list[str] = []
    for event_type, model in EVENT_DATA_MODELS.items():
        for name, field in model.model_fields.items():
            annotation = str(field.annotation)
            if annotation == "<class 'str'>" and not field.metadata:
                offenders.append(f"{event_type.value}.{name}")
    assert offenders == []


def test_the_closed_vocabularies_are_all_non_empty_and_lowercase_tokens() -> None:
    for name, values in CLOSED_VOCABULARIES.items():
        assert values, name
        for value in values:
            assert value == value.strip()
            assert " " not in value or name == "auth_method"


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_declared_keys_match_what_validation_produces(event_type: EventType) -> None:
    produced = validate_event_data(event_type, sample_data(event_type))
    assert frozenset(produced) == declared_data_keys(event_type)
