"""Clock, ids and settings. No database, so these run anywhere."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from esign.clock import AdvancingClock, FixedClock, SystemClock, utc
from esign.config import Settings
from esign.ids import advisory_lock_key, is_uuid4, new_id, parse_id


# --------------------------------------------------------------------------- clock
def test_system_clock_is_timezone_aware_utc() -> None:
    now = SystemClock().now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_fixed_clock_stands_still() -> None:
    clock = FixedClock(utc(2026, 3, 17, 14, 30))
    assert clock.now() == clock.now() == utc(2026, 3, 17, 14, 30)


def test_fixed_clock_advances_by_seconds_or_timedelta() -> None:
    clock = FixedClock(utc(2026, 1, 1))
    assert clock.advance(90) == utc(2026, 1, 1, 0, 1, 30)
    assert clock.advance(timedelta(hours=1)) == utc(2026, 1, 1, 1, 1, 30)


def test_time_does_not_run_backwards() -> None:
    clock = FixedClock(utc(2026, 1, 1))
    with pytest.raises(ValueError, match="backwards"):
        clock.advance(timedelta(seconds=-1))


def test_a_naive_datetime_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        FixedClock(datetime(2026, 1, 1))


def test_a_non_utc_time_is_normalised() -> None:
    eastern = datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=-5)))
    normalised = FixedClock(eastern).now()
    assert normalised.tzinfo is UTC
    assert normalised == utc(2026, 1, 1, 17, 0)


def test_advancing_clock_never_repeats_a_timestamp() -> None:
    clock = AdvancingClock(utc(2026, 1, 1), step=timedelta(milliseconds=1))
    seen = [clock.now() for _ in range(5)]
    assert seen == sorted(seen)
    assert len(set(seen)) == 5


def test_advancing_clock_needs_a_positive_step() -> None:
    with pytest.raises(ValueError, match="positive"):
        AdvancingClock(utc(2026, 1, 1), step=timedelta(0))


# --------------------------------------------------------------------------- ids
def test_new_id_is_a_uuid4() -> None:
    generated = new_id()
    assert is_uuid4(generated)
    assert parse_id(str(generated)) == generated


def test_advisory_lock_keys_are_stable_and_namespaced() -> None:
    value = new_id()
    assert advisory_lock_key("audit", value) == advisory_lock_key("audit", value)
    assert advisory_lock_key("audit", value) != advisory_lock_key("seal", value)


def test_advisory_lock_keys_fit_a_postgres_bigint() -> None:
    for _ in range(200):
        key = advisory_lock_key("audit", new_id())
        assert -(2**63) <= key < 2**63


# --------------------------------------------------------------------------- settings
def test_defaults_match_the_spec(settings_no_db: Settings) -> None:
    assert settings_no_db.session_ttl_seconds == 1800
    assert settings_no_db.auth_max_age_seconds == 43200
    assert settings_no_db.reauth_max_age_seconds == 120
    assert settings_no_db.default_retention_years == 10
    assert settings_no_db.envelope_default_ttl_days == 14
    assert settings_no_db.seal_key_backend == "local"
    assert settings_no_db.blob_backend == "fs"


def test_retention_falls_back_to_ten_years(settings_no_db: Settings) -> None:
    assert settings_no_db.retention_years("anything_unlisted") == 10


def test_retention_can_be_set_per_document_type() -> None:
    settings = Settings(retention_years_by_document_type={"procedure_consent": 25})
    assert settings.retention_years("procedure_consent") == 25
    assert settings.retention_years("patient_consent") == 10
    until = settings.retain_until("procedure_consent", utc(2026, 1, 1))
    assert until.year == 2050


def test_retention_map_parses_from_a_json_env_value() -> None:
    settings = Settings(retention_years_by_document_type='{"hipaa_acknowledgement": 7}')
    assert settings.retention_years("hipaa_acknowledgement") == 7


def test_list_settings_accept_plain_comma_separated_env_values() -> None:
    settings = Settings(
        trusted_proxy_cidrs="10.0.0.0/8, 192.168.0.0/16",
        approved_document_types="patient_consent,procedure_consent",
    )
    assert settings.trusted_proxy_cidrs == ("10.0.0.0/8", "192.168.0.0/16")
    assert settings.approved_document_types == ("patient_consent", "procedure_consent")
    assert settings.is_approved_document_type("patient_consent")
    assert not settings.is_approved_document_type("hipaa_acknowledgement")


def test_list_settings_also_accept_json() -> None:
    settings = Settings(trusted_proxy_cidrs='["10.0.0.0/8"]')
    assert settings.trusted_proxy_cidrs == ("10.0.0.0/8",)


def test_an_unknown_seal_profile_is_refused() -> None:
    with pytest.raises(ValueError, match="seal_profile"):
        Settings(seal_profile="PAdES-B-MAYBE")


def test_default_expiry_uses_the_configured_ttl(settings_no_db: Settings) -> None:
    assert settings_no_db.default_expiry(utc(2026, 1, 1)) == utc(2026, 1, 15)


def test_no_secret_value_ships_as_a_default(settings_no_db: Settings) -> None:
    """Dev credentials point at the local container and nothing else; real keys arrive by env."""
    assert settings_no_db.seal_kms_key_id == ""
    assert settings_no_db.blob_s3_bucket == ""
    assert "localhost" in settings_no_db.database_url
