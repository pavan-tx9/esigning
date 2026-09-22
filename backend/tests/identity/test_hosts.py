"""Host registration and API-key authentication, against the real schema."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.contracts import NotFound, Unauthorized, ValidationFailed
from esign.identity import HOST_KEY_PREFIX, create_host, disable_host, normalise_origin, rotate_host_key
from esign.identity.hosts import rotate_webhook_secret
from esign.identity.service import SqlIdentityService
from esign.identity.tokens import TOKEN_LENGTH
from esign.ids import new_id


def test_create_host_returns_a_key_once_and_stores_only_its_hash(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    key, host = create_host(db, "Northside EHR", ["https://ehr.example.org"], None, clock=clock)

    assert key.startswith(HOST_KEY_PREFIX)
    assert len(key) == TOKEN_LENGTH
    assert host.name == "Northside EHR"
    assert host.allowed_origins == ("https://ehr.example.org",)
    assert identity.authenticate_host(db, key).id == host.id


def test_the_plaintext_key_never_reaches_the_database(db: Session, clock: FixedClock) -> None:
    """Asked of every column of the row, not just the one we meant to write."""
    key, host = create_host(db, "Northside EHR", clock=clock)
    row = db.execute(text("SELECT to_jsonb(h)::text AS dump FROM hosts h WHERE id = :id"), {"id": host.id}).scalar_one()
    assert key not in str(row)
    assert key[len(HOST_KEY_PREFIX) :] not in str(row)


def test_the_created_row_is_timed_by_the_clock(db: Session, clock: FixedClock) -> None:
    _, host = create_host(db, "Northside EHR", clock=clock)
    created_at = db.execute(text("SELECT created_at FROM hosts WHERE id = :id"), {"id": host.id}).scalar_one()
    assert created_at == clock.now()


def test_an_authorization_header_is_accepted_verbatim(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    key, host = create_host(db, "Northside EHR", clock=clock)
    assert identity.authenticate_host(db, f"Bearer {key}").id == host.id


@pytest.mark.parametrize(
    "bearer",
    ["", "   ", "esk_wrong", "esk_" + "a" * 43, "est_" + "a" * 43, "Bearer nonsense", "' OR 1=1 --"],
)
def test_every_bad_key_is_the_same_unauthorized(
    db: Session, clock: FixedClock, identity: SqlIdentityService, bearer: str
) -> None:
    create_host(db, "Northside EHR", clock=clock)
    with pytest.raises(Unauthorized) as caught:
        identity.authenticate_host(db, bearer)
    assert caught.value.code == "unauthorized"
    assert str(caught.value) == "invalid credentials"


def test_a_disabled_host_cannot_authenticate_and_looks_no_different(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    key, host = create_host(db, "Northside EHR", clock=clock)
    disable_host(db, host.id, clock=clock)

    with pytest.raises(Unauthorized) as caught:
        identity.authenticate_host(db, key)
    assert str(caught.value) == "invalid credentials"

    disabled_at = db.execute(text("SELECT disabled_at FROM hosts WHERE id = :id"), {"id": host.id}).scalar_one()
    assert disabled_at == clock.now()


def test_disable_is_idempotent_and_unknown_hosts_are_not_found(db: Session, clock: FixedClock) -> None:
    _, host = create_host(db, "Northside EHR", clock=clock)
    disable_host(db, host.id, clock=clock)
    disable_host(db, host.id, clock=clock)
    with pytest.raises(NotFound):
        disable_host(db, new_id(), clock=clock)


def test_rotating_a_key_invalidates_the_previous_one(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    old_key, host = create_host(db, "Northside EHR", ["https://ehr.example.org"], clock=clock)
    new_key, rotated = rotate_host_key(db, host.id)

    assert new_key != old_key
    assert rotated.id == host.id
    assert rotated.allowed_origins == ("https://ehr.example.org",)
    assert identity.authenticate_host(db, new_key).id == host.id
    with pytest.raises(Unauthorized):
        identity.authenticate_host(db, old_key)


def test_a_disabled_host_cannot_have_its_key_rotated(db: Session, clock: FixedClock) -> None:
    _, host = create_host(db, "Northside EHR", clock=clock)
    disable_host(db, host.id, clock=clock)
    with pytest.raises(NotFound):
        rotate_host_key(db, host.id)


def test_a_webhook_url_mints_a_signing_secret(db: Session, clock: FixedClock) -> None:
    _, host = create_host(db, "Northside EHR", [], "https://ehr.example.org/hooks", clock=clock)
    secret = db.execute(text("SELECT webhook_secret FROM hosts WHERE id = :id"), {"id": host.id}).scalar_one()
    assert secret is not None
    assert len(bytes(secret)) == 32

    rotated = rotate_webhook_secret(db, host.id)
    assert len(rotated) == 32
    assert bytes(secret) != rotated


def test_a_host_without_a_webhook_has_no_secret(db: Session, clock: FixedClock) -> None:
    _, host = create_host(db, "Northside EHR", clock=clock)
    secret = db.execute(text("SELECT webhook_secret FROM hosts WHERE id = :id"), {"id": host.id}).scalar_one()
    assert secret is None


def test_origins_are_normalised_and_deduplicated(db: Session, clock: FixedClock) -> None:
    _, host = create_host(
        db,
        "Northside EHR",
        ["HTTPS://EHR.Example.org/", "https://ehr.example.org", "https://portal.example.org:8443"],
        clock=clock,
    )
    assert host.allowed_origins == ("https://ehr.example.org", "https://portal.example.org:8443")


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://*.example.org",
        "https://ehr.example.org/sign",
        "https://ehr.example.org?x=1",
        "http://ehr.example.org",
        "ftp://ehr.example.org",
        "ehr.example.org",
        "https://user:pass@ehr.example.org",
        "",
        "https://" + "a" * 300,
    ],
)
def test_an_origin_that_is_not_an_origin_is_refused(db: Session, clock: FixedClock, origin: str) -> None:
    with pytest.raises(ValidationFailed) as caught:
        create_host(db, "Northside EHR", [origin], clock=clock)
    assert caught.value.code == "invalid_origin"


@pytest.mark.parametrize(
    "origin",
    [
        pytest.param("https://ehr.example.org;script-src evil.com", id="a second CSP directive"),
        pytest.param("https://ehr.example.org'", id="a quote"),
        pytest.param('https://ehr.example.org"', id="a double quote"),
        pytest.param("https://ehr.example.org\ttab", id="a tab, which urlsplit silently drops"),
        pytest.param("https://ehr.example.org%20x", id="a percent escape"),
        pytest.param("https://ehr.example.org x", id="a bare space"),
        pytest.param("https://ehr.example.org\nx", id="a newline"),
        pytest.param("https://ehr.example.org\x00", id="a null byte"),
        pytest.param("https://-ehr.example.org", id="a label starting with a hyphen"),
        pytest.param("https://ehr..example.org", id="an empty label"),
    ],
)
def test_an_origin_with_csp_breaking_characters_is_refused(origin: str) -> None:
    """This value is interpolated verbatim into ``frame-ancestors`` and into a meta tag.

    ``urlsplit`` will happily put ``;``, quotes and ``%`` in a netloc, and it drops a tab -- which
    yields a *different* origin than the operator typed, stored and trusted. Refused, not stripped.
    """
    with pytest.raises(ValidationFailed) as caught:
        normalise_origin(origin)
    assert caught.value.code == "invalid_origin"


def test_loopback_may_use_http_for_development() -> None:
    assert normalise_origin("http://localhost:5273") == "http://localhost:5273"
    assert normalise_origin("http://127.0.0.1:5273") == "http://127.0.0.1:5273"


def test_the_origins_a_real_host_uses_still_pass() -> None:
    assert normalise_origin("https://EHR.Example.org/") == "https://ehr.example.org"
    assert normalise_origin("https://ehr.example.org:8443") == "https://ehr.example.org:8443"
    assert normalise_origin("https://[2001:db8::1]:8443") == "https://[2001:db8::1]:8443"
    assert normalise_origin("https://203.0.113.10") == "https://203.0.113.10"


@pytest.mark.parametrize("url", ["http://ehr.example.org/hooks", "not-a-url", "ftp://x/y", "https://" + "a" * 600])
def test_a_webhook_url_must_be_https(db: Session, clock: FixedClock, url: str) -> None:
    with pytest.raises(ValidationFailed) as caught:
        create_host(db, "Northside EHR", [], url, clock=clock)
    assert caught.value.code == "invalid_webhook_url"


@pytest.mark.parametrize("name", ["", "   ", "x" * 201])
def test_a_host_needs_a_usable_name(db: Session, clock: FixedClock, name: str) -> None:
    with pytest.raises(ValidationFailed) as caught:
        create_host(db, name, clock=clock)
    assert caught.value.code == "invalid_host_name"


def test_too_many_origins_are_refused(db: Session, clock: FixedClock) -> None:
    origins = [f"https://host{index}.example.org" for index in range(21)]
    with pytest.raises(ValidationFailed):
        create_host(db, "Northside EHR", origins, clock=clock)


def test_two_hosts_do_not_share_a_key(db: Session, clock: FixedClock, identity: SqlIdentityService) -> None:
    first_key, first = create_host(db, "First", clock=clock)
    second_key, second = create_host(db, "Second", clock=clock)
    assert first_key != second_key
    assert identity.authenticate_host(db, first_key).id == first.id
    assert identity.authenticate_host(db, second_key).id == second.id
