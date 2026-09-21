"""Consent texts: immutable, hash-checked, and the right one for the locale.

What the signer was shown is the heart of an ESIGN defence, so these tests care about three
things: the stored words cannot change, the hash always matches them, and ``current_consent``
returns something sensible for every locale the UI might ask for.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import Conflict, IntegrityFailure, NotFound, ValidationFailed
from esign.identity import (
    SqlIdentityService,
    add_consent_text,
    body_sha256,
    bundled_consent_texts,
    normalise_locale,
    seed_default_consent,
)
from esign.ids import new_id

# --------------------------------------------------------------------------- the shipped text


def test_a_default_us_english_disclosure_ships_with_the_package() -> None:
    bundled = bundled_consent_texts()
    assert bundled
    default = next(item for item in bundled if item.locale == "en-US")
    assert default.version
    assert default.effective_at.tzinfo is not None


def test_the_shipped_disclosure_covers_what_esign_requires() -> None:
    """Right to paper, how to withdraw, what hardware and software are needed, how to get a copy."""
    body = next(item for item in bundled_consent_texts() if item.locale == "en-US").body.lower()
    for phrase in ("sign on paper", "withdraw", "browser", "copy", "no charge"):
        assert phrase in body, f"the disclosure does not mention {phrase!r}"
    assert "!" not in body


def test_the_shipped_disclosure_hashes_the_same_every_time() -> None:
    body = next(item for item in bundled_consent_texts() if item.locale == "en-US").body
    assert body_sha256(body) == body_sha256(body.replace("\n", "\r\n"))
    assert body_sha256(body) == hashlib.sha256(body.encode("utf-8")).digest()


# --------------------------------------------------------------------------- seeding


def test_seeding_is_idempotent(db: Session) -> None:
    first = seed_default_consent(db)
    second = seed_default_consent(db)
    assert [item.id for item in first] == [item.id for item in second]

    count = db.execute(text("SELECT count(*) FROM consent_texts")).scalar_one()
    assert count == len(first)


def test_the_stored_hash_matches_the_stored_body(db: Session) -> None:
    for consent in seed_default_consent(db):
        row = db.execute(text("SELECT body, body_sha256 FROM consent_texts WHERE id = :id"), {"id": consent.id}).one()
        assert hashlib.sha256(str(row.body).encode("utf-8")).digest() == bytes(row.body_sha256)


def test_the_same_version_with_different_words_is_a_conflict(db: Session, clock: FixedClock) -> None:
    add_consent_text(db, version="2026-09", locale="en-US", body="Original text.", effective_at=clock.now())
    with pytest.raises(Conflict) as caught:
        add_consent_text(db, version="2026-09", locale="en-US", body="Quietly edited.", effective_at=clock.now())
    assert caught.value.code == "consent_version_exists"

    stored = db.execute(
        text("SELECT body FROM consent_texts WHERE version = '2026-09' AND locale = 'en-US'")
    ).scalar_one()
    assert stored == "Original text.\n"


def test_whitespace_only_differences_do_not_create_a_conflict(db: Session, clock: FixedClock) -> None:
    first = add_consent_text(db, version="v1", locale="en-US", body="Line one.\nLine two.", effective_at=clock.now())
    again = add_consent_text(
        db, version="v1", locale="en-US", body="Line one.\r\nLine two.\n\n", effective_at=clock.now()
    )
    assert first.id == again.id


@pytest.mark.parametrize("version", ["", "   ", "-bad", "x" * 65, "has space", "semi;colon"])
def test_a_version_must_be_a_usable_label(db: Session, clock: FixedClock, version: str) -> None:
    with pytest.raises(ValidationFailed) as caught:
        add_consent_text(db, version=version, locale="en-US", body="Body.", effective_at=clock.now())
    assert caught.value.code == "invalid_consent_version"


@pytest.mark.parametrize("locale", ["", "english", "en-USA", "e", "en-US-x", "12"])
def test_a_locale_must_be_a_language_tag(db: Session, clock: FixedClock, locale: str) -> None:
    with pytest.raises(ValidationFailed) as caught:
        add_consent_text(db, version="v1", locale=locale, body="Body.", effective_at=clock.now())
    assert caught.value.code == "invalid_locale"


def test_an_empty_body_is_refused(db: Session, clock: FixedClock) -> None:
    with pytest.raises(ValidationFailed):
        add_consent_text(db, version="v1", locale="en-US", body="   \n  ", effective_at=clock.now())


def test_locales_are_normalised(db: Session, clock: FixedClock) -> None:
    consent = add_consent_text(db, version="v1", locale="EN_us", body="Body.", effective_at=clock.now())
    assert consent.locale == "en-US"
    assert normalise_locale("en-us") == "en-US"


# --------------------------------------------------------------------------- choosing one


def test_current_consent_returns_the_latest_effective_version(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    add_consent_text(db, version="2025-01", locale="en-US", body="Old.", effective_at=clock.now() - timedelta(days=30))
    add_consent_text(db, version="2026-03", locale="en-US", body="Current.", effective_at=clock.now())

    assert identity.current_consent(db, "en-US").version == "2026-03"


def test_a_version_that_is_not_yet_effective_is_not_used(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    add_consent_text(db, version="2026-03", locale="en-US", body="Current.", effective_at=clock.now())
    add_consent_text(db, version="2027-01", locale="en-US", body="Future.", effective_at=clock.now() + timedelta(1))

    assert identity.current_consent(db, "en-US").version == "2026-03"

    clock.advance(timedelta(days=1))
    assert identity.current_consent(db, "en-US").version == "2027-01"


def test_an_unknown_locale_falls_back_to_the_default(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    add_consent_text(db, version="2026-03", locale="en-US", body="English.", effective_at=clock.now())
    fallback = identity.current_consent(db, "fr-FR")
    assert fallback.locale == "en-US"


def test_an_unusable_locale_string_falls_back_rather_than_failing(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    add_consent_text(db, version="2026-03", locale="en-US", body="English.", effective_at=clock.now())
    assert identity.current_consent(db, "not a locale").locale == "en-US"
    assert identity.current_consent(db, "en-us").locale == "en-US"


def test_a_matching_locale_is_preferred_over_the_default(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    add_consent_text(db, version="2026-03", locale="en-US", body="English.", effective_at=clock.now())
    add_consent_text(db, version="2026-03", locale="es-US", body="Espanol.", effective_at=clock.now())
    assert identity.current_consent(db, "es-US").locale == "es-US"


def test_with_nothing_in_force_the_answer_is_not_found_rather_than_a_blank_disclosure(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    add_consent_text(db, version="2027-01", locale="en-US", body="Future.", effective_at=clock.now() + timedelta(1))
    with pytest.raises(NotFound) as caught:
        identity.current_consent(db, "en-US")
    assert caught.value.code == "consent_not_found"


def test_get_consent_returns_exactly_what_was_accepted(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    stored = add_consent_text(db, version="2026-03", locale="en-US", body="The words.", effective_at=clock.now())
    fetched = identity.get_consent(db, stored.id)
    assert fetched == stored
    assert fetched.body_sha256 == hashlib.sha256(fetched.body.encode("utf-8")).digest()


def test_get_consent_for_an_unknown_id_is_not_found(db: Session, identity: SqlIdentityService) -> None:
    with pytest.raises(NotFound):
        identity.get_consent(db, new_id())


# --------------------------------------------------------------------------- immutability


def test_a_consent_row_cannot_be_edited_by_the_app_role(db: Session, clock: FixedClock) -> None:
    consent = add_consent_text(db, version="2026-03", locale="en-US", body="The words.", effective_at=clock.now())
    for statement in (
        "UPDATE consent_texts SET body = 'edited' WHERE id = :id",
        "DELETE FROM consent_texts WHERE id = :id",
    ):
        with pytest.raises(DBAPIError) as caught, db.begin_nested():
            db.execute(text(statement), {"id": consent.id})
        assert getattr(caught.value.orig, "sqlstate", None) == "42501"


def test_even_the_owner_role_hits_the_append_only_trigger(owner_db: Session, clock: FixedClock) -> None:
    consent = add_consent_text(owner_db, version="2026-03", locale="en-US", body="The words.", effective_at=clock.now())
    with pytest.raises(DBAPIError) as caught, owner_db.begin_nested():
        owner_db.execute(text("UPDATE consent_texts SET body = 'edited' WHERE id = :id"), {"id": consent.id})
    assert getattr(caught.value.orig, "sqlstate", None) == "P0001"


def test_a_body_that_does_not_match_its_hash_is_an_integrity_failure(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    """The row cannot be edited, so corruption arrives as a row that never matched."""
    consent_id = new_id()
    db.execute(
        text(
            "INSERT INTO consent_texts (id, version, locale, body, body_sha256, effective_at) "
            "VALUES (:id, 'tampered', 'en-US', 'These are not the words that were agreed.', :sha, :now)"
        ),
        {"id": consent_id, "sha": hashlib.sha256(b"the words that were agreed").digest(), "now": clock.now()},
    )

    with pytest.raises(IntegrityFailure):
        identity.get_consent(db, consent_id)
    with pytest.raises(IntegrityFailure):
        identity.current_consent(db, "en-US")


def test_the_default_locale_comes_from_settings(db: Session, clock: FixedClock, settings: Settings) -> None:
    add_consent_text(db, version="2026-03", locale="fr-CA", body="Francais.", effective_at=clock.now())
    service = SqlIdentityService(settings.model_copy(update={"default_locale": "fr-CA"}), clock)
    assert service.current_consent(db, "de-DE").locale == "fr-CA"
