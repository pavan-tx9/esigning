"""Versioned, immutable ESIGN disclosures.

What a signer agreed to is evidence, so the exact words are stored, hashed and never edited. A
correction is a new version with a later ``effective_at``; the row a signer accepted stays exactly
as it was, and ``consent_texts`` is append-only in the schema and in the grants.

The default US English disclosure ships as a text file in ``esign/identity/consent/`` so that it
can be reviewed as prose and diffed as prose. ``esign consent add`` seeds it -- and any later
version -- through :func:`add_consent_text`, which is idempotent for identical text and refuses to
redefine a version that already exists.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Final

from sqlalchemy import RowMapping, text
from sqlalchemy.orm import Session

from esign.contracts import Conflict, ConsentText, IntegrityFailure, NotFound, ValidationFailed
from esign.identity.rows import raw_bytes, req_str, req_uuid, to_utc
from esign.ids import new_id

__all__ = [
    "CONSENT_COLUMNS",
    "BundledConsent",
    "add_consent_text",
    "body_sha256",
    "bundled_consent_texts",
    "normalise_body",
    "normalise_locale",
    "row_to_consent_text",
    "seed_default_consent",
]

#: Directory inside the package holding ``<locale>.<version>.txt`` disclosures.
_CONSENT_DIR: Final = "consent"

_VERSION_RE: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_LOCALE_RE: Final = re.compile(r"\A[a-z]{2,3}(-[A-Z]{2})?\Z")
_MAX_BODY_CHARS: Final = 200_000
_HEADER_SEPARATOR: Final = "---"


@dataclass(frozen=True)
class BundledConsent:
    """A disclosure shipped with the code, before it reaches the database."""

    version: str
    locale: str
    effective_at: datetime
    body: str


# --------------------------------------------------------------------------- normalisation


def normalise_locale(locale: str) -> str:
    """``en-us`` and ``EN-US`` are the same locale as ``en-US``. Raises for anything unusable."""
    cleaned = locale.strip().replace("_", "-")
    parts = cleaned.split("-")
    if len(parts) == 1:
        candidate = parts[0].lower()
    elif len(parts) == 2:
        candidate = f"{parts[0].lower()}-{parts[1].upper()}"
    else:
        raise ValidationFailed("unsupported locale", code="invalid_locale")
    if not _LOCALE_RE.match(candidate):
        raise ValidationFailed("unsupported locale", code="invalid_locale")
    return candidate


def normalise_body(body: str) -> str:
    """Line endings to ``\\n`` and no trailing blank line, so the hash is stable across checkouts."""
    cleaned = body.replace("\r\n", "\n").replace("\r", "\n").rstrip() + "\n"
    if len(cleaned.strip()) == 0:
        raise ValidationFailed("consent text is empty", code="invalid_consent_text")
    if len(cleaned) > _MAX_BODY_CHARS:
        raise ValidationFailed("consent text is too long", code="invalid_consent_text")
    return cleaned


def body_sha256(body: str) -> bytes:
    """The hash recorded with an acceptance. Always over the normalised text."""
    return hashlib.sha256(normalise_body(body).encode("utf-8")).digest()


# --------------------------------------------------------------------------- bundled files


def _parse_bundled(name: str, raw: str) -> BundledConsent:
    header, separator, body = raw.replace("\r\n", "\n").partition(f"\n{_HEADER_SEPARATOR}\n")
    if not separator:
        raise ValueError(f"{name}: expected a '{_HEADER_SEPARATOR}' line after the header")
    fields: dict[str, str] = {}
    for line in header.split("\n"):
        if not line.strip():
            continue
        key, _, value = line.partition(":")
        fields[key.strip().lower()] = value.strip()
    missing = {"version", "locale", "effective_at"} - fields.keys()
    if missing:
        raise ValueError(f"{name}: header is missing {sorted(missing)}")
    return BundledConsent(
        version=fields["version"],
        locale=normalise_locale(fields["locale"]),
        effective_at=to_utc(datetime.fromisoformat(fields["effective_at"])),
        body=normalise_body(body),
    )


def bundled_consent_texts() -> tuple[BundledConsent, ...]:
    """Every disclosure shipped with the package, oldest effective date first."""
    directory = files("esign.identity").joinpath(_CONSENT_DIR)
    found: list[BundledConsent] = []
    for entry in sorted(directory.iterdir(), key=lambda item: item.name):
        if not entry.name.endswith(".txt"):
            continue
        found.append(_parse_bundled(entry.name, entry.read_text(encoding="utf-8")))
    if not found:  # pragma: no cover - the package always ships one
        raise RuntimeError("no bundled consent texts found")
    return tuple(sorted(found, key=lambda item: (item.effective_at, item.version)))


def seed_default_consent(db: Session) -> tuple[ConsentText, ...]:
    """Insert every bundled disclosure that is not in the database yet. Safe to re-run."""
    return tuple(
        add_consent_text(
            db,
            version=bundled.version,
            locale=bundled.locale,
            body=bundled.body,
            effective_at=bundled.effective_at,
        )
        for bundled in bundled_consent_texts()
    )


# --------------------------------------------------------------------------- database


#: Every column ``row_to_consent_text`` needs. Statements spell it out; this documents it.
CONSENT_COLUMNS: Final = "id, version, locale, body, body_sha256"


def row_to_consent_text(row: RowMapping) -> ConsentText:
    """Build the contract type, checking the stored hash against the stored body.

    A mismatch means the row and its hash disagree, which is exactly the kind of quiet corruption
    the product exists to detect. It is an ``IntegrityFailure`` and is never swallowed.
    """
    version = req_str(row, "version")
    locale = req_str(row, "locale")
    body = req_str(row, "body")
    stored_hash = raw_bytes(row, "body_sha256")
    computed = hashlib.sha256(body.encode("utf-8")).digest()
    if computed != stored_hash:
        raise IntegrityFailure(f"consent text {version}/{locale} does not match its recorded hash")
    return ConsentText(id=req_uuid(row, "id"), version=version, locale=locale, body=body, body_sha256=stored_hash)


def add_consent_text(
    db: Session,
    *,
    version: str,
    locale: str,
    body: str,
    effective_at: datetime,
) -> ConsentText:
    """Add a disclosure version.

    Idempotent for identical text: re-running the seed changes nothing. A second, *different* body
    under the same version is a ``Conflict`` -- a version that could mean two things is not
    evidence.
    """
    if not _VERSION_RE.match(version.strip()):
        raise ValidationFailed("unsupported consent version", code="invalid_consent_version")
    clean_version = version.strip()
    clean_locale = normalise_locale(locale)
    clean_body = normalise_body(body)
    digest = hashlib.sha256(clean_body.encode("utf-8")).digest()
    if effective_at.tzinfo is None:
        raise ValidationFailed("effective_at must be timezone aware", code="invalid_consent_text")

    db.execute(
        text(
            "INSERT INTO consent_texts (id, version, locale, body, body_sha256, effective_at) "
            "VALUES (:id, :version, :locale, :body, :digest, :effective_at) "
            "ON CONFLICT (version, locale) DO NOTHING"
        ),
        {
            "id": new_id(),
            "version": clean_version,
            "locale": clean_locale,
            "body": clean_body,
            "digest": digest,
            "effective_at": to_utc(effective_at),
        },
    )
    row = (
        db.execute(
            text(
                "SELECT id, version, locale, body, body_sha256 FROM consent_texts "
                "WHERE version = :version AND locale = :locale"
            ),
            {"version": clean_version, "locale": clean_locale},
        )
        .mappings()
        .first()
    )
    if row is None:  # pragma: no cover - the insert above has either written or conflicted
        raise NotFound("consent text", code="consent_not_found")
    stored = row_to_consent_text(row)
    if stored.body_sha256 != digest:
        raise Conflict(
            f"consent version {clean_version} already exists for {clean_locale} with different text",
            code="consent_version_exists",
        )
    return stored
