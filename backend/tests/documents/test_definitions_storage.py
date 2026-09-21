"""The codec against the real ``jsonb`` columns it exists for.

``DocumentService`` itself never touches the database, but ``codec`` does its job on the way out of
``template_versions.fields`` / ``.prefill_fields`` / ``.signer_roles``. Postgres round-trips
``jsonb`` through its own type system -- integers may come back as ``Decimal`` from some drivers,
key order is not preserved, ``42.0`` and ``42`` are not the same thing -- so the round trip is
tested against Postgres rather than against a dict literal.

The published-version trigger is exercised at the same time: it is the reason a definition that
decodes loosely can never be corrected in place.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from esign.contracts import DocumentService
from esign.documents.codec import definitions_from_json, definitions_to_json

pytestmark = pytest.mark.db

TEMPLATE_DIR = Path(__file__).resolve().parents[3] / "templates"


def seed_template_version(db: Session, definitions: dict[str, Any], *, status: str = "published") -> UUID:
    host_id = UUID("00000000-0000-4000-8000-000000000001")
    template_id = UUID("00000000-0000-4000-8000-000000000002")
    version_id = UUID("00000000-0000-4000-8000-000000000003")
    digest = hashlib.sha256(b"template pdf bytes").digest()

    db.execute(
        text("INSERT INTO hosts (id, name, api_key_hash) VALUES (:id, :name, :hash)"),
        {"id": host_id, "name": "Test EHR", "hash": hashlib.sha256(b"key").digest()},
    )
    db.execute(
        text("INSERT INTO blobs (sha256, size_bytes, kind, storage_key) VALUES (:sha, :size, :kind, :key)"),
        {"sha": digest, "size": 19, "kind": "template_pdf", "key": digest.hex()},
    )
    db.execute(
        text("INSERT INTO templates (id, host_id, key, name, document_type) VALUES (:id, :host, :key, :name, :type)"),
        {
            "id": template_id,
            "host": host_id,
            "key": "procedure_consent",
            "name": "Consent to a procedure",
            "type": "procedure_consent",
        },
    )
    db.execute(
        text(
            "INSERT INTO template_versions "
            "(id, template_id, version, status, pdf_sha256, fields, prefill_fields, signer_roles) "
            "VALUES (:id, :template, 1, :status, :sha, "
            "CAST(:fields AS jsonb), CAST(:prefill AS jsonb), CAST(:roles AS jsonb))"
        ),
        {
            "id": version_id,
            "template": template_id,
            "status": status,
            "sha": digest,
            "fields": json.dumps(definitions["fields"]),
            "prefill": json.dumps(definitions["prefill_fields"]),
            "roles": json.dumps(definitions["signer_roles"]),
        },
    )
    return version_id


def read_back(db: Session, version_id: UUID) -> dict[str, Any]:
    row = db.execute(
        text("SELECT fields, prefill_fields, signer_roles FROM template_versions WHERE id = :id"),
        {"id": version_id},
    ).one()
    return {"fields": row[0], "prefill_fields": row[1], "signer_roles": row[2]}


def sample_definitions() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((TEMPLATE_DIR / "procedure_consent.json").read_text())
    return loaded


def test_definitions_survive_a_round_trip_through_jsonb(db: Session, documents: DocumentService) -> None:
    original = definitions_from_json(sample_definitions())
    version_id = seed_template_version(
        db, definitions_to_json(original.fields, original.prefill_fields, original.signer_roles)
    )
    decoded = definitions_from_json(read_back(db, version_id))

    assert decoded.fields == original.fields
    assert decoded.prefill_fields == original.prefill_fields
    assert decoded.signer_roles == original.signer_roles

    info = documents.inspect_template_pdf((TEMPLATE_DIR / "procedure_consent.pdf").read_bytes())
    documents.validate_definitions(info, decoded.fields, decoded.prefill_fields, decoded.signer_roles)


def test_a_definition_stored_with_a_surprise_key_is_refused_on_the_way_out(db: Session) -> None:
    """``jsonb`` will store anything. The decoder is what stops it being used."""
    definitions = sample_definitions()
    definitions["fields"][0]["surprise"] = "ignored by Postgres, not by us"
    version_id = seed_template_version(db, definitions)

    from esign.contracts import ValidationFailed

    with pytest.raises(ValidationFailed) as excinfo:
        definitions_from_json(read_back(db, version_id))
    assert excinfo.value.code == "template_definitions_malformed"


def test_a_published_version_cannot_have_its_definitions_rewritten(db: Session) -> None:
    """Which is why the decoder has to be strict: there is no fixing it afterwards."""
    version_id = seed_template_version(db, sample_definitions(), status="published")
    with pytest.raises(DBAPIError) as excinfo:
        db.execute(
            text("UPDATE template_versions SET fields = '[]'::jsonb WHERE id = :id"),
            {"id": version_id},
        )
    assert "immutable" in str(excinfo.value)


def test_rect_numbers_do_not_lose_precision_in_postgres(db: Session) -> None:
    """A rect that arrives a hundredth of a point off puts a mark a hundredth of a point off."""
    definitions = sample_definitions()
    definitions["fields"][0]["rect"] = {"x": 72.125, "y": 100.0625, "w": 200.03125, "h": 44.5}
    version_id = seed_template_version(db, definitions)

    decoded = definitions_from_json(read_back(db, version_id))
    rect = decoded.fields[0].rect
    assert (rect.x, rect.y, rect.w, rect.h) == (72.125, 100.0625, 200.03125, 44.5)
