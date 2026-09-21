"""Templates: the PDFs and definitions a host uploads ahead of time (SPEC sections 6 and 9).

Lifecycle: ``draft -> published -> retired``. A draft can be replaced by a newer draft version; a
published version is immutable (the schema's ``template_versions_guard`` trigger refuses anything
but ``published -> retired``). Publishing and retiring are recorded on the template's own audit
stream. Everything is scoped to the host in the query itself, so another host's template is simply
not there: ``not_found``, never ``forbidden``.

Used by the Host API and by ``esign templates import``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.config import Settings
from esign.contracts import (
    Actor,
    AuditLog,
    BlobService,
    Clock,
    Conflict,
    DocumentService,
    EventType,
    Host,
    NotFound,
    RequestContext,
    ValidationFailed,
)
from esign.documents import definitions_from_json, definitions_to_json
from esign.ids import advisory_lock_key, new_id
from esign.logging import get_logger

__all__ = ["TemplateService", "TemplateVersionView", "TemplateView"]

log = get_logger(__name__)

#: Template keys, role keys and field ids all reach the audit trail, which only takes slugs.
_KEY: Final = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,63}\Z")
_SLUG: Final = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
_MAX_NAME: Final = 200


@dataclass(frozen=True)
class TemplateVersionView:
    id: UUID
    version: int
    status: str
    pdf_sha256: bytes
    fields: Any
    prefill_fields: Any
    signer_roles: Any
    created_at: datetime
    published_at: datetime | None


@dataclass(frozen=True)
class TemplateView:
    id: UUID
    key: str
    name: str
    document_type: str
    created_at: datetime
    versions: tuple[TemplateVersionView, ...]


class TemplateService:
    def __init__(
        self, settings: Settings, clock: Clock, *, audit: AuditLog, blobs: BlobService, documents: DocumentService
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._audit = audit
        self._blobs = blobs
        self._documents = documents

    # ----------------------------------------------------------------- writes

    def create(
        self, db: Session, host: Host, *, key: str, name: str, document_type: str, pdf: bytes, definitions: Any
    ) -> TemplateView:
        """A new template with draft version 1."""
        if not _KEY.match(key or ""):
            raise ValidationFailed("template key must be a short lowercase slug", code="template_key_invalid")
        clean_name = (name or "").strip()
        if not clean_name or len(clean_name) > _MAX_NAME:
            raise ValidationFailed("template name is missing or too long", code="template_name_invalid")
        if not self._settings.is_approved_document_type(document_type):
            # SPEC section 1: out-of-scope document types are refused, not approximated.
            raise ValidationFailed("document type is not approved here", code="document_type_not_approved")

        self._lock(db, host, key)
        exists = db.execute(
            text("SELECT 1 FROM templates WHERE host_id = :host AND key = :key"), {"host": host.id, "key": key}
        ).first()
        if exists is not None:
            raise Conflict("a template with that key already exists", code="template_exists")

        template_id = new_id()
        now = self._clock.now()
        db.execute(
            text(
                "INSERT INTO templates (id, host_id, key, name, document_type, created_at) "
                "VALUES (:id, :host, :key, :name, :document_type, :now)"
            ),
            {
                "id": template_id,
                "host": host.id,
                "key": key,
                "name": clean_name,
                "document_type": document_type,
                "now": now,
            },
        )
        self._insert_version(db, template_id, 1, pdf, definitions, now)
        log.info("template.created", host_id=host.id, template_id=template_id, template_key=key, template_version=1)
        return self.get(db, host, key)

    def add_version(self, db: Session, host: Host, key: str, *, pdf: bytes, definitions: Any) -> TemplateView:
        """The next draft version. Earlier versions are untouched."""
        self._lock(db, host, key)
        template = self._template_row(db, host, key)
        latest = db.execute(
            text("SELECT COALESCE(MAX(version), 0) FROM template_versions WHERE template_id = :id"),
            {"id": template.id},
        ).scalar_one()
        version = int(latest) + 1
        self._insert_version(db, template.id, version, pdf, definitions, self._clock.now())
        log.info(
            "template.version_created",
            host_id=host.id,
            template_id=template.id,
            template_key=key,
            template_version=version,
        )
        return self.get(db, host, key)

    def publish(self, db: Session, host: Host, key: str, version: int, ctx: RequestContext) -> TemplateView:
        self._lock(db, host, key)
        template = self._template_row(db, host, key)
        row = self._version_row(db, template.id, version)
        if row.status != "draft":
            raise Conflict("only a draft can be published", code="template_not_draft")
        # Re-read and re-check what is about to become immutable. BlobService.get re-hashes.
        pdf = self._blobs.get(db, bytes(row.pdf_sha256))
        info = self._documents.inspect_template_pdf(pdf)
        now = self._clock.now()
        db.execute(
            text("UPDATE template_versions SET status = 'published', published_at = :now WHERE id = :id"),
            {"id": row.id, "now": now},
        )
        self._audit.append(
            db,
            stream_type="template",
            stream_id=template.id,
            event_type=EventType.TEMPLATE_PUBLISHED,
            actor=Actor(role="host"),
            ctx=ctx,
            document_sha256=bytes(row.pdf_sha256),
            data={
                "template_id": template.id,
                "template_key": key,
                "template_version": version,
                "template_version_id": row.id,
                "pdf_sha256": bytes(row.pdf_sha256),
                "page_count": info.page_count,
                "field_count": len(row.fields),
                "signer_role_count": len(row.signer_roles),
            },
        )
        log.info(
            "template.published", host_id=host.id, template_id=template.id, template_key=key, template_version=version
        )
        return self.get(db, host, key)

    def retire(self, db: Session, host: Host, key: str, version: int, ctx: RequestContext) -> TemplateView:
        self._lock(db, host, key)
        template = self._template_row(db, host, key)
        row = self._version_row(db, template.id, version)
        if row.status != "published":
            raise Conflict("only a published version can be retired", code="template_not_published")
        db.execute(text("UPDATE template_versions SET status = 'retired' WHERE id = :id"), {"id": row.id})
        self._audit.append(
            db,
            stream_type="template",
            stream_id=template.id,
            event_type=EventType.TEMPLATE_RETIRED,
            actor=Actor(role="host"),
            ctx=ctx,
            data={
                "template_id": template.id,
                "template_key": key,
                "template_version": version,
                "template_version_id": row.id,
            },
        )
        log.info(
            "template.retired", host_id=host.id, template_id=template.id, template_key=key, template_version=version
        )
        return self.get(db, host, key)

    # ----------------------------------------------------------------- reads

    def list(self, db: Session, host: Host) -> list[TemplateView]:
        keys = db.execute(text("SELECT key FROM templates WHERE host_id = :host ORDER BY key"), {"host": host.id}).all()
        return [self.get(db, host, str(row.key)) for row in keys]

    def get(self, db: Session, host: Host, key: str) -> TemplateView:
        template = self._template_row(db, host, key)
        versions = db.execute(
            text(
                "SELECT id, version, status, pdf_sha256, fields, prefill_fields, signer_roles, created_at, published_at "
                "FROM template_versions WHERE template_id = :id ORDER BY version"
            ),
            {"id": template.id},
        ).all()
        return TemplateView(
            id=template.id,
            key=str(template.key),
            name=str(template.name),
            document_type=str(template.document_type),
            created_at=template.created_at,
            versions=tuple(
                TemplateVersionView(
                    id=v.id,
                    version=int(v.version),
                    status=str(v.status),
                    pdf_sha256=bytes(v.pdf_sha256),
                    fields=v.fields,
                    prefill_fields=v.prefill_fields,
                    signer_roles=v.signer_roles,
                    created_at=v.created_at,
                    published_at=v.published_at,
                )
                for v in versions
            ),
        )

    # ----------------------------------------------------------------- internals

    def _lock(self, db: Session, host: Host, key: str) -> None:
        """Serialise writers per (host, key): two uploads must not both become version 2."""
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": advisory_lock_key("template", f"{host.id}:{key}")})

    def _template_row(self, db: Session, host: Host, key: str) -> Any:
        row = db.execute(
            text("SELECT id, key, name, document_type, created_at FROM templates WHERE host_id = :host AND key = :key"),
            {"host": host.id, "key": key},
        ).first()
        if row is None:
            raise NotFound("no such template", code="template_not_found")
        return row

    def _version_row(self, db: Session, template_id: UUID, version: int) -> Any:
        row = db.execute(
            text(
                "SELECT id, status, pdf_sha256, fields, signer_roles FROM template_versions "
                "WHERE template_id = :id AND version = :version FOR UPDATE"
            ),
            {"id": template_id, "version": version},
        ).first()
        if row is None:
            raise NotFound("no such template version", code="template_not_found")
        return row

    def _insert_version(
        self, db: Session, template_id: UUID, version: int, pdf: bytes, definitions: Any, now: datetime
    ) -> None:
        info = self._documents.inspect_template_pdf(pdf)
        decoded = definitions_from_json(definitions)
        self._documents.validate_definitions(info, decoded.fields, decoded.prefill_fields, decoded.signer_roles)
        bad = [r.key for r in decoded.signer_roles if not _SLUG.match(r.key)]
        bad += [f.id for f in decoded.fields if not _SLUG.match(f.id)]
        if bad:
            # They are recorded in the audit trail, which refuses anything that is not a slug --
            # better refused at upload than when the first person signs.
            raise ValidationFailed("role keys and field ids must be lowercase slugs", code="definition_key_invalid")
        ref = self._blobs.put(db, pdf, kind="template_pdf")
        stored = definitions_to_json(decoded.fields, decoded.prefill_fields, decoded.signer_roles)
        db.execute(
            text(
                "INSERT INTO template_versions (id, template_id, version, status, pdf_sha256, fields, prefill_fields, "
                "  signer_roles, created_at) "
                "VALUES (:id, :template_id, :version, 'draft', :sha, CAST(:fields AS jsonb), "
                "  CAST(:prefill AS jsonb), CAST(:roles AS jsonb), :now)"
            ),
            {
                "id": new_id(),
                "template_id": template_id,
                "version": version,
                "sha": ref.sha256,
                "fields": json.dumps(stored["fields"]),
                "prefill": json.dumps(stored["prefill_fields"]),
                "roles": json.dumps(stored["signer_roles"]),
                "now": now,
            },
        )
