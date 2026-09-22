"""Row access for the archives module (Addendum 1 A).

Plain SQL against ``migrations/0001_schema.sql`` as amended by ``0700_addendum_1.sql``, in the
same style as the envelopes module: no ORM models, every value a bound parameter, no function
commits. The only rows this module writes are the ones a paper archive is made of -- the envelope,
its single ``scan`` revision, and its seal job.

The attestation is stored as jsonb with exactly the five keys ``envelopes_attestation_shape``
allows. The names inside it are PHI: they reach the database, the cover page and the certificate,
and nothing else (``archive.attested`` records a count).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import Attestation, EnvelopeStatus

__all__ = [
    "SupersededRow",
    "attestation_json",
    "enqueue_seal_job",
    "insert_archive_envelope",
    "insert_scan_revision",
    "lock_envelope",
    "mark_pending_seal",
    "superseded_by",
]


@dataclass(frozen=True)
class SupersededRow:
    """The little an archive needs to know about the envelope it corrects."""

    id: UUID
    host_id: UUID
    status: EnvelopeStatus


def attestation_json(attestation: Attestation) -> dict[str, Any]:
    """The jsonb shape ``envelopes_attestation_shape`` requires: exactly these five keys."""
    return {
        "staff_user_id": attestation.staff_user_id,
        "staff_display_name": attestation.staff_display_name,
        "statement": attestation.statement,
        "original_disposition": attestation.original_disposition,
        "paper_signers": [
            {"display_name": signer.display_name, "capacity": signer.capacity} for signer in attestation.paper_signers
        ],
    }


def lock_envelope(db: Session, envelope_id: UUID) -> SupersededRow | None:
    """``SELECT ... FOR UPDATE`` on the envelope a new archive would supersede."""
    row = db.execute(
        text("SELECT id, host_id, status FROM envelopes WHERE id = :id FOR UPDATE"),
        {"id": envelope_id},
    ).one_or_none()
    if row is None:
        return None
    return SupersededRow(
        id=row.id if isinstance(row.id, UUID) else UUID(str(row.id)),
        host_id=row.host_id if isinstance(row.host_id, UUID) else UUID(str(row.host_id)),
        status=str(row.status),  # type: ignore[arg-type]  # CHECK-constrained in the schema
    )


def superseded_by(db: Session, envelope_id: UUID) -> UUID | None:
    row = db.execute(
        text("SELECT id FROM envelopes WHERE supersedes_envelope_id = :id ORDER BY created_at LIMIT 1"),
        {"id": envelope_id},
    ).one_or_none()
    if row is None:
        return None
    return row.id if isinstance(row.id, UUID) else UUID(str(row.id))


def insert_archive_envelope(
    db: Session,
    *,
    envelope_id: UUID,
    host_id: UUID,
    document_type: str,
    patient_ref: str,
    host_document_ref: str | None,
    scan_sha256: bytes,
    paper_signed_on: date,
    attestation: dict[str, Any],
    attested_at: datetime,
    supersedes_envelope_id: UUID | None,
    expires_at: datetime,
    created_at: datetime,
) -> None:
    """The envelope row for a filed scan: no template, no signing order, no signers.

    It starts ``created`` and is moved to ``completed_pending_seal`` by ``mark_pending_seal`` in
    the same transaction, so the row goes through the state the audit trail describes rather than
    appearing in a state nothing explains.
    """
    db.execute(
        text(
            "INSERT INTO envelopes (id, host_id, template_version_id, document_type, patient_ref, "
            "  host_document_ref, signing_order, kind, status, presented_sha256, current_revision_sha256, "
            "  supersedes_envelope_id, expires_at, created_at, paper_signed_on, attestation, attested_at) "
            "VALUES (:id, :host_id, NULL, :document_type, :patient_ref, :host_document_ref, NULL, "
            "  'paper_archive', 'created', :sha, :sha, :supersedes, :expires_at, :created_at, "
            "  :paper_signed_on, CAST(:attestation AS jsonb), :attested_at)"
        ),
        {
            "id": envelope_id,
            "host_id": host_id,
            "document_type": document_type,
            "patient_ref": patient_ref,
            "host_document_ref": host_document_ref,
            "sha": scan_sha256,
            "supersedes": supersedes_envelope_id,
            "expires_at": expires_at,
            "created_at": created_at,
            "paper_signed_on": paper_signed_on,
            "attestation": _dumps(attestation),
            "attested_at": attested_at,
        },
    )


def insert_scan_revision(
    db: Session, *, revision_id: UUID, envelope_id: UUID, sha256: bytes, page_count: int, created_at: datetime
) -> None:
    """Revision 1 of a paper archive: the scan as it was received, kind ``scan``.

    Addendum 2 persists ``page_count`` on every revision as it is written, so that nothing later
    re-parses the PDF to count its pages. The archive service has already counted this one while
    inspecting the scan, so the number costs nothing here; readers fall back to counting when the
    column is NULL, and this is the last writer that was leaving it so.
    """
    db.execute(
        text(
            "INSERT INTO document_revisions "
            "(id, envelope_id, revision_no, kind, sha256, signer_id, created_at, page_count) "
            "VALUES (:id, :env, 1, 'scan', :sha, NULL, :at, :pages)"
        ),
        {"id": revision_id, "env": envelope_id, "sha": sha256, "at": created_at, "pages": page_count},
    )


def mark_pending_seal(db: Session, envelope_id: UUID, at: datetime) -> None:
    """``created -> completed_pending_seal``. Nobody signs an archive, so filing completes it."""
    db.execute(
        text("UPDATE envelopes SET status = 'completed_pending_seal', completed_at = :at WHERE id = :id"),
        {"id": envelope_id, "at": at},
    )


def enqueue_seal_job(db: Session, envelope_id: UUID, at: datetime) -> None:
    db.execute(
        text(
            "INSERT INTO seal_jobs (envelope_id, attempts, next_attempt_at) VALUES (:id, 0, :at) "
            "ON CONFLICT (envelope_id) DO NOTHING"
        ),
        {"id": envelope_id, "at": at},
    )


def _dumps(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False)
